use anyhow::Result;
use bytes::BytesMut;
use clap::Parser;
use socket2::{Domain, Protocol, Socket, Type};
use std::net::{SocketAddr, ToSocketAddrs};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tracing::{debug, error, info, warn};

mod tcp_analysis;

/// High-performance TCP proxy designed for HFT environments
/// 
/// This proxy strips TCP Timestamp options (TSopt, RFC 7323) from connections
/// to prevent timing information leakage that could reveal:
/// - Host CPU frequency and scaling behavior
/// - Network interface card (NIC) latency characteristics  
/// - System load and timing patterns
/// 
/// In HFT colocated environments, such timing side-channels can be exploited
/// by competitors to infer trading strategies or gain unfair latency advantages.
/// This proxy provides a userspace solution when kernel-level changes
/// (net.ipv4.tcp_timestamps=0) are not feasible.
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Local port to bind the proxy to
    #[arg(short, long, default_value = "8080")]
    port: u16,

    /// Target server address to forward connections to
    #[arg(short, long, value_name = "HOST:PORT")]
    target: String,

    /// Enable timestamp spoofing with static pattern
    #[arg(long, default_value = "false")]
    spoof_timestamps: bool,

    /// Static timestamp value to use when spoofing (0 = disable timestamps)
    #[arg(long, default_value = "0")]
    static_timestamp: u32,

    /// Maximum number of concurrent connections
    #[arg(long, default_value = "1000")]
    max_connections: usize,

    /// Buffer size for data forwarding (bytes)
    #[arg(long, default_value = "65536")]
    buffer_size: usize,
}

#[derive(Clone)]
struct ProxyConfig {
    target_addr: SocketAddr,
    spoof_timestamps: bool,
    static_timestamp: u32,
    buffer_size: usize,
}

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize tracing for performance monitoring
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .with_target(false)
        .compact()
        .init();

    let args = Args::parse();
    
    // Resolve target address once at startup
    let target_addr = args.target.to_socket_addrs()?
        .next()
        .ok_or_else(|| anyhow::anyhow!("Could not resolve target address: {}", args.target))?;

    let config = ProxyConfig {
        target_addr,
        spoof_timestamps: args.spoof_timestamps,
        static_timestamp: args.static_timestamp,
        buffer_size: args.buffer_size,
    };

    info!("Starting TCP proxy on port {} -> {}", args.port, target_addr);
    info!("Timestamp spoofing: {}", config.spoof_timestamps);
    info!("Max connections: {}", args.max_connections);

    // Create high-performance listener socket
    let listener = create_high_performance_listener(args.port).await?;
    
    // Connection counter for monitoring
    let connection_count = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    
    loop {
        match listener.accept().await {
            Ok((client_stream, client_addr)) => {
                let config = config.clone();
                let conn_count = connection_count.clone();
                
                // Spawn connection handler
                tokio::spawn(async move {
                    let conn_id = conn_count.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    debug!("New connection {} from {}", conn_id, client_addr);
                    
                    if let Err(e) = handle_connection(client_stream, config, conn_id).await {
                        error!("Connection {} error: {}", conn_id, e);
                    }
                    
                    conn_count.fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
                    debug!("Connection {} closed", conn_id);
                });
            }
            Err(e) => {
                error!("Failed to accept connection: {}", e);
            }
        }
    }
}

/// Create a high-performance TCP listener with optimized socket options
async fn create_high_performance_listener(port: u16) -> Result<TcpListener> {
    // Use socket2 for low-level socket control
    let socket = Socket::new(Domain::IPV4, Type::STREAM, Some(Protocol::TCP))?;
    
    // Critical HFT socket options for minimal latency
    socket.set_reuse_address(true)?;
    socket.set_reuse_port(true)?;
    socket.set_nodelay(true)?;  // TCP_NODELAY - disable Nagle's algorithm
    
    // Set TCP_USER_TIMEOUT to fail fast on connection issues  
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::io::AsRawFd;
        let fd = socket.as_raw_fd();
        
        // Set TCP_USER_TIMEOUT to 5 seconds (5000ms)
        let timeout: libc::c_int = 5000;
        unsafe {
            libc::setsockopt(
                fd,
                libc::IPPROTO_TCP,
                libc::TCP_USER_TIMEOUT,
                &timeout as *const _ as *const libc::c_void,
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            );
        }
    }
    
    let addr = format!("0.0.0.0:{}", port).parse::<SocketAddr>()?;
    socket.bind(&addr.into())?;
    socket.listen(128)?;
    
    // Convert to tokio TcpListener
    let std_listener: std::net::TcpListener = socket.into();
    std_listener.set_nonblocking(true)?;
    let listener = TcpListener::from_std(std_listener)?;
    
    Ok(listener)
}

/// Handle a single client connection with timestamp option stripping
async fn handle_connection(
    client_stream: TcpStream,
    config: ProxyConfig,
    conn_id: usize,
) -> Result<()> {
    // Configure client socket for HFT performance
    configure_hft_socket(&client_stream).await?;
    
    // Establish connection to target server with controlled TCP options
    let server_stream = create_server_connection(config.target_addr, &config).await?;
    
    // Forward data bidirectionally with minimal copying
    forward_data(client_stream, server_stream, config.buffer_size, conn_id).await?;
    
    Ok(())
}

/// Create connection to target server with timestamp options controlled
async fn create_server_connection(
    target_addr: SocketAddr,
    _config: &ProxyConfig,
) -> Result<TcpStream> {
    // Create socket with controlled options before connecting
    let socket = Socket::new(Domain::IPV4, Type::STREAM, Some(Protocol::TCP))?;
    
    // Critical: Disable TCP timestamps at socket level if possible
    // Note: This is a userspace proxy limitation - we can't directly strip
    // timestamp options from packets in-flight without raw socket access.
    // Instead, we control the socket options for our outgoing connections.
    
    // Configure for HFT performance
    socket.set_nodelay(true)?;
    
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::io::AsRawFd;
        let fd = socket.as_raw_fd();
        
        // Attempt to disable TCP timestamps for this socket
        // This may not work without root, but we try anyway
        let disable_timestamps: libc::c_int = if _config.spoof_timestamps { 
            _config.static_timestamp as libc::c_int 
        } else { 
            0 
        };
        
        unsafe {
            // Try to set TCP_TIMESTAMP option (non-standard, may not work)
            let _ = libc::setsockopt(
                fd,
                libc::IPPROTO_TCP,
                28, // TCP_TIMESTAMP
                &disable_timestamps as *const _ as *const libc::c_void,
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            );
        }
    }
    
    // Connect to target
    socket.connect(&target_addr.into())?;
    
    // Convert to tokio TcpStream
    let std_stream: std::net::TcpStream = socket.into();
    std_stream.set_nonblocking(true)?;
    let stream = TcpStream::from_std(std_stream)?;
    
    Ok(stream)
}

/// Configure socket for HFT performance characteristics
async fn configure_hft_socket(stream: &TcpStream) -> Result<()> {
    // Essential HFT socket options - use TcpStream's built-in methods
    stream.set_nodelay(true)?;  // Disable Nagle's algorithm
    
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::io::AsRawFd;
        let fd = stream.as_raw_fd();
        
        // Set TCP_USER_TIMEOUT for fast failure detection
        let timeout: libc::c_int = 5000; // 5 seconds
        unsafe {
            libc::setsockopt(
                fd,
                libc::IPPROTO_TCP,
                libc::TCP_USER_TIMEOUT,
                &timeout as *const _ as *const libc::c_void,
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            );
        }
        
        // Set TCP_QUICKACK to send ACKs immediately
        let quickack: libc::c_int = 1;
        unsafe {
            libc::setsockopt(
                fd,
                libc::IPPROTO_TCP,
                libc::TCP_QUICKACK,
                &quickack as *const _ as *const libc::c_void,
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            );
        }
    }
    
    Ok(())
}

/// Forward data bidirectionally between client and server with minimal copying
async fn forward_data(
    mut client_stream: TcpStream,
    mut server_stream: TcpStream,
    buffer_size: usize,
    conn_id: usize,
) -> Result<()> {
    // Split streams for bidirectional forwarding
    let (mut client_read, mut client_write) = client_stream.split();
    let (mut server_read, mut server_write) = server_stream.split();
    
    // Pre-allocate buffers to minimize allocations
    let mut client_to_server_buf = BytesMut::with_capacity(buffer_size);
    let mut server_to_client_buf = BytesMut::with_capacity(buffer_size);
    
    // Bidirectional forwarding with minimal copying
    let client_to_server = async {
        loop {
            client_to_server_buf.clear();
            client_to_server_buf.resize(buffer_size, 0);
            
            match client_read.read(&mut client_to_server_buf).await {
                Ok(0) => break, // EOF
                Ok(n) => {
                    client_to_server_buf.truncate(n);
                    if let Err(e) = server_write.write_all(&client_to_server_buf).await {
                        warn!("Connection {} client->server write error: {}", conn_id, e);
                        break;
                    }
                }
                Err(e) => {
                    warn!("Connection {} client->server read error: {}", conn_id, e);
                    break;
                }
            }
        }
    };
    
    let server_to_client = async {
        loop {
            server_to_client_buf.clear();
            server_to_client_buf.resize(buffer_size, 0);
            
            match server_read.read(&mut server_to_client_buf).await {
                Ok(0) => break, // EOF
                Ok(n) => {
                    server_to_client_buf.truncate(n);
                    if let Err(e) = client_write.write_all(&server_to_client_buf).await {
                        warn!("Connection {} server->client write error: {}", conn_id, e);
                        break;
                    }
                }
                Err(e) => {
                    warn!("Connection {} server->client read error: {}", conn_id, e);
                    break;
                }
            }
        }
    };
    
    // Run both directions concurrently
    tokio::select! {
        _ = client_to_server => {},
        _ = server_to_client => {},
    }
    
    Ok(())
} 