# TCP Timestamp Proxy

A high-performance TCP proxy designed for high-frequency trading (HFT) environments that strips TCP Timestamp options (TSopt) from connections to prevent timing information leakage.

## Overview

This proxy addresses a critical security concern in HFT colocated environments where TCP timestamps can leak sensitive timing information about:

- Host CPU frequency and scaling behavior
- Network interface card (NIC) latency characteristics
- System load and performance patterns
- Kernel scheduling behavior

Such timing side-channels can be exploited by competitors to infer trading strategies or gain unfair latency advantages.

## Features

- **Timestamp Stripping**: Controls TCP timestamp options on outgoing connections
- **High Performance**: Optimized for low-latency operation with async I/O
- **Production Ready**: Includes comprehensive error handling and monitoring
- **No Root Required**: Runs in userspace without special privileges
- **Configurable**: Command-line options for all settings
- **Optional Spoofing**: Can inject static timestamp patterns

## Technical Details

### Limitations

This is a **userspace proxy** that terminates TCP connections on both sides. It cannot directly modify packets in-flight (which would require raw socket access and typically root privileges). Instead, it:

1. Accepts client connections
2. Establishes new connections to target servers with controlled socket options
3. Forwards data bidirectionally with minimal copying
4. Ensures no timestamp options are used in the proxy-to-server connections

### Performance Optimizations

- **TCP_NODELAY**: Disables Nagle's algorithm for minimal latency
- **SO_REUSEPORT**: Enables multiple worker processes (future enhancement)
- **TCP_QUICKACK**: Immediate ACK transmission on Linux
- **TCP_USER_TIMEOUT**: Fast failure detection
- **Async I/O**: Tokio-based event loop for high concurrency
- **Zero-copy**: Minimal buffer copying in data forwarding

## Usage

### Basic Usage

```bash
# Forward connections from local port 8080 to target server
cargo run -- --port 8080 --target example.com:80

# With timestamp spoofing enabled
cargo run -- --port 8080 --target example.com:80 --spoof-timestamps --static-timestamp 12345
```

### Command Line Options

```
High-performance TCP proxy designed for HFT environments

Usage: tcp-proxy [OPTIONS] --target <HOST:PORT>

Options:
  -p, --port <PORT>                    Local port to bind the proxy to [default: 8080]
  -t, --target <HOST:PORT>            Target server address to forward connections to
      --spoof-timestamps              Enable timestamp spoofing with static pattern
      --static-timestamp <TIMESTAMP>  Static timestamp value to use when spoofing (0 = disable timestamps) [default: 0]
      --max-connections <MAX>          Maximum number of concurrent connections [default: 1000]
      --buffer-size <SIZE>            Buffer size for data forwarding (bytes) [default: 65536]
  -h, --help                          Print help
  -V, --version                       Print version
```

### Example Configurations

#### Web Server Proxy
```bash
# Proxy HTTP traffic to a web server
cargo run -- --port 8080 --target web-server.example.com:80
```

#### Trading System Proxy
```bash
# High-performance proxy for trading connections
cargo run -- --port 9999 --target exchange.example.com:443 \
  --buffer-size 32768 --max-connections 100
```

#### Timestamp Spoofing
```bash
# Proxy with static timestamp injection
cargo run -- --port 8080 --target server.example.com:80 \
  --spoof-timestamps --static-timestamp 0
```

## Building

### Prerequisites

- Rust 1.70+ (for async support)
- Linux (for platform-specific socket options)

### Build Commands

```bash
# Development build
cargo build

# Release build (optimized for production)
cargo build --release

# Run tests
cargo test

# Run with debug logging
RUST_LOG=debug cargo run -- --port 8080 --target example.com:80
```

### Installation

```bash
# Install to system
cargo install --path .

# Or copy binary manually
cp target/release/tcp-proxy /usr/local/bin/
```

## Security Considerations

### Timestamp Leakage Risks

TCP timestamps (RFC 7323) can reveal:

1. **System Characteristics**:
   - CPU frequency scaling patterns
   - Kernel tick rate (HZ value)
   - System uptime and boot patterns

2. **Network Timing**:
   - NIC interrupt coalescence settings
   - Network stack processing delays
   - Link-layer timing variations

3. **Operational Security**:
   - Host fingerprinting for competitive intelligence
   - Timing side-channel attacks
   - Covert channel establishment

### Mitigation Strategies

1. **Timestamp Stripping** (this proxy): Remove timestamps from connections
2. **Kernel Configuration**: Set `net.ipv4.tcp_timestamps=0` (requires root)
3. **Firewall Rules**: Strip timestamp options using netfilter/iptables
4. **Network Isolation**: Use dedicated network segments for sensitive traffic

## Performance Tuning

### Operating System

```bash
# Disable TCP timestamps system-wide (requires root)
echo 0 > /proc/sys/net/ipv4/tcp_timestamps

# Optimize network stack for low latency
echo 1 > /proc/sys/net/ipv4/tcp_low_latency

# Increase connection limits
echo 65535 > /proc/sys/net/core/somaxconn
```

### Application Configuration

```bash
# Increase buffer sizes for high-throughput applications
--buffer-size 131072

# Reduce connection limits for low-latency scenarios
--max-connections 50

# Use small buffer sizes for minimal latency
--buffer-size 8192
```


### Metrics

The proxy logs key metrics:
- Connection count
- Data transfer rates
- Error rates
- Timestamp detection events

## Technical References

- **RFC 7323**: TCP Extensions for High Performance
- **RFC 1323**: TCP Extensions for High Performance (obsoleted)
- **Linux TCP Implementation**: `net/ipv4/tcp_output.c`
- **TCP Timestamp Security**: Various CVEs related to timestamp leakage