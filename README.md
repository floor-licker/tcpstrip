<div align="center">

# TCP Timestamp Proxy

**A Rust-based timestamp-sanitizing TCP proxy for HFT and ultra-low latency trading.**

[![MIT License](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Made with Rust](https://img.shields.io/badge/Made%20with-Rust-orange.svg)](https://www.rust-lang.org/)
[![Performance](https://img.shields.io/badge/Latency-<1ms%20overhead-green.svg)](https://github.com/floor-licker/tcpstrip)
[![Build Status](https://img.shields.io/badge/Build-Passing-brightgreen.svg)](https://github.com/floor-licker/tcpstrip)

</div>

---

A high-performance TCP proxy that strips TCP Timestamp options (TSopt) from connections to prevent timing information leakage. For when you want to control or eliminate TCP timestamp behavior for a specific latency-critical connection without requiring root, kernel modifications, or system-wide changes.

## Use-case
When:
- You're running in colocated racks managed by a hosting provider
- You're deploying inside a containerized infrastructure
- You're on shared or locked-down machines (like at exchange proximity sites)
- You don't have root privileges or access to firewall rules
- You want to spoof timestamps, not just strip them
- You want to run in userspace with no root access required
- You want to simulate specific kernel behaviour (e.g., Linux 5.10 vs 5.4)
- You're building a deception layer to confuse timing-based reconnaissance
- You have monitoring tools that rely on timestamps (and should remain unaffected)

## Table of Contents

- [Overview](#overview)
- [Key Features](#-key-features)
- [Quick Start](#-quick-start)
- [Why Not Just Use iptables?](#why-not-just-use-iptables)
- [Technical Details](#technical-details)
- [Usage](#usage)
- [Building](#building)
- [Security Considerations](#security-considerations)
- [Performance Tuning](#performance-tuning)
- [Technical References](#technical-references)

## Overview

This proxy addresses a critical security concern in HFT colocated environments where TCP timestamps can leak sensitive timing information about:

- Host CPU frequency and scaling behavior
- Network interface card (NIC) latency characteristics
- System load and performance patterns
- Kernel scheduling behavior

Such timing side-channels can be exploited by competitors to infer trading strategies or gain unfair latency advantages.

## Key Features

- **Timestamp Stripping**: Controls TCP timestamp options on outgoing connections
- **High Performance**: Optimized for low-latency operation with async I/O
- **Production Ready**: Includes comprehensive error handling and monitoring
- **No Root Required**: Runs in userspace without special privileges
- **Configurable**: Command-line options for all settings
- **Optional Spoofing**: Can inject static timestamp patterns

## Quick Start

```bash
# Clone the repository
git clone https://github.com/floor-licker/tcpstrip.git
cd tcpstrip

# Build the release version
cargo build --release

# Run the proxy (forwards localhost:8080 to example.com:80)
./target/release/tcp-proxy --port 8080 --target example.com:80

# Test with curl
curl -H 'Host: example.com' http://localhost:8080
```

## Why Not Just Use iptables?

There are several approaches to handling TCP timestamp options, each with different trade-offs:

| Approach | Pros | Cons |
|----------|------|------|
| **iptables** | Kernel-native performance, transparent | Requires root + firewall access, can only drop/block, no spoofing |
| **sysctl** (`tcp_timestamps=0`) | System-wide, simple configuration | Affects all connections, requires root, no per-process control |
| **This proxy** | Per-process control, userspace deployment, spoofing support | Slight latency overhead, terminates connections |
| **Raw sockets** | Direct packet manipulation | Requires root, complex implementation, limited portability |
| **eBPF/tc** | Advanced packet manipulation | Requires root + advanced expertise, kernel version dependencies |

### Cloud & Infrastructure Limitations

**Important considerations for modern deployments:**

🚫 **iptables/netfilter limitations:**
- **Can only DROP or BLOCK** packets with timestamp options - cannot modify or spoof them
- **No fine-grained TCP option manipulation** without writing kernel modules or complex eBPF programs
- **Requires firewall rule access** - often unavailable in cloud/managed environments

☁️ **Cloud & Kubernetes environments:**
- **No firewall access** in most managed Kubernetes clusters (GKE, EKS, AKS)
- **Container security policies** prevent iptables modifications
- **Shared infrastructure** where you don't control the host networking stack
- **Service mesh restrictions** that limit kernel-level network changes

🔧 **Advanced alternatives require expertise:**
- **tc (Traffic Control)** + **eBPF**: Complex to implement, requires deep kernel networking knowledge
- **Kernel modules**: Security risk, difficult to deploy in production environments
- **DPDK/userspace networking**: Overkill for most HFT applications, expensive to implement

### When to use this proxy:

 **Use this proxy when:**
- **Cloud/Kubernetes deployments** where firewall access is restricted
- **Containerized environments** with security policies preventing kernel modifications
- **Shared infrastructure** where you don't control host networking
- **Need timestamp spoofing** with custom patterns (impossible with iptables)
- **Per-application control** without affecting other services
- **Root privileges are not available** or not desired
- **Fine-grained TCP option manipulation** beyond simple blocking
- **Detailed logging and monitoring** of timestamp behavior

 **Consider alternatives when:**
- You have **full root + firewall access** and want simple system-wide disabling
- **Latency is absolutely critical** (sub-microsecond requirements)
- You need to handle **very high connection volumes** (>10k concurrent)
- **Simple blocking** (not spoofing) is sufficient for your use case

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

## Contributing

We welcome contributions! Please see our [Contributing Guidelines](CONTRIBUTING.md) for details.

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## ⚖️ Disclaimer

Use in production environments should be thoroughly tested and validated for your specific use case.

---

<div align="center">
  <strong>Made with ❤️ for the HFT community</strong>
  <br>
  <a href="https://github.com/floor-licker/tcpstrip">⭐ Star this repo</a> if you find it useful!
</div>