#!/bin/bash

# TCP Timestamp Proxy - Basic Usage Examples
# This script demonstrates various ways to use the TCP proxy

echo "TCP Timestamp Proxy - Usage Examples"
echo "====================================="

# Example 1: Basic HTTP proxy
echo "Example 1: Basic HTTP proxy"
echo "Forward HTTP traffic through the proxy:"
echo "  ./target/release/tcp-proxy --port 8080 --target httpbin.org:80"
echo ""

# Example 2: HTTPS proxy  
echo "Example 2: HTTPS proxy"
echo "Forward HTTPS traffic through the proxy:"
echo "  ./target/release/tcp-proxy --port 8443 --target httpbin.org:443"
echo ""

# Example 3: High-performance trading proxy
echo "Example 3: High-performance trading proxy"
echo "Optimized for low-latency trading connections:"
echo "  ./target/release/tcp-proxy --port 9999 --target exchange.example.com:443 \\"
echo "    --buffer-size 32768 --max-connections 100"
echo ""

# Example 4: Timestamp spoofing
echo "Example 4: Timestamp spoofing"
echo "Proxy with static timestamp injection:"
echo "  ./target/release/tcp-proxy --port 8080 --target server.example.com:80 \\"
echo "    --spoof-timestamps --static-timestamp 0"
echo ""

# Example 5: Debug mode
echo "Example 5: Debug mode"
echo "Run with verbose logging:"
echo "  RUST_LOG=debug ./target/release/tcp-proxy --port 8080 --target example.com:80"
echo ""

# Example 6: Test with curl
echo "Example 6: Test with curl"
echo "Start the proxy and test with curl:"
echo "  # Terminal 1:"
echo "  ./target/release/tcp-proxy --port 8080 --target httpbin.org:80"
echo ""
echo "  # Terminal 2:"
echo "  curl -H 'Host: httpbin.org' http://localhost:8080/get"
echo ""

echo "For more information, see the README.md file." 