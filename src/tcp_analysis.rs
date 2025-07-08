/// TCP packet analysis and timestamp option handling
/// 
/// This module provides utilities for analyzing TCP packets and handling
/// timestamp options as specified in RFC 7323. In HFT environments, TCP
/// timestamps can leak sensitive timing information that reveals:
/// 
/// 1. Host timing characteristics:
///    - CPU frequency scaling patterns
///    - System load and performance variations
///    - Kernel scheduling behavior
/// 
/// 2. Network timing patterns:
///    - NIC interrupt coalescence settings
///    - Network stack processing delays
///    - Link-layer timing variations
/// 
/// 3. Security implications:
///    - Host fingerprinting based on timestamp generation
///    - Timing side-channel attacks
///    - Covert channel establishment
/// 
/// References:
/// - RFC 7323: TCP Extensions for High Performance
/// - RFC 1323: TCP Extensions for High Performance (obsoleted by RFC 7323)
/// - Linux kernel: net/ipv4/tcp_output.c (timestamp generation)

use tracing::{debug, warn};

/// TCP option types as defined in RFC 793 and extensions
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum TcpOptionType {
    EndOfOptionList = 0,
    NoOperation = 1,
    MaximumSegmentSize = 2,
    WindowScale = 3,
    SackPermitted = 4,
    Sack = 5,
    Timestamp = 8,  // RFC 7323 - This is our primary concern
    Unknown(u8),
}

impl From<u8> for TcpOptionType {
    fn from(value: u8) -> Self {
        match value {
            0 => TcpOptionType::EndOfOptionList,
            1 => TcpOptionType::NoOperation,
            2 => TcpOptionType::MaximumSegmentSize,
            3 => TcpOptionType::WindowScale,
            4 => TcpOptionType::SackPermitted,
            5 => TcpOptionType::Sack,
            8 => TcpOptionType::Timestamp,
            other => TcpOptionType::Unknown(other),
        }
    }
}

/// TCP Timestamp Option structure (RFC 7323 Section 3.2)
/// 
/// The timestamp option format is:
/// 
/// +-------+-------+---------------------+---------------------+
/// | Kind  | Length|   TSval (32 bits)   |   TSecr (32 bits)   |
/// +-------+-------+---------------------+---------------------+
///     8       10    Timestamp Value        Timestamp Echo Reply
/// 
/// Where:
/// - Kind: 8 (timestamp option)
/// - Length: 10 (option header + 8 bytes of timestamp data)
/// - TSval: Timestamp value (sender's view of time)
/// - TSecr: Timestamp echo reply (echoed from previous segment)
#[derive(Debug, Clone, Copy)]
pub struct TcpTimestamp {
    pub ts_val: u32,    // Timestamp value
    pub ts_ecr: u32,    // Timestamp echo reply
}

/// Parsed TCP option
#[derive(Debug, Clone)]
pub struct TcpOption {
    pub kind: TcpOptionType,
    pub length: u8,
    pub data: Vec<u8>,
}

/// Results of TCP packet analysis
#[derive(Debug, Clone)]
pub struct TcpAnalysisResult {
    pub has_timestamp: bool,
    pub timestamp: Option<TcpTimestamp>,
    pub options: Vec<TcpOption>,
    pub fingerprint_risk: FingerprintRisk,
}

/// Risk assessment for TCP fingerprinting
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FingerprintRisk {
    Low,      // No timestamp options present
    Medium,   // Timestamp present but values appear randomized
    High,     // Timestamp present with predictable patterns
    Critical, // Timestamp reveals clear system characteristics
}

/// Parse TCP options from a packet
/// 
/// This function parses TCP options from the TCP header. In a real implementation,
/// this would require raw socket access to inspect packets in-flight. For our
/// userspace proxy, we use this for analysis and monitoring purposes.
pub fn parse_tcp_options(options_data: &[u8]) -> Vec<TcpOption> {
    let mut options = Vec::new();
    let mut pos = 0;
    
    while pos < options_data.len() {
        let kind = TcpOptionType::from(options_data[pos]);
        
        match kind {
            TcpOptionType::EndOfOptionList => break,
            TcpOptionType::NoOperation => {
                options.push(TcpOption {
                    kind,
                    length: 1,
                    data: vec![],
                });
                pos += 1;
            }
            _ => {
                if pos + 1 >= options_data.len() {
                    warn!("Malformed TCP option: truncated length field");
                    break;
                }
                
                let length = options_data[pos + 1];
                if length < 2 {
                    warn!("Invalid TCP option length: {}", length);
                    break;
                }
                
                if pos + length as usize > options_data.len() {
                    warn!("TCP option extends beyond options field");
                    break;
                }
                
                let data = if length > 2 {
                    options_data[pos + 2..pos + length as usize].to_vec()
                } else {
                    vec![]
                };
                
                options.push(TcpOption {
                    kind,
                    length,
                    data,
                });
                
                pos += length as usize;
            }
        }
    }
    
    options
}

/// Extract timestamp from TCP timestamp option
pub fn extract_timestamp(option: &TcpOption) -> Option<TcpTimestamp> {
    if option.kind != TcpOptionType::Timestamp || option.data.len() != 8 {
        return None;
    }
    
    // Parse 32-bit timestamp values (big-endian)
    let ts_val = u32::from_be_bytes([
        option.data[0], option.data[1], option.data[2], option.data[3]
    ]);
    
    let ts_ecr = u32::from_be_bytes([
        option.data[4], option.data[5], option.data[6], option.data[7]
    ]);
    
    Some(TcpTimestamp { ts_val, ts_ecr })
}

/// Analyze TCP packet for timestamp options and fingerprinting risks
pub fn analyze_tcp_packet(options_data: &[u8]) -> TcpAnalysisResult {
    let options = parse_tcp_options(options_data);
    
    let mut has_timestamp = false;
    let mut timestamp = None;
    let mut fingerprint_risk = FingerprintRisk::Low;
    
    for option in &options {
        if option.kind == TcpOptionType::Timestamp {
            has_timestamp = true;
            timestamp = extract_timestamp(option);
            
            if let Some(ts) = timestamp {
                // Analyze timestamp for fingerprinting risks
                fingerprint_risk = assess_timestamp_risk(ts);
                
                debug!("TCP timestamp detected: TSval={}, TSecr={}, risk={:?}", 
                       ts.ts_val, ts.ts_ecr, fingerprint_risk);
            }
        }
    }
    
    TcpAnalysisResult {
        has_timestamp,
        timestamp,
        options,
        fingerprint_risk,
    }
}

/// Assess fingerprinting risk based on timestamp patterns
/// 
/// This function analyzes timestamp values to determine the risk of
/// host fingerprinting. Different operating systems and configurations
/// generate timestamps with distinct patterns:
/// 
/// - Linux: Uses jiffies (HZ-based) or high-resolution timers
/// - Windows: Uses performance counters
/// - FreeBSD: Uses tick-based timestamps
/// - Virtualized environments: May show timing artifacts
fn assess_timestamp_risk(ts: TcpTimestamp) -> FingerprintRisk {
    // Simple heuristics for timestamp analysis
    // In a production system, this would use more sophisticated analysis
    
    let ts_val = ts.ts_val;
    
    // Check for common timestamp patterns that reveal system characteristics
    if ts_val == 0 {
        // Explicitly disabled timestamps
        return FingerprintRisk::Low;
    }
    
    // Check for HZ-based patterns (common in Linux)
    // Linux systems often use 100Hz, 250Hz, 1000Hz tick rates
    let common_hz_values = [100, 250, 300, 1000];
    for &hz in &common_hz_values {
        if ts_val % hz == 0 {
            return FingerprintRisk::High;
        }
    }
    
    // Check for suspiciously regular patterns
    if ts_val % 1000 == 0 {
        return FingerprintRisk::Medium;
    }
    
    // Check for very small values (system recently booted)
    if ts_val < 10000 {
        return FingerprintRisk::High;
    }
    
    // Default to medium risk for any timestamp
    FingerprintRisk::Medium
}

/// Generate spoofed timestamp values
/// 
/// This function generates timestamp values that appear legitimate but
/// don't reveal system characteristics. The strategy is to:
/// 
/// 1. Use randomized increments to avoid predictable patterns
/// 2. Avoid values that align with common system tick rates
/// 3. Maintain temporal consistency within connections
pub fn generate_spoofed_timestamp(base_time: u32, increment: u32) -> TcpTimestamp {
    // Generate timestamp with some randomization to avoid patterns
    let random_offset = (base_time.wrapping_mul(1103515245).wrapping_add(12345)) % 1000;
    let spoofed_ts_val = base_time.wrapping_add(increment).wrapping_add(random_offset);
    
    TcpTimestamp {
        ts_val: spoofed_ts_val,
        ts_ecr: 0, // Echo reply is typically echoed from peer
    }
}

/// Create TCP option bytes with timestamp option stripped
/// 
/// This function reconstructs TCP options with the timestamp option removed.
/// It preserves all other options and maintains proper padding.
pub fn strip_timestamp_option(original_options: &[u8]) -> Vec<u8> {
    let options = parse_tcp_options(original_options);
    let mut result = Vec::new();
    
    for option in options {
        if option.kind != TcpOptionType::Timestamp {
            // Keep non-timestamp options
            let kind_byte = match option.kind {
                TcpOptionType::EndOfOptionList => 0,
                TcpOptionType::NoOperation => 1,
                TcpOptionType::MaximumSegmentSize => 2,
                TcpOptionType::WindowScale => 3,
                TcpOptionType::SackPermitted => 4,
                TcpOptionType::Sack => 5,
                TcpOptionType::Timestamp => 8,
                TcpOptionType::Unknown(val) => val,
            };
            result.push(kind_byte);
            
            match option.kind {
                TcpOptionType::EndOfOptionList | TcpOptionType::NoOperation => {
                    // These options don't have length or data fields
                }
                _ => {
                    result.push(option.length);
                    result.extend_from_slice(&option.data);
                }
            }
        }
    }
    
    // Pad to 4-byte boundary if necessary
    while result.len() % 4 != 0 {
        result.push(0); // End of option list padding
    }
    
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_timestamp_option_parsing() {
        // Create a timestamp option: Kind=8, Length=10, TSval=0x12345678, TSecr=0x87654321
        let option_data = vec![
            8, 10, // Kind and Length
            0x12, 0x34, 0x56, 0x78, // TSval
            0x87, 0x65, 0x43, 0x21, // TSecr
        ];
        
        let options = parse_tcp_options(&option_data);
        assert_eq!(options.len(), 1);
        assert_eq!(options[0].kind, TcpOptionType::Timestamp);
        
        let timestamp = extract_timestamp(&options[0]).unwrap();
        assert_eq!(timestamp.ts_val, 0x12345678);
        assert_eq!(timestamp.ts_ecr, 0x87654321);
    }
    
    #[test]
    fn test_timestamp_stripping() {
        // Original options with timestamp
        let original = vec![
            2, 4, 0x05, 0xb4, // MSS option
            8, 10, 0x12, 0x34, 0x56, 0x78, 0x87, 0x65, 0x43, 0x21, // Timestamp
            1, // NOP
            0, // End of options
        ];
        
        let stripped = strip_timestamp_option(&original);
        
        // Should contain MSS and NOP, but no timestamp
        let options = parse_tcp_options(&stripped);
        assert_eq!(options.len(), 2);
        assert_eq!(options[0].kind, TcpOptionType::MaximumSegmentSize);
        assert_eq!(options[1].kind, TcpOptionType::NoOperation);
    }
} 