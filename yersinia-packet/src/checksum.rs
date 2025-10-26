//! Checksum calculations for network packets
//!
//! This module provides functions for calculating checksums used in various
//! network protocols, particularly the Internet Checksum (RFC 1071) used in
//! IP, TCP, and UDP headers.

/// Calculates the Internet Checksum as defined in RFC 1071.
///
/// This checksum is used in IP, TCP, and UDP headers. The algorithm works by
/// treating the data as a sequence of 16-bit words, summing them, and then
/// taking the one's complement of the result.
///
/// # Arguments
///
/// * `data` - The data to calculate the checksum for
///
/// # Returns
///
/// The 16-bit Internet checksum
///
/// # Examples
///
/// ```
/// use yersinia_packet::checksum::internet_checksum;
///
/// let data = vec![0x45, 0x00, 0x00, 0x3c];
/// let checksum = internet_checksum(&data);
/// ```
pub fn internet_checksum(data: &[u8]) -> u16 {
    let mut sum: u32 = 0;

    // Process 16-bit words
    let mut chunks = data.chunks_exact(2);
    for chunk in &mut chunks {
        let word = u16::from_be_bytes([chunk[0], chunk[1]]);
        sum += word as u32;
    }

    // Handle odd byte if present
    if let Some(&byte) = chunks.remainder().first() {
        sum += (byte as u32) << 8;
    }

    // Fold 32-bit sum to 16 bits
    while (sum >> 16) != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    // Return one's complement
    !sum as u16
}

/// Calculates the checksum for a TCP or UDP packet including the pseudo-header.
///
/// The pseudo-header includes the source and destination IP addresses, protocol,
/// and length, which are used to prevent misdelivery of packets.
///
/// # Arguments
///
/// * `src_ip` - Source IP address (4 bytes)
/// * `dst_ip` - Destination IP address (4 bytes)
/// * `protocol` - IP protocol number (6 for TCP, 17 for UDP)
/// * `data` - The TCP/UDP header and payload data
///
/// # Returns
///
/// The 16-bit checksum including pseudo-header
///
/// # Examples
///
/// ```
/// use yersinia_packet::checksum::transport_checksum;
///
/// let src_ip = [192, 168, 1, 1];
/// let dst_ip = [192, 168, 1, 2];
/// let protocol = 17; // UDP
/// let data = vec![0x00, 0x35, 0x00, 0x35, 0x00, 0x08, 0x00, 0x00];
/// let checksum = transport_checksum(&src_ip, &dst_ip, protocol, &data);
/// ```
pub fn transport_checksum(src_ip: &[u8; 4], dst_ip: &[u8; 4], protocol: u8, data: &[u8]) -> u16 {
    let mut pseudo_header = Vec::with_capacity(12 + data.len());

    // Source IP (4 bytes)
    pseudo_header.extend_from_slice(src_ip);

    // Destination IP (4 bytes)
    pseudo_header.extend_from_slice(dst_ip);

    // Zero byte (1 byte)
    pseudo_header.push(0);

    // Protocol (1 byte)
    pseudo_header.push(protocol);

    // Length (2 bytes) - length of TCP/UDP header + data
    let length = data.len() as u16;
    pseudo_header.extend_from_slice(&length.to_be_bytes());

    // TCP/UDP header and data
    pseudo_header.extend_from_slice(data);

    internet_checksum(&pseudo_header)
}

/// Validates an Internet checksum.
///
/// To validate a checksum, calculate the checksum over the entire packet
/// including the checksum field. The result should be 0 (or 0xFFFF which is
/// equivalent in one's complement).
///
/// # Arguments
///
/// * `data` - The data to validate (including the checksum field)
///
/// # Returns
///
/// `true` if the checksum is valid, `false` otherwise
///
/// # Examples
///
/// ```
/// use yersinia_packet::checksum::validate_checksum;
///
/// let data_with_checksum = vec![0x45, 0x00, 0x00, 0x3c, 0x12, 0x34];
/// let is_valid = validate_checksum(&data_with_checksum);
/// ```
pub fn validate_checksum(data: &[u8]) -> bool {
    let result = internet_checksum(data);
    result == 0 || result == 0xFFFF
}

/// Calculates a checksum with carry handling for special cases.
///
/// Some protocols may need different handling of the final carry.
/// This is a utility function for such cases.
///
/// # Arguments
///
/// * `data` - The data to calculate the checksum for
///
/// # Returns
///
/// The accumulated sum before one's complement (for debugging or special use)
pub fn checksum_accumulate(data: &[u8]) -> u32 {
    let mut sum: u32 = 0;

    let mut chunks = data.chunks_exact(2);
    for chunk in &mut chunks {
        let word = u16::from_be_bytes([chunk[0], chunk[1]]);
        sum += word as u32;
    }

    if let Some(&byte) = chunks.remainder().first() {
        sum += (byte as u32) << 8;
    }

    while (sum >> 16) != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    sum
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_internet_checksum_empty() {
        let data = vec![];
        let checksum = internet_checksum(&data);
        assert_eq!(checksum, 0xFFFF);
    }

    #[test]
    fn test_internet_checksum_simple() {
        // Test case from RFC 1071
        let data = vec![0x00, 0x01, 0xf2, 0x03, 0xf4, 0xf5, 0xf6, 0xf7];
        let checksum = internet_checksum(&data);
        // Expected checksum can be verified manually
        assert_ne!(checksum, 0);
    }

    #[test]
    fn test_internet_checksum_odd_length() {
        let data = vec![0x00, 0x01, 0x02];
        let checksum = internet_checksum(&data);
        assert_ne!(checksum, 0);
    }

    #[test]
    fn test_validate_checksum() {
        let data = vec![0x45, 0x00, 0x00, 0x3c];
        let checksum = internet_checksum(&data);

        // Create data with checksum included
        let mut data_with_checksum = data.clone();
        data_with_checksum.extend_from_slice(&checksum.to_be_bytes());

        // Checksum of data including the checksum should be valid
        assert!(validate_checksum(&data_with_checksum));
    }

    #[test]
    fn test_transport_checksum() {
        let src_ip = [192, 168, 1, 1];
        let dst_ip = [192, 168, 1, 2];
        let protocol = 17; // UDP

        // Simple UDP header (ports + length + checksum=0)
        let data = vec![0x00, 0x35, 0x00, 0x35, 0x00, 0x08, 0x00, 0x00];

        let checksum = transport_checksum(&src_ip, &dst_ip, protocol, &data);
        assert_ne!(checksum, 0);
    }

    #[test]
    fn test_checksum_accumulate() {
        let data = vec![0x00, 0x01, 0x00, 0x02];
        let sum = checksum_accumulate(&data);
        assert_eq!(sum, 0x0003);
    }

    #[test]
    fn test_checksum_complement_identity() {
        let data = vec![0x12, 0x34, 0x56, 0x78];
        let checksum = internet_checksum(&data);

        let mut data_with_checksum = data;
        data_with_checksum.extend_from_slice(&checksum.to_be_bytes());

        let result = internet_checksum(&data_with_checksum);
        // Result should be 0 or 0xFFFF (equivalent in one's complement)
        assert!(result == 0 || result == 0xFFFF);
    }
}
