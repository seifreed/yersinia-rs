//! UDP datagram construction and parsing
//!
//! This module provides functionality for building and parsing UDP datagrams,
//! including header construction and checksum calculation.

use crate::checksum::transport_checksum;
use bytes::{BufMut, BytesMut};
use std::net::Ipv4Addr;

/// Common UDP port numbers
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UdpPort(pub u16);

impl UdpPort {
    /// DNS (53)
    pub const DNS: UdpPort = UdpPort(53);

    /// DHCP Server (67)
    pub const DHCP_SERVER: UdpPort = UdpPort(67);

    /// DHCP Client (68)
    pub const DHCP_CLIENT: UdpPort = UdpPort(68);

    /// TFTP (69)
    pub const TFTP: UdpPort = UdpPort(69);

    /// NTP (123)
    pub const NTP: UdpPort = UdpPort(123);

    /// SNMP (161)
    pub const SNMP: UdpPort = UdpPort(161);

    /// SNMP Trap (162)
    pub const SNMP_TRAP: UdpPort = UdpPort(162);

    /// Syslog (514)
    pub const SYSLOG: UdpPort = UdpPort(514);

    /// RIP (520)
    pub const RIP: UdpPort = UdpPort(520);

    pub fn new(port: u16) -> Self {
        UdpPort(port)
    }

    pub fn to_u16(self) -> u16 {
        self.0
    }
}

impl From<u16> for UdpPort {
    fn from(port: u16) -> Self {
        UdpPort(port)
    }
}

impl From<UdpPort> for u16 {
    fn from(port: UdpPort) -> Self {
        port.0
    }
}

/// UDP datagram
#[derive(Debug, Clone)]
pub struct UdpDatagram {
    /// Source port
    pub source_port: UdpPort,
    /// Destination port
    pub destination_port: UdpPort,
    /// Length (header + data)
    pub length: u16,
    /// Checksum
    pub checksum: u16,
    /// Payload data
    pub payload: Vec<u8>,
}

impl UdpDatagram {
    /// UDP header size in bytes
    pub const HEADER_SIZE: usize = 8;

    /// Create a new UDP datagram
    ///
    /// Note: The checksum is set to 0 and must be calculated later using
    /// `calculate_checksum()` with the source and destination IP addresses.
    pub fn new(source_port: UdpPort, destination_port: UdpPort, payload: Vec<u8>) -> Self {
        let length = (Self::HEADER_SIZE + payload.len()) as u16;

        UdpDatagram {
            source_port,
            destination_port,
            length,
            checksum: 0, // Will be calculated with IP addresses
            payload,
        }
    }

    /// Calculate and set the UDP checksum
    ///
    /// The UDP checksum includes a pseudo-header containing the source and
    /// destination IP addresses, which is why they must be provided here.
    ///
    /// # Arguments
    ///
    /// * `src_ip` - Source IPv4 address
    /// * `dst_ip` - Destination IPv4 address
    pub fn calculate_checksum(&mut self, src_ip: Ipv4Addr, dst_ip: Ipv4Addr) {
        // Set checksum to 0 before calculation
        self.checksum = 0;

        // Build UDP header and payload for checksum
        let data = self.build_for_checksum();

        // Calculate checksum with pseudo-header
        let checksum = transport_checksum(
            &src_ip.octets(),
            &dst_ip.octets(),
            17, // UDP protocol number
            &data,
        );

        // UDP checksum of 0 means no checksum; if calculated checksum is 0, use 0xFFFF
        self.checksum = if checksum == 0 { 0xFFFF } else { checksum };
    }

    /// Build UDP datagram bytes for checksum calculation
    fn build_for_checksum(&self) -> Vec<u8> {
        let mut buffer = BytesMut::with_capacity(self.length as usize);

        // Source port
        buffer.put_u16(self.source_port.to_u16());

        // Destination port
        buffer.put_u16(self.destination_port.to_u16());

        // Length
        buffer.put_u16(self.length);

        // Checksum
        buffer.put_u16(self.checksum);

        // Payload
        buffer.put_slice(&self.payload);

        buffer.to_vec()
    }

    /// Convert the UDP datagram to bytes
    ///
    /// Note: This does not calculate the checksum. You must call
    /// `calculate_checksum()` before this if you want a valid checksum.
    pub fn to_bytes(&self) -> Vec<u8> {
        self.build_for_checksum()
    }

    /// Convert the UDP datagram to bytes with checksum calculation
    ///
    /// This is a convenience method that calculates the checksum and
    /// returns the bytes in one call.
    ///
    /// # Arguments
    ///
    /// * `src_ip` - Source IPv4 address
    /// * `dst_ip` - Destination IPv4 address
    pub fn to_bytes_with_checksum(&self, src_ip: Ipv4Addr, dst_ip: Ipv4Addr) -> Vec<u8> {
        let mut datagram = self.clone();
        datagram.calculate_checksum(src_ip, dst_ip);
        datagram.to_bytes()
    }

    /// Parse a UDP datagram from bytes
    ///
    /// Note: This does not validate the checksum. To validate, you need the
    /// source and destination IP addresses.
    pub fn from_bytes(data: &[u8]) -> Option<Self> {
        if data.len() < Self::HEADER_SIZE {
            return None;
        }

        let source_port = UdpPort::new(u16::from_be_bytes([data[0], data[1]]));
        let destination_port = UdpPort::new(u16::from_be_bytes([data[2], data[3]]));
        let length = u16::from_be_bytes([data[4], data[5]]);
        let checksum = u16::from_be_bytes([data[6], data[7]]);

        let payload = if data.len() > Self::HEADER_SIZE {
            data[Self::HEADER_SIZE..].to_vec()
        } else {
            Vec::new()
        };

        Some(UdpDatagram {
            source_port,
            destination_port,
            length,
            checksum,
            payload,
        })
    }

    /// Validate the UDP checksum
    ///
    /// # Arguments
    ///
    /// * `src_ip` - Source IPv4 address
    /// * `dst_ip` - Destination IPv4 address
    ///
    /// # Returns
    ///
    /// `true` if the checksum is valid or if checksum is 0 (no checksum),
    /// `false` otherwise
    pub fn validate_checksum(&self, src_ip: Ipv4Addr, dst_ip: Ipv4Addr) -> bool {
        // UDP checksum of 0 means no checksum
        if self.checksum == 0 {
            return true;
        }

        let data = self.build_for_checksum();
        let calculated = transport_checksum(
            &src_ip.octets(),
            &dst_ip.octets(),
            17, // UDP protocol number
            &data,
        );

        // The checksum should be 0 or 0xFFFF when validated
        calculated == 0 || calculated == 0xFFFF
    }

    /// Get the total datagram size in bytes
    pub fn len(&self) -> usize {
        self.length as usize
    }

    /// Check if empty
    pub fn is_empty(&self) -> bool {
        false
    }

    /// Get payload length
    pub fn payload_len(&self) -> usize {
        self.payload.len()
    }
}

/// UDP datagram builder
pub struct UdpBuilder {
    source_port: Option<UdpPort>,
    destination_port: Option<UdpPort>,
    payload: Vec<u8>,
}

impl UdpBuilder {
    /// Create a new UDP builder
    pub fn new() -> Self {
        UdpBuilder {
            source_port: None,
            destination_port: None,
            payload: Vec::new(),
        }
    }

    /// Set the source port
    pub fn source_port(mut self, port: u16) -> Self {
        self.source_port = Some(UdpPort::new(port));
        self
    }

    /// Set the destination port
    pub fn destination_port(mut self, port: u16) -> Self {
        self.destination_port = Some(UdpPort::new(port));
        self
    }

    /// Set the payload
    pub fn payload(mut self, data: Vec<u8>) -> Self {
        self.payload = data;
        self
    }

    /// Build the UDP datagram
    ///
    /// Returns `None` if source or destination port is not set.
    pub fn build(self) -> Option<UdpDatagram> {
        let source_port = self.source_port?;
        let destination_port = self.destination_port?;

        Some(UdpDatagram::new(
            source_port,
            destination_port,
            self.payload,
        ))
    }
}

impl Default for UdpBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_udp_port_constants() {
        assert_eq!(UdpPort::DNS.0, 53);
        assert_eq!(UdpPort::DHCP_SERVER.0, 67);
        assert_eq!(UdpPort::DHCP_CLIENT.0, 68);
    }

    #[test]
    fn test_udp_datagram_new() {
        let src_port = UdpPort::new(12345);
        let dst_port = UdpPort::DNS;
        let payload = vec![0x01, 0x02, 0x03, 0x04];

        let datagram = UdpDatagram::new(src_port, dst_port, payload);

        assert_eq!(datagram.source_port, src_port);
        assert_eq!(datagram.destination_port, dst_port);
        assert_eq!(datagram.length, 12); // 8 (header) + 4 (payload)
        assert_eq!(datagram.checksum, 0); // Not calculated yet
    }

    #[test]
    fn test_udp_datagram_to_bytes() {
        let src_port = UdpPort::new(12345);
        let dst_port = UdpPort::DNS;
        let payload = vec![0x01, 0x02, 0x03, 0x04];

        let datagram = UdpDatagram::new(src_port, dst_port, payload);
        let bytes = datagram.to_bytes();

        // Check header fields
        assert_eq!(u16::from_be_bytes([bytes[0], bytes[1]]), 12345); // Source port
        assert_eq!(u16::from_be_bytes([bytes[2], bytes[3]]), 53); // Dest port
        assert_eq!(u16::from_be_bytes([bytes[4], bytes[5]]), 12); // Length

        // Check payload
        assert_eq!(&bytes[8..12], &[0x01, 0x02, 0x03, 0x04]);
    }

    #[test]
    fn test_udp_datagram_checksum() {
        let src_ip = Ipv4Addr::new(192, 168, 1, 1);
        let dst_ip = Ipv4Addr::new(192, 168, 1, 2);
        let src_port = UdpPort::new(12345);
        let dst_port = UdpPort::DNS;
        let payload = vec![0x01, 0x02, 0x03, 0x04];

        let mut datagram = UdpDatagram::new(src_port, dst_port, payload);
        datagram.calculate_checksum(src_ip, dst_ip);

        // Checksum should be non-zero
        assert_ne!(datagram.checksum, 0);

        // Validate the checksum
        assert!(datagram.validate_checksum(src_ip, dst_ip));
    }

    #[test]
    fn test_udp_datagram_from_bytes() {
        let data = vec![
            0x30, 0x39, // Source port (12345)
            0x00, 0x35, // Dest port (53)
            0x00, 0x0C, // Length (12)
            0x00, 0x00, // Checksum (0)
            0x01, 0x02, 0x03, 0x04, // Payload
        ];

        let datagram = UdpDatagram::from_bytes(&data).unwrap();

        assert_eq!(datagram.source_port.0, 12345);
        assert_eq!(datagram.destination_port.0, 53);
        assert_eq!(datagram.length, 12);
        assert_eq!(datagram.payload, vec![0x01, 0x02, 0x03, 0x04]);
    }

    #[test]
    fn test_udp_datagram_roundtrip() {
        let src_ip = Ipv4Addr::new(192, 168, 1, 1);
        let dst_ip = Ipv4Addr::new(192, 168, 1, 2);
        let src_port = UdpPort::new(12345);
        let dst_port = UdpPort::DNS;
        let payload = vec![0x01, 0x02, 0x03, 0x04];

        let datagram1 = UdpDatagram::new(src_port, dst_port, payload);
        let bytes = datagram1.to_bytes_with_checksum(src_ip, dst_ip);
        let datagram2 = UdpDatagram::from_bytes(&bytes).unwrap();

        assert_eq!(datagram1.source_port, datagram2.source_port);
        assert_eq!(datagram1.destination_port, datagram2.destination_port);
        assert_eq!(datagram1.length, datagram2.length);
        assert_eq!(datagram1.payload, datagram2.payload);

        // Validate checksum
        assert!(datagram2.validate_checksum(src_ip, dst_ip));
    }

    #[test]
    fn test_udp_builder() {
        let datagram = UdpBuilder::new()
            .source_port(12345)
            .destination_port(53)
            .payload(vec![0x01, 0x02, 0x03, 0x04])
            .build()
            .unwrap();

        assert_eq!(datagram.source_port.0, 12345);
        assert_eq!(datagram.destination_port.0, 53);
        assert_eq!(datagram.payload, vec![0x01, 0x02, 0x03, 0x04]);
    }

    #[test]
    fn test_udp_builder_incomplete() {
        let result = UdpBuilder::new()
            .source_port(12345)
            // Missing destination port
            .build();

        assert!(result.is_none());
    }

    #[test]
    fn test_udp_validate_checksum_zero() {
        let src_ip = Ipv4Addr::new(192, 168, 1, 1);
        let dst_ip = Ipv4Addr::new(192, 168, 1, 2);
        let src_port = UdpPort::new(12345);
        let dst_port = UdpPort::DNS;
        let payload = vec![0x01, 0x02, 0x03, 0x04];

        let datagram = UdpDatagram::new(src_port, dst_port, payload);

        // Checksum of 0 means no checksum, should validate as true
        assert_eq!(datagram.checksum, 0);
        assert!(datagram.validate_checksum(src_ip, dst_ip));
    }
}
