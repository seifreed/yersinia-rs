//! IPv4 packet construction and parsing
//!
//! This module provides functionality for building and parsing IPv4 packets,
//! including header construction, checksum calculation, and protocol support.

use crate::checksum::internet_checksum;
use bytes::{BufMut, BytesMut};
use std::net::Ipv4Addr;

/// IP Protocol numbers
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IpProtocol {
    /// ICMP (1)
    ICMP,
    /// IGMP (2)
    IGMP,
    /// TCP (6)
    TCP,
    /// UDP (17)
    UDP,
    /// GRE (47)
    GRE,
    /// ESP (50)
    ESP,
    /// AH (51)
    AH,
    /// EIGRP (88)
    EIGRP,
    /// OSPF (89)
    OSPF,
    /// VRRP (112)
    VRRP,
    /// Custom protocol number
    Custom(u8),
}

impl IpProtocol {
    pub fn to_u8(self) -> u8 {
        match self {
            IpProtocol::ICMP => 1,
            IpProtocol::IGMP => 2,
            IpProtocol::TCP => 6,
            IpProtocol::UDP => 17,
            IpProtocol::GRE => 47,
            IpProtocol::ESP => 50,
            IpProtocol::AH => 51,
            IpProtocol::EIGRP => 88,
            IpProtocol::OSPF => 89,
            IpProtocol::VRRP => 112,
            IpProtocol::Custom(val) => val,
        }
    }

    pub fn from_u8(value: u8) -> Self {
        match value {
            1 => IpProtocol::ICMP,
            2 => IpProtocol::IGMP,
            6 => IpProtocol::TCP,
            17 => IpProtocol::UDP,
            47 => IpProtocol::GRE,
            50 => IpProtocol::ESP,
            51 => IpProtocol::AH,
            88 => IpProtocol::EIGRP,
            89 => IpProtocol::OSPF,
            112 => IpProtocol::VRRP,
            val => IpProtocol::Custom(val),
        }
    }
}

/// Type of Service (ToS) / Differentiated Services Code Point (DSCP)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TypeOfService(pub u8);

impl TypeOfService {
    /// Default ToS (0)
    pub const DEFAULT: TypeOfService = TypeOfService(0);

    /// Minimize delay
    pub const MINIMIZE_DELAY: TypeOfService = TypeOfService(0x10);

    /// Maximize throughput
    pub const MAXIMIZE_THROUGHPUT: TypeOfService = TypeOfService(0x08);

    /// Maximize reliability
    pub const MAXIMIZE_RELIABILITY: TypeOfService = TypeOfService(0x04);

    /// Minimize cost
    pub const MINIMIZE_COST: TypeOfService = TypeOfService(0x02);

    pub fn new(value: u8) -> Self {
        TypeOfService(value)
    }

    pub fn to_u8(self) -> u8 {
        self.0
    }
}

/// IP Flags
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IpFlags {
    /// Reserved bit (must be 0)
    pub reserved: bool,
    /// Don't Fragment flag
    pub dont_fragment: bool,
    /// More Fragments flag
    pub more_fragments: bool,
}

impl IpFlags {
    /// No flags set
    pub const NONE: IpFlags = IpFlags {
        reserved: false,
        dont_fragment: false,
        more_fragments: false,
    };

    /// Don't Fragment flag set
    pub const DONT_FRAGMENT: IpFlags = IpFlags {
        reserved: false,
        dont_fragment: true,
        more_fragments: false,
    };

    pub fn new() -> Self {
        IpFlags::NONE
    }

    pub fn with_dont_fragment(mut self, df: bool) -> Self {
        self.dont_fragment = df;
        self
    }

    pub fn with_more_fragments(mut self, mf: bool) -> Self {
        self.more_fragments = mf;
        self
    }

    /// Convert to 3-bit value
    pub fn to_u8(self) -> u8 {
        let mut flags = 0u8;
        if self.reserved {
            flags |= 0b100;
        }
        if self.dont_fragment {
            flags |= 0b010;
        }
        if self.more_fragments {
            flags |= 0b001;
        }
        flags
    }

    /// Parse from 3-bit value
    pub fn from_u8(value: u8) -> Self {
        IpFlags {
            reserved: (value & 0b100) != 0,
            dont_fragment: (value & 0b010) != 0,
            more_fragments: (value & 0b001) != 0,
        }
    }
}

impl Default for IpFlags {
    fn default() -> Self {
        IpFlags::NONE
    }
}

/// IPv4 packet
#[derive(Debug, Clone)]
pub struct Ipv4Packet {
    /// Version (always 4 for IPv4)
    pub version: u8,
    /// Internet Header Length in 32-bit words (minimum 5)
    pub ihl: u8,
    /// Type of Service / DSCP
    pub tos: TypeOfService,
    /// Total length (header + data) in bytes
    pub total_length: u16,
    /// Identification
    pub identification: u16,
    /// Flags
    pub flags: IpFlags,
    /// Fragment offset (in 8-byte blocks)
    pub fragment_offset: u16,
    /// Time to Live
    pub ttl: u8,
    /// Protocol
    pub protocol: IpProtocol,
    /// Header checksum
    pub checksum: u16,
    /// Source IP address
    pub source: Ipv4Addr,
    /// Destination IP address
    pub destination: Ipv4Addr,
    /// Options (if IHL > 5)
    pub options: Vec<u8>,
    /// Payload data
    pub payload: Vec<u8>,
}

impl Ipv4Packet {
    /// Minimum IPv4 header size (without options)
    pub const MIN_HEADER_SIZE: usize = 20;

    /// Maximum IPv4 header size (with maximum options)
    pub const MAX_HEADER_SIZE: usize = 60;

    /// Maximum IPv4 packet size
    pub const MAX_PACKET_SIZE: usize = 65535;

    /// Create a new IPv4 packet with default values
    pub fn new(
        source: Ipv4Addr,
        destination: Ipv4Addr,
        protocol: IpProtocol,
        payload: Vec<u8>,
    ) -> Self {
        let total_length = (Self::MIN_HEADER_SIZE + payload.len()) as u16;

        Ipv4Packet {
            version: 4,
            ihl: 5, // 5 * 4 = 20 bytes (minimum header)
            tos: TypeOfService::DEFAULT,
            total_length,
            identification: 0,
            flags: IpFlags::DONT_FRAGMENT,
            fragment_offset: 0,
            ttl: 64,
            protocol,
            checksum: 0, // Will be calculated
            source,
            destination,
            options: Vec::new(),
            payload,
        }
    }

    /// Set the Time to Live
    pub fn with_ttl(mut self, ttl: u8) -> Self {
        self.ttl = ttl;
        self
    }

    /// Set the Type of Service
    pub fn with_tos(mut self, tos: TypeOfService) -> Self {
        self.tos = tos;
        self
    }

    /// Set the identification field
    pub fn with_identification(mut self, id: u16) -> Self {
        self.identification = id;
        self
    }

    /// Set the flags
    pub fn with_flags(mut self, flags: IpFlags) -> Self {
        self.flags = flags;
        self
    }

    /// Set the fragment offset
    pub fn with_fragment_offset(mut self, offset: u16) -> Self {
        self.fragment_offset = offset & 0x1FFF; // Only 13 bits
        self
    }

    /// Set IP options
    pub fn with_options(mut self, options: Vec<u8>) -> Self {
        // Options must be padded to 4-byte boundary
        let padded_len = (options.len() + 3) & !3;
        let mut padded_options = options;
        padded_options.resize(padded_len, 0);

        self.options = padded_options;
        self.ihl = (Self::MIN_HEADER_SIZE + self.options.len()) as u8 / 4;
        self.total_length =
            (Self::MIN_HEADER_SIZE + self.options.len() + self.payload.len()) as u16;
        self
    }

    /// Calculate and update the header checksum
    pub fn calculate_checksum(&mut self) {
        // Set checksum to 0 before calculation
        self.checksum = 0;

        // Build header for checksum calculation
        let header = self.build_header_for_checksum();

        // Calculate checksum
        self.checksum = internet_checksum(&header);
    }

    /// Build header bytes for checksum calculation (without payload)
    fn build_header_for_checksum(&self) -> Vec<u8> {
        let header_size = Self::MIN_HEADER_SIZE + self.options.len();
        let mut buffer = BytesMut::with_capacity(header_size);

        // Version (4 bits) + IHL (4 bits)
        buffer.put_u8((self.version << 4) | (self.ihl & 0x0F));

        // Type of Service
        buffer.put_u8(self.tos.to_u8());

        // Total Length
        buffer.put_u16(self.total_length);

        // Identification
        buffer.put_u16(self.identification);

        // Flags (3 bits) + Fragment Offset (13 bits)
        let flags_and_offset =
            ((self.flags.to_u8() as u16) << 13) | (self.fragment_offset & 0x1FFF);
        buffer.put_u16(flags_and_offset);

        // Time to Live
        buffer.put_u8(self.ttl);

        // Protocol
        buffer.put_u8(self.protocol.to_u8());

        // Header Checksum
        buffer.put_u16(self.checksum);

        // Source IP
        buffer.put_slice(&self.source.octets());

        // Destination IP
        buffer.put_slice(&self.destination.octets());

        // Options (if any)
        buffer.put_slice(&self.options);

        buffer.to_vec()
    }

    /// Convert the packet to bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut packet = self.clone();
        packet.calculate_checksum();

        let mut buffer = BytesMut::with_capacity(packet.total_length as usize);

        // Add header
        buffer.put_slice(&packet.build_header_for_checksum());

        // Add payload
        buffer.put_slice(&packet.payload);

        buffer.to_vec()
    }

    /// Parse an IPv4 packet from bytes
    pub fn from_bytes(data: &[u8]) -> Option<Self> {
        if data.len() < Self::MIN_HEADER_SIZE {
            return None;
        }

        let version_ihl = data[0];
        let version = version_ihl >> 4;
        let ihl = version_ihl & 0x0F;

        if version != 4 {
            return None;
        }

        let header_len = (ihl as usize) * 4;
        if data.len() < header_len {
            return None;
        }

        let tos = TypeOfService::new(data[1]);
        let total_length = u16::from_be_bytes([data[2], data[3]]);
        let identification = u16::from_be_bytes([data[4], data[5]]);

        let flags_and_offset = u16::from_be_bytes([data[6], data[7]]);
        let flags = IpFlags::from_u8((flags_and_offset >> 13) as u8);
        let fragment_offset = flags_and_offset & 0x1FFF;

        let ttl = data[8];
        let protocol = IpProtocol::from_u8(data[9]);
        let checksum = u16::from_be_bytes([data[10], data[11]]);

        let source = Ipv4Addr::new(data[12], data[13], data[14], data[15]);
        let destination = Ipv4Addr::new(data[16], data[17], data[18], data[19]);

        let options = if header_len > Self::MIN_HEADER_SIZE {
            data[Self::MIN_HEADER_SIZE..header_len].to_vec()
        } else {
            Vec::new()
        };

        let payload = if data.len() > header_len {
            data[header_len..].to_vec()
        } else {
            Vec::new()
        };

        Some(Ipv4Packet {
            version,
            ihl,
            tos,
            total_length,
            identification,
            flags,
            fragment_offset,
            ttl,
            protocol,
            checksum,
            source,
            destination,
            options,
            payload,
        })
    }

    /// Get the header size in bytes
    pub fn header_len(&self) -> usize {
        (self.ihl as usize) * 4
    }

    /// Get the total packet size in bytes
    pub fn len(&self) -> usize {
        self.total_length as usize
    }

    /// Check if empty
    pub fn is_empty(&self) -> bool {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ip_protocol_conversion() {
        assert_eq!(IpProtocol::TCP.to_u8(), 6);
        assert_eq!(IpProtocol::UDP.to_u8(), 17);
        assert_eq!(IpProtocol::from_u8(6), IpProtocol::TCP);
    }

    #[test]
    fn test_ip_flags() {
        let flags = IpFlags::DONT_FRAGMENT;
        assert!(!flags.reserved);
        assert!(flags.dont_fragment);
        assert!(!flags.more_fragments);

        let flags_byte = flags.to_u8();
        assert_eq!(flags_byte, 0b010);

        let flags2 = IpFlags::from_u8(flags_byte);
        assert_eq!(flags.dont_fragment, flags2.dont_fragment);
    }

    #[test]
    fn test_ipv4_packet_new() {
        let src = Ipv4Addr::new(192, 168, 1, 1);
        let dst = Ipv4Addr::new(192, 168, 1, 2);
        let payload = vec![0x01, 0x02, 0x03, 0x04];

        let packet = Ipv4Packet::new(src, dst, IpProtocol::UDP, payload);

        assert_eq!(packet.version, 4);
        assert_eq!(packet.ihl, 5);
        assert_eq!(packet.source, src);
        assert_eq!(packet.destination, dst);
        assert_eq!(packet.protocol, IpProtocol::UDP);
        assert_eq!(packet.total_length, 24); // 20 (header) + 4 (payload)
    }

    #[test]
    fn test_ipv4_packet_to_bytes() {
        let src = Ipv4Addr::new(192, 168, 1, 1);
        let dst = Ipv4Addr::new(192, 168, 1, 2);
        let payload = vec![0x01, 0x02, 0x03, 0x04];

        let packet = Ipv4Packet::new(src, dst, IpProtocol::UDP, payload);
        let bytes = packet.to_bytes();

        // Check version and IHL
        assert_eq!(bytes[0] >> 4, 4); // Version
        assert_eq!(bytes[0] & 0x0F, 5); // IHL

        // Check protocol
        assert_eq!(bytes[9], 17); // UDP

        // Check source IP
        assert_eq!(&bytes[12..16], &[192, 168, 1, 1]);

        // Check destination IP
        assert_eq!(&bytes[16..20], &[192, 168, 1, 2]);

        // Check payload
        assert_eq!(&bytes[20..24], &[0x01, 0x02, 0x03, 0x04]);
    }

    #[test]
    fn test_ipv4_packet_checksum() {
        let src = Ipv4Addr::new(192, 168, 1, 1);
        let dst = Ipv4Addr::new(192, 168, 1, 2);
        let payload = vec![0x01, 0x02, 0x03, 0x04];

        let mut packet = Ipv4Packet::new(src, dst, IpProtocol::UDP, payload);
        packet.calculate_checksum();

        // Checksum should be non-zero
        assert_ne!(packet.checksum, 0);
    }

    #[test]
    fn test_ipv4_packet_roundtrip() {
        let src = Ipv4Addr::new(192, 168, 1, 1);
        let dst = Ipv4Addr::new(192, 168, 1, 2);
        let payload = vec![0x01, 0x02, 0x03, 0x04];

        let packet1 = Ipv4Packet::new(src, dst, IpProtocol::UDP, payload);
        let bytes = packet1.to_bytes();
        let packet2 = Ipv4Packet::from_bytes(&bytes).unwrap();

        assert_eq!(packet1.version, packet2.version);
        assert_eq!(packet1.ihl, packet2.ihl);
        assert_eq!(packet1.source, packet2.source);
        assert_eq!(packet1.destination, packet2.destination);
        assert_eq!(packet1.protocol.to_u8(), packet2.protocol.to_u8());
        assert_eq!(packet1.payload, packet2.payload);
    }

    #[test]
    fn test_ipv4_packet_with_ttl() {
        let src = Ipv4Addr::new(192, 168, 1, 1);
        let dst = Ipv4Addr::new(192, 168, 1, 2);
        let payload = vec![];

        let packet = Ipv4Packet::new(src, dst, IpProtocol::TCP, payload).with_ttl(128);

        assert_eq!(packet.ttl, 128);
    }

    #[test]
    fn test_type_of_service() {
        let tos = TypeOfService::MINIMIZE_DELAY;
        assert_eq!(tos.to_u8(), 0x10);

        let tos2 = TypeOfService::new(0x10);
        assert_eq!(tos.0, tos2.0);
    }
}
