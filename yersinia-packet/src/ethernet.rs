//! Ethernet frame construction and parsing
//!
//! This module provides functionality for building and parsing Ethernet II frames,
//! which are the most common type of Ethernet frame used in modern networks.

use bytes::{BufMut, BytesMut};
use std::fmt;

/// Common EtherType values used in Ethernet II frames
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EtherType {
    /// IPv4 (0x0800)
    IPv4,
    /// ARP (0x0806)
    ARP,
    /// VLAN-tagged frame (0x8100)
    VLAN,
    /// IPv6 (0x86DD)
    IPv6,
    /// MPLS unicast (0x8847)
    MPLS,
    /// MPLS multicast (0x8848)
    MPLSMulticast,
    /// PPPoE Discovery (0x8863)
    PPPoEDiscovery,
    /// PPPoE Session (0x8864)
    PPPoESession,
    /// LLDP (0x88CC)
    LLDP,
    /// 802.1X (0x888E)
    Dot1X,
    /// Q-in-Q/802.1ad (0x88A8)
    QinQ,
    /// Slow Protocols (0x8809) - LACP, LAMP, etc
    SlowProtocols,
    /// CDP/VTP/DTP/STP (LLC/SNAP encapsulation) - length field used instead
    LLC,
    /// Custom EtherType
    Custom(u16),
}

impl EtherType {
    /// Convert EtherType to u16 value
    pub fn to_u16(self) -> u16 {
        match self {
            EtherType::IPv4 => 0x0800,
            EtherType::ARP => 0x0806,
            EtherType::VLAN => 0x8100,
            EtherType::IPv6 => 0x86DD,
            EtherType::MPLS => 0x8847,
            EtherType::MPLSMulticast => 0x8848,
            EtherType::PPPoEDiscovery => 0x8863,
            EtherType::PPPoESession => 0x8864,
            EtherType::LLDP => 0x88CC,
            EtherType::Dot1X => 0x888E,
            EtherType::QinQ => 0x88A8,
            EtherType::SlowProtocols => 0x8809,
            EtherType::LLC => 0, // Will be replaced with length
            EtherType::Custom(val) => val,
        }
    }

    /// Create EtherType from u16 value
    pub fn from_u16(value: u16) -> Self {
        match value {
            0x0800 => EtherType::IPv4,
            0x0806 => EtherType::ARP,
            0x8100 => EtherType::VLAN,
            0x86DD => EtherType::IPv6,
            0x8847 => EtherType::MPLS,
            0x8848 => EtherType::MPLSMulticast,
            0x8863 => EtherType::PPPoEDiscovery,
            0x8864 => EtherType::PPPoESession,
            0x88CC => EtherType::LLDP,
            0x888E => EtherType::Dot1X,
            0x88A8 => EtherType::QinQ,
            0x8809 => EtherType::SlowProtocols,
            val => EtherType::Custom(val),
        }
    }
}

impl fmt::Display for EtherType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            EtherType::IPv4 => write!(f, "IPv4"),
            EtherType::ARP => write!(f, "ARP"),
            EtherType::VLAN => write!(f, "VLAN"),
            EtherType::IPv6 => write!(f, "IPv6"),
            EtherType::MPLS => write!(f, "MPLS"),
            EtherType::MPLSMulticast => write!(f, "MPLS-Multicast"),
            EtherType::PPPoEDiscovery => write!(f, "PPPoE-Discovery"),
            EtherType::PPPoESession => write!(f, "PPPoE-Session"),
            EtherType::LLDP => write!(f, "LLDP"),
            EtherType::Dot1X => write!(f, "802.1X"),
            EtherType::QinQ => write!(f, "Q-in-Q"),
            EtherType::SlowProtocols => write!(f, "Slow Protocols"),
            EtherType::LLC => write!(f, "LLC"),
            EtherType::Custom(val) => write!(f, "0x{:04X}", val),
        }
    }
}

/// MAC address (6 bytes)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MacAddress(pub [u8; 6]);

impl MacAddress {
    /// Broadcast MAC address (FF:FF:FF:FF:FF:FF)
    pub const BROADCAST: MacAddress = MacAddress([0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]);

    /// Zero MAC address (00:00:00:00:00:00)
    pub const ZERO: MacAddress = MacAddress([0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);

    /// CDP/VTP/DTP multicast address (01:00:0C:CC:CC:CC)
    pub const CDP_MULTICAST: MacAddress = MacAddress([0x01, 0x00, 0x0C, 0xCC, 0xCC, 0xCC]);

    /// STP multicast address (01:80:C2:00:00:00)
    pub const STP_MULTICAST: MacAddress = MacAddress([0x01, 0x80, 0xC2, 0x00, 0x00, 0x00]);

    /// LLDP multicast address (01:80:C2:00:00:0E)
    pub const LLDP_MULTICAST: MacAddress = MacAddress([0x01, 0x80, 0xC2, 0x00, 0x00, 0x0E]);

    /// Create a new MAC address from a byte array
    pub fn new(bytes: [u8; 6]) -> Self {
        MacAddress(bytes)
    }

    /// Create a MAC address from a slice
    pub fn from_slice(slice: &[u8]) -> Option<Self> {
        if slice.len() == 6 {
            let mut bytes = [0u8; 6];
            bytes.copy_from_slice(slice);
            Some(MacAddress(bytes))
        } else {
            None
        }
    }

    /// Get the MAC address as a byte array
    pub fn as_bytes(&self) -> &[u8; 6] {
        &self.0
    }

    /// Check if this is a broadcast address
    pub fn is_broadcast(&self) -> bool {
        self.0 == [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]
    }

    /// Check if this is a multicast address (bit 0 of first octet is 1)
    pub fn is_multicast(&self) -> bool {
        self.0[0] & 0x01 == 0x01
    }

    /// Check if this is a unicast address
    pub fn is_unicast(&self) -> bool {
        !self.is_multicast() && !self.is_broadcast()
    }
}

impl fmt::Display for MacAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
            self.0[0], self.0[1], self.0[2], self.0[3], self.0[4], self.0[5]
        )
    }
}

impl From<[u8; 6]> for MacAddress {
    fn from(bytes: [u8; 6]) -> Self {
        MacAddress(bytes)
    }
}

impl From<MacAddress> for [u8; 6] {
    fn from(mac: MacAddress) -> Self {
        mac.0
    }
}

/// Ethernet II frame
#[derive(Debug, Clone)]
pub struct EthernetFrame {
    /// Destination MAC address
    pub destination: MacAddress,
    /// Source MAC address
    pub source: MacAddress,
    /// EtherType or length field
    pub ethertype: EtherType,
    /// Payload data
    pub payload: Vec<u8>,
}

impl EthernetFrame {
    /// Minimum Ethernet frame size (without FCS)
    pub const MIN_FRAME_SIZE: usize = 60;

    /// Maximum Ethernet frame size (without FCS)
    pub const MAX_FRAME_SIZE: usize = 1514;

    /// Ethernet header size (dst + src + type/length)
    pub const HEADER_SIZE: usize = 14;

    /// Minimum payload size
    pub const MIN_PAYLOAD_SIZE: usize = 46;

    /// Maximum payload size (MTU)
    pub const MAX_PAYLOAD_SIZE: usize = 1500;

    /// Create a new Ethernet frame
    pub fn new(
        destination: MacAddress,
        source: MacAddress,
        ethertype: EtherType,
        payload: Vec<u8>,
    ) -> Self {
        EthernetFrame {
            destination,
            source,
            ethertype,
            payload,
        }
    }

    /// Convert the frame to bytes
    ///
    /// This will automatically pad the frame to minimum size if needed
    /// and set the length field for LLC frames.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buffer = BytesMut::with_capacity(Self::MAX_FRAME_SIZE);

        // Destination MAC (6 bytes)
        buffer.put_slice(self.destination.as_bytes());

        // Source MAC (6 bytes)
        buffer.put_slice(self.source.as_bytes());

        // EtherType or Length (2 bytes)
        if self.ethertype == EtherType::LLC {
            // For LLC frames, use length field instead of EtherType
            buffer.put_u16(self.payload.len() as u16);
        } else {
            buffer.put_u16(self.ethertype.to_u16());
        }

        // Payload
        buffer.put_slice(&self.payload);

        let mut result = buffer.to_vec();

        // Pad to minimum frame size if necessary (excluding FCS)
        if result.len() < Self::MIN_FRAME_SIZE {
            result.resize(Self::MIN_FRAME_SIZE, 0);
        }

        result
    }

    /// Parse an Ethernet frame from bytes
    pub fn from_bytes(data: &[u8]) -> Option<Self> {
        if data.len() < Self::HEADER_SIZE {
            return None;
        }

        let destination = MacAddress::from_slice(&data[0..6])?;
        let source = MacAddress::from_slice(&data[6..12])?;

        let ethertype_or_length = u16::from_be_bytes([data[12], data[13]]);

        // Values <= 1500 indicate length (LLC), values >= 1536 indicate EtherType
        let (ethertype, payload_len) = if ethertype_or_length <= 1500 {
            (EtherType::LLC, ethertype_or_length as usize)
        } else {
            (
                EtherType::from_u16(ethertype_or_length),
                data.len() - Self::HEADER_SIZE,
            )
        };

        let payload = data[Self::HEADER_SIZE..]
            .iter()
            .take(payload_len)
            .copied()
            .collect();

        Some(EthernetFrame {
            destination,
            source,
            ethertype,
            payload,
        })
    }

    /// Get the total frame size in bytes
    pub fn len(&self) -> usize {
        let raw_len = Self::HEADER_SIZE + self.payload.len();
        raw_len.max(Self::MIN_FRAME_SIZE)
    }

    /// Check if the frame is empty (should never be true for valid frames)
    pub fn is_empty(&self) -> bool {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ethertype_conversion() {
        assert_eq!(EtherType::IPv4.to_u16(), 0x0800);
        assert_eq!(EtherType::ARP.to_u16(), 0x0806);
        assert_eq!(EtherType::from_u16(0x0800), EtherType::IPv4);
    }

    #[test]
    fn test_mac_address_display() {
        let mac = MacAddress([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
        assert_eq!(format!("{}", mac), "00:11:22:33:44:55");
    }

    #[test]
    fn test_mac_address_broadcast() {
        assert!(MacAddress::BROADCAST.is_broadcast());
        assert!(!MacAddress::ZERO.is_broadcast());
    }

    #[test]
    fn test_mac_address_multicast() {
        assert!(MacAddress::CDP_MULTICAST.is_multicast());
        assert!(!MacAddress([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]).is_multicast());
    }

    #[test]
    fn test_ethernet_frame_to_bytes() {
        let src = MacAddress([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
        let dst = MacAddress([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]);
        let payload = vec![0x01, 0x02, 0x03, 0x04];

        let frame = EthernetFrame::new(dst, src, EtherType::IPv4, payload);
        let bytes = frame.to_bytes();

        // Check minimum size padding
        assert!(bytes.len() >= EthernetFrame::MIN_FRAME_SIZE);

        // Check header
        assert_eq!(&bytes[0..6], dst.as_bytes());
        assert_eq!(&bytes[6..12], src.as_bytes());
        assert_eq!(u16::from_be_bytes([bytes[12], bytes[13]]), 0x0800);
    }

    #[test]
    fn test_ethernet_frame_from_bytes() {
        let data = vec![
            0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, // dst
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, // src
            0x08, 0x00, // IPv4
            0x01, 0x02, 0x03, 0x04, // payload
        ];

        let frame = EthernetFrame::from_bytes(&data).unwrap();
        assert_eq!(frame.destination.0, [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]);
        assert_eq!(frame.source.0, [0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
        assert_eq!(frame.ethertype, EtherType::IPv4);
        assert_eq!(frame.payload, vec![0x01, 0x02, 0x03, 0x04]);
    }

    #[test]
    fn test_ethernet_frame_llc() {
        let src = MacAddress([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
        let dst = MacAddress::CDP_MULTICAST;
        let payload = vec![0xAA, 0xAA, 0x03]; // LLC header start

        let frame = EthernetFrame::new(dst, src, EtherType::LLC, payload.clone());
        let bytes = frame.to_bytes();

        // For LLC, the length field should be payload length
        let length = u16::from_be_bytes([bytes[12], bytes[13]]);
        assert_eq!(length, payload.len() as u16);
    }

    #[test]
    fn test_ethernet_roundtrip() {
        let src = MacAddress([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
        let dst = MacAddress([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]);
        let payload = vec![0x01, 0x02, 0x03, 0x04];

        let frame1 = EthernetFrame::new(dst, src, EtherType::IPv4, payload.clone());
        let bytes = frame1.to_bytes();
        let frame2 = EthernetFrame::from_bytes(&bytes).unwrap();

        assert_eq!(frame1.destination, frame2.destination);
        assert_eq!(frame1.source, frame2.source);
        assert_eq!(frame1.ethertype, frame2.ethertype);
        // When roundtripping, the payload may include padding for minimum frame size
        // For non-LLC frames, we can't distinguish between payload and padding
        // So we check that the original payload is at the start
        assert_eq!(&frame2.payload[..payload.len()], &payload[..]);
    }
}
