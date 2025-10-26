//! MPLS Packet Structure and Parsing
//!
//! Implementation of MPLS header format and packet building.

use bytes::{BufMut, BytesMut};
use yersinia_core::{Error, Result};

/// MPLS EtherType (0x8847 for unicast, 0x8848 for multicast)
pub const ETHERTYPE_MPLS_UNICAST: u16 = 0x8847;
pub const ETHERTYPE_MPLS_MULTICAST: u16 = 0x8848;

/// MPLS Header (4 bytes)
///
/// Format:
/// ```text
///  0                   1                   2                   3
///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                Label                  | Exp |S|       TTL     |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MplsHeader {
    /// Label value (20 bits)
    pub label: u32,
    /// Experimental bits (3 bits) - used for QoS
    pub exp: u8,
    /// Bottom of stack flag (1 bit) - 1 if last label, 0 if more labels follow
    pub bottom_of_stack: bool,
    /// Time to Live (8 bits)
    pub ttl: u8,
}

impl MplsHeader {
    /// Create a new MPLS header
    pub fn new(label: u32, exp: u8, bottom_of_stack: bool, ttl: u8) -> Self {
        Self {
            label: label & 0xFFFFF, // Ensure 20 bits
            exp: exp & 0x07,        // Ensure 3 bits
            bottom_of_stack,
            ttl,
        }
    }

    /// Parse MPLS header from bytes
    pub fn parse(data: &[u8]) -> Result<Self> {
        if data.len() < 4 {
            return Err(Error::protocol("MPLS header too short"));
        }

        // Extract fields from 4 bytes
        let byte0 = data[0];
        let byte1 = data[1];
        let byte2 = data[2];
        let byte3 = data[3];

        // Label: 20 bits (byte0 << 12 | byte1 << 4 | byte2 >> 4)
        let label = ((byte0 as u32) << 12) | ((byte1 as u32) << 4) | ((byte2 as u32) >> 4);

        // Exp: 3 bits (byte2 bits 1-3)
        let exp = (byte2 >> 1) & 0x07;

        // Bottom of stack: 1 bit (byte2 bit 0)
        let bottom_of_stack = (byte2 & 0x01) == 1;

        // TTL: 8 bits
        let ttl = byte3;

        Ok(Self {
            label,
            exp,
            bottom_of_stack,
            ttl,
        })
    }

    /// Serialize MPLS header to bytes
    pub fn serialize(&self) -> Vec<u8> {
        let mut bytes = vec![0u8; 4];

        // Pack fields into 4 bytes
        bytes[0] = ((self.label >> 12) & 0xFF) as u8;
        bytes[1] = ((self.label >> 4) & 0xFF) as u8;
        bytes[2] = (((self.label & 0x0F) << 4)
            | ((self.exp as u32 & 0x07) << 1)
            | (self.bottom_of_stack as u32)) as u8;
        bytes[3] = self.ttl;

        bytes
    }

    /// Get header size in bytes (always 4)
    pub const fn size() -> usize {
        4
    }
}

/// MPLS Packet with optional label stacking
#[derive(Debug, Clone)]
pub struct MplsPacket {
    /// Primary MPLS label
    pub label1: MplsHeader,
    /// Optional second label (for label stacking)
    pub label2: Option<MplsHeader>,
    /// Encapsulated payload
    pub payload: Vec<u8>,
}

impl MplsPacket {
    /// Create new MPLS packet with single label
    pub fn new_single(label: u32, exp: u8, ttl: u8, payload: Vec<u8>) -> Self {
        Self {
            label1: MplsHeader::new(label, exp, true, ttl), // bottom_of_stack = true
            label2: None,
            payload,
        }
    }

    /// Create new MPLS packet with double label (label stacking)
    pub fn new_double(
        label1: u32,
        exp1: u8,
        ttl1: u8,
        label2: u32,
        exp2: u8,
        ttl2: u8,
        payload: Vec<u8>,
    ) -> Self {
        Self {
            label1: MplsHeader::new(label1, exp1, false, ttl1), // bottom_of_stack = false
            label2: Some(MplsHeader::new(label2, exp2, true, ttl2)), // bottom_of_stack = true
            payload,
        }
    }

    /// Parse MPLS packet from bytes
    pub fn parse(data: &[u8]) -> Result<Self> {
        if data.len() < 4 {
            return Err(Error::protocol("MPLS packet too short"));
        }

        // Parse first label
        let label1 = MplsHeader::parse(data)?;
        let mut offset = 4;

        // Check if there's a second label
        let label2 = if !label1.bottom_of_stack && data.len() >= offset + 4 {
            let l2 = MplsHeader::parse(&data[offset..])?;
            offset += 4;
            Some(l2)
        } else {
            None
        };

        // Remaining bytes are payload
        let payload = data[offset..].to_vec();

        Ok(Self {
            label1,
            label2,
            payload,
        })
    }

    /// Serialize MPLS packet to bytes
    pub fn serialize(&self) -> Vec<u8> {
        let mut buf = BytesMut::new();

        // Add first label
        buf.put_slice(&self.label1.serialize());

        // Add second label if present
        if let Some(ref label2) = self.label2 {
            buf.put_slice(&label2.serialize());
        }

        // Add payload
        buf.put_slice(&self.payload);

        buf.to_vec()
    }

    /// Get total packet size
    pub fn size(&self) -> usize {
        4 + self.label2.as_ref().map_or(0, |_| 4) + self.payload.len()
    }

    /// Check if packet uses label stacking
    pub fn is_label_stacked(&self) -> bool {
        self.label2.is_some()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mpls_header_new() {
        let header = MplsHeader::new(1000, 5, true, 64);
        assert_eq!(header.label, 1000);
        assert_eq!(header.exp, 5);
        assert!(header.bottom_of_stack);
        assert_eq!(header.ttl, 64);
    }

    #[test]
    fn test_mpls_header_serialize_parse() {
        let header = MplsHeader::new(12345, 3, true, 128);
        let bytes = header.serialize();
        assert_eq!(bytes.len(), 4);

        let parsed = MplsHeader::parse(&bytes).unwrap();
        assert_eq!(parsed.label, header.label);
        assert_eq!(parsed.exp, header.exp);
        assert_eq!(parsed.bottom_of_stack, header.bottom_of_stack);
        assert_eq!(parsed.ttl, header.ttl);
    }

    #[test]
    fn test_mpls_header_max_label() {
        // Test maximum 20-bit label value
        let header = MplsHeader::new(0xFFFFF, 0, false, 0);
        assert_eq!(header.label, 0xFFFFF);

        let bytes = header.serialize();
        let parsed = MplsHeader::parse(&bytes).unwrap();
        assert_eq!(parsed.label, 0xFFFFF);
    }

    #[test]
    fn test_mpls_packet_single_label() {
        let payload = vec![1, 2, 3, 4];
        let packet = MplsPacket::new_single(100, 2, 64, payload.clone());

        assert_eq!(packet.label1.label, 100);
        assert_eq!(packet.label1.exp, 2);
        assert!(packet.label1.bottom_of_stack);
        assert_eq!(packet.label1.ttl, 64);
        assert!(packet.label2.is_none());
        assert_eq!(packet.payload, payload);
        assert!(!packet.is_label_stacked());
    }

    #[test]
    fn test_mpls_packet_double_label() {
        let payload = vec![5, 6, 7, 8];
        let packet = MplsPacket::new_double(100, 1, 64, 200, 2, 32, payload.clone());

        assert_eq!(packet.label1.label, 100);
        assert!(!packet.label1.bottom_of_stack);
        assert!(packet.label2.is_some());

        let label2 = packet.label2.as_ref().unwrap();
        assert_eq!(label2.label, 200);
        assert!(label2.bottom_of_stack);
        assert!(packet.is_label_stacked());
    }

    #[test]
    fn test_mpls_packet_serialize_parse() {
        let payload = vec![0xAA, 0xBB, 0xCC, 0xDD];
        let packet = MplsPacket::new_single(500, 4, 128, payload.clone());

        let bytes = packet.serialize();
        let parsed = MplsPacket::parse(&bytes).unwrap();

        assert_eq!(parsed.label1.label, packet.label1.label);
        assert_eq!(parsed.label1.exp, packet.label1.exp);
        assert_eq!(parsed.label1.ttl, packet.label1.ttl);
        assert_eq!(parsed.payload, payload);
    }

    #[test]
    fn test_mpls_packet_double_serialize_parse() {
        let payload = vec![0x11, 0x22, 0x33];
        let packet = MplsPacket::new_double(1000, 3, 255, 2000, 5, 200, payload.clone());

        let bytes = packet.serialize();
        let parsed = MplsPacket::parse(&bytes).unwrap();

        assert_eq!(parsed.label1.label, 1000);
        assert_eq!(parsed.label2.as_ref().unwrap().label, 2000);
        assert_eq!(parsed.payload, payload);
    }

    #[test]
    fn test_mpls_header_too_short() {
        let data = vec![0x01, 0x02];
        assert!(MplsHeader::parse(&data).is_err());
    }
}
