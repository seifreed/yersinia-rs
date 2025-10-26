//! 802.1Q Packet Structures and Parsing
//!
//! This module implements IEEE 802.1Q VLAN tag parsing and building.

use bytes::{Buf, BufMut, Bytes, BytesMut};
use std::fmt;
use yersinia_core::{Error, Result};

/// 802.1Q Tag Protocol Identifier (TPID)
pub const DOT1Q_TPID: u16 = 0x8100;

/// Minimum valid VLAN ID (1)
pub const DOT1Q_MIN_VLAN: u16 = 1;

/// Maximum valid VLAN ID (4094)
pub const DOT1Q_MAX_VLAN: u16 = 4094;

/// Size of 802.1Q tag in bytes (4 bytes: 2 TPID + 2 TCI)
pub const DOT1Q_TAG_SIZE: usize = 4;

/// VLAN ID mask (12 bits)
const VLAN_ID_MASK: u16 = 0x0FFF;

/// Priority mask (3 bits, shifted left 13)
const PRIORITY_MASK: u16 = 0xE000;

/// DEI/CFI mask (1 bit, bit 12)
const DEI_MASK: u16 = 0x1000;

/// 802.1Q VLAN Tag
///
/// Represents a single 802.1Q tag with VLAN ID, priority, and DEI bit.
/// The tag is 4 bytes total: 2 bytes TPID (0x8100) + 2 bytes TCI.
///
/// TCI (Tag Control Information) format:
/// ```text
/// | PCP (3 bits) | DEI (1 bit) | VID (12 bits) |
/// |   Priority   | Drop Eligible |   VLAN ID    |
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Dot1qTag {
    /// VLAN Identifier (1-4094)
    pub vlan_id: u16,
    /// Priority Code Point (0-7)
    pub priority: u8,
    /// Drop Eligible Indicator (0 or 1)
    pub dei: bool,
}

impl Dot1qTag {
    /// Create a new 802.1Q tag with VLAN ID and default priority 0, DEI false
    ///
    /// # Arguments
    ///
    /// * `vlan_id` - VLAN identifier (1-4094)
    ///
    /// # Returns
    ///
    /// Returns `Ok(Dot1qTag)` if VLAN ID is valid, `Err` otherwise
    ///
    /// # Example
    ///
    /// ```
    /// use yersinia_protocols::dot1q::Dot1qTag;
    ///
    /// let tag = Dot1qTag::new(100).unwrap();
    /// assert_eq!(tag.vlan_id, 100);
    /// assert_eq!(tag.priority, 0);
    /// assert_eq!(tag.dei, false);
    /// ```
    pub fn new(vlan_id: u16) -> Result<Self> {
        if !Self::is_valid_vlan_id(vlan_id) {
            return Err(Error::InvalidParameter {
                name: "vlan_id".to_string(),
                reason: format!(
                    "Invalid VLAN ID: {}. Must be between {} and {}",
                    vlan_id, DOT1Q_MIN_VLAN, DOT1Q_MAX_VLAN
                ),
            });
        }

        Ok(Self {
            vlan_id,
            priority: 0,
            dei: false,
        })
    }

    /// Create a new 802.1Q tag with all fields specified
    ///
    /// # Arguments
    ///
    /// * `vlan_id` - VLAN identifier (1-4094)
    /// * `priority` - Priority code point (0-7)
    /// * `dei` - Drop eligible indicator
    ///
    /// # Returns
    ///
    /// Returns `Ok(Dot1qTag)` if parameters are valid, `Err` otherwise
    ///
    /// # Example
    ///
    /// ```
    /// use yersinia_protocols::dot1q::Dot1qTag;
    ///
    /// let tag = Dot1qTag::with_priority(100, 5, false).unwrap();
    /// assert_eq!(tag.vlan_id, 100);
    /// assert_eq!(tag.priority, 5);
    /// ```
    pub fn with_priority(vlan_id: u16, priority: u8, dei: bool) -> Result<Self> {
        if !Self::is_valid_vlan_id(vlan_id) {
            return Err(Error::InvalidParameter {
                name: "vlan_id".to_string(),
                reason: format!(
                    "Invalid VLAN ID: {}. Must be between {} and {}",
                    vlan_id, DOT1Q_MIN_VLAN, DOT1Q_MAX_VLAN
                ),
            });
        }

        if priority > 7 {
            return Err(Error::InvalidParameter {
                name: "priority".to_string(),
                reason: format!("Invalid priority: {}. Must be between 0 and 7", priority),
            });
        }

        Ok(Self {
            vlan_id,
            priority,
            dei,
        })
    }

    /// Check if a VLAN ID is valid (1-4094)
    ///
    /// # Arguments
    ///
    /// * `vlan_id` - VLAN ID to validate
    ///
    /// # Returns
    ///
    /// `true` if VLAN ID is in valid range, `false` otherwise
    ///
    /// # Example
    ///
    /// ```
    /// use yersinia_protocols::dot1q::Dot1qTag;
    ///
    /// assert!(Dot1qTag::is_valid_vlan_id(1));
    /// assert!(Dot1qTag::is_valid_vlan_id(100));
    /// assert!(Dot1qTag::is_valid_vlan_id(4094));
    /// assert!(!Dot1qTag::is_valid_vlan_id(0));
    /// assert!(!Dot1qTag::is_valid_vlan_id(4095));
    /// ```
    pub fn is_valid_vlan_id(vlan_id: u16) -> bool {
        (DOT1Q_MIN_VLAN..=DOT1Q_MAX_VLAN).contains(&vlan_id)
    }

    /// Parse 802.1Q tag from bytes
    ///
    /// Expects 4 bytes: 2 bytes TPID (0x8100) + 2 bytes TCI
    ///
    /// # Arguments
    ///
    /// * `data` - Buffer containing the 802.1Q tag
    ///
    /// # Returns
    ///
    /// Returns `Ok(Dot1qTag)` if parsing succeeds, `Err` otherwise
    ///
    /// # Example
    ///
    /// ```
    /// use yersinia_protocols::dot1q::Dot1qTag;
    ///
    /// // 0x8100 (TPID) + 0xA064 (PCP=5, DEI=0, VID=100)
    /// let data = vec![0x81, 0x00, 0xA0, 0x64];
    /// let tag = Dot1qTag::parse(&data).unwrap();
    /// assert_eq!(tag.vlan_id, 100);
    /// assert_eq!(tag.priority, 5);
    /// ```
    pub fn parse(data: &[u8]) -> Result<Self> {
        if data.len() < DOT1Q_TAG_SIZE {
            return Err(Error::PacketParsing(format!(
                "802.1Q tag too short: {} bytes, expected {}",
                data.len(),
                DOT1Q_TAG_SIZE
            )));
        }

        let mut buf = Bytes::copy_from_slice(data);

        // Parse TPID
        let tpid = buf.get_u16();
        if tpid != DOT1Q_TPID {
            return Err(Error::PacketParsing(format!(
                "Invalid TPID: 0x{:04X}, expected 0x{:04X}",
                tpid, DOT1Q_TPID
            )));
        }

        // Parse TCI (Tag Control Information)
        let tci = buf.get_u16();

        // Extract fields from TCI
        let priority = ((tci & PRIORITY_MASK) >> 13) as u8;
        let dei = (tci & DEI_MASK) != 0;
        let vlan_id = tci & VLAN_ID_MASK;

        // Validate VLAN ID
        if !Self::is_valid_vlan_id(vlan_id) {
            return Err(Error::PacketParsing(format!(
                "Invalid VLAN ID in tag: {}",
                vlan_id
            )));
        }

        Ok(Self {
            vlan_id,
            priority,
            dei,
        })
    }

    /// Build 802.1Q tag bytes
    ///
    /// Creates 4 bytes: 2 bytes TPID (0x8100) + 2 bytes TCI
    ///
    /// # Returns
    ///
    /// 4-byte vector containing the 802.1Q tag
    ///
    /// # Example
    ///
    /// ```
    /// use yersinia_protocols::dot1q::Dot1qTag;
    ///
    /// let tag = Dot1qTag::with_priority(100, 5, false).unwrap();
    /// let bytes = tag.build();
    /// assert_eq!(bytes.len(), 4);
    /// assert_eq!(bytes[0..2], [0x81, 0x00]); // TPID
    /// ```
    pub fn build(&self) -> Bytes {
        let mut buf = BytesMut::with_capacity(DOT1Q_TAG_SIZE);

        // Write TPID
        buf.put_u16(DOT1Q_TPID);

        // Build TCI
        let mut tci: u16 = 0;
        tci |= ((self.priority as u16) << 13) & PRIORITY_MASK;
        if self.dei {
            tci |= DEI_MASK;
        }
        tci |= self.vlan_id & VLAN_ID_MASK;

        // Write TCI
        buf.put_u16(tci);

        buf.freeze()
    }

    /// Get the TCI (Tag Control Information) as a 16-bit value
    ///
    /// This is useful for directly building frames or debugging.
    ///
    /// # Returns
    ///
    /// 16-bit TCI value containing priority, DEI, and VLAN ID
    pub fn tci(&self) -> u16 {
        let mut tci: u16 = 0;
        tci |= ((self.priority as u16) << 13) & PRIORITY_MASK;
        if self.dei {
            tci |= DEI_MASK;
        }
        tci |= self.vlan_id & VLAN_ID_MASK;
        tci
    }
}

impl Default for Dot1qTag {
    /// Create default 802.1Q tag with VLAN ID 1, priority 0, DEI false
    fn default() -> Self {
        Self {
            vlan_id: 1,
            priority: 0,
            dei: false,
        }
    }
}

impl fmt::Display for Dot1qTag {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "VLAN {} (Priority: {}, DEI: {})",
            self.vlan_id,
            self.priority,
            if self.dei { "1" } else { "0" }
        )
    }
}

/// Double-tagged 802.1Q frame structure
///
/// Represents a frame with two 802.1Q tags for Q-in-Q (double tagging) attacks.
/// Used for VLAN hopping by exploiting how switches process nested VLAN tags.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DoubleTaggedFrame {
    /// Outer 802.1Q tag (native VLAN)
    pub outer_tag: Dot1qTag,
    /// Inner 802.1Q tag (target VLAN)
    pub inner_tag: Dot1qTag,
    /// EtherType after inner tag (e.g., 0x0800 for IPv4)
    pub ethertype: u16,
    /// Payload data
    pub payload: Vec<u8>,
}

impl DoubleTaggedFrame {
    /// Create a new double-tagged frame
    ///
    /// # Arguments
    ///
    /// * `outer_tag` - Outer 802.1Q tag (attacker's VLAN)
    /// * `inner_tag` - Inner 802.1Q tag (target VLAN)
    /// * `ethertype` - EtherType following inner tag
    /// * `payload` - Frame payload
    pub fn new(outer_tag: Dot1qTag, inner_tag: Dot1qTag, ethertype: u16, payload: Vec<u8>) -> Self {
        Self {
            outer_tag,
            inner_tag,
            ethertype,
            payload,
        }
    }

    /// Build double-tagged frame bytes (both tags + ethertype + payload)
    ///
    /// # Returns
    ///
    /// Byte vector containing: outer tag (4 bytes) + inner tag (4 bytes) + ethertype (2 bytes) + payload
    pub fn build(&self) -> Bytes {
        let total_size = DOT1Q_TAG_SIZE + DOT1Q_TAG_SIZE + 2 + self.payload.len();
        let mut buf = BytesMut::with_capacity(total_size);

        // Write outer tag
        buf.put(self.outer_tag.build());

        // Write inner tag
        buf.put(self.inner_tag.build());

        // Write EtherType
        buf.put_u16(self.ethertype);

        // Write payload
        buf.put_slice(&self.payload);

        buf.freeze()
    }

    /// Parse double-tagged frame from bytes
    ///
    /// # Arguments
    ///
    /// * `data` - Buffer containing double-tagged frame
    ///
    /// # Returns
    ///
    /// Returns `Ok(DoubleTaggedFrame)` if parsing succeeds, `Err` otherwise
    pub fn parse(data: &[u8]) -> Result<Self> {
        if data.len() < DOT1Q_TAG_SIZE + DOT1Q_TAG_SIZE + 2 {
            return Err(Error::PacketParsing("Double-tagged frame too short".into()));
        }

        // Parse outer tag
        let outer_tag = Dot1qTag::parse(&data[0..DOT1Q_TAG_SIZE])?;

        // Parse inner tag
        let inner_tag = Dot1qTag::parse(&data[DOT1Q_TAG_SIZE..DOT1Q_TAG_SIZE * 2])?;

        // Parse EtherType
        let mut buf = Bytes::copy_from_slice(&data[DOT1Q_TAG_SIZE * 2..]);
        let ethertype = buf.get_u16();

        // Remaining is payload
        let payload = data[DOT1Q_TAG_SIZE * 2 + 2..].to_vec();

        Ok(Self {
            outer_tag,
            inner_tag,
            ethertype,
            payload,
        })
    }

    /// Calculate total frame size
    pub fn size(&self) -> usize {
        DOT1Q_TAG_SIZE + DOT1Q_TAG_SIZE + 2 + self.payload.len()
    }
}

impl fmt::Display for DoubleTaggedFrame {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "Double-Tagged 802.1Q Frame:")?;
        writeln!(f, "  Outer: {}", self.outer_tag)?;
        writeln!(f, "  Inner: {}", self.inner_tag)?;
        writeln!(f, "  EtherType: 0x{:04X}", self.ethertype)?;
        writeln!(f, "  Payload: {} bytes", self.payload.len())?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vlan_id_validation() {
        assert!(!Dot1qTag::is_valid_vlan_id(0));
        assert!(Dot1qTag::is_valid_vlan_id(1));
        assert!(Dot1qTag::is_valid_vlan_id(100));
        assert!(Dot1qTag::is_valid_vlan_id(4094));
        assert!(!Dot1qTag::is_valid_vlan_id(4095));
        assert!(!Dot1qTag::is_valid_vlan_id(5000));
    }

    #[test]
    fn test_tag_new() {
        let tag = Dot1qTag::new(100).unwrap();
        assert_eq!(tag.vlan_id, 100);
        assert_eq!(tag.priority, 0);
        assert!(!tag.dei);
    }

    #[test]
    fn test_tag_new_invalid_vlan() {
        assert!(Dot1qTag::new(0).is_err());
        assert!(Dot1qTag::new(4095).is_err());
    }

    #[test]
    fn test_tag_with_priority() {
        let tag = Dot1qTag::with_priority(200, 5, true).unwrap();
        assert_eq!(tag.vlan_id, 200);
        assert_eq!(tag.priority, 5);
        assert!(tag.dei);
    }

    #[test]
    fn test_tag_with_invalid_priority() {
        assert!(Dot1qTag::with_priority(100, 8, false).is_err());
    }

    #[test]
    fn test_tag_build_parse() {
        let tag = Dot1qTag::with_priority(100, 5, false).unwrap();
        let bytes = tag.build();

        assert_eq!(bytes.len(), DOT1Q_TAG_SIZE);

        let parsed = Dot1qTag::parse(&bytes).unwrap();
        assert_eq!(parsed.vlan_id, 100);
        assert_eq!(parsed.priority, 5);
        assert!(!parsed.dei);
    }

    #[test]
    fn test_tag_tci() {
        let tag = Dot1qTag::with_priority(100, 5, false).unwrap();
        let tci = tag.tci();

        // Priority 5 = 101 in binary, shifted left 13 = 0xA000
        // VLAN 100 = 0x0064
        // Combined: 0xA064
        assert_eq!(tci, 0xA064);
    }

    #[test]
    fn test_tag_parse_invalid_tpid() {
        let data = vec![0x88, 0x48, 0x00, 0x64]; // Wrong TPID
        assert!(Dot1qTag::parse(&data).is_err());
    }

    #[test]
    fn test_tag_parse_too_short() {
        let data = vec![0x81, 0x00]; // Only 2 bytes
        assert!(Dot1qTag::parse(&data).is_err());
    }

    #[test]
    fn test_tag_default() {
        let tag = Dot1qTag::default();
        assert_eq!(tag.vlan_id, 1);
        assert_eq!(tag.priority, 0);
        assert!(!tag.dei);
    }

    #[test]
    fn test_tag_display() {
        let tag = Dot1qTag::with_priority(100, 5, true).unwrap();
        let display = format!("{}", tag);
        assert!(display.contains("VLAN 100"));
        assert!(display.contains("Priority: 5"));
        assert!(display.contains("DEI: 1"));
    }

    #[test]
    fn test_double_tagged_new() {
        let outer = Dot1qTag::new(10).unwrap();
        let inner = Dot1qTag::new(20).unwrap();
        let payload = vec![0xDE, 0xAD, 0xBE, 0xEF];

        let frame = DoubleTaggedFrame::new(outer, inner, 0x0800, payload.clone());
        assert_eq!(frame.outer_tag.vlan_id, 10);
        assert_eq!(frame.inner_tag.vlan_id, 20);
        assert_eq!(frame.ethertype, 0x0800);
        assert_eq!(frame.payload, payload);
    }

    #[test]
    fn test_double_tagged_build_parse() {
        let outer = Dot1qTag::with_priority(10, 3, false).unwrap();
        let inner = Dot1qTag::with_priority(20, 5, true).unwrap();
        let payload = vec![0xAA, 0xBB, 0xCC, 0xDD];

        let frame = DoubleTaggedFrame::new(outer, inner, 0x0800, payload.clone());
        let bytes = frame.build();

        // Should be 4 (outer tag) + 4 (inner tag) + 2 (ethertype) + 4 (payload) = 14 bytes
        assert_eq!(bytes.len(), 14);

        let parsed = DoubleTaggedFrame::parse(&bytes).unwrap();
        assert_eq!(parsed.outer_tag.vlan_id, 10);
        assert_eq!(parsed.outer_tag.priority, 3);
        assert_eq!(parsed.inner_tag.vlan_id, 20);
        assert_eq!(parsed.inner_tag.priority, 5);
        assert!(parsed.inner_tag.dei);
        assert_eq!(parsed.ethertype, 0x0800);
        assert_eq!(parsed.payload, payload);
    }

    #[test]
    fn test_double_tagged_size() {
        let outer = Dot1qTag::new(10).unwrap();
        let inner = Dot1qTag::new(20).unwrap();
        let payload = vec![0; 100];

        let frame = DoubleTaggedFrame::new(outer, inner, 0x0800, payload);

        // 4 + 4 + 2 + 100 = 110 bytes
        assert_eq!(frame.size(), 110);
    }

    #[test]
    fn test_double_tagged_parse_too_short() {
        let data = vec![0x81, 0x00, 0x00, 0x0A]; // Only 4 bytes (one tag)
        assert!(DoubleTaggedFrame::parse(&data).is_err());
    }

    #[test]
    fn test_constants() {
        assert_eq!(DOT1Q_TPID, 0x8100);
        assert_eq!(DOT1Q_MIN_VLAN, 1);
        assert_eq!(DOT1Q_MAX_VLAN, 4094);
        assert_eq!(DOT1Q_TAG_SIZE, 4);
    }
}
