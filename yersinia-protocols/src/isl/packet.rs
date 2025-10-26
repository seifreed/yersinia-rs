//! ISL Packet Structures and Parsing
//!
//! Implements complete ISL frame parsing and building with CRC32 validation.
//! ISL is a legacy Cisco protocol for VLAN trunking that wraps entire Ethernet frames.

use bytes::{Buf, BufMut, Bytes, BytesMut};
use std::fmt;
use yersinia_core::{Error, MacAddr, Result};

/// ISL header size (26 bytes)
pub const ISL_HEADER_SIZE: usize = 26;

/// ISL trailer size (4 bytes CRC)
pub const ISL_TRAILER_SIZE: usize = 4;

/// ISL total overhead (header + trailer)
pub const ISL_TOTAL_OVERHEAD: usize = ISL_HEADER_SIZE + ISL_TRAILER_SIZE;

/// ISL destination address type for Ethernet (DA field, 5 bits)
pub const ISL_DA_TYPE_ETHERNET: u8 = 0x00;

/// ISL frame type values (Type field, 4 bits)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IslFrameType {
    /// Ethernet frame (0x0)
    Ethernet = 0x0,
    /// Token Ring frame (0x1)
    TokenRing = 0x1,
    /// FDDI frame (0x2)
    Fddi = 0x2,
    /// ATM frame (0x3)
    Atm = 0x3,
}

impl IslFrameType {
    /// Convert from u8 value
    pub fn from_u8(value: u8) -> Option<Self> {
        match value & 0x0F {
            0x0 => Some(Self::Ethernet),
            0x1 => Some(Self::TokenRing),
            0x2 => Some(Self::Fddi),
            0x3 => Some(Self::Atm),
            _ => None,
        }
    }

    /// Convert to u8 value
    pub fn as_u8(&self) -> u8 {
        *self as u8
    }
}

impl fmt::Display for IslFrameType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Ethernet => write!(f, "Ethernet"),
            Self::TokenRing => write!(f, "Token Ring"),
            Self::Fddi => write!(f, "FDDI"),
            Self::Atm => write!(f, "ATM"),
        }
    }
}

/// ISL SNAP LLC header constant (0xAAAA03)
pub const ISL_SNAP: [u8; 3] = [0xAA, 0xAA, 0x03];

/// ISL default destination MAC address (01:00:0C:00:00:00)
pub const ISL_DEFAULT_DST_MAC: MacAddr = MacAddr([0x01, 0x00, 0x0C, 0x00, 0x00, 0x00]);

/// Complete ISL frame structure
///
/// ISL Frame Format:
/// ```text
/// +------------------+
/// | DA (40 bits)     |  Destination Address (bits 40-1)
/// | Type (4 bits)    |  Frame type
/// | User (4 bits)    |  User priority
/// | SA (48 bits)     |  Source Address
/// | LEN (16 bits)    |  Length of frame
/// | AAAA03 (24 bits) |  SNAP LLC
/// | HSA (24 bits)    |  High bits of SA
/// | VLAN (15 bits)   |  VLAN ID (0-32767)
/// | BPDU (1 bit)     |  BPDU indicator
/// | INDEX (16 bits)  |  Port index
/// | RES (16 bits)    |  Reserved
/// +------------------+
/// | Encapsulated     |
/// | Ethernet Frame   |
/// +------------------+
/// | CRC (32 bits)    |  CRC32 checksum
/// +------------------+
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IslFrame {
    /// Destination address type (5 bits, always 0x00 for Ethernet)
    pub da_type: u8,
    /// Frame type (4 bits)
    pub frame_type: IslFrameType,
    /// User-defined priority bits (4 bits)
    pub user: u8,
    /// Source MAC address (48 bits)
    pub src_mac: MacAddr,
    /// Length of encapsulated frame (16 bits)
    pub length: u16,
    /// SNAP LLC (24 bits, always 0xAAAA03)
    pub snap: [u8; 3],
    /// High bits of source address (24 bits)
    pub hsa: [u8; 3],
    /// VLAN ID (15 bits, 0-32767)
    pub vlan_id: u16,
    /// BPDU indicator (1 bit)
    pub bpdu: bool,
    /// Port index (16 bits)
    pub index: u16,
    /// Reserved (16 bits)
    pub reserved: u16,
    /// Encapsulated frame payload
    pub payload: Bytes,
    /// CRC32 checksum (calculated)
    pub crc: u32,
}

impl IslFrame {
    /// Create a new ISL frame with specified VLAN ID and payload
    pub fn new(vlan_id: u16, payload: impl Into<Bytes>) -> Self {
        let payload = payload.into();
        let length = payload.len() as u16;

        // Generate random source MAC (Cisco range)
        let mut src_mac = [0u8; 6];
        use rand::Rng;
        let mut rng = rand::thread_rng();
        rng.fill(&mut src_mac);
        src_mac[0] = 0x00;
        src_mac[1] = 0x0C; // Cisco OUI
        src_mac[2] = 0x0C;

        let mut frame = Self {
            da_type: ISL_DA_TYPE_ETHERNET,
            frame_type: IslFrameType::Ethernet,
            user: 0x0,
            src_mac: MacAddr(src_mac),
            length,
            snap: ISL_SNAP,
            hsa: [0x00, 0x00, 0x00],
            vlan_id: vlan_id & 0x7FFF, // 15 bits max
            bpdu: false,
            index: 0x0000,
            reserved: 0x0000,
            payload,
            crc: 0,
        };

        // Calculate CRC
        frame.crc = frame.calculate_crc();
        frame
    }

    /// Create ISL frame with custom source MAC
    pub fn with_src_mac(mut self, mac: MacAddr) -> Self {
        self.src_mac = mac;
        self.crc = self.calculate_crc();
        self
    }

    /// Create ISL frame with custom frame type
    pub fn with_frame_type(mut self, frame_type: IslFrameType) -> Self {
        self.frame_type = frame_type;
        self.crc = self.calculate_crc();
        self
    }

    /// Create ISL frame with user priority
    pub fn with_user(mut self, user: u8) -> Self {
        self.user = user & 0x0F; // 4 bits only
        self.crc = self.calculate_crc();
        self
    }

    /// Create ISL frame with BPDU indicator
    pub fn with_bpdu(mut self, bpdu: bool) -> Self {
        self.bpdu = bpdu;
        self.crc = self.calculate_crc();
        self
    }

    /// Create ISL frame with port index
    pub fn with_index(mut self, index: u16) -> Self {
        self.index = index;
        self.crc = self.calculate_crc();
        self
    }

    /// Calculate CRC32 for ISL frame
    ///
    /// CRC is calculated over the entire frame (header + payload + placeholder CRC)
    pub fn calculate_crc(&self) -> u32 {
        use crc32fast::Hasher;

        let mut hasher = Hasher::new();

        // Build header for CRC calculation
        let header = self.build_header();
        hasher.update(&header);

        // Add payload
        hasher.update(&self.payload);

        // Add 4 zero bytes for CRC placeholder
        hasher.update(&[0u8; 4]);

        hasher.finalize()
    }

    /// Verify CRC32 checksum
    pub fn verify_crc(&self) -> bool {
        self.crc == self.calculate_crc()
    }

    /// Build ISL header (26 bytes)
    fn build_header(&self) -> [u8; ISL_HEADER_SIZE] {
        let mut header = [0u8; ISL_HEADER_SIZE];

        // Byte 0-4: DA (40 bits) + Type/User (8 bits)
        // DA is first 5 bytes of ISL default multicast MAC
        header[0] = ISL_DEFAULT_DST_MAC.0[0];
        header[1] = ISL_DEFAULT_DST_MAC.0[1];
        header[2] = ISL_DEFAULT_DST_MAC.0[2];
        header[3] = ISL_DEFAULT_DST_MAC.0[3];
        header[4] = ISL_DEFAULT_DST_MAC.0[4];

        // Byte 5: DA_type (top 5 bits) + Frame type (4 bits) + User (4 bits)
        // DA is split: first 40 bits in bytes 0-4, last 5 bits in top of byte 5
        // Frame type in middle 4 bits, User in bottom 4 bits
        header[5] = ((self.da_type & 0x1F) << 3)
            | ((self.frame_type.as_u8() & 0x0F) << 4)
            | (self.user & 0x0F);

        // Byte 6-11: Source MAC (48 bits)
        header[6..12].copy_from_slice(&self.src_mac.0);

        // Byte 12-13: Length (16 bits, big-endian)
        header[12] = (self.length >> 8) as u8;
        header[13] = (self.length & 0xFF) as u8;

        // Byte 14-16: SNAP LLC (24 bits)
        header[14..17].copy_from_slice(&self.snap);

        // Byte 17-19: HSA (24 bits)
        header[17..20].copy_from_slice(&self.hsa);

        // Byte 20-21: VLAN (15 bits) + BPDU (1 bit), big-endian
        let vlan_bpdu = ((self.vlan_id & 0x7FFF) << 1) | (self.bpdu as u16);
        header[20] = (vlan_bpdu >> 8) as u8;
        header[21] = (vlan_bpdu & 0xFF) as u8;

        // Byte 22-23: Index (16 bits, big-endian)
        header[22] = (self.index >> 8) as u8;
        header[23] = (self.index & 0xFF) as u8;

        // Byte 24-25: Reserved (16 bits, big-endian)
        header[24] = (self.reserved >> 8) as u8;
        header[25] = (self.reserved & 0xFF) as u8;

        header
    }

    /// Build complete ISL frame as bytes
    pub fn build(&self) -> Bytes {
        let total_size = ISL_HEADER_SIZE + self.payload.len() + ISL_TRAILER_SIZE;
        let mut buf = BytesMut::with_capacity(total_size);

        // Write header
        buf.put_slice(&self.build_header());

        // Write payload
        buf.put_slice(&self.payload);

        // Write CRC (32 bits, big-endian)
        buf.put_u32(self.crc);

        buf.freeze()
    }

    /// Parse ISL frame from bytes
    pub fn parse(data: &[u8]) -> Result<Self> {
        if data.len() < ISL_HEADER_SIZE + ISL_TRAILER_SIZE {
            return Err(Error::PacketParsing(format!(
                "ISL frame too short: {} bytes (minimum {})",
                data.len(),
                ISL_HEADER_SIZE + ISL_TRAILER_SIZE
            )));
        }

        let mut buf = Bytes::copy_from_slice(data);

        // Parse header
        let mut header = [0u8; ISL_HEADER_SIZE];
        buf.copy_to_slice(&mut header);

        // Byte 5 contains DA_type (top 5 bits), Frame type (middle 4 bits), User (bottom 4 bits)
        let byte5 = header[5];
        let da_type = (byte5 >> 3) & 0x1F;
        let frame_type_val = (byte5 >> 4) & 0x0F;
        let user = byte5 & 0x0F;

        let frame_type = IslFrameType::from_u8(frame_type_val).ok_or_else(|| {
            Error::PacketParsing(format!("Invalid ISL frame type: 0x{:X}", frame_type_val))
        })?;

        // Source MAC
        let mut src_mac = [0u8; 6];
        src_mac.copy_from_slice(&header[6..12]);

        // Length
        let length = u16::from_be_bytes([header[12], header[13]]);

        // SNAP
        let mut snap = [0u8; 3];
        snap.copy_from_slice(&header[14..17]);

        // HSA
        let mut hsa = [0u8; 3];
        hsa.copy_from_slice(&header[17..20]);

        // VLAN + BPDU
        let vlan_bpdu = u16::from_be_bytes([header[20], header[21]]);
        let vlan_id = vlan_bpdu >> 1;
        let bpdu = (vlan_bpdu & 0x01) != 0;

        // Index
        let index = u16::from_be_bytes([header[22], header[23]]);

        // Reserved
        let reserved = u16::from_be_bytes([header[24], header[25]]);

        // Payload (everything except last 4 bytes which are CRC)
        let payload_len = buf.remaining() - ISL_TRAILER_SIZE;
        if payload_len < length as usize {
            return Err(Error::PacketParsing(format!(
                "ISL payload truncated: expected {} bytes, got {}",
                length, payload_len
            )));
        }

        let payload = buf.copy_to_bytes(payload_len);

        // CRC
        let crc = buf.get_u32();

        let frame = Self {
            da_type,
            frame_type,
            user,
            src_mac: MacAddr(src_mac),
            length,
            snap,
            hsa,
            vlan_id,
            bpdu,
            index,
            reserved,
            payload,
            crc,
        };

        Ok(frame)
    }

    /// Get total frame size
    pub fn size(&self) -> usize {
        ISL_HEADER_SIZE + self.payload.len() + ISL_TRAILER_SIZE
    }
}

impl fmt::Display for IslFrame {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "ISL Frame:")?;
        writeln!(f, "  DA Type: 0x{:02X}", self.da_type)?;
        writeln!(
            f,
            "  Frame Type: {} (0x{:X})",
            self.frame_type,
            self.frame_type.as_u8()
        )?;
        writeln!(f, "  User: 0x{:X}", self.user)?;
        writeln!(f, "  Source MAC: {}", self.src_mac)?;
        writeln!(f, "  Length: {}", self.length)?;
        writeln!(
            f,
            "  SNAP: {:02X}{:02X}{:02X}",
            self.snap[0], self.snap[1], self.snap[2]
        )?;
        writeln!(
            f,
            "  HSA: {:02X}{:02X}{:02X}",
            self.hsa[0], self.hsa[1], self.hsa[2]
        )?;
        writeln!(f, "  VLAN ID: {}", self.vlan_id)?;
        writeln!(f, "  BPDU: {}", self.bpdu)?;
        writeln!(f, "  Index: 0x{:04X}", self.index)?;
        writeln!(f, "  Reserved: 0x{:04X}", self.reserved)?;
        writeln!(f, "  Payload: {} bytes", self.payload.len())?;
        writeln!(f, "  CRC: 0x{:08X}", self.crc)?;
        writeln!(f, "  CRC Valid: {}", self.verify_crc())?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_isl_frame_type_conversion() {
        assert_eq!(IslFrameType::from_u8(0x0), Some(IslFrameType::Ethernet));
        assert_eq!(IslFrameType::from_u8(0x1), Some(IslFrameType::TokenRing));
        assert_eq!(IslFrameType::from_u8(0x2), Some(IslFrameType::Fddi));
        assert_eq!(IslFrameType::from_u8(0x3), Some(IslFrameType::Atm));
        assert_eq!(IslFrameType::from_u8(0xF), None);
    }

    #[test]
    fn test_isl_frame_new() {
        let payload = vec![0u8; 64];
        let frame = IslFrame::new(100, payload.clone());

        assert_eq!(frame.da_type, ISL_DA_TYPE_ETHERNET);
        assert_eq!(frame.frame_type, IslFrameType::Ethernet);
        assert_eq!(frame.user, 0x0);
        assert_eq!(frame.vlan_id, 100);
        assert_eq!(frame.length, 64);
        assert_eq!(frame.payload.len(), 64);
        assert_eq!(frame.snap, ISL_SNAP);
        assert!(!frame.bpdu);
    }

    #[test]
    fn test_isl_frame_vlan_range() {
        let payload = vec![0u8; 64];
        let frame = IslFrame::new(0x8FFF, payload); // > 15 bits
        assert!(frame.vlan_id <= 0x7FFF); // Should be masked to 15 bits
    }

    #[test]
    fn test_isl_frame_with_methods() {
        let payload = vec![0u8; 64];
        let mac = MacAddr([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]);

        let frame = IslFrame::new(100, payload)
            .with_src_mac(mac)
            .with_user(0x05)
            .with_bpdu(true)
            .with_index(0x1234);

        assert_eq!(frame.src_mac, mac);
        assert_eq!(frame.user, 0x05);
        assert!(frame.bpdu);
        assert_eq!(frame.index, 0x1234);
    }

    #[test]
    fn test_isl_crc_calculation() {
        let payload = vec![0x12, 0x34, 0x56, 0x78];
        let frame = IslFrame::new(100, payload);

        // CRC should be non-zero
        assert_ne!(frame.crc, 0);

        // Verify CRC
        assert!(frame.verify_crc());
    }

    #[test]
    fn test_isl_build_parse_roundtrip() {
        let payload = vec![0xAA; 128];
        let mac = MacAddr([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);

        let original = IslFrame::new(200, payload.clone())
            .with_src_mac(mac)
            .with_user(0x03)
            .with_bpdu(true)
            .with_index(0x5678);

        let bytes = original.build();
        let parsed = IslFrame::parse(&bytes).unwrap();

        assert_eq!(original.da_type, parsed.da_type);
        assert_eq!(original.frame_type, parsed.frame_type);
        assert_eq!(original.user, parsed.user);
        assert_eq!(original.src_mac, parsed.src_mac);
        assert_eq!(original.length, parsed.length);
        assert_eq!(original.snap, parsed.snap);
        assert_eq!(original.hsa, parsed.hsa);
        assert_eq!(original.vlan_id, parsed.vlan_id);
        assert_eq!(original.bpdu, parsed.bpdu);
        assert_eq!(original.index, parsed.index);
        assert_eq!(original.reserved, parsed.reserved);
        assert_eq!(original.payload, parsed.payload);
        assert_eq!(original.crc, parsed.crc);
    }

    #[test]
    fn test_isl_parse_too_short() {
        let data = vec![0u8; 20]; // Less than minimum ISL size
        let result = IslFrame::parse(&data);
        assert!(result.is_err());
    }

    #[test]
    fn test_isl_parse_invalid_frame_type() {
        // Create minimal ISL frame with invalid frame type
        let mut data = vec![0u8; ISL_HEADER_SIZE + ISL_TRAILER_SIZE];

        // Set byte 5 with invalid frame type (0xF in middle nibble)
        data[5] = 0xF0; // Invalid frame type

        let result = IslFrame::parse(&data);
        assert!(result.is_err());
    }

    #[test]
    fn test_isl_header_building() {
        let payload = vec![0u8; 64];
        let frame = IslFrame::new(100, payload);

        let header = frame.build_header();

        assert_eq!(header.len(), ISL_HEADER_SIZE);

        // Check DA (first 5 bytes)
        assert_eq!(header[0], ISL_DEFAULT_DST_MAC.0[0]);
        assert_eq!(header[1], ISL_DEFAULT_DST_MAC.0[1]);
        assert_eq!(header[2], ISL_DEFAULT_DST_MAC.0[2]);
        assert_eq!(header[3], ISL_DEFAULT_DST_MAC.0[3]);
        assert_eq!(header[4], ISL_DEFAULT_DST_MAC.0[4]);

        // Check SNAP
        assert_eq!(&header[14..17], &ISL_SNAP);
    }

    #[test]
    fn test_isl_size() {
        let payload = vec![0u8; 100];
        let frame = IslFrame::new(1, payload);

        assert_eq!(frame.size(), ISL_HEADER_SIZE + 100 + ISL_TRAILER_SIZE);
    }

    #[test]
    fn test_isl_display() {
        let payload = vec![0xAB; 64];
        let frame = IslFrame::new(42, payload);

        let display = format!("{}", frame);
        assert!(display.contains("ISL Frame"));
        assert!(display.contains("VLAN ID: 42"));
        assert!(display.contains("Payload: 64 bytes"));
    }

    #[test]
    fn test_isl_constants() {
        assert_eq!(ISL_HEADER_SIZE, 26);
        assert_eq!(ISL_TRAILER_SIZE, 4);
        assert_eq!(ISL_TOTAL_OVERHEAD, 30);
        assert_eq!(ISL_DA_TYPE_ETHERNET, 0x00);
    }

    #[test]
    fn test_isl_snap_constant() {
        assert_eq!(ISL_SNAP, [0xAA, 0xAA, 0x03]);
    }

    #[test]
    fn test_isl_default_dst_mac() {
        assert_eq!(ISL_DEFAULT_DST_MAC.0, [0x01, 0x00, 0x0C, 0x00, 0x00, 0x00]);
    }

    #[test]
    fn test_frame_type_display() {
        assert_eq!(IslFrameType::Ethernet.to_string(), "Ethernet");
        assert_eq!(IslFrameType::TokenRing.to_string(), "Token Ring");
        assert_eq!(IslFrameType::Fddi.to_string(), "FDDI");
        assert_eq!(IslFrameType::Atm.to_string(), "ATM");
    }

    #[test]
    fn test_isl_user_priority() {
        let payload = vec![0u8; 64];
        let frame = IslFrame::new(1, payload).with_user(0xFF); // Try to set > 4 bits

        assert_eq!(frame.user, 0x0F); // Should be masked to 4 bits
    }
}
