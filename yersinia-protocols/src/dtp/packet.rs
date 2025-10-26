//! DTP Packet Structures and Parsing
//!
//! This module implements complete DTP packet parsing and building with TLV support.

use bytes::{Buf, BufMut, Bytes, BytesMut};
use std::fmt;
use yersinia_core::{Error, MacAddr, Result};

/// DTP multicast destination MAC address (01:00:0C:CC:CC:CC)
pub const DTP_MULTICAST_MAC: MacAddr = MacAddr([0x01, 0x00, 0x0C, 0xCC, 0xCC, 0xCC]);

/// DTP protocol version (always 0x01)
pub const DTP_VERSION: u8 = 0x01;

/// SNAP type for DTP (0x2004)
pub const DTP_SNAP_TYPE: u16 = 0x2004;

/// DTP hello interval in seconds (30 seconds like Cisco)
pub const DTP_HELLO_INTERVAL: u64 = 30;

/// Maximum domain name length
pub const DTP_DOMAIN_MAX_LEN: usize = 32;

/// TLV Type values
pub mod tlv_types {
    /// Domain TLV (0x0001) - VTP domain name
    pub const DOMAIN: u16 = 0x0001;
    /// Status TLV (0x0002) - Port status (trunk/access/auto/desirable)
    pub const STATUS: u16 = 0x0002;
    /// Type TLV (0x0003) - Trunk type (ISL/802.1Q/negotiate)
    pub const TYPE: u16 = 0x0003;
    /// Neighbor TLV (0x0004) - Neighbor MAC address
    pub const NEIGHBOR: u16 = 0x0004;
}

/// DTP Status byte values
///
/// The status byte is composed of:
/// - High nibble (0xF0): Trunk Operating Status (TOS)
///   - 0x00 = Access mode
///   - 0x80 = Trunk mode
/// - Low nibble (0x0F): Trunk Administrative Status (TAS)
///   - 0x01 = On (forced)
///   - 0x02 = Off (disabled)
///   - 0x03 = Desirable (actively negotiate)
///   - 0x04 = Auto (passively negotiate)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DtpStatus(pub u8);

impl DtpStatus {
    // Trunk Operating Status (TOS) - high nibble
    pub const TOS_ACCESS: u8 = 0x00;
    pub const TOS_TRUNK: u8 = 0x80;

    // Trunk Administrative Status (TAS) - low nibble
    pub const TAS_ON: u8 = 0x01;
    pub const TAS_OFF: u8 = 0x02;
    pub const TAS_DESIRABLE: u8 = 0x03;
    pub const TAS_AUTO: u8 = 0x04;

    // Combined common values (matches Yersinia C constants)
    pub const ACCESS_ON: u8 = Self::TOS_ACCESS | Self::TAS_ON;
    pub const ACCESS_OFF: u8 = Self::TOS_ACCESS | Self::TAS_OFF;
    pub const ACCESS_DESIRABLE: u8 = Self::TOS_ACCESS | Self::TAS_DESIRABLE;
    pub const ACCESS_AUTO: u8 = Self::TOS_ACCESS | Self::TAS_AUTO;
    pub const TRUNK_ON: u8 = Self::TOS_TRUNK | Self::TAS_ON;
    pub const TRUNK_OFF: u8 = Self::TOS_TRUNK | Self::TAS_OFF;
    pub const TRUNK_DESIRABLE: u8 = Self::TOS_TRUNK | Self::TAS_DESIRABLE;
    pub const TRUNK_AUTO: u8 = Self::TOS_TRUNK | Self::TAS_AUTO;

    /// Create a new status from raw byte
    pub fn new(value: u8) -> Self {
        Self(value)
    }

    /// Create status for trunk desirable mode (most aggressive)
    pub fn trunk_desirable() -> Self {
        Self(Self::TRUNK_DESIRABLE)
    }

    /// Create status for access desirable mode
    pub fn access_desirable() -> Self {
        Self(Self::ACCESS_DESIRABLE)
    }

    /// Create status for trunk on (forced trunk)
    pub fn trunk_on() -> Self {
        Self(Self::TRUNK_ON)
    }

    /// Create status for access auto mode
    pub fn access_auto() -> Self {
        Self(Self::ACCESS_AUTO)
    }

    /// Get the Trunk Operating Status (TOS)
    pub fn operating_status(&self) -> u8 {
        self.0 & 0xF0
    }

    /// Get the Trunk Administrative Status (TAS)
    pub fn admin_status(&self) -> u8 {
        self.0 & 0x0F
    }

    /// Check if this is trunk mode
    pub fn is_trunk(&self) -> bool {
        self.operating_status() == Self::TOS_TRUNK
    }

    /// Check if this is access mode
    pub fn is_access(&self) -> bool {
        self.operating_status() == Self::TOS_ACCESS
    }

    /// Check if this will actively negotiate
    pub fn is_desirable(&self) -> bool {
        self.admin_status() == Self::TAS_DESIRABLE
    }

    /// Check if this will passively negotiate
    pub fn is_auto(&self) -> bool {
        self.admin_status() == Self::TAS_AUTO
    }

    /// Get raw byte value
    pub fn as_u8(&self) -> u8 {
        self.0
    }
}

impl fmt::Display for DtpStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let tos = match self.operating_status() {
            Self::TOS_ACCESS => "ACCESS",
            Self::TOS_TRUNK => "TRUNK",
            _ => "UNKNOWN",
        };
        let tas = match self.admin_status() {
            Self::TAS_ON => "ON",
            Self::TAS_OFF => "OFF",
            Self::TAS_DESIRABLE => "DESIRABLE",
            Self::TAS_AUTO => "AUTO",
            _ => "UNKNOWN",
        };
        write!(f, "{}/{}", tos, tas)
    }
}

/// DTP Type byte values
///
/// The type byte is composed of:
/// - High bits: Trunk Operating Type (TOT)
///   - 0x20 = Native
///   - 0x40 = ISL
///   - 0xA0 = 802.1Q
/// - Low bits: Trunk Administrative Type (TAT)
///   - 0x00 = Negotiated
///   - 0x01 = Native
///   - 0x02 = ISL
///   - 0x05 = 802.1Q
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DtpType(pub u8);

impl DtpType {
    // Trunk Operating Type (TOT) - high bits
    pub const TOT_NATIVE: u8 = 0x20;
    pub const TOT_ISL: u8 = 0x40;
    pub const TOT_DOT1Q: u8 = 0xA0;

    // Trunk Administrative Type (TAT) - low bits
    pub const TAT_NEGOTIATED: u8 = 0x00;
    pub const TAT_NATIVE: u8 = 0x01;
    pub const TAT_ISL: u8 = 0x02;
    pub const TAT_DOT1Q: u8 = 0x05;

    // Combined common values (matches Yersinia C constants)
    pub const DOT1Q_DOT1Q: u8 = Self::TOT_DOT1Q | Self::TAT_DOT1Q;
    pub const DOT1Q_ISL: u8 = Self::TOT_DOT1Q | Self::TAT_ISL;
    pub const DOT1Q_NATIVE: u8 = Self::TOT_DOT1Q | Self::TAT_NATIVE;
    pub const DOT1Q_NEGOTIATED: u8 = Self::TOT_DOT1Q | Self::TAT_NEGOTIATED;
    pub const ISL_ISL: u8 = Self::TOT_ISL | Self::TAT_ISL;
    pub const ISL_DOT1Q: u8 = Self::TOT_ISL | Self::TAT_DOT1Q;
    pub const ISL_NATIVE: u8 = Self::TOT_ISL | Self::TAT_NATIVE;
    pub const ISL_NEGOTIATED: u8 = Self::TOT_ISL | Self::TAT_NEGOTIATED;
    pub const NATIVE_NATIVE: u8 = Self::TOT_NATIVE | Self::TAT_NATIVE;
    pub const NATIVE_DOT1Q: u8 = Self::TOT_NATIVE | Self::TAT_DOT1Q;
    pub const NATIVE_ISL: u8 = Self::TOT_NATIVE | Self::TAT_ISL;
    pub const NATIVE_NEGOTIATED: u8 = Self::TOT_NATIVE | Self::TAT_NEGOTIATED;

    /// Create a new type from raw byte
    pub fn new(value: u8) -> Self {
        Self(value)
    }

    /// Create type for 802.1Q trunking
    pub fn dot1q() -> Self {
        Self(Self::DOT1Q_DOT1Q)
    }

    /// Create type for ISL trunking
    pub fn isl() -> Self {
        Self(Self::ISL_ISL)
    }

    /// Create type for negotiate mode
    pub fn negotiate() -> Self {
        Self(Self::DOT1Q_NEGOTIATED)
    }

    /// Get the Trunk Operating Type (TOT)
    pub fn operating_type(&self) -> u8 {
        self.0 & 0xE0
    }

    /// Get the Trunk Administrative Type (TAT)
    pub fn admin_type(&self) -> u8 {
        self.0 & 0x0F
    }

    /// Check if this is 802.1Q
    pub fn is_dot1q(&self) -> bool {
        self.operating_type() == Self::TOT_DOT1Q
    }

    /// Check if this is ISL
    pub fn is_isl(&self) -> bool {
        self.operating_type() == Self::TOT_ISL
    }

    /// Get raw byte value
    pub fn as_u8(&self) -> u8 {
        self.0
    }
}

impl fmt::Display for DtpType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let tot = match self.operating_type() {
            Self::TOT_NATIVE => "NATIVE",
            Self::TOT_ISL => "ISL",
            Self::TOT_DOT1Q => "802.1Q",
            _ => "UNKNOWN",
        };
        let tat = match self.admin_type() {
            Self::TAT_NEGOTIATED => "NEGOTIATED",
            Self::TAT_NATIVE => "NATIVE",
            Self::TAT_ISL => "ISL",
            Self::TAT_DOT1Q => "802.1Q",
            _ => "UNKNOWN",
        };
        write!(f, "{}/{}", tot, tat)
    }
}

/// DTP TLV (Type-Length-Value)
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DtpTlv {
    /// Domain name TLV (type 0x0001)
    Domain(String),
    /// Status TLV (type 0x0002)
    Status(DtpStatus),
    /// Type TLV (type 0x0003)
    Type(DtpType),
    /// Neighbor MAC address TLV (type 0x0004)
    Neighbor(MacAddr),
}

impl DtpTlv {
    /// Get the TLV type code
    pub fn tlv_type(&self) -> u16 {
        match self {
            Self::Domain(_) => tlv_types::DOMAIN,
            Self::Status(_) => tlv_types::STATUS,
            Self::Type(_) => tlv_types::TYPE,
            Self::Neighbor(_) => tlv_types::NEIGHBOR,
        }
    }

    /// Get the TLV length (including 4-byte header)
    pub fn tlv_length(&self) -> u16 {
        match self {
            Self::Domain(s) => 4 + s.len() as u16,
            Self::Status(_) => 5,
            Self::Type(_) => 5,
            Self::Neighbor(_) => 10,
        }
    }

    /// Parse a TLV from bytes
    pub fn parse(data: &mut impl Buf) -> Result<Self> {
        if data.remaining() < 4 {
            return Err(Error::PacketParsing("DTP TLV too short".into()));
        }

        let tlv_type = data.get_u16();
        let tlv_len = data.get_u16();

        if tlv_len < 4 {
            return Err(Error::PacketParsing("DTP TLV length < 4".into()));
        }

        let data_len = tlv_len - 4;
        if data.remaining() < data_len as usize {
            return Err(Error::PacketParsing("DTP TLV data truncated".into()));
        }

        match tlv_type {
            tlv_types::DOMAIN => {
                let mut domain = vec![0u8; data_len as usize];
                data.copy_to_slice(&mut domain);
                // Remove null terminator if present
                if let Some(pos) = domain.iter().position(|&b| b == 0) {
                    domain.truncate(pos);
                }
                let domain_str = String::from_utf8(domain)
                    .unwrap_or_else(|e| String::from_utf8_lossy(&e.into_bytes()).to_string());
                Ok(Self::Domain(domain_str))
            }
            tlv_types::STATUS => {
                if data_len != 1 {
                    return Err(Error::PacketParsing("DTP Status TLV invalid length".into()));
                }
                Ok(Self::Status(DtpStatus::new(data.get_u8())))
            }
            tlv_types::TYPE => {
                if data_len != 1 {
                    return Err(Error::PacketParsing("DTP Type TLV invalid length".into()));
                }
                Ok(Self::Type(DtpType::new(data.get_u8())))
            }
            tlv_types::NEIGHBOR => {
                if data_len != 6 {
                    return Err(Error::PacketParsing(
                        "DTP Neighbor TLV invalid length".into(),
                    ));
                }
                let mut mac = [0u8; 6];
                data.copy_to_slice(&mut mac);
                Ok(Self::Neighbor(MacAddr(mac)))
            }
            _ => {
                // Unknown TLV - skip it
                data.advance(data_len as usize);
                Err(Error::PacketParsing(format!(
                    "Unknown DTP TLV type: 0x{:04X}",
                    tlv_type
                )))
            }
        }
    }

    /// Write TLV to buffer
    pub fn write(&self, buf: &mut impl BufMut) {
        buf.put_u16(self.tlv_type());
        buf.put_u16(self.tlv_length());

        match self {
            Self::Domain(s) => {
                buf.put_slice(s.as_bytes());
            }
            Self::Status(status) => {
                buf.put_u8(status.as_u8());
            }
            Self::Type(typ) => {
                buf.put_u8(typ.as_u8());
            }
            Self::Neighbor(mac) => {
                buf.put_slice(&mac.0);
            }
        }
    }
}

/// Complete DTP packet
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DtpPacket {
    /// DTP version (always 0x01)
    pub version: u8,
    /// List of TLVs
    pub tlvs: Vec<DtpTlv>,
}

impl DtpPacket {
    /// Create a new DTP packet with default version
    pub fn new() -> Self {
        Self {
            version: DTP_VERSION,
            tlvs: Vec::new(),
        }
    }

    /// Add a TLV to the packet
    pub fn add_tlv(mut self, tlv: DtpTlv) -> Self {
        self.tlvs.push(tlv);
        self
    }

    /// Set domain TLV
    pub fn with_domain(self, domain: impl Into<String>) -> Self {
        self.add_tlv(DtpTlv::Domain(domain.into()))
    }

    /// Set status TLV
    pub fn with_status(self, status: DtpStatus) -> Self {
        self.add_tlv(DtpTlv::Status(status))
    }

    /// Set type TLV
    pub fn with_type(self, typ: DtpType) -> Self {
        self.add_tlv(DtpTlv::Type(typ))
    }

    /// Set neighbor TLV
    pub fn with_neighbor(self, mac: MacAddr) -> Self {
        self.add_tlv(DtpTlv::Neighbor(mac))
    }

    /// Get domain from TLVs
    pub fn domain(&self) -> Option<&str> {
        self.tlvs.iter().find_map(|tlv| match tlv {
            DtpTlv::Domain(d) => Some(d.as_str()),
            _ => None,
        })
    }

    /// Get status from TLVs
    pub fn status(&self) -> Option<DtpStatus> {
        self.tlvs.iter().find_map(|tlv| match tlv {
            DtpTlv::Status(s) => Some(*s),
            _ => None,
        })
    }

    /// Get type from TLVs
    pub fn trunk_type(&self) -> Option<DtpType> {
        self.tlvs.iter().find_map(|tlv| match tlv {
            DtpTlv::Type(t) => Some(*t),
            _ => None,
        })
    }

    /// Get neighbor from TLVs
    pub fn neighbor(&self) -> Option<MacAddr> {
        self.tlvs.iter().find_map(|tlv| match tlv {
            DtpTlv::Neighbor(m) => Some(*m),
            _ => None,
        })
    }

    /// Parse a DTP packet from bytes (without Ethernet/LLC/SNAP headers)
    pub fn parse(data: &[u8]) -> Result<Self> {
        let mut buf = Bytes::copy_from_slice(data);

        if buf.remaining() < 1 {
            return Err(Error::PacketParsing("DTP packet too short".into()));
        }

        let version = buf.get_u8();

        let mut tlvs = Vec::new();
        while buf.remaining() >= 4 {
            match DtpTlv::parse(&mut buf) {
                Ok(tlv) => tlvs.push(tlv),
                Err(_) => {
                    // Skip unknown TLVs or break on error
                    if buf.remaining() < 4 {
                        break;
                    }
                    // Try to skip malformed TLV
                    let _ = buf.get_u16(); // type
                    let len = buf.get_u16(); // length
                    if len >= 4 && buf.remaining() >= (len - 4) as usize {
                        buf.advance((len - 4) as usize);
                    } else {
                        break;
                    }
                }
            }
        }

        Ok(Self { version, tlvs })
    }

    /// Build DTP packet bytes (without Ethernet/LLC/SNAP headers)
    pub fn build(&self) -> Bytes {
        let mut buf = BytesMut::new();

        // Write version
        buf.put_u8(self.version);

        // Write all TLVs
        for tlv in &self.tlvs {
            tlv.write(&mut buf);
        }

        buf.freeze()
    }

    /// Calculate total packet size
    pub fn size(&self) -> usize {
        1 + self
            .tlvs
            .iter()
            .map(|tlv| tlv.tlv_length() as usize)
            .sum::<usize>()
    }
}

impl Default for DtpPacket {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for DtpPacket {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "DTP Packet:")?;
        writeln!(f, "  Version: 0x{:02X}", self.version)?;
        writeln!(f, "  TLVs:")?;
        for tlv in &self.tlvs {
            match tlv {
                DtpTlv::Domain(d) => writeln!(f, "    Domain: \"{}\"", d)?,
                DtpTlv::Status(s) => writeln!(f, "    Status: {} (0x{:02X})", s, s.as_u8())?,
                DtpTlv::Type(t) => writeln!(f, "    Type: {} (0x{:02X})", t, t.as_u8())?,
                DtpTlv::Neighbor(m) => writeln!(f, "    Neighbor: {}", m)?,
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dtp_status_constants() {
        assert_eq!(DtpStatus::ACCESS_DESIRABLE, 0x03);
        assert_eq!(DtpStatus::ACCESS_AUTO, 0x04);
        assert_eq!(DtpStatus::TRUNK_DESIRABLE, 0x83);
        assert_eq!(DtpStatus::TRUNK_AUTO, 0x84);
    }

    #[test]
    fn test_dtp_status_trunk_desirable() {
        let status = DtpStatus::trunk_desirable();
        assert_eq!(status.as_u8(), 0x83);
        assert!(status.is_trunk());
        assert!(status.is_desirable());
        assert!(!status.is_access());
        assert!(!status.is_auto());
    }

    #[test]
    fn test_dtp_status_access_auto() {
        let status = DtpStatus::new(0x04);
        assert!(status.is_access());
        assert!(status.is_auto());
        assert!(!status.is_trunk());
        assert!(!status.is_desirable());
    }

    #[test]
    fn test_dtp_type_constants() {
        assert_eq!(DtpType::DOT1Q_DOT1Q, 0xA5);
        assert_eq!(DtpType::ISL_ISL, 0x42);
        assert_eq!(DtpType::DOT1Q_NEGOTIATED, 0xA0);
    }

    #[test]
    fn test_dtp_type_dot1q() {
        let typ = DtpType::dot1q();
        assert_eq!(typ.as_u8(), 0xA5);
        assert!(typ.is_dot1q());
        assert!(!typ.is_isl());
    }

    #[test]
    fn test_dtp_type_isl() {
        let typ = DtpType::isl();
        assert_eq!(typ.as_u8(), 0x42);
        assert!(typ.is_isl());
        assert!(!typ.is_dot1q());
    }

    #[test]
    fn test_tlv_domain() {
        let tlv = DtpTlv::Domain("test".to_string());
        assert_eq!(tlv.tlv_type(), tlv_types::DOMAIN);
        assert_eq!(tlv.tlv_length(), 8); // 4 header + 4 data
    }

    #[test]
    fn test_tlv_status() {
        let tlv = DtpTlv::Status(DtpStatus::trunk_desirable());
        assert_eq!(tlv.tlv_type(), tlv_types::STATUS);
        assert_eq!(tlv.tlv_length(), 5); // 4 header + 1 data
    }

    #[test]
    fn test_tlv_type() {
        let tlv = DtpTlv::Type(DtpType::dot1q());
        assert_eq!(tlv.tlv_type(), tlv_types::TYPE);
        assert_eq!(tlv.tlv_length(), 5);
    }

    #[test]
    fn test_tlv_neighbor() {
        let mac = MacAddr([0x00, 0x01, 0x02, 0x03, 0x04, 0x05]);
        let tlv = DtpTlv::Neighbor(mac);
        assert_eq!(tlv.tlv_type(), tlv_types::NEIGHBOR);
        assert_eq!(tlv.tlv_length(), 10); // 4 header + 6 data
    }

    #[test]
    fn test_tlv_write_parse_domain() {
        let tlv = DtpTlv::Domain("testdomain".to_string());
        let mut buf = BytesMut::new();
        tlv.write(&mut buf);

        let mut data = buf.freeze();
        let parsed = DtpTlv::parse(&mut data).unwrap();

        assert_eq!(tlv, parsed);
    }

    #[test]
    fn test_tlv_write_parse_status() {
        let tlv = DtpTlv::Status(DtpStatus::trunk_desirable());
        let mut buf = BytesMut::new();
        tlv.write(&mut buf);

        let mut data = buf.freeze();
        let parsed = DtpTlv::parse(&mut data).unwrap();

        assert_eq!(tlv, parsed);
    }

    #[test]
    fn test_packet_build_parse() {
        let mac = MacAddr([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]);
        let packet = DtpPacket::new()
            .with_domain("testdomain")
            .with_status(DtpStatus::trunk_desirable())
            .with_type(DtpType::dot1q())
            .with_neighbor(mac);

        let bytes = packet.build();
        let parsed = DtpPacket::parse(&bytes).unwrap();

        assert_eq!(packet.version, parsed.version);
        assert_eq!(packet.domain(), parsed.domain());
        assert_eq!(packet.status(), parsed.status());
        assert_eq!(packet.trunk_type(), parsed.trunk_type());
        assert_eq!(packet.neighbor(), parsed.neighbor());
    }

    #[test]
    fn test_packet_empty_domain() {
        let packet = DtpPacket::new()
            .with_domain("")
            .with_status(DtpStatus::access_desirable())
            .with_type(DtpType::dot1q());

        let bytes = packet.build();
        let parsed = DtpPacket::parse(&bytes).unwrap();

        assert_eq!(parsed.domain(), Some(""));
    }

    #[test]
    fn test_packet_null_domain() {
        // Test with null bytes in domain (like Yersinia default)
        let packet = DtpPacket::new()
            .with_domain("\x00\x00\x00\x00\x00\x00\x00\x00")
            .with_status(DtpStatus::access_desirable())
            .with_type(DtpType::dot1q());

        let bytes = packet.build();
        let parsed = DtpPacket::parse(&bytes).unwrap();

        // Should parse as empty string (nulls removed)
        assert_eq!(parsed.domain(), Some(""));
    }

    #[test]
    fn test_packet_getters() {
        let mac = MacAddr([0x11, 0x22, 0x33, 0x44, 0x55, 0x66]);
        let packet = DtpPacket::new()
            .with_domain("corp")
            .with_status(DtpStatus::trunk_on())
            .with_type(DtpType::isl())
            .with_neighbor(mac);

        assert_eq!(packet.domain(), Some("corp"));
        assert_eq!(packet.status(), Some(DtpStatus::trunk_on()));
        assert_eq!(packet.trunk_type(), Some(DtpType::isl()));
        assert_eq!(packet.neighbor(), Some(mac));
    }

    #[test]
    fn test_packet_size() {
        let packet = DtpPacket::new()
            .with_domain("test")
            .with_status(DtpStatus::trunk_desirable())
            .with_type(DtpType::dot1q())
            .with_neighbor(MacAddr([0; 6]));

        // 1 (version) + 8 (domain) + 5 (status) + 5 (type) + 10 (neighbor) = 29
        assert_eq!(packet.size(), 29);
    }

    #[test]
    fn test_status_display() {
        assert_eq!(DtpStatus::trunk_desirable().to_string(), "TRUNK/DESIRABLE");
        assert_eq!(DtpStatus::access_auto().to_string(), "ACCESS/AUTO");
        assert_eq!(DtpStatus::trunk_on().to_string(), "TRUNK/ON");
    }

    #[test]
    fn test_type_display() {
        assert_eq!(DtpType::dot1q().to_string(), "802.1Q/802.1Q");
        assert_eq!(DtpType::isl().to_string(), "ISL/ISL");
        assert_eq!(DtpType::negotiate().to_string(), "802.1Q/NEGOTIATED");
    }

    #[test]
    fn test_parse_truncated_packet() {
        let data = vec![0x01]; // Only version byte
        let result = DtpPacket::parse(&data);
        assert!(result.is_ok()); // Should parse with no TLVs
    }

    #[test]
    fn test_parse_invalid_tlv_length() {
        let mut data = vec![0x01]; // version
        data.extend_from_slice(&[0x00, 0x01]); // TLV type
        data.extend_from_slice(&[0x00, 0x02]); // TLV length too short (< 4)

        let result = DtpPacket::parse(&data);
        // Should handle gracefully
        assert!(result.is_ok());
    }
}
