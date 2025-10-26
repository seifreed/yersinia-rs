//! LLC (Logical Link Control) and SNAP (SubNetwork Access Protocol)
//!
//! This module provides support for LLC frames with SNAP extension,
//! which are used by protocols like CDP, VTP, DTP, STP, and others
//! in Cisco and other vendor equipment.

use bytes::{BufMut, BytesMut};

/// LLC DSAP (Destination Service Access Point) values
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LlcDsap {
    /// SNAP (0xAA)
    SNAP,
    /// STP/BPDU (0x42)
    STP,
    /// NetBIOS (0xF0)
    NetBIOS,
    /// Custom DSAP value
    Custom(u8),
}

impl LlcDsap {
    pub fn to_u8(self) -> u8 {
        match self {
            LlcDsap::SNAP => 0xAA,
            LlcDsap::STP => 0x42,
            LlcDsap::NetBIOS => 0xF0,
            LlcDsap::Custom(val) => val,
        }
    }

    pub fn from_u8(value: u8) -> Self {
        match value {
            0xAA => LlcDsap::SNAP,
            0x42 => LlcDsap::STP,
            0xF0 => LlcDsap::NetBIOS,
            val => LlcDsap::Custom(val),
        }
    }
}

/// LLC SSAP (Source Service Access Point) values
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LlcSsap {
    /// SNAP (0xAA)
    SNAP,
    /// STP/BPDU (0x42)
    STP,
    /// NetBIOS (0xF0)
    NetBIOS,
    /// Custom SSAP value
    Custom(u8),
}

impl LlcSsap {
    pub fn to_u8(self) -> u8 {
        match self {
            LlcSsap::SNAP => 0xAA,
            LlcSsap::STP => 0x42,
            LlcSsap::NetBIOS => 0xF0,
            LlcSsap::Custom(val) => val,
        }
    }

    pub fn from_u8(value: u8) -> Self {
        match value {
            0xAA => LlcSsap::SNAP,
            0x42 => LlcSsap::STP,
            0xF0 => LlcSsap::NetBIOS,
            val => LlcSsap::Custom(val),
        }
    }
}

/// LLC Control field values
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LlcControl {
    /// Unnumbered Information (0x03) - most common for SNAP
    UnnumberedInformation,
    /// Custom control value
    Custom(u8),
}

impl LlcControl {
    pub fn to_u8(self) -> u8 {
        match self {
            LlcControl::UnnumberedInformation => 0x03,
            LlcControl::Custom(val) => val,
        }
    }

    pub fn from_u8(value: u8) -> Self {
        match value {
            0x03 => LlcControl::UnnumberedInformation,
            val => LlcControl::Custom(val),
        }
    }
}

/// OUI (Organizationally Unique Identifier) - 3 bytes
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Oui(pub [u8; 3]);

impl Oui {
    /// Cisco OUI (0x00000C)
    pub const CISCO: Oui = Oui([0x00, 0x00, 0x0C]);

    /// IEEE 802.1 OUI (0x00000E) - used for some protocols
    pub const IEEE_802_1: Oui = Oui([0x00, 0x00, 0x0E]);

    /// Nortel OUI (0x00000E)
    pub const NORTEL: Oui = Oui([0x00, 0x00, 0x0E]);

    /// RFC 1042 OUI (0x000000) - for IP over LLC
    pub const RFC_1042: Oui = Oui([0x00, 0x00, 0x00]);

    pub fn new(bytes: [u8; 3]) -> Self {
        Oui(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; 3] {
        &self.0
    }
}

impl From<[u8; 3]> for Oui {
    fn from(bytes: [u8; 3]) -> Self {
        Oui(bytes)
    }
}

/// SNAP Protocol ID (2 bytes)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SnapProtocolId(pub u16);

impl SnapProtocolId {
    /// CDP (0x2000)
    pub const CDP: SnapProtocolId = SnapProtocolId(0x2000);

    /// VTP (0x2003)
    pub const VTP: SnapProtocolId = SnapProtocolId(0x2003);

    /// DTP (0x2004)
    pub const DTP: SnapProtocolId = SnapProtocolId(0x2004);

    /// UDLD (0x0111)
    pub const UDLD: SnapProtocolId = SnapProtocolId(0x0111);

    /// PVST+ (0x010B)
    pub const PVST_PLUS: SnapProtocolId = SnapProtocolId(0x010B);

    pub fn new(value: u16) -> Self {
        SnapProtocolId(value)
    }

    pub fn to_u16(self) -> u16 {
        self.0
    }
}

impl From<u16> for SnapProtocolId {
    fn from(value: u16) -> Self {
        SnapProtocolId(value)
    }
}

/// LLC header (3 bytes)
#[derive(Debug, Clone)]
pub struct LlcHeader {
    /// Destination Service Access Point
    pub dsap: LlcDsap,
    /// Source Service Access Point
    pub ssap: LlcSsap,
    /// Control field
    pub control: LlcControl,
}

impl LlcHeader {
    /// LLC header size in bytes
    pub const SIZE: usize = 3;

    /// Create a new LLC header
    pub fn new(dsap: LlcDsap, ssap: LlcSsap, control: LlcControl) -> Self {
        LlcHeader {
            dsap,
            ssap,
            control,
        }
    }

    /// Create a standard SNAP LLC header (DSAP=0xAA, SSAP=0xAA, Control=0x03)
    pub fn snap() -> Self {
        LlcHeader {
            dsap: LlcDsap::SNAP,
            ssap: LlcSsap::SNAP,
            control: LlcControl::UnnumberedInformation,
        }
    }

    /// Create an STP LLC header (DSAP=0x42, SSAP=0x42, Control=0x03)
    pub fn stp() -> Self {
        LlcHeader {
            dsap: LlcDsap::STP,
            ssap: LlcSsap::STP,
            control: LlcControl::UnnumberedInformation,
        }
    }

    /// Convert to bytes
    pub fn to_bytes(&self) -> [u8; 3] {
        [self.dsap.to_u8(), self.ssap.to_u8(), self.control.to_u8()]
    }

    /// Parse from bytes
    pub fn from_bytes(data: &[u8]) -> Option<Self> {
        if data.len() < Self::SIZE {
            return None;
        }

        Some(LlcHeader {
            dsap: LlcDsap::from_u8(data[0]),
            ssap: LlcSsap::from_u8(data[1]),
            control: LlcControl::from_u8(data[2]),
        })
    }
}

/// SNAP header (5 bytes)
#[derive(Debug, Clone)]
pub struct SnapHeader {
    /// Organizationally Unique Identifier (3 bytes)
    pub oui: Oui,
    /// Protocol ID (2 bytes)
    pub protocol_id: SnapProtocolId,
}

impl SnapHeader {
    /// SNAP header size in bytes
    pub const SIZE: usize = 5;

    /// Create a new SNAP header
    pub fn new(oui: Oui, protocol_id: SnapProtocolId) -> Self {
        SnapHeader { oui, protocol_id }
    }

    /// Create a CDP SNAP header (Cisco OUI + CDP protocol)
    pub fn cdp() -> Self {
        SnapHeader {
            oui: Oui::CISCO,
            protocol_id: SnapProtocolId::CDP,
        }
    }

    /// Create a VTP SNAP header (Cisco OUI + VTP protocol)
    pub fn vtp() -> Self {
        SnapHeader {
            oui: Oui::CISCO,
            protocol_id: SnapProtocolId::VTP,
        }
    }

    /// Create a DTP SNAP header (Cisco OUI + DTP protocol)
    pub fn dtp() -> Self {
        SnapHeader {
            oui: Oui::CISCO,
            protocol_id: SnapProtocolId::DTP,
        }
    }

    /// Create a UDLD SNAP header (Cisco OUI + UDLD protocol)
    pub fn udld() -> Self {
        SnapHeader {
            oui: Oui::CISCO,
            protocol_id: SnapProtocolId::UDLD,
        }
    }

    /// Convert to bytes
    pub fn to_bytes(&self) -> [u8; 5] {
        let mut bytes = [0u8; 5];
        bytes[0..3].copy_from_slice(self.oui.as_bytes());
        bytes[3..5].copy_from_slice(&self.protocol_id.to_u16().to_be_bytes());
        bytes
    }

    /// Parse from bytes
    pub fn from_bytes(data: &[u8]) -> Option<Self> {
        if data.len() < Self::SIZE {
            return None;
        }

        let mut oui_bytes = [0u8; 3];
        oui_bytes.copy_from_slice(&data[0..3]);

        let protocol_id = u16::from_be_bytes([data[3], data[4]]);

        Some(SnapHeader {
            oui: Oui(oui_bytes),
            protocol_id: SnapProtocolId(protocol_id),
        })
    }
}

/// Complete LLC/SNAP frame
#[derive(Debug, Clone)]
pub struct LlcSnapFrame {
    /// LLC header (3 bytes)
    pub llc: LlcHeader,
    /// SNAP header (5 bytes)
    pub snap: SnapHeader,
    /// Payload data
    pub payload: Vec<u8>,
}

impl LlcSnapFrame {
    /// Total LLC/SNAP header size (LLC + SNAP)
    pub const HEADER_SIZE: usize = LlcHeader::SIZE + SnapHeader::SIZE;

    /// Create a new LLC/SNAP frame
    pub fn new(llc: LlcHeader, snap: SnapHeader, payload: Vec<u8>) -> Self {
        LlcSnapFrame { llc, snap, payload }
    }

    /// Create a CDP LLC/SNAP frame
    pub fn cdp(payload: Vec<u8>) -> Self {
        LlcSnapFrame {
            llc: LlcHeader::snap(),
            snap: SnapHeader::cdp(),
            payload,
        }
    }

    /// Create a VTP LLC/SNAP frame
    pub fn vtp(payload: Vec<u8>) -> Self {
        LlcSnapFrame {
            llc: LlcHeader::snap(),
            snap: SnapHeader::vtp(),
            payload,
        }
    }

    /// Create a DTP LLC/SNAP frame
    pub fn dtp(payload: Vec<u8>) -> Self {
        LlcSnapFrame {
            llc: LlcHeader::snap(),
            snap: SnapHeader::dtp(),
            payload,
        }
    }

    /// Create a UDLD LLC/SNAP frame
    pub fn udld(payload: Vec<u8>) -> Self {
        LlcSnapFrame {
            llc: LlcHeader::snap(),
            snap: SnapHeader::udld(),
            payload,
        }
    }

    /// Create a custom LLC/SNAP frame
    pub fn custom(oui: Oui, protocol_id: SnapProtocolId, payload: Vec<u8>) -> Self {
        LlcSnapFrame {
            llc: LlcHeader::snap(),
            snap: SnapHeader::new(oui, protocol_id),
            payload,
        }
    }

    /// Convert to bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buffer = BytesMut::with_capacity(Self::HEADER_SIZE + self.payload.len());

        // LLC header (3 bytes)
        buffer.put_slice(&self.llc.to_bytes());

        // SNAP header (5 bytes)
        buffer.put_slice(&self.snap.to_bytes());

        // Payload
        buffer.put_slice(&self.payload);

        buffer.to_vec()
    }

    /// Parse from bytes
    pub fn from_bytes(data: &[u8]) -> Option<Self> {
        if data.len() < Self::HEADER_SIZE {
            return None;
        }

        let llc = LlcHeader::from_bytes(&data[0..3])?;
        let snap = SnapHeader::from_bytes(&data[3..8])?;

        let payload = data[Self::HEADER_SIZE..].to_vec();

        Some(LlcSnapFrame { llc, snap, payload })
    }

    /// Get the total size in bytes
    pub fn len(&self) -> usize {
        Self::HEADER_SIZE + self.payload.len()
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
    fn test_llc_header_snap() {
        let header = LlcHeader::snap();
        assert_eq!(header.dsap, LlcDsap::SNAP);
        assert_eq!(header.ssap, LlcSsap::SNAP);
        assert_eq!(header.control, LlcControl::UnnumberedInformation);

        let bytes = header.to_bytes();
        assert_eq!(bytes, [0xAA, 0xAA, 0x03]);
    }

    #[test]
    fn test_llc_header_roundtrip() {
        let header1 = LlcHeader::snap();
        let bytes = header1.to_bytes();
        let header2 = LlcHeader::from_bytes(&bytes).unwrap();

        assert_eq!(header1.dsap.to_u8(), header2.dsap.to_u8());
        assert_eq!(header1.ssap.to_u8(), header2.ssap.to_u8());
        assert_eq!(header1.control.to_u8(), header2.control.to_u8());
    }

    #[test]
    fn test_snap_header_cdp() {
        let header = SnapHeader::cdp();
        assert_eq!(header.oui, Oui::CISCO);
        assert_eq!(header.protocol_id, SnapProtocolId::CDP);

        let bytes = header.to_bytes();
        assert_eq!(&bytes[0..3], &[0x00, 0x00, 0x0C]); // Cisco OUI
        assert_eq!(u16::from_be_bytes([bytes[3], bytes[4]]), 0x2000); // CDP
    }

    #[test]
    fn test_snap_header_vtp() {
        let header = SnapHeader::vtp();
        assert_eq!(header.oui, Oui::CISCO);
        assert_eq!(header.protocol_id, SnapProtocolId::VTP);

        let bytes = header.to_bytes();
        assert_eq!(u16::from_be_bytes([bytes[3], bytes[4]]), 0x2003); // VTP
    }

    #[test]
    fn test_snap_header_roundtrip() {
        let header1 = SnapHeader::cdp();
        let bytes = header1.to_bytes();
        let header2 = SnapHeader::from_bytes(&bytes).unwrap();

        assert_eq!(header1.oui, header2.oui);
        assert_eq!(header1.protocol_id.to_u16(), header2.protocol_id.to_u16());
    }

    #[test]
    fn test_llc_snap_frame_cdp() {
        let payload = vec![0x01, 0x02, 0x03, 0x04];
        let frame = LlcSnapFrame::cdp(payload.clone());

        assert_eq!(frame.llc.dsap, LlcDsap::SNAP);
        assert_eq!(frame.snap.oui, Oui::CISCO);
        assert_eq!(frame.snap.protocol_id, SnapProtocolId::CDP);
        assert_eq!(frame.payload, payload);
    }

    #[test]
    fn test_llc_snap_frame_to_bytes() {
        let payload = vec![0x01, 0x02, 0x03, 0x04];
        let frame = LlcSnapFrame::cdp(payload.clone());
        let bytes = frame.to_bytes();

        // Check LLC header
        assert_eq!(&bytes[0..3], &[0xAA, 0xAA, 0x03]);

        // Check SNAP header
        assert_eq!(&bytes[3..6], &[0x00, 0x00, 0x0C]); // Cisco OUI
        assert_eq!(u16::from_be_bytes([bytes[6], bytes[7]]), 0x2000); // CDP

        // Check payload
        assert_eq!(&bytes[8..], &payload[..]);
    }

    #[test]
    fn test_llc_snap_frame_roundtrip() {
        let payload = vec![0x01, 0x02, 0x03, 0x04];
        let frame1 = LlcSnapFrame::cdp(payload.clone());
        let bytes = frame1.to_bytes();
        let frame2 = LlcSnapFrame::from_bytes(&bytes).unwrap();

        assert_eq!(frame1.llc.dsap.to_u8(), frame2.llc.dsap.to_u8());
        assert_eq!(frame1.snap.oui, frame2.snap.oui);
        assert_eq!(
            frame1.snap.protocol_id.to_u16(),
            frame2.snap.protocol_id.to_u16()
        );
        assert_eq!(frame1.payload, frame2.payload);
    }

    #[test]
    fn test_llc_snap_frame_custom() {
        let oui = Oui::new([0x01, 0x02, 0x03]);
        let protocol_id = SnapProtocolId::new(0x1234);
        let payload = vec![0xFF, 0xEE];

        let frame = LlcSnapFrame::custom(oui, protocol_id, payload.clone());

        assert_eq!(frame.snap.oui.0, [0x01, 0x02, 0x03]);
        assert_eq!(frame.snap.protocol_id.0, 0x1234);
        assert_eq!(frame.payload, payload);
    }

    #[test]
    fn test_oui_constants() {
        assert_eq!(Oui::CISCO.0, [0x00, 0x00, 0x0C]);
        assert_eq!(Oui::RFC_1042.0, [0x00, 0x00, 0x00]);
    }

    #[test]
    fn test_protocol_id_constants() {
        assert_eq!(SnapProtocolId::CDP.0, 0x2000);
        assert_eq!(SnapProtocolId::VTP.0, 0x2003);
        assert_eq!(SnapProtocolId::DTP.0, 0x2004);
        assert_eq!(SnapProtocolId::UDLD.0, 0x0111);
    }
}
