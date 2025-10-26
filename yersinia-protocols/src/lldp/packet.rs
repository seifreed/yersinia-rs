//! LLDP Packet Structures and Parsing

use bytes::{BufMut, BytesMut};

/// LLDP multicast MAC address (nearest bridge)
pub const LLDP_MULTICAST_MAC: [u8; 6] = [0x01, 0x80, 0xC2, 0x00, 0x00, 0x0E];

/// LLDP Ethertype
pub const LLDP_ETHERTYPE: u16 = 0x88CC;

/// Default TTL (seconds)
pub const LLDP_TTL_DEFAULT: u16 = 120;

/// LLDP TLV Types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum LldpTlvType {
    EndOfLldpdu = 0,
    ChassisId = 1,
    PortId = 2,
    Ttl = 3,
    PortDescription = 4,
    SystemName = 5,
    SystemDescription = 6,
    SystemCapabilities = 7,
    ManagementAddress = 8,
    OrganizationallySpecific = 127,
}

impl From<u8> for LldpTlvType {
    fn from(value: u8) -> Self {
        match value {
            0 => LldpTlvType::EndOfLldpdu,
            1 => LldpTlvType::ChassisId,
            2 => LldpTlvType::PortId,
            3 => LldpTlvType::Ttl,
            4 => LldpTlvType::PortDescription,
            5 => LldpTlvType::SystemName,
            6 => LldpTlvType::SystemDescription,
            7 => LldpTlvType::SystemCapabilities,
            8 => LldpTlvType::ManagementAddress,
            127 => LldpTlvType::OrganizationallySpecific,
            _ => LldpTlvType::EndOfLldpdu, // Unknown types treated as end
        }
    }
}

/// Chassis ID Subtypes
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ChassisIdSubtype {
    Reserved = 0,
    ChassisComponent = 1,
    InterfaceAlias = 2,
    PortComponent = 3,
    MacAddress = 4,
    NetworkAddress = 5,
    InterfaceName = 6,
    LocallyAssigned = 7,
}

/// Port ID Subtypes
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum PortIdSubtype {
    Reserved = 0,
    InterfaceAlias = 1,
    PortComponent = 2,
    MacAddress = 3,
    NetworkAddress = 4,
    InterfaceName = 5,
    AgentCircuitId = 6,
    LocallyAssigned = 7,
}

/// System Capabilities (bitmap)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LldpCapabilities(pub u16);

impl LldpCapabilities {
    pub const OTHER: u16 = 0x0001;
    pub const REPEATER: u16 = 0x0002;
    pub const BRIDGE: u16 = 0x0004;
    pub const WLAN_ACCESS_POINT: u16 = 0x0008;
    pub const ROUTER: u16 = 0x0010;
    pub const TELEPHONE: u16 = 0x0020;
    pub const DOCSIS: u16 = 0x0040;
    pub const STATION_ONLY: u16 = 0x0080;

    pub fn new() -> Self {
        Self(0)
    }

    pub fn with_bridge_router() -> Self {
        Self(Self::BRIDGE | Self::ROUTER)
    }

    pub fn is_bridge(&self) -> bool {
        self.0 & Self::BRIDGE != 0
    }

    pub fn is_router(&self) -> bool {
        self.0 & Self::ROUTER != 0
    }
}

impl Default for LldpCapabilities {
    fn default() -> Self {
        Self::new()
    }
}

/// LLDP TLV (Type-Length-Value)
#[derive(Debug, Clone)]
pub struct LldpTlv {
    pub tlv_type: LldpTlvType,
    pub value: Vec<u8>,
}

impl LldpTlv {
    pub fn new(tlv_type: LldpTlvType, value: Vec<u8>) -> Self {
        Self { tlv_type, value }
    }

    pub fn chassis_id(subtype: ChassisIdSubtype, id: Vec<u8>) -> Self {
        let mut value = Vec::with_capacity(id.len() + 1);
        value.push(subtype as u8);
        value.extend_from_slice(&id);
        Self::new(LldpTlvType::ChassisId, value)
    }

    pub fn chassis_id_mac(mac: [u8; 6]) -> Self {
        Self::chassis_id(ChassisIdSubtype::MacAddress, mac.to_vec())
    }

    pub fn port_id(subtype: PortIdSubtype, id: Vec<u8>) -> Self {
        let mut value = Vec::with_capacity(id.len() + 1);
        value.push(subtype as u8);
        value.extend_from_slice(&id);
        Self::new(LldpTlvType::PortId, value)
    }

    pub fn port_id_interface(name: &str) -> Self {
        Self::port_id(PortIdSubtype::InterfaceName, name.as_bytes().to_vec())
    }

    pub fn ttl(seconds: u16) -> Self {
        Self::new(LldpTlvType::Ttl, seconds.to_be_bytes().to_vec())
    }

    pub fn port_description(desc: &str) -> Self {
        Self::new(LldpTlvType::PortDescription, desc.as_bytes().to_vec())
    }

    pub fn system_name(name: &str) -> Self {
        Self::new(LldpTlvType::SystemName, name.as_bytes().to_vec())
    }

    pub fn system_description(desc: &str) -> Self {
        Self::new(LldpTlvType::SystemDescription, desc.as_bytes().to_vec())
    }

    pub fn system_capabilities(capabilities: u16, enabled: u16) -> Self {
        let mut value = Vec::with_capacity(4);
        value.extend_from_slice(&capabilities.to_be_bytes());
        value.extend_from_slice(&enabled.to_be_bytes());
        Self::new(LldpTlvType::SystemCapabilities, value)
    }

    pub fn end_of_lldpdu() -> Self {
        Self::new(LldpTlvType::EndOfLldpdu, vec![])
    }

    /// Encode TLV to bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        let len = self.value.len();
        let mut bytes = Vec::with_capacity(2 + len);

        // Type (7 bits) | Length (9 bits)
        let type_length = ((self.tlv_type as u16) << 9) | (len as u16 & 0x1FF);
        bytes.extend_from_slice(&type_length.to_be_bytes());
        bytes.extend_from_slice(&self.value);

        bytes
    }

    /// Parse TLV from bytes
    pub fn from_bytes(data: &[u8]) -> Option<(Self, usize)> {
        if data.len() < 2 {
            return None;
        }

        let type_length = u16::from_be_bytes([data[0], data[1]]);
        let tlv_type = LldpTlvType::from((type_length >> 9) as u8);
        let length = (type_length & 0x1FF) as usize;

        if data.len() < 2 + length {
            return None;
        }

        let value = data[2..2 + length].to_vec();
        Some((Self::new(tlv_type, value), 2 + length))
    }
}

/// LLDP Packet
#[derive(Debug, Clone)]
pub struct LldpPacket {
    pub tlvs: Vec<LldpTlv>,
}

impl LldpPacket {
    pub fn new() -> Self {
        Self { tlvs: Vec::new() }
    }

    /// Create a basic LLDP packet with mandatory TLVs
    pub fn new_basic(chassis_id: [u8; 6], port_id: &str, ttl: u16) -> Self {
        let mut packet = Self::new();
        packet.add_tlv(LldpTlv::chassis_id_mac(chassis_id));
        packet.add_tlv(LldpTlv::port_id_interface(port_id));
        packet.add_tlv(LldpTlv::ttl(ttl));
        packet.add_tlv(LldpTlv::end_of_lldpdu());
        packet
    }

    /// Create a complete LLDP packet with optional TLVs
    pub fn new_complete(
        chassis_id: [u8; 6],
        port_id: &str,
        ttl: u16,
        system_name: Option<&str>,
        system_description: Option<&str>,
        port_description: Option<&str>,
        capabilities: Option<(u16, u16)>,
    ) -> Self {
        let mut packet = Self::new();

        // Mandatory TLVs
        packet.add_tlv(LldpTlv::chassis_id_mac(chassis_id));
        packet.add_tlv(LldpTlv::port_id_interface(port_id));
        packet.add_tlv(LldpTlv::ttl(ttl));

        // Optional TLVs
        if let Some(desc) = port_description {
            packet.add_tlv(LldpTlv::port_description(desc));
        }
        if let Some(name) = system_name {
            packet.add_tlv(LldpTlv::system_name(name));
        }
        if let Some(desc) = system_description {
            packet.add_tlv(LldpTlv::system_description(desc));
        }
        if let Some((caps, enabled)) = capabilities {
            packet.add_tlv(LldpTlv::system_capabilities(caps, enabled));
        }

        packet.add_tlv(LldpTlv::end_of_lldpdu());
        packet
    }

    pub fn add_tlv(&mut self, tlv: LldpTlv) {
        self.tlvs.push(tlv);
    }

    /// Encode packet to bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = BytesMut::new();
        for tlv in &self.tlvs {
            bytes.put_slice(&tlv.to_bytes());
        }
        bytes.to_vec()
    }

    /// Parse packet from bytes
    pub fn from_bytes(data: &[u8]) -> Option<Self> {
        let mut packet = Self::new();
        let mut offset = 0;

        while offset < data.len() {
            match LldpTlv::from_bytes(&data[offset..]) {
                Some((tlv, consumed)) => {
                    let is_end = matches!(tlv.tlv_type, LldpTlvType::EndOfLldpdu);
                    packet.add_tlv(tlv);
                    offset += consumed;
                    if is_end {
                        break;
                    }
                }
                None => break,
            }
        }

        if packet.tlvs.is_empty() {
            None
        } else {
            Some(packet)
        }
    }

    /// Get chassis ID from packet
    pub fn get_chassis_id(&self) -> Option<&[u8]> {
        self.tlvs
            .iter()
            .find(|tlv| matches!(tlv.tlv_type, LldpTlvType::ChassisId))
            .map(|tlv| tlv.value.as_slice())
    }

    /// Get system name from packet
    pub fn get_system_name(&self) -> Option<String> {
        self.tlvs
            .iter()
            .find(|tlv| matches!(tlv.tlv_type, LldpTlvType::SystemName))
            .and_then(|tlv| String::from_utf8(tlv.value.clone()).ok())
    }
}

impl Default for LldpPacket {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tlv_encoding() {
        let tlv = LldpTlv::system_name("TestRouter");
        let bytes = tlv.to_bytes();

        // Type 5 (SystemName), length 10
        assert_eq!(bytes[0], 0x0A); // (5 << 1) = 10
        assert_eq!(bytes[1], 0x0A); // length 10
        assert_eq!(&bytes[2..], b"TestRouter");
    }

    #[test]
    fn test_basic_packet() {
        let mac = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];
        let packet = LldpPacket::new_basic(mac, "eth0", 120);

        assert_eq!(packet.tlvs.len(), 4); // Chassis, Port, TTL, End

        let bytes = packet.to_bytes();
        assert!(!bytes.is_empty());

        let parsed = LldpPacket::from_bytes(&bytes).unwrap();
        assert_eq!(parsed.tlvs.len(), 4);
    }

    #[test]
    fn test_complete_packet() {
        let mac = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];
        let packet = LldpPacket::new_complete(
            mac,
            "GigabitEthernet0/1",
            120,
            Some("RouterA"),
            Some("Linux Router"),
            Some("Uplink Port"),
            Some((
                LldpCapabilities::BRIDGE | LldpCapabilities::ROUTER,
                LldpCapabilities::BRIDGE | LldpCapabilities::ROUTER,
            )),
        );

        assert!(packet.tlvs.len() >= 4);
        assert_eq!(packet.get_system_name(), Some("RouterA".to_string()));
    }

    #[test]
    fn test_capabilities() {
        let caps = LldpCapabilities::with_bridge_router();
        assert!(caps.is_bridge());
        assert!(caps.is_router());
    }
}
