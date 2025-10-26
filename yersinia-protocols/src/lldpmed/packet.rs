//! LLDP-MED Packet Structures
pub const LLDP_MULTICAST: [u8; 6] = [0x01, 0x80, 0xC2, 0x00, 0x00, 0x0E];
pub const LLDP_ETHERTYPE: u16 = 0x88CC;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LldpMedTlvType {
    Capabilities = 1,
    NetworkPolicy = 2,
    Location = 3,
    ExtendedPowerViaMdi = 4,
    InventoryHardwareRev = 5,
    InventoryFirmwareRev = 6,
    InventorySoftwareRev = 7,
    InventorySerialNumber = 8,
}

#[derive(Debug, Clone)]
pub struct LldpMedTlv {
    pub tlv_type: u8,
    pub length: u16,
    pub value: Vec<u8>,
}

impl LldpMedTlv {
    pub fn new(tlv_type: u8, value: Vec<u8>) -> Self {
        Self {
            tlv_type,
            length: value.len() as u16,
            value,
        }
    }

    pub fn capabilities(device_type: u8, capabilities: u16) -> Self {
        let mut value = Vec::new();
        value.push(device_type);
        value.extend_from_slice(&capabilities.to_be_bytes());
        Self::new(LldpMedTlvType::Capabilities as u8, value)
    }

    pub fn network_policy(app_type: u8, vlan_id: u16, priority: u8) -> Self {
        let mut value = Vec::new();
        value.push(app_type);
        let policy = ((vlan_id as u32) << 12) | ((priority as u32) << 9);
        value.extend_from_slice(&policy.to_be_bytes());
        Self::new(LldpMedTlvType::NetworkPolicy as u8, value)
    }

    pub fn power_via_mdi(
        power_type: u8,
        power_source: u8,
        power_priority: u8,
        power_value: u16,
    ) -> Self {
        let mut value = Vec::new();
        value.push((power_type << 6) | (power_source << 4) | power_priority);
        value.extend_from_slice(&power_value.to_be_bytes());
        Self::new(LldpMedTlvType::ExtendedPowerViaMdi as u8, value)
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        let header = ((self.tlv_type as u16) << 9) | (self.length & 0x1FF);
        bytes.extend_from_slice(&header.to_be_bytes());
        bytes.extend_from_slice(&self.value);
        bytes
    }
}

#[derive(Debug, Clone)]
pub struct LldpMedPacket {
    pub chassis_id: Vec<u8>,
    pub port_id: Vec<u8>,
    pub ttl: u16,
    pub med_tlvs: Vec<LldpMedTlv>,
}

impl LldpMedPacket {
    pub fn new(chassis_id: Vec<u8>, port_id: Vec<u8>) -> Self {
        Self {
            chassis_id,
            port_id,
            ttl: 120,
            med_tlvs: Vec::new(),
        }
    }

    pub fn with_ttl(mut self, ttl: u16) -> Self {
        self.ttl = ttl;
        self
    }

    pub fn with_tlv(mut self, tlv: LldpMedTlv) -> Self {
        self.med_tlvs.push(tlv);
        self
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();

        // Chassis ID TLV
        let chassis_tlv = LldpMedTlv::new(1, self.chassis_id.clone());
        bytes.extend_from_slice(&chassis_tlv.to_bytes());

        // Port ID TLV
        let port_tlv = LldpMedTlv::new(2, self.port_id.clone());
        bytes.extend_from_slice(&port_tlv.to_bytes());

        // TTL TLV
        let ttl_tlv = LldpMedTlv::new(3, self.ttl.to_be_bytes().to_vec());
        bytes.extend_from_slice(&ttl_tlv.to_bytes());

        // MED TLVs
        for tlv in &self.med_tlvs {
            bytes.extend_from_slice(&tlv.to_bytes());
        }

        // End TLV
        bytes.extend_from_slice(&[0x00, 0x00]);

        bytes
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_lldp_med_tlv() {
        let tlv = LldpMedTlv::capabilities(1, 0x0F);
        assert_eq!(tlv.tlv_type, 1);
    }

    #[test]
    fn test_network_policy() {
        let tlv = LldpMedTlv::network_policy(1, 100, 5);
        assert!(!tlv.value.is_empty());
    }

    #[test]
    fn test_lldp_med_packet() {
        let pkt = LldpMedPacket::new(vec![1, 2, 3], vec![4, 5, 6]);
        assert_eq!(pkt.ttl, 120);
    }

    #[test]
    fn test_packet_to_bytes() {
        let pkt = LldpMedPacket::new(vec![1], vec![2]);
        let bytes = pkt.to_bytes();
        assert!(!bytes.is_empty());
    }
}
