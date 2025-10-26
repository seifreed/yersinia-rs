//! Q-in-Q (802.1ad) Packet Structures

pub const QINQ_ETHERTYPE: u16 = 0x88A8; // 802.1ad S-TAG
pub const DOT1Q_ETHERTYPE: u16 = 0x8100; // 802.1Q C-TAG

#[derive(Debug, Clone)]
pub struct QinQTag {
    pub tpid: u16,    // Tag Protocol Identifier
    pub pcp: u8,      // Priority Code Point (3 bits)
    pub dei: bool,    // Drop Eligible Indicator
    pub vlan_id: u16, // VLAN ID (12 bits)
}

impl QinQTag {
    pub fn s_tag(vlan_id: u16) -> Self {
        Self {
            tpid: QINQ_ETHERTYPE,
            pcp: 0,
            dei: false,
            vlan_id: vlan_id & 0xFFF,
        }
    }

    pub fn c_tag(vlan_id: u16) -> Self {
        Self {
            tpid: DOT1Q_ETHERTYPE,
            pcp: 0,
            dei: false,
            vlan_id: vlan_id & 0xFFF,
        }
    }

    pub fn with_priority(mut self, pcp: u8) -> Self {
        self.pcp = pcp & 0x07;
        self
    }

    pub fn with_dei(mut self) -> Self {
        self.dei = true;
        self
    }

    pub fn tci(&self) -> u16 {
        let pcp_bits = (self.pcp as u16) << 13;
        let dei_bit = if self.dei { 1u16 << 12 } else { 0 };
        pcp_bits | dei_bit | self.vlan_id
    }

    pub fn to_bytes(&self) -> [u8; 4] {
        let mut bytes = [0u8; 4];
        bytes[0..2].copy_from_slice(&self.tpid.to_be_bytes());
        bytes[2..4].copy_from_slice(&self.tci().to_be_bytes());
        bytes
    }
}

#[derive(Debug, Clone)]
pub struct QinQPacket {
    pub s_tag: QinQTag, // Service Tag (Provider)
    pub c_tag: QinQTag, // Customer Tag
    pub ethertype: u16, // Inner ethertype
    pub payload: Vec<u8>,
}

impl QinQPacket {
    pub fn new(service_vlan: u16, customer_vlan: u16) -> Self {
        Self {
            s_tag: QinQTag::s_tag(service_vlan),
            c_tag: QinQTag::c_tag(customer_vlan),
            ethertype: 0x0800, // IPv4
            payload: vec![],
        }
    }

    pub fn with_s_priority(mut self, pcp: u8) -> Self {
        self.s_tag = self.s_tag.with_priority(pcp);
        self
    }

    pub fn with_c_priority(mut self, pcp: u8) -> Self {
        self.c_tag = self.c_tag.with_priority(pcp);
        self
    }

    pub fn with_payload(mut self, payload: Vec<u8>) -> Self {
        self.payload = payload;
        self
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();

        // S-TAG (802.1ad)
        bytes.extend_from_slice(&self.s_tag.to_bytes());

        // C-TAG (802.1Q)
        bytes.extend_from_slice(&self.c_tag.to_bytes());

        // Inner ethertype
        bytes.extend_from_slice(&self.ethertype.to_be_bytes());

        // Payload
        bytes.extend_from_slice(&self.payload);

        bytes
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_s_tag() {
        let tag = QinQTag::s_tag(100);
        assert_eq!(tag.tpid, QINQ_ETHERTYPE);
        assert_eq!(tag.vlan_id, 100);
    }

    #[test]
    fn test_c_tag() {
        let tag = QinQTag::c_tag(200);
        assert_eq!(tag.tpid, DOT1Q_ETHERTYPE);
        assert_eq!(tag.vlan_id, 200);
    }

    #[test]
    fn test_tag_with_priority() {
        let tag = QinQTag::s_tag(100).with_priority(5);
        assert_eq!(tag.pcp, 5);
        let tci = tag.tci();
        assert_eq!((tci >> 13) & 0x07, 5);
    }

    #[test]
    fn test_qinq_packet() {
        let pkt = QinQPacket::new(10, 20);
        assert_eq!(pkt.s_tag.vlan_id, 10);
        assert_eq!(pkt.c_tag.vlan_id, 20);
    }

    #[test]
    fn test_qinq_to_bytes() {
        let pkt = QinQPacket::new(100, 200).with_payload(vec![0xAA; 64]);
        let bytes = pkt.to_bytes();
        // S-TAG (4) + C-TAG (4) + ethertype (2) + payload (64)
        assert_eq!(bytes.len(), 4 + 4 + 2 + 64);
    }

    #[test]
    fn test_tag_bytes() {
        let tag = QinQTag::s_tag(100).with_priority(3);
        let bytes = tag.to_bytes();
        assert_eq!(bytes.len(), 4);
        assert_eq!(&bytes[0..2], &QINQ_ETHERTYPE.to_be_bytes());
    }
}
