//! GVRP/MVRP Packet Structures

// GVRP uses IEEE 802.1Q GARP (Generic Attribute Registration Protocol)
pub const GVRP_MULTICAST: [u8; 6] = [0x01, 0x80, 0xC2, 0x00, 0x00, 21];
pub const MVRP_MULTICAST: [u8; 6] = [0x01, 0x80, 0xC2, 0x00, 0x00, 0x21];
pub const GVRP_ETHERTYPE: u16 = 0x88F5; // IEEE 802.1Q

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GarpAttributeType {
    VlanIdentifier = 1,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GarpAttributeEvent {
    LeaveAll = 0,
    JoinEmpty = 1,
    JoinIn = 2,
    LeaveEmpty = 3,
    LeaveIn = 4,
    Empty = 5,
}

#[derive(Debug, Clone)]
pub struct GvrpPacket {
    pub protocol_id: u16, // 0x0001 for GVRP
    pub attributes: Vec<GvrpAttribute>,
}

#[derive(Debug, Clone)]
pub struct GvrpAttribute {
    pub attribute_type: GarpAttributeType,
    pub attribute_length: u8,
    pub event: GarpAttributeEvent,
    pub vlan_id: u16,
}

impl Default for GvrpPacket {
    fn default() -> Self {
        Self::new()
    }
}

impl GvrpPacket {
    pub fn new() -> Self {
        Self {
            protocol_id: 0x0001,
            attributes: vec![],
        }
    }

    pub fn with_vlan_registration(mut self, vlan_id: u16) -> Self {
        self.attributes.push(GvrpAttribute {
            attribute_type: GarpAttributeType::VlanIdentifier,
            attribute_length: 2,
            event: GarpAttributeEvent::JoinEmpty,
            vlan_id,
        });
        self
    }

    pub fn with_vlan_deregistration(mut self, vlan_id: u16) -> Self {
        self.attributes.push(GvrpAttribute {
            attribute_type: GarpAttributeType::VlanIdentifier,
            attribute_length: 2,
            event: GarpAttributeEvent::LeaveEmpty,
            vlan_id,
        });
        self
    }

    pub fn with_leave_all(mut self) -> Self {
        self.attributes.push(GvrpAttribute {
            attribute_type: GarpAttributeType::VlanIdentifier,
            attribute_length: 2,
            event: GarpAttributeEvent::LeaveAll,
            vlan_id: 0,
        });
        self
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&self.protocol_id.to_be_bytes());

        for attr in &self.attributes {
            bytes.push(attr.attribute_type as u8);
            bytes.push(attr.attribute_length);
            bytes.push(attr.event as u8);
            bytes.extend_from_slice(&attr.vlan_id.to_be_bytes());
        }

        // End mark
        bytes.push(0);
        bytes
    }
}

#[derive(Debug, Clone)]
pub struct MvrpPacket {
    pub protocol_version: u8, // 0x00 for MRP
    pub messages: Vec<MvrpMessage>,
}

#[derive(Debug, Clone)]
pub struct MvrpMessage {
    pub attribute_type: u8,
    pub attribute_length: u8,
    pub attribute_list_length: u16,
    pub vlan_ids: Vec<u16>,
    pub vector_header: u8, // 3-packed events
}

impl Default for MvrpPacket {
    fn default() -> Self {
        Self::new()
    }
}

impl MvrpPacket {
    pub fn new() -> Self {
        Self {
            protocol_version: 0x00,
            messages: vec![],
        }
    }

    pub fn with_vlan_registration(mut self, vlan_id: u16) -> Self {
        self.messages.push(MvrpMessage {
            attribute_type: 1, // VID
            attribute_length: 2,
            attribute_list_length: 3,
            vlan_ids: vec![vlan_id],
            vector_header: 0x20, // JoinIn
        });
        self
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.push(self.protocol_version);

        for msg in &self.messages {
            bytes.push(msg.attribute_type);
            bytes.push(msg.attribute_length);
            bytes.extend_from_slice(&msg.attribute_list_length.to_be_bytes());
            bytes.push(msg.vector_header);
            for vlan in &msg.vlan_ids {
                bytes.extend_from_slice(&vlan.to_be_bytes());
            }
        }

        // End mark
        bytes.extend_from_slice(&[0, 0]);
        bytes
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_gvrp_packet_registration() {
        let pkt = GvrpPacket::new().with_vlan_registration(100);
        assert_eq!(pkt.attributes.len(), 1);
        assert_eq!(pkt.attributes[0].vlan_id, 100);
        assert_eq!(pkt.attributes[0].event, GarpAttributeEvent::JoinEmpty);
    }

    #[test]
    fn test_gvrp_packet_deregistration() {
        let pkt = GvrpPacket::new().with_vlan_deregistration(200);
        assert_eq!(pkt.attributes.len(), 1);
        assert_eq!(pkt.attributes[0].event, GarpAttributeEvent::LeaveEmpty);
    }

    #[test]
    fn test_gvrp_to_bytes() {
        let pkt = GvrpPacket::new().with_vlan_registration(100);
        let bytes = pkt.to_bytes();
        assert!(!bytes.is_empty());
        assert_eq!(bytes[0..2], [0x00, 0x01]); // Protocol ID
    }

    #[test]
    fn test_mvrp_packet() {
        let pkt = MvrpPacket::new().with_vlan_registration(100);
        assert_eq!(pkt.messages.len(), 1);
        let bytes = pkt.to_bytes();
        assert!(!bytes.is_empty());
        assert_eq!(bytes[0], 0x00); // Protocol version
    }
}
