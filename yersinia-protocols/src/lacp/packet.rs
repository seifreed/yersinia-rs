//! LACP Packet
pub const LACP_MULTICAST_MAC: [u8; 6] = [0x01, 0x80, 0xC2, 0x00, 0x00, 0x02];
pub const LACP_SLOW_PROTOCOL_SUBTYPE: u8 = 0x01;

#[derive(Debug, Clone)]
pub struct LacpPacket {
    pub version: u8,
    pub actor_system: [u8; 6],
    pub actor_port: u16,
    pub actor_key: u16,
    pub actor_state: u8,
    pub partner_system: [u8; 6],
    pub partner_port: u16,
    pub partner_key: u16,
    pub partner_state: u8,
}

impl LacpPacket {
    pub fn new(system_id: [u8; 6], port: u16, key: u16) -> Self {
        Self {
            version: 0x01,
            actor_system: system_id,
            actor_port: port,
            actor_key: key,
            actor_state: 0x3D, // Aggregatable, in sync, collecting, distributing
            partner_system: [0; 6],
            partner_port: 0,
            partner_key: 0,
            partner_state: 0,
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut b = vec![0x01, 0x01]; // Subtype + Version
        b.push(0x01); // Actor TLV type
        b.push(0x14); // Actor info length
        b.extend_from_slice(&self.actor_system);
        b.extend_from_slice(&self.actor_port.to_be_bytes());
        b.extend_from_slice(&self.actor_key.to_be_bytes());
        b.push(self.actor_state);
        b.resize(124, 0);
        b
    }
}
