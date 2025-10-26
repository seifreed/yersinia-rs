//! PAgP Packet Structures
pub const PAGP_MULTICAST_MAC: [u8; 6] = [0x01, 0x00, 0x0C, 0xCC, 0xCC, 0xCC];
pub const PAGP_DST_MAC: [u8; 6] = [0x01, 0x00, 0x0C, 0xCC, 0xCC, 0xCC];

#[derive(Debug, Clone)]
pub struct PagpPacket {
    pub version: u8,
    pub flags: u8,
    pub device_id: [u8; 6],
    pub port_id: [u8; 6],
    pub group_capability: u8,
    pub auto_mode: u8,
}

impl PagpPacket {
    pub fn new(device_id: [u8; 6], port_id: [u8; 6]) -> Self {
        Self {
            version: 1,
            flags: 0x01,
            device_id,
            port_id,
            group_capability: 0x01,
            auto_mode: 0x00, // Desirable mode
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(128);
        bytes.push(self.version);
        bytes.push(self.flags);
        bytes.extend_from_slice(&self.device_id);
        bytes.extend_from_slice(&self.port_id);
        bytes.push(self.group_capability);
        bytes.push(self.auto_mode);
        bytes.resize(128, 0);
        bytes
    }
}
