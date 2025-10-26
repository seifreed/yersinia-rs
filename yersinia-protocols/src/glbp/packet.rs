//! GLBP Packet
use std::net::Ipv4Addr;
pub const GLBP_MULTICAST: [u8; 4] = [224, 0, 0, 102];

#[derive(Debug, Clone)]
pub struct GlbpPacket {
    pub version: u8,
    pub group: u16,
    pub priority: u8,
    pub virtual_ip: Ipv4Addr,
}

impl GlbpPacket {
    pub fn new(group: u16, priority: u8, vip: Ipv4Addr) -> Self {
        Self {
            version: 1,
            group,
            priority,
            virtual_ip: vip,
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut b = vec![self.version];
        b.extend_from_slice(&self.group.to_be_bytes());
        b.push(self.priority);
        b.extend_from_slice(&self.virtual_ip.octets());
        b
    }
}
