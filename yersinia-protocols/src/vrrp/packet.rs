//! VRRP Packet Structures

use std::net::Ipv4Addr;

pub const VRRP_MULTICAST_V2: [u8; 4] = [224, 0, 0, 18];
pub const VRRP_MULTICAST_V3: [u8; 4] = [224, 0, 0, 18];
pub const VRRP_PROTOCOL_NUMBER: u8 = 112;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VrrpVersion {
    V2 = 2,
    V3 = 3,
}

#[derive(Debug, Clone)]
pub struct VrrpPacket {
    pub version: VrrpVersion,
    pub vrid: u8,
    pub priority: u8,
    pub count_ip: u8,
    pub adver_int: u16,
    pub checksum: u16,
    pub ip_addresses: Vec<Ipv4Addr>,
}

impl VrrpPacket {
    pub fn new_v2(vrid: u8, priority: u8, adver_int: u8, ip_addresses: Vec<Ipv4Addr>) -> Self {
        Self {
            version: VrrpVersion::V2,
            vrid,
            priority,
            count_ip: ip_addresses.len() as u8,
            adver_int: adver_int as u16,
            checksum: 0,
            ip_addresses,
        }
    }

    pub fn new_v3(vrid: u8, priority: u8, max_adver_int: u16, ip_addresses: Vec<Ipv4Addr>) -> Self {
        Self {
            version: VrrpVersion::V3,
            vrid,
            priority,
            count_ip: ip_addresses.len() as u8,
            adver_int: max_adver_int,
            checksum: 0,
            ip_addresses,
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();

        let version_type = ((self.version as u8) << 4) | 0x01;
        bytes.push(version_type);
        bytes.push(self.vrid);
        bytes.push(self.priority);
        bytes.push(self.count_ip);

        if self.version == VrrpVersion::V2 {
            bytes.push(self.adver_int as u8);
        } else {
            bytes.extend_from_slice(&self.adver_int.to_be_bytes());
        }

        bytes.extend_from_slice(&self.checksum.to_be_bytes());

        for ip in &self.ip_addresses {
            bytes.extend_from_slice(&ip.octets());
        }

        bytes
    }

    pub fn calculate_checksum(&mut self) {
        self.checksum = 0;
        let bytes = self.to_bytes();
        self.checksum = internet_checksum(&bytes);
    }
}

fn internet_checksum(data: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut i = 0;

    while i < data.len() - 1 {
        sum += u16::from_be_bytes([data[i], data[i + 1]]) as u32;
        i += 2;
    }

    if i < data.len() {
        sum += (data[i] as u32) << 8;
    }

    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    !sum as u16
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vrrp_v2_packet() {
        let ips = vec![Ipv4Addr::new(192, 168, 1, 1)];
        let mut packet = VrrpPacket::new_v2(1, 255, 1, ips);
        packet.calculate_checksum();

        let bytes = packet.to_bytes();
        assert!(!bytes.is_empty());
        assert_eq!(bytes[1], 1); // VRID
        assert_eq!(bytes[2], 255); // Priority
    }

    #[test]
    fn test_vrrp_v3_packet() {
        let ips = vec![Ipv4Addr::new(192, 168, 1, 1)];
        let packet = VrrpPacket::new_v3(1, 255, 100, ips);

        let bytes = packet.to_bytes();
        assert!(!bytes.is_empty());
    }
}
