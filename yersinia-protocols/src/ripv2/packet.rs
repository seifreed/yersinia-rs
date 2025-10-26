//! RIPv2 Packet Structures - RFC 2453

use std::net::Ipv4Addr;

pub const RIP_PORT: u16 = 520;
pub const RIP_VERSION_1: u8 = 1;
pub const RIP_VERSION_2: u8 = 2;
pub const RIP_MULTICAST: [u8; 4] = [224, 0, 0, 9];

/// RIP Commands
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum RipCommand {
    Request = 1,
    Response = 2,
}

/// RIP Route Entry (20 bytes)
#[derive(Debug, Clone)]
pub struct RipEntry {
    pub address_family: u16,
    pub route_tag: u16,
    pub ip_address: Ipv4Addr,
    pub subnet_mask: Ipv4Addr,
    pub next_hop: Ipv4Addr,
    pub metric: u32,
}

impl RipEntry {
    /// Create a new RIP entry
    pub fn new(ip: Ipv4Addr, mask: Ipv4Addr, metric: u32) -> Self {
        Self {
            address_family: 2, // IPv4
            route_tag: 0,
            ip_address: ip,
            subnet_mask: mask,
            next_hop: Ipv4Addr::new(0, 0, 0, 0),
            metric,
        }
    }

    /// Create route with custom next hop
    pub fn with_next_hop(ip: Ipv4Addr, mask: Ipv4Addr, next_hop: Ipv4Addr, metric: u32) -> Self {
        Self {
            address_family: 2,
            route_tag: 0,
            ip_address: ip,
            subnet_mask: mask,
            next_hop,
            metric,
        }
    }

    /// Create a poisoned route (metric 16 = infinity)
    pub fn poisoned(ip: Ipv4Addr, mask: Ipv4Addr) -> Self {
        Self::new(ip, mask, 16)
    }

    /// Encode entry to bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(20);
        bytes.extend_from_slice(&self.address_family.to_be_bytes());
        bytes.extend_from_slice(&self.route_tag.to_be_bytes());
        bytes.extend_from_slice(&self.ip_address.octets());
        bytes.extend_from_slice(&self.subnet_mask.octets());
        bytes.extend_from_slice(&self.next_hop.octets());
        bytes.extend_from_slice(&self.metric.to_be_bytes());
        bytes
    }

    /// Parse entry from bytes
    pub fn from_bytes(data: &[u8]) -> Option<Self> {
        if data.len() < 20 {
            return None;
        }

        Some(Self {
            address_family: u16::from_be_bytes([data[0], data[1]]),
            route_tag: u16::from_be_bytes([data[2], data[3]]),
            ip_address: Ipv4Addr::new(data[4], data[5], data[6], data[7]),
            subnet_mask: Ipv4Addr::new(data[8], data[9], data[10], data[11]),
            next_hop: Ipv4Addr::new(data[12], data[13], data[14], data[15]),
            metric: u32::from_be_bytes([data[16], data[17], data[18], data[19]]),
        })
    }
}

/// RIP Packet
#[derive(Debug, Clone)]
pub struct RipPacket {
    pub command: RipCommand,
    pub version: u8,
    pub entries: Vec<RipEntry>,
}

impl RipPacket {
    /// Create new RIP response
    pub fn new_response(entries: Vec<RipEntry>) -> Self {
        Self {
            command: RipCommand::Response,
            version: RIP_VERSION_2,
            entries,
        }
    }

    /// Create new RIP request
    pub fn new_request() -> Self {
        Self {
            command: RipCommand::Request,
            version: RIP_VERSION_2,
            entries: vec![],
        }
    }

    /// Encode packet to bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.push(self.command as u8);
        bytes.push(self.version);
        bytes.extend_from_slice(&[0u8; 2]); // Reserved

        for entry in &self.entries {
            bytes.extend_from_slice(&entry.to_bytes());
        }

        bytes
    }

    /// Parse packet from bytes
    pub fn from_bytes(data: &[u8]) -> Option<Self> {
        if data.len() < 4 {
            return None;
        }

        let command = match data[0] {
            1 => RipCommand::Request,
            2 => RipCommand::Response,
            _ => return None,
        };

        let version = data[1];
        let mut entries = Vec::new();
        let mut offset = 4;

        while offset + 20 <= data.len() {
            if let Some(entry) = RipEntry::from_bytes(&data[offset..]) {
                entries.push(entry);
            }
            offset += 20;
        }

        Some(Self {
            command,
            version,
            entries,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rip_entry_encoding() {
        let entry = RipEntry::new(
            Ipv4Addr::new(192, 168, 1, 0),
            Ipv4Addr::new(255, 255, 255, 0),
            1,
        );

        let bytes = entry.to_bytes();
        assert_eq!(bytes.len(), 20);

        let parsed = RipEntry::from_bytes(&bytes).unwrap();
        assert_eq!(parsed.ip_address, entry.ip_address);
        assert_eq!(parsed.metric, 1);
    }

    #[test]
    fn test_rip_packet_response() {
        let entries = vec![RipEntry::new(
            Ipv4Addr::new(10, 0, 0, 0),
            Ipv4Addr::new(255, 0, 0, 0),
            5,
        )];

        let packet = RipPacket::new_response(entries);
        let bytes = packet.to_bytes();

        assert_eq!(bytes[0], 2); // Response
        assert_eq!(bytes[1], 2); // Version 2

        let parsed = RipPacket::from_bytes(&bytes).unwrap();
        assert_eq!(parsed.entries.len(), 1);
    }

    #[test]
    fn test_poisoned_route() {
        let poisoned = RipEntry::poisoned(
            Ipv4Addr::new(192, 168, 1, 0),
            Ipv4Addr::new(255, 255, 255, 0),
        );
        assert_eq!(poisoned.metric, 16);
    }
}
