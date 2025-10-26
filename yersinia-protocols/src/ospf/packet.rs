//! OSPF Packet Structures

use std::net::Ipv4Addr;

pub const OSPF_PROTOCOL: u8 = 89;
pub const OSPF_VERSION: u8 = 2;

/// AllSPFRouters multicast address (224.0.0.5)
pub const OSPF_MULTICAST_ALL_SPF: [u8; 4] = [224, 0, 0, 5];

/// AllDRouters multicast address (224.0.0.6)
pub const OSPF_MULTICAST_ALL_DR: [u8; 4] = [224, 0, 0, 6];

/// OSPF Packet Types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum OspfPacketType {
    Hello = 1,
    DatabaseDescription = 2,
    LinkStateRequest = 3,
    LinkStateUpdate = 4,
    LinkStateAck = 5,
}

impl OspfPacketType {
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            1 => Some(Self::Hello),
            2 => Some(Self::DatabaseDescription),
            3 => Some(Self::LinkStateRequest),
            4 => Some(Self::LinkStateUpdate),
            5 => Some(Self::LinkStateAck),
            _ => None,
        }
    }
}

/// OSPF LSA Types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum OspfLsaType {
    RouterLsa = 1,
    NetworkLsa = 2,
    SummaryLsa = 3,
    AsbrSummaryLsa = 4,
    ExternalLsa = 5,
}

impl OspfLsaType {
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            1 => Some(Self::RouterLsa),
            2 => Some(Self::NetworkLsa),
            3 => Some(Self::SummaryLsa),
            4 => Some(Self::AsbrSummaryLsa),
            5 => Some(Self::ExternalLsa),
            _ => None,
        }
    }
}

/// OSPF LSA Header
#[derive(Debug, Clone)]
pub struct OspfLsaHeader {
    pub age: u16,
    pub options: u8,
    pub lsa_type: OspfLsaType,
    pub link_state_id: Ipv4Addr,
    pub advertising_router: Ipv4Addr,
    pub sequence: u32,
    pub checksum: u16,
    pub length: u16,
}

impl OspfLsaHeader {
    pub fn new(
        lsa_type: OspfLsaType,
        link_state_id: Ipv4Addr,
        advertising_router: Ipv4Addr,
    ) -> Self {
        Self {
            age: 0,
            options: 0x02, // E-bit (external routing capability)
            lsa_type,
            link_state_id,
            advertising_router,
            sequence: 0x80000001, // Initial sequence number
            checksum: 0,
            length: 20, // Header size
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&self.age.to_be_bytes());
        bytes.push(self.options);
        bytes.push(self.lsa_type as u8);
        bytes.extend_from_slice(&self.link_state_id.octets());
        bytes.extend_from_slice(&self.advertising_router.octets());
        bytes.extend_from_slice(&self.sequence.to_be_bytes());
        bytes.extend_from_slice(&self.checksum.to_be_bytes());
        bytes.extend_from_slice(&self.length.to_be_bytes());
        bytes
    }
}

/// OSPF LSA (Link State Advertisement)
#[derive(Debug, Clone)]
pub struct OspfLsa {
    pub header: OspfLsaHeader,
    pub data: Vec<u8>,
}

impl OspfLsa {
    pub fn new(header: OspfLsaHeader, data: Vec<u8>) -> Self {
        Self { header, data }
    }

    /// Create Router LSA
    pub fn router_lsa(router_id: Ipv4Addr, _area_id: Ipv4Addr, num_links: u16) -> Self {
        let header = OspfLsaHeader::new(OspfLsaType::RouterLsa, router_id, router_id);

        let mut data = Vec::new();
        data.push(0x01); // Flags: B bit (area border router)
        data.push(0); // Reserved
        data.extend_from_slice(&num_links.to_be_bytes());

        Self { header, data }
    }

    /// Create Network LSA
    pub fn network_lsa(
        network_id: Ipv4Addr,
        dr_router_id: Ipv4Addr,
        netmask: Ipv4Addr,
        attached_routers: Vec<Ipv4Addr>,
    ) -> Self {
        let header = OspfLsaHeader::new(OspfLsaType::NetworkLsa, network_id, dr_router_id);

        let mut data = Vec::new();
        data.extend_from_slice(&netmask.octets());
        for router in attached_routers {
            data.extend_from_slice(&router.octets());
        }

        Self { header, data }
    }

    /// Create Summary LSA (Type 3)
    pub fn summary_lsa(
        network: Ipv4Addr,
        netmask: Ipv4Addr,
        advertising_router: Ipv4Addr,
        metric: u32,
    ) -> Self {
        let header = OspfLsaHeader::new(OspfLsaType::SummaryLsa, network, advertising_router);

        let mut data = Vec::new();
        data.extend_from_slice(&netmask.octets());
        data.push(0); // Reserved
                      // Metric (24 bits)
        let metric_bytes = metric.to_be_bytes();
        data.extend_from_slice(&metric_bytes[1..4]);

        Self { header, data }
    }

    /// Create External LSA (Type 5)
    pub fn external_lsa(
        network: Ipv4Addr,
        netmask: Ipv4Addr,
        advertising_router: Ipv4Addr,
        forward_addr: Ipv4Addr,
        metric: u32,
        external_route_tag: u32,
    ) -> Self {
        let header = OspfLsaHeader::new(OspfLsaType::ExternalLsa, network, advertising_router);

        let mut data = Vec::new();
        data.extend_from_slice(&netmask.octets());

        // E-bit and metric (32 bits total)
        let mut metric_with_flags = metric & 0x00FFFFFF;
        metric_with_flags |= 0x80000000; // Set E-bit (Type 2 external metric)
        data.extend_from_slice(&metric_with_flags.to_be_bytes());

        data.extend_from_slice(&forward_addr.octets());
        data.extend_from_slice(&external_route_tag.to_be_bytes());

        Self { header, data }
    }

    /// Set LSA to max age (for flushing)
    pub fn set_max_age(mut self) -> Self {
        self.header.age = 3600; // MaxAge
        self
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = self.header.to_bytes();
        bytes.extend_from_slice(&self.data);
        bytes
    }
}

/// OSPF Hello Packet
#[derive(Debug, Clone)]
pub struct OspfHello {
    pub network_mask: Ipv4Addr,
    pub hello_interval: u16,
    pub options: u8,
    pub router_priority: u8,
    pub router_dead_interval: u32,
    pub designated_router: Ipv4Addr,
    pub backup_designated_router: Ipv4Addr,
    pub neighbors: Vec<Ipv4Addr>,
}

impl OspfHello {
    pub fn new(network_mask: Ipv4Addr) -> Self {
        Self {
            network_mask,
            hello_interval: 10,
            options: 0x02, // E-bit
            router_priority: 1,
            router_dead_interval: 40,
            designated_router: Ipv4Addr::UNSPECIFIED,
            backup_designated_router: Ipv4Addr::UNSPECIFIED,
            neighbors: vec![],
        }
    }

    pub fn with_dr(mut self, dr: Ipv4Addr) -> Self {
        self.designated_router = dr;
        self
    }

    pub fn with_bdr(mut self, bdr: Ipv4Addr) -> Self {
        self.backup_designated_router = bdr;
        self
    }

    pub fn add_neighbor(mut self, neighbor: Ipv4Addr) -> Self {
        self.neighbors.push(neighbor);
        self
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&self.network_mask.octets());
        bytes.extend_from_slice(&self.hello_interval.to_be_bytes());
        bytes.push(self.options);
        bytes.push(self.router_priority);
        bytes.extend_from_slice(&self.router_dead_interval.to_be_bytes());
        bytes.extend_from_slice(&self.designated_router.octets());
        bytes.extend_from_slice(&self.backup_designated_router.octets());

        for neighbor in &self.neighbors {
            bytes.extend_from_slice(&neighbor.octets());
        }

        bytes
    }
}

/// OSPF Packet
#[derive(Debug, Clone)]
pub struct OspfPacket {
    pub version: u8,
    pub packet_type: OspfPacketType,
    pub packet_length: u16,
    pub router_id: Ipv4Addr,
    pub area_id: Ipv4Addr,
    pub checksum: u16,
    pub auth_type: u16,
    pub authentication: [u8; 8],
    pub data: Vec<u8>,
}

impl OspfPacket {
    pub fn new(packet_type: OspfPacketType, router_id: Ipv4Addr, area_id: Ipv4Addr) -> Self {
        Self {
            version: OSPF_VERSION,
            packet_type,
            packet_length: 24, // Header only
            router_id,
            area_id,
            checksum: 0,
            auth_type: 0, // No authentication
            authentication: [0u8; 8],
            data: vec![],
        }
    }

    pub fn hello(router_id: Ipv4Addr, area_id: Ipv4Addr, hello_data: OspfHello) -> Self {
        let data = hello_data.to_bytes();
        let mut packet = Self::new(OspfPacketType::Hello, router_id, area_id);
        packet.data = data;
        packet.packet_length = 24 + packet.data.len() as u16;
        packet
    }

    pub fn link_state_update(router_id: Ipv4Addr, area_id: Ipv4Addr, lsas: Vec<OspfLsa>) -> Self {
        let mut data = Vec::new();
        data.extend_from_slice(&(lsas.len() as u32).to_be_bytes());

        for lsa in lsas {
            data.extend_from_slice(&lsa.to_bytes());
        }

        let mut packet = Self::new(OspfPacketType::LinkStateUpdate, router_id, area_id);
        packet.data = data;
        packet.packet_length = 24 + packet.data.len() as u16;
        packet
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.push(self.version);
        bytes.push(self.packet_type as u8);
        bytes.extend_from_slice(&self.packet_length.to_be_bytes());
        bytes.extend_from_slice(&self.router_id.octets());
        bytes.extend_from_slice(&self.area_id.octets());
        bytes.extend_from_slice(&self.checksum.to_be_bytes());
        bytes.extend_from_slice(&self.auth_type.to_be_bytes());
        bytes.extend_from_slice(&self.authentication);
        bytes.extend_from_slice(&self.data);
        bytes
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hello_packet() {
        let hello = OspfHello::new("255.255.255.0".parse().unwrap())
            .add_neighbor("10.0.0.2".parse().unwrap());

        let packet = OspfPacket::hello(
            "10.0.0.1".parse().unwrap(),
            "0.0.0.0".parse().unwrap(),
            hello,
        );

        let bytes = packet.to_bytes();
        assert_eq!(bytes[0], OSPF_VERSION);
        assert_eq!(bytes[1], OspfPacketType::Hello as u8);
    }

    #[test]
    fn test_router_lsa() {
        let lsa = OspfLsa::router_lsa("10.0.0.1".parse().unwrap(), "0.0.0.0".parse().unwrap(), 2);

        let bytes = lsa.to_bytes();
        assert!(bytes.len() >= 20); // At least header size
    }

    #[test]
    fn test_external_lsa() {
        let lsa = OspfLsa::external_lsa(
            "192.168.1.0".parse().unwrap(),
            "255.255.255.0".parse().unwrap(),
            "10.0.0.1".parse().unwrap(),
            "0.0.0.0".parse().unwrap(),
            100,
            0,
        );

        assert_eq!(lsa.header.lsa_type, OspfLsaType::ExternalLsa);
    }
}
