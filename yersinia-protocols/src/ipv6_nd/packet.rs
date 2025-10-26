//! IPv6 Neighbor Discovery Packet Structures

use std::net::Ipv6Addr;

pub const ICMPV6_PROTOCOL: u8 = 58;

/// All-routers multicast address (ff02::2)
pub const ICMPV6_RA_MULTICAST: [u8; 16] = [
    0xFF, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02,
];

/// All-nodes multicast address (ff02::1)
pub const ICMPV6_ALL_NODES: [u8; 16] = [
    0xFF, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
];

/// Solicited-node multicast prefix (ff02::1:ff00:0/104)
pub const ICMPV6_NS_MULTICAST_PREFIX: [u8; 13] = [
    0xFF, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0xFF,
];

/// ICMPv6 ND Message Types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Ipv6NdType {
    RouterSolicitation = 133,
    RouterAdvertisement = 134,
    NeighborSolicitation = 135,
    NeighborAdvertisement = 136,
    Redirect = 137,
}

impl Ipv6NdType {
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            133 => Some(Self::RouterSolicitation),
            134 => Some(Self::RouterAdvertisement),
            135 => Some(Self::NeighborSolicitation),
            136 => Some(Self::NeighborAdvertisement),
            137 => Some(Self::Redirect),
            _ => None,
        }
    }
}

/// IPv6 ND Option Types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Ipv6NdOptionType {
    SourceLinkLayerAddress = 1,
    TargetLinkLayerAddress = 2,
    PrefixInformation = 3,
    RedirectedHeader = 4,
    Mtu = 5,
    RouteInformation = 24,   // RFC 4191
    RecursiveDnsServer = 25, // RFC 8106
    DnsSearchList = 31,      // RFC 8106
}

impl Ipv6NdOptionType {
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            1 => Some(Self::SourceLinkLayerAddress),
            2 => Some(Self::TargetLinkLayerAddress),
            3 => Some(Self::PrefixInformation),
            4 => Some(Self::RedirectedHeader),
            5 => Some(Self::Mtu),
            24 => Some(Self::RouteInformation),
            25 => Some(Self::RecursiveDnsServer),
            31 => Some(Self::DnsSearchList),
            _ => None,
        }
    }
}

/// IPv6 ND Option
#[derive(Debug, Clone)]
pub struct Ipv6NdOption {
    pub option_type: Ipv6NdOptionType,
    pub data: Vec<u8>,
}

impl Ipv6NdOption {
    pub fn new(option_type: Ipv6NdOptionType, data: Vec<u8>) -> Self {
        Self { option_type, data }
    }

    /// Source Link-Layer Address
    pub fn source_ll_addr(mac: [u8; 6]) -> Self {
        Self {
            option_type: Ipv6NdOptionType::SourceLinkLayerAddress,
            data: mac.to_vec(),
        }
    }

    /// Target Link-Layer Address
    pub fn target_ll_addr(mac: [u8; 6]) -> Self {
        Self {
            option_type: Ipv6NdOptionType::TargetLinkLayerAddress,
            data: mac.to_vec(),
        }
    }

    /// Prefix Information Option
    pub fn prefix_information(
        prefix: Ipv6Addr,
        prefix_len: u8,
        on_link: bool,
        autonomous: bool,
        valid_lifetime: u32,
        preferred_lifetime: u32,
    ) -> Self {
        let mut data = Vec::new();

        data.push(prefix_len);

        // Flags: L (on-link), A (autonomous)
        let mut flags = 0u8;
        if on_link {
            flags |= 0x80;
        }
        if autonomous {
            flags |= 0x40;
        }
        data.push(flags);

        // Valid lifetime
        data.extend_from_slice(&valid_lifetime.to_be_bytes());

        // Preferred lifetime
        data.extend_from_slice(&preferred_lifetime.to_be_bytes());

        // Reserved
        data.extend_from_slice(&[0u8; 4]);

        // Prefix
        data.extend_from_slice(&prefix.octets());

        Self {
            option_type: Ipv6NdOptionType::PrefixInformation,
            data,
        }
    }

    /// MTU Option
    pub fn mtu(mtu: u32) -> Self {
        let mut data = vec![0u8; 2]; // Reserved
        data.extend_from_slice(&mtu.to_be_bytes());
        Self {
            option_type: Ipv6NdOptionType::Mtu,
            data,
        }
    }

    /// Recursive DNS Server Option (RDNSS)
    pub fn rdnss(lifetime: u32, servers: Vec<Ipv6Addr>) -> Self {
        let mut data = Vec::new();
        data.extend_from_slice(&[0u8; 2]); // Reserved
        data.extend_from_slice(&lifetime.to_be_bytes());
        for server in servers {
            data.extend_from_slice(&server.octets());
        }
        Self {
            option_type: Ipv6NdOptionType::RecursiveDnsServer,
            data,
        }
    }

    /// Encode option to bytes (Type + Length + Data)
    /// Length is in units of 8 octets
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.push(self.option_type as u8);

        // Calculate length in 8-octet units
        let total_len = 2 + self.data.len(); // type + len + data
        let len_8octets = total_len.div_ceil(8) as u8;
        bytes.push(len_8octets);

        bytes.extend_from_slice(&self.data);

        // Pad to 8-octet boundary
        let padding = (len_8octets as usize * 8) - total_len;
        bytes.extend(vec![0u8; padding]);

        bytes
    }

    /// Parse option from bytes
    pub fn from_bytes(data: &[u8]) -> Option<(Self, usize)> {
        if data.len() < 2 {
            return None;
        }

        let option_type = Ipv6NdOptionType::from_u8(data[0])?;
        let length_8octets = data[1] as usize;
        let total_bytes = length_8octets * 8;

        if data.len() < total_bytes {
            return None;
        }

        let option_data = data[2..total_bytes].to_vec();

        Some((
            Self {
                option_type,
                data: option_data,
            },
            total_bytes,
        ))
    }
}

/// Router Advertisement Packet
#[derive(Debug, Clone)]
pub struct RouterAdvertisement {
    pub cur_hop_limit: u8,
    pub managed_flag: bool,      // M flag (DHCPv6)
    pub other_config_flag: bool, // O flag (DHCPv6 for other config)
    pub router_lifetime: u16,
    pub reachable_time: u32,
    pub retrans_timer: u32,
    pub options: Vec<Ipv6NdOption>,
}

impl Default for RouterAdvertisement {
    fn default() -> Self {
        Self::new()
    }
}

impl RouterAdvertisement {
    pub fn new() -> Self {
        Self {
            cur_hop_limit: 64,
            managed_flag: false,
            other_config_flag: false,
            router_lifetime: 1800,
            reachable_time: 0,
            retrans_timer: 0,
            options: vec![],
        }
    }

    pub fn with_prefix(
        mut self,
        prefix: Ipv6Addr,
        prefix_len: u8,
        valid_lifetime: u32,
        preferred_lifetime: u32,
    ) -> Self {
        self.options.push(Ipv6NdOption::prefix_information(
            prefix,
            prefix_len,
            true, // on-link
            true, // autonomous (SLAAC)
            valid_lifetime,
            preferred_lifetime,
        ));
        self
    }

    pub fn with_source_ll(mut self, mac: [u8; 6]) -> Self {
        self.options.push(Ipv6NdOption::source_ll_addr(mac));
        self
    }

    pub fn with_rdnss(mut self, lifetime: u32, servers: Vec<Ipv6Addr>) -> Self {
        self.options.push(Ipv6NdOption::rdnss(lifetime, servers));
        self
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();

        bytes.push(self.cur_hop_limit);

        // Flags
        let mut flags = 0u8;
        if self.managed_flag {
            flags |= 0x80;
        }
        if self.other_config_flag {
            flags |= 0x40;
        }
        bytes.push(flags);

        bytes.extend_from_slice(&self.router_lifetime.to_be_bytes());
        bytes.extend_from_slice(&self.reachable_time.to_be_bytes());
        bytes.extend_from_slice(&self.retrans_timer.to_be_bytes());

        // Options
        for option in &self.options {
            bytes.extend_from_slice(&option.to_bytes());
        }

        bytes
    }
}

/// Neighbor Solicitation Packet
#[derive(Debug, Clone)]
pub struct NeighborSolicitation {
    pub target_address: Ipv6Addr,
    pub options: Vec<Ipv6NdOption>,
}

impl NeighborSolicitation {
    pub fn new(target: Ipv6Addr) -> Self {
        Self {
            target_address: target,
            options: vec![],
        }
    }

    pub fn with_source_ll(mut self, mac: [u8; 6]) -> Self {
        self.options.push(Ipv6NdOption::source_ll_addr(mac));
        self
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&[0u8; 4]); // Reserved
        bytes.extend_from_slice(&self.target_address.octets());

        for option in &self.options {
            bytes.extend_from_slice(&option.to_bytes());
        }

        bytes
    }
}

/// Neighbor Advertisement Packet
#[derive(Debug, Clone)]
pub struct NeighborAdvertisement {
    pub router_flag: bool,
    pub solicited_flag: bool,
    pub override_flag: bool,
    pub target_address: Ipv6Addr,
    pub options: Vec<Ipv6NdOption>,
}

impl NeighborAdvertisement {
    pub fn new(target: Ipv6Addr, is_router: bool) -> Self {
        Self {
            router_flag: is_router,
            solicited_flag: true,
            override_flag: true,
            target_address: target,
            options: vec![],
        }
    }

    pub fn with_target_ll(mut self, mac: [u8; 6]) -> Self {
        self.options.push(Ipv6NdOption::target_ll_addr(mac));
        self
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();

        // Flags
        let mut flags = 0u32;
        if self.router_flag {
            flags |= 0x80000000;
        }
        if self.solicited_flag {
            flags |= 0x40000000;
        }
        if self.override_flag {
            flags |= 0x20000000;
        }
        bytes.extend_from_slice(&flags.to_be_bytes());

        bytes.extend_from_slice(&self.target_address.octets());

        for option in &self.options {
            bytes.extend_from_slice(&option.to_bytes());
        }

        bytes
    }
}

/// Generic IPv6 ND Packet
#[derive(Debug, Clone)]
pub enum Ipv6NdPacket {
    RouterAdvertisement(RouterAdvertisement),
    NeighborSolicitation(NeighborSolicitation),
    NeighborAdvertisement(NeighborAdvertisement),
}

impl Ipv6NdPacket {
    pub fn get_type(&self) -> Ipv6NdType {
        match self {
            Self::RouterAdvertisement(_) => Ipv6NdType::RouterAdvertisement,
            Self::NeighborSolicitation(_) => Ipv6NdType::NeighborSolicitation,
            Self::NeighborAdvertisement(_) => Ipv6NdType::NeighborAdvertisement,
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        match self {
            Self::RouterAdvertisement(ra) => ra.to_bytes(),
            Self::NeighborSolicitation(ns) => ns.to_bytes(),
            Self::NeighborAdvertisement(na) => na.to_bytes(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_router_advertisement() {
        let ra = RouterAdvertisement::new()
            .with_prefix("2001:db8::".parse().unwrap(), 64, 86400, 14400)
            .with_source_ll([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);

        let bytes = ra.to_bytes();
        assert_eq!(bytes[0], 64); // hop limit
        assert!(bytes.len() > 12); // base + options
    }

    #[test]
    fn test_neighbor_solicitation() {
        let ns = NeighborSolicitation::new("2001:db8::1".parse().unwrap())
            .with_source_ll([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]);

        let bytes = ns.to_bytes();
        assert_eq!(
            &bytes[4..20],
            &"2001:db8::1".parse::<Ipv6Addr>().unwrap().octets()
        );
    }

    #[test]
    fn test_neighbor_advertisement() {
        let na = NeighborAdvertisement::new("2001:db8::1".parse().unwrap(), false)
            .with_target_ll([0x11, 0x22, 0x33, 0x44, 0x55, 0x66]);

        let bytes = na.to_bytes();
        assert!(bytes.len() >= 20); // flags + target + option
    }
}
