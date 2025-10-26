//! DHCPv6 Packet Structures

use std::net::Ipv6Addr;

pub const DHCPV6_CLIENT_PORT: u16 = 546;
pub const DHCPV6_SERVER_PORT: u16 = 547;
pub const DHCPV6_MULTICAST: [u8; 16] = [
    0xFF, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x02,
]; // ff02::1:2

/// DHCPv6 Message Types (RFC 8415)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Dhcpv6MessageType {
    Solicit = 1,
    Advertise = 2,
    Request = 3,
    Confirm = 4,
    Renew = 5,
    Rebind = 6,
    Reply = 7,
    Release = 8,
    Decline = 9,
    Reconfigure = 10,
    InformationRequest = 11,
    RelayForw = 12,
    RelayRepl = 13,
}

impl Dhcpv6MessageType {
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            1 => Some(Self::Solicit),
            2 => Some(Self::Advertise),
            3 => Some(Self::Request),
            4 => Some(Self::Confirm),
            5 => Some(Self::Renew),
            6 => Some(Self::Rebind),
            7 => Some(Self::Reply),
            8 => Some(Self::Release),
            9 => Some(Self::Decline),
            10 => Some(Self::Reconfigure),
            11 => Some(Self::InformationRequest),
            12 => Some(Self::RelayForw),
            13 => Some(Self::RelayRepl),
            _ => None,
        }
    }
}

/// DHCPv6 Option Types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum Dhcpv6OptionType {
    ClientId = 1,
    ServerId = 2,
    IaNa = 3,   // Identity Association for Non-temporary Addresses
    IaTa = 4,   // Identity Association for Temporary Addresses
    IaAddr = 5, // IA Address
    Oro = 6,    // Option Request Option
    Preference = 7,
    ElapsedTime = 8,
    RelayMsg = 9,
    Auth = 11,
    Unicast = 12,
    StatusCode = 13,
    RapidCommit = 14,
    UserClass = 15,
    VendorClass = 16,
    VendorOpts = 17,
    InterfaceId = 18,
    ReconfMsg = 19,
    ReconfAccept = 20,
    DnsServers = 23,
    DomainList = 24,
    IaPd = 25, // Identity Association for Prefix Delegation
    IaPrefix = 26,
}

impl Dhcpv6OptionType {
    pub fn from_u16(value: u16) -> Option<Self> {
        match value {
            1 => Some(Self::ClientId),
            2 => Some(Self::ServerId),
            3 => Some(Self::IaNa),
            4 => Some(Self::IaTa),
            5 => Some(Self::IaAddr),
            6 => Some(Self::Oro),
            7 => Some(Self::Preference),
            8 => Some(Self::ElapsedTime),
            9 => Some(Self::RelayMsg),
            11 => Some(Self::Auth),
            12 => Some(Self::Unicast),
            13 => Some(Self::StatusCode),
            14 => Some(Self::RapidCommit),
            15 => Some(Self::UserClass),
            16 => Some(Self::VendorClass),
            17 => Some(Self::VendorOpts),
            18 => Some(Self::InterfaceId),
            19 => Some(Self::ReconfMsg),
            20 => Some(Self::ReconfAccept),
            23 => Some(Self::DnsServers),
            24 => Some(Self::DomainList),
            25 => Some(Self::IaPd),
            26 => Some(Self::IaPrefix),
            _ => None,
        }
    }
}

/// DHCPv6 Option
#[derive(Debug, Clone)]
pub struct Dhcpv6Option {
    pub option_type: Dhcpv6OptionType,
    pub data: Vec<u8>,
}

impl Dhcpv6Option {
    pub fn new(option_type: Dhcpv6OptionType, data: Vec<u8>) -> Self {
        Self { option_type, data }
    }

    /// Client Identifier (DUID)
    pub fn client_id(duid: Vec<u8>) -> Self {
        Self {
            option_type: Dhcpv6OptionType::ClientId,
            data: duid,
        }
    }

    /// Server Identifier (DUID)
    pub fn server_id(duid: Vec<u8>) -> Self {
        Self {
            option_type: Dhcpv6OptionType::ServerId,
            data: duid,
        }
    }

    /// IA_NA (Identity Association for Non-temporary Addresses)
    pub fn ia_na(iaid: u32, t1: u32, t2: u32, options: Vec<Dhcpv6Option>) -> Self {
        let mut data = Vec::new();
        data.extend_from_slice(&iaid.to_be_bytes());
        data.extend_from_slice(&t1.to_be_bytes());
        data.extend_from_slice(&t2.to_be_bytes());
        for opt in options {
            data.extend_from_slice(&opt.to_bytes());
        }
        Self {
            option_type: Dhcpv6OptionType::IaNa,
            data,
        }
    }

    /// IA Address
    pub fn ia_addr(addr: Ipv6Addr, preferred_lifetime: u32, valid_lifetime: u32) -> Self {
        let mut data = Vec::new();
        data.extend_from_slice(&addr.octets());
        data.extend_from_slice(&preferred_lifetime.to_be_bytes());
        data.extend_from_slice(&valid_lifetime.to_be_bytes());
        Self {
            option_type: Dhcpv6OptionType::IaAddr,
            data,
        }
    }

    /// Option Request Option (ORO)
    pub fn oro(requested_options: Vec<Dhcpv6OptionType>) -> Self {
        let mut data = Vec::new();
        for opt_type in requested_options {
            data.extend_from_slice(&(opt_type as u16).to_be_bytes());
        }
        Self {
            option_type: Dhcpv6OptionType::Oro,
            data,
        }
    }

    /// DNS Recursive Name Server
    pub fn dns_servers(servers: Vec<Ipv6Addr>) -> Self {
        let mut data = Vec::new();
        for server in servers {
            data.extend_from_slice(&server.octets());
        }
        Self {
            option_type: Dhcpv6OptionType::DnsServers,
            data,
        }
    }

    /// Elapsed Time (in 1/100ths of a second)
    pub fn elapsed_time(time_cs: u16) -> Self {
        Self {
            option_type: Dhcpv6OptionType::ElapsedTime,
            data: time_cs.to_be_bytes().to_vec(),
        }
    }

    /// Rapid Commit
    pub fn rapid_commit() -> Self {
        Self {
            option_type: Dhcpv6OptionType::RapidCommit,
            data: vec![],
        }
    }

    /// Encode option to bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&(self.option_type as u16).to_be_bytes());
        bytes.extend_from_slice(&(self.data.len() as u16).to_be_bytes());
        bytes.extend_from_slice(&self.data);
        bytes
    }

    /// Parse option from bytes
    pub fn from_bytes(data: &[u8]) -> Option<(Self, usize)> {
        if data.len() < 4 {
            return None;
        }

        let option_type = u16::from_be_bytes([data[0], data[1]]);
        let length = u16::from_be_bytes([data[2], data[3]]) as usize;

        if data.len() < 4 + length {
            return None;
        }

        let option_type = Dhcpv6OptionType::from_u16(option_type)?;
        let option_data = data[4..4 + length].to_vec();

        Some((
            Self {
                option_type,
                data: option_data,
            },
            4 + length,
        ))
    }
}

/// DHCPv6 Packet
#[derive(Debug, Clone)]
pub struct Dhcpv6Packet {
    /// Message type
    pub msg_type: Dhcpv6MessageType,
    /// Transaction ID (24 bits)
    pub transaction_id: [u8; 3],
    /// Options
    pub options: Vec<Dhcpv6Option>,
}

impl Dhcpv6Packet {
    pub fn new(msg_type: Dhcpv6MessageType, transaction_id: [u8; 3]) -> Self {
        Self {
            msg_type,
            transaction_id,
            options: vec![],
        }
    }

    pub fn with_options(mut self, options: Vec<Dhcpv6Option>) -> Self {
        self.options = options;
        self
    }

    pub fn add_option(mut self, option: Dhcpv6Option) -> Self {
        self.options.push(option);
        self
    }

    /// Create a SOLICIT message
    pub fn solicit(transaction_id: [u8; 3], client_duid: Vec<u8>) -> Self {
        Self::new(Dhcpv6MessageType::Solicit, transaction_id)
            .add_option(Dhcpv6Option::client_id(client_duid))
            .add_option(Dhcpv6Option::elapsed_time(0))
            .add_option(Dhcpv6Option::oro(vec![
                Dhcpv6OptionType::DnsServers,
                Dhcpv6OptionType::DomainList,
            ]))
    }

    /// Create an ADVERTISE message
    pub fn advertise(transaction_id: [u8; 3], server_duid: Vec<u8>, client_duid: Vec<u8>) -> Self {
        Self::new(Dhcpv6MessageType::Advertise, transaction_id)
            .add_option(Dhcpv6Option::server_id(server_duid))
            .add_option(Dhcpv6Option::client_id(client_duid))
    }

    /// Create a REQUEST message
    pub fn request(transaction_id: [u8; 3], client_duid: Vec<u8>, server_duid: Vec<u8>) -> Self {
        Self::new(Dhcpv6MessageType::Request, transaction_id)
            .add_option(Dhcpv6Option::client_id(client_duid))
            .add_option(Dhcpv6Option::server_id(server_duid))
            .add_option(Dhcpv6Option::elapsed_time(0))
    }

    /// Create a REPLY message
    pub fn reply(transaction_id: [u8; 3], server_duid: Vec<u8>, client_duid: Vec<u8>) -> Self {
        Self::new(Dhcpv6MessageType::Reply, transaction_id)
            .add_option(Dhcpv6Option::server_id(server_duid))
            .add_option(Dhcpv6Option::client_id(client_duid))
    }

    /// Encode packet to bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();

        // Message type (1 byte) + Transaction ID (3 bytes)
        bytes.push(self.msg_type as u8);
        bytes.extend_from_slice(&self.transaction_id);

        // Options
        for option in &self.options {
            bytes.extend_from_slice(&option.to_bytes());
        }

        bytes
    }

    /// Parse packet from bytes
    pub fn from_bytes(data: &[u8]) -> Option<Self> {
        if data.len() < 4 {
            return None;
        }

        let msg_type = Dhcpv6MessageType::from_u8(data[0])?;
        let transaction_id = [data[1], data[2], data[3]];

        let mut options = vec![];
        let mut offset = 4;

        while offset < data.len() {
            if let Some((option, consumed)) = Dhcpv6Option::from_bytes(&data[offset..]) {
                options.push(option);
                offset += consumed;
            } else {
                break;
            }
        }

        Some(Self {
            msg_type,
            transaction_id,
            options,
        })
    }

    /// Generate random transaction ID
    pub fn random_transaction_id() -> [u8; 3] {
        [rand::random(), rand::random(), rand::random()]
    }

    /// Generate DUID-LLT (DUID based on Link-layer Address Plus Time)
    pub fn generate_duid_llt(hardware_type: u16, mac: [u8; 6]) -> Vec<u8> {
        let mut duid = Vec::new();
        duid.extend_from_slice(&1u16.to_be_bytes()); // DUID type: LLT
        duid.extend_from_slice(&hardware_type.to_be_bytes());

        // Time: seconds since midnight (UTC), January 1, 2000
        let time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
            - 946684800; // Seconds from 1970 to 2000
        duid.extend_from_slice(&(time as u32).to_be_bytes());

        duid.extend_from_slice(&mac);
        duid
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_solicit_encoding() {
        let duid = Dhcpv6Packet::generate_duid_llt(1, [0x11, 0x22, 0x33, 0x44, 0x55, 0x66]);
        let packet = Dhcpv6Packet::solicit([0x12, 0x34, 0x56], duid);
        let bytes = packet.to_bytes();

        assert_eq!(bytes[0], Dhcpv6MessageType::Solicit as u8);
        assert_eq!(&bytes[1..4], &[0x12, 0x34, 0x56]);

        let decoded = Dhcpv6Packet::from_bytes(&bytes).unwrap();
        assert_eq!(decoded.msg_type, Dhcpv6MessageType::Solicit);
        assert_eq!(decoded.transaction_id, [0x12, 0x34, 0x56]);
    }

    #[test]
    fn test_option_encoding() {
        let opt = Dhcpv6Option::elapsed_time(100);
        let bytes = opt.to_bytes();

        assert_eq!(u16::from_be_bytes([bytes[0], bytes[1]]), 8); // ElapsedTime option
        assert_eq!(u16::from_be_bytes([bytes[2], bytes[3]]), 2); // Length

        let (decoded, consumed) = Dhcpv6Option::from_bytes(&bytes).unwrap();
        assert_eq!(decoded.option_type, Dhcpv6OptionType::ElapsedTime);
        assert_eq!(consumed, 6);
    }

    #[test]
    fn test_duid_generation() {
        let duid = Dhcpv6Packet::generate_duid_llt(1, [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]);
        assert_eq!(u16::from_be_bytes([duid[0], duid[1]]), 1); // DUID type
        assert_eq!(duid.len(), 14); // 2 + 2 + 4 + 6
    }
}
