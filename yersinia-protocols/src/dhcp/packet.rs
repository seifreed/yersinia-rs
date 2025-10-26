//! DHCP packet parsing and building
//!
//! This module implements complete DHCP packet parsing and construction
//! according to RFC 2131 and RFC 2132.

use std::fmt;
use std::net::Ipv4Addr;

/// DHCP magic cookie value (0x63825363)
pub const DHCP_MAGIC_COOKIE: u32 = 0x63825363;

/// DHCP server port
pub const DHCP_SERVER_PORT: u16 = 67;

/// DHCP client port
pub const DHCP_CLIENT_PORT: u16 = 68;

/// Broadcast flag value
pub const DHCP_BROADCAST_FLAG: u16 = 0x8000;

/// BOOTREQUEST opcode
pub const BOOTREQUEST: u8 = 1;

/// BOOTREPLY opcode
pub const BOOTREPLY: u8 = 2;

/// Ethernet hardware type
pub const HTYPE_ETHERNET: u8 = 1;

/// Ethernet hardware address length
pub const HLEN_ETHERNET: u8 = 6;

/// Maximum DHCP options size
pub const MAX_OPTIONS_SIZE: usize = 312;

/// DHCP Message Types (RFC 2132)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DhcpMessageType {
    Discover = 1,
    Offer = 2,
    Request = 3,
    Decline = 4,
    Ack = 5,
    Nak = 6,
    Release = 7,
    Inform = 8,
}

impl DhcpMessageType {
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            1 => Some(DhcpMessageType::Discover),
            2 => Some(DhcpMessageType::Offer),
            3 => Some(DhcpMessageType::Request),
            4 => Some(DhcpMessageType::Decline),
            5 => Some(DhcpMessageType::Ack),
            6 => Some(DhcpMessageType::Nak),
            7 => Some(DhcpMessageType::Release),
            8 => Some(DhcpMessageType::Inform),
            _ => None,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            DhcpMessageType::Discover => "DISCOVER",
            DhcpMessageType::Offer => "OFFER",
            DhcpMessageType::Request => "REQUEST",
            DhcpMessageType::Decline => "DECLINE",
            DhcpMessageType::Ack => "ACK",
            DhcpMessageType::Nak => "NAK",
            DhcpMessageType::Release => "RELEASE",
            DhcpMessageType::Inform => "INFORM",
        }
    }
}

impl fmt::Display for DhcpMessageType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// DHCP Option Codes (RFC 2132)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OptionCode {
    Pad = 0,
    SubnetMask = 1,
    Router = 3,
    DnsServer = 6,
    Hostname = 12,
    DomainName = 15,
    RequestedIpAddress = 50,
    LeaseTime = 51,
    MessageType = 53,
    ServerId = 54,
    ParameterRequestList = 55,
    Message = 56,
    RenewalTime = 58,
    RebindingTime = 59,
    ClientIdentifier = 61,
    End = 255,
}

impl OptionCode {
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            0 => Some(OptionCode::Pad),
            1 => Some(OptionCode::SubnetMask),
            3 => Some(OptionCode::Router),
            6 => Some(OptionCode::DnsServer),
            12 => Some(OptionCode::Hostname),
            15 => Some(OptionCode::DomainName),
            50 => Some(OptionCode::RequestedIpAddress),
            51 => Some(OptionCode::LeaseTime),
            53 => Some(OptionCode::MessageType),
            54 => Some(OptionCode::ServerId),
            55 => Some(OptionCode::ParameterRequestList),
            56 => Some(OptionCode::Message),
            58 => Some(OptionCode::RenewalTime),
            59 => Some(OptionCode::RebindingTime),
            61 => Some(OptionCode::ClientIdentifier),
            255 => Some(OptionCode::End),
            _ => None,
        }
    }
}

/// DHCP Option
#[derive(Debug, Clone, PartialEq)]
pub enum DhcpOption {
    Pad,
    SubnetMask(Ipv4Addr),
    Router(Vec<Ipv4Addr>),
    DnsServer(Vec<Ipv4Addr>),
    Hostname(String),
    DomainName(String),
    RequestedIpAddress(Ipv4Addr),
    LeaseTime(u32),
    MessageType(DhcpMessageType),
    ServerId(Ipv4Addr),
    ParameterRequestList(Vec<u8>),
    Message(String),
    RenewalTime(u32),
    RebindingTime(u32),
    ClientIdentifier(Vec<u8>),
    End,
    Unknown(u8, Vec<u8>),
}

impl DhcpOption {
    /// Parse a DHCP option from bytes
    pub fn parse(code: u8, data: &[u8]) -> Result<Self, String> {
        match code {
            0 => Ok(DhcpOption::Pad),
            1 => {
                if data.len() != 4 {
                    return Err("SubnetMask must be 4 bytes".to_string());
                }
                Ok(DhcpOption::SubnetMask(Ipv4Addr::new(
                    data[0], data[1], data[2], data[3],
                )))
            }
            3 => {
                if data.len() % 4 != 0 {
                    return Err("Router addresses must be multiples of 4 bytes".to_string());
                }
                let addrs = data
                    .chunks(4)
                    .map(|chunk| Ipv4Addr::new(chunk[0], chunk[1], chunk[2], chunk[3]))
                    .collect();
                Ok(DhcpOption::Router(addrs))
            }
            6 => {
                if data.len() % 4 != 0 {
                    return Err("DNS addresses must be multiples of 4 bytes".to_string());
                }
                let addrs = data
                    .chunks(4)
                    .map(|chunk| Ipv4Addr::new(chunk[0], chunk[1], chunk[2], chunk[3]))
                    .collect();
                Ok(DhcpOption::DnsServer(addrs))
            }
            12 => Ok(DhcpOption::Hostname(
                String::from_utf8_lossy(data).to_string(),
            )),
            15 => Ok(DhcpOption::DomainName(
                String::from_utf8_lossy(data).to_string(),
            )),
            50 => {
                if data.len() != 4 {
                    return Err("RequestedIpAddress must be 4 bytes".to_string());
                }
                Ok(DhcpOption::RequestedIpAddress(Ipv4Addr::new(
                    data[0], data[1], data[2], data[3],
                )))
            }
            51 => {
                if data.len() != 4 {
                    return Err("LeaseTime must be 4 bytes".to_string());
                }
                let time = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
                Ok(DhcpOption::LeaseTime(time))
            }
            53 => {
                if data.len() != 1 {
                    return Err("MessageType must be 1 byte".to_string());
                }
                let msg_type = DhcpMessageType::from_u8(data[0])
                    .ok_or_else(|| format!("Invalid message type: {}", data[0]))?;
                Ok(DhcpOption::MessageType(msg_type))
            }
            54 => {
                if data.len() != 4 {
                    return Err("ServerId must be 4 bytes".to_string());
                }
                Ok(DhcpOption::ServerId(Ipv4Addr::new(
                    data[0], data[1], data[2], data[3],
                )))
            }
            55 => Ok(DhcpOption::ParameterRequestList(data.to_vec())),
            56 => Ok(DhcpOption::Message(
                String::from_utf8_lossy(data).to_string(),
            )),
            58 => {
                if data.len() != 4 {
                    return Err("RenewalTime must be 4 bytes".to_string());
                }
                let time = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
                Ok(DhcpOption::RenewalTime(time))
            }
            59 => {
                if data.len() != 4 {
                    return Err("RebindingTime must be 4 bytes".to_string());
                }
                let time = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
                Ok(DhcpOption::RebindingTime(time))
            }
            61 => Ok(DhcpOption::ClientIdentifier(data.to_vec())),
            255 => Ok(DhcpOption::End),
            _ => Ok(DhcpOption::Unknown(code, data.to_vec())),
        }
    }

    /// Build a DHCP option into bytes
    pub fn build(&self) -> Vec<u8> {
        match self {
            DhcpOption::Pad => vec![0],
            DhcpOption::End => vec![255],
            DhcpOption::SubnetMask(addr) => {
                let mut bytes = vec![1, 4];
                bytes.extend_from_slice(&addr.octets());
                bytes
            }
            DhcpOption::Router(addrs) => {
                let mut bytes = vec![3, (addrs.len() * 4) as u8];
                for addr in addrs {
                    bytes.extend_from_slice(&addr.octets());
                }
                bytes
            }
            DhcpOption::DnsServer(addrs) => {
                let mut bytes = vec![6, (addrs.len() * 4) as u8];
                for addr in addrs {
                    bytes.extend_from_slice(&addr.octets());
                }
                bytes
            }
            DhcpOption::Hostname(name) => {
                let mut bytes = vec![12, name.len() as u8];
                bytes.extend_from_slice(name.as_bytes());
                bytes
            }
            DhcpOption::DomainName(name) => {
                let mut bytes = vec![15, name.len() as u8];
                bytes.extend_from_slice(name.as_bytes());
                bytes
            }
            DhcpOption::RequestedIpAddress(addr) => {
                let mut bytes = vec![50, 4];
                bytes.extend_from_slice(&addr.octets());
                bytes
            }
            DhcpOption::LeaseTime(time) => {
                let mut bytes = vec![51, 4];
                bytes.extend_from_slice(&time.to_be_bytes());
                bytes
            }
            DhcpOption::MessageType(msg_type) => vec![53, 1, *msg_type as u8],
            DhcpOption::ServerId(addr) => {
                let mut bytes = vec![54, 4];
                bytes.extend_from_slice(&addr.octets());
                bytes
            }
            DhcpOption::ParameterRequestList(params) => {
                let mut bytes = vec![55, params.len() as u8];
                bytes.extend_from_slice(params);
                bytes
            }
            DhcpOption::Message(msg) => {
                let mut bytes = vec![56, msg.len() as u8];
                bytes.extend_from_slice(msg.as_bytes());
                bytes
            }
            DhcpOption::RenewalTime(time) => {
                let mut bytes = vec![58, 4];
                bytes.extend_from_slice(&time.to_be_bytes());
                bytes
            }
            DhcpOption::RebindingTime(time) => {
                let mut bytes = vec![59, 4];
                bytes.extend_from_slice(&time.to_be_bytes());
                bytes
            }
            DhcpOption::ClientIdentifier(id) => {
                let mut bytes = vec![61, id.len() as u8];
                bytes.extend_from_slice(id);
                bytes
            }
            DhcpOption::Unknown(code, data) => {
                let mut bytes = vec![*code, data.len() as u8];
                bytes.extend_from_slice(data);
                bytes
            }
        }
    }

    pub fn code(&self) -> u8 {
        match self {
            DhcpOption::Pad => 0,
            DhcpOption::SubnetMask(_) => 1,
            DhcpOption::Router(_) => 3,
            DhcpOption::DnsServer(_) => 6,
            DhcpOption::Hostname(_) => 12,
            DhcpOption::DomainName(_) => 15,
            DhcpOption::RequestedIpAddress(_) => 50,
            DhcpOption::LeaseTime(_) => 51,
            DhcpOption::MessageType(_) => 53,
            DhcpOption::ServerId(_) => 54,
            DhcpOption::ParameterRequestList(_) => 55,
            DhcpOption::Message(_) => 56,
            DhcpOption::RenewalTime(_) => 58,
            DhcpOption::RebindingTime(_) => 59,
            DhcpOption::ClientIdentifier(_) => 61,
            DhcpOption::End => 255,
            DhcpOption::Unknown(code, _) => *code,
        }
    }
}

/// DHCP Packet structure (RFC 2131)
#[derive(Debug, Clone, PartialEq)]
pub struct DhcpPacket {
    /// Message op code / message type (1 = BOOTREQUEST, 2 = BOOTREPLY)
    pub op: u8,
    /// Hardware address type (1 = Ethernet)
    pub htype: u8,
    /// Hardware address length (6 for Ethernet)
    pub hlen: u8,
    /// Hops
    pub hops: u8,
    /// Transaction ID
    pub xid: u32,
    /// Seconds elapsed since client began address acquisition
    pub secs: u16,
    /// Flags (broadcast bit)
    pub flags: u16,
    /// Client IP address (if known)
    pub ciaddr: Ipv4Addr,
    /// Your (client) IP address
    pub yiaddr: Ipv4Addr,
    /// Server IP address
    pub siaddr: Ipv4Addr,
    /// Gateway IP address
    pub giaddr: Ipv4Addr,
    /// Client hardware address (16 bytes, but only first hlen bytes used)
    pub chaddr: [u8; 16],
    /// Server host name (64 bytes)
    pub sname: [u8; 64],
    /// Boot file name (128 bytes)
    pub file: [u8; 128],
    /// Magic cookie (0x63825363)
    pub magic_cookie: u32,
    /// DHCP options
    pub options: Vec<DhcpOption>,
}

impl DhcpPacket {
    /// Create a new DHCP packet with default values
    pub fn new() -> Self {
        Self {
            op: BOOTREQUEST,
            htype: HTYPE_ETHERNET,
            hlen: HLEN_ETHERNET,
            hops: 0,
            xid: 0,
            secs: 0,
            flags: 0,
            ciaddr: Ipv4Addr::UNSPECIFIED,
            yiaddr: Ipv4Addr::UNSPECIFIED,
            siaddr: Ipv4Addr::UNSPECIFIED,
            giaddr: Ipv4Addr::UNSPECIFIED,
            chaddr: [0; 16],
            sname: [0; 64],
            file: [0; 128],
            magic_cookie: DHCP_MAGIC_COOKIE,
            options: Vec::new(),
        }
    }

    /// Create a DHCP DISCOVER packet
    pub fn new_discover(xid: u32, chaddr: [u8; 6]) -> Self {
        let mut packet = Self::new();
        packet.op = BOOTREQUEST;
        packet.xid = xid;
        packet.flags = DHCP_BROADCAST_FLAG;
        packet.chaddr[..6].copy_from_slice(&chaddr);
        packet.options = vec![
            DhcpOption::MessageType(DhcpMessageType::Discover),
            DhcpOption::End,
        ];
        packet
    }

    /// Create a DHCP REQUEST packet
    pub fn new_request(
        xid: u32,
        chaddr: [u8; 6],
        requested_ip: Ipv4Addr,
        server_id: Ipv4Addr,
    ) -> Self {
        let mut packet = Self::new();
        packet.op = BOOTREQUEST;
        packet.xid = xid;
        packet.flags = DHCP_BROADCAST_FLAG;
        packet.chaddr[..6].copy_from_slice(&chaddr);
        packet.options = vec![
            DhcpOption::MessageType(DhcpMessageType::Request),
            DhcpOption::RequestedIpAddress(requested_ip),
            DhcpOption::ServerId(server_id),
            DhcpOption::End,
        ];
        packet
    }

    /// Create a DHCP RELEASE packet
    pub fn new_release(
        xid: u32,
        chaddr: [u8; 6],
        client_ip: Ipv4Addr,
        server_id: Ipv4Addr,
    ) -> Self {
        let mut packet = Self::new();
        packet.op = BOOTREQUEST;
        packet.xid = xid;
        packet.ciaddr = client_ip;
        packet.chaddr[..6].copy_from_slice(&chaddr);
        packet.options = vec![
            DhcpOption::MessageType(DhcpMessageType::Release),
            DhcpOption::ServerId(server_id),
            DhcpOption::End,
        ];
        packet
    }

    /// Create a DHCP INFORM packet
    pub fn new_inform(xid: u32, chaddr: [u8; 6], client_ip: Ipv4Addr) -> Self {
        let mut packet = Self::new();
        packet.op = BOOTREQUEST;
        packet.xid = xid;
        packet.ciaddr = client_ip;
        packet.chaddr[..6].copy_from_slice(&chaddr);
        packet.options = vec![
            DhcpOption::MessageType(DhcpMessageType::Inform),
            DhcpOption::End,
        ];
        packet
    }

    /// Parse a DHCP packet from bytes
    pub fn parse(data: &[u8]) -> Result<Self, String> {
        if data.len() < 236 {
            return Err(format!(
                "DHCP packet too short: {} bytes (minimum 236)",
                data.len()
            ));
        }

        let op = data[0];
        let htype = data[1];
        let hlen = data[2];
        let hops = data[3];

        let xid = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
        let secs = u16::from_be_bytes([data[8], data[9]]);
        let flags = u16::from_be_bytes([data[10], data[11]]);

        let ciaddr = Ipv4Addr::new(data[12], data[13], data[14], data[15]);
        let yiaddr = Ipv4Addr::new(data[16], data[17], data[18], data[19]);
        let siaddr = Ipv4Addr::new(data[20], data[21], data[22], data[23]);
        let giaddr = Ipv4Addr::new(data[24], data[25], data[26], data[27]);

        let mut chaddr = [0u8; 16];
        chaddr.copy_from_slice(&data[28..44]);

        let mut sname = [0u8; 64];
        sname.copy_from_slice(&data[44..108]);

        let mut file = [0u8; 128];
        file.copy_from_slice(&data[108..236]);

        let magic_cookie = if data.len() >= 240 {
            u32::from_be_bytes([data[236], data[237], data[238], data[239]])
        } else {
            DHCP_MAGIC_COOKIE
        };

        // Parse options
        let mut options = Vec::new();
        let mut offset = 240;

        while offset < data.len() {
            let code = data[offset];
            offset += 1;

            if code == 0 {
                // Pad
                options.push(DhcpOption::Pad);
                continue;
            }

            if code == 255 {
                // End
                options.push(DhcpOption::End);
                break;
            }

            if offset >= data.len() {
                break;
            }

            let length = data[offset] as usize;
            offset += 1;

            if offset + length > data.len() {
                return Err(format!(
                    "Option {} length {} exceeds packet size",
                    code, length
                ));
            }

            let option_data = &data[offset..offset + length];
            offset += length;

            match DhcpOption::parse(code, option_data) {
                Ok(option) => options.push(option),
                Err(e) => {
                    // Continue parsing even if one option fails
                    eprintln!("Warning: Failed to parse option {}: {}", code, e);
                }
            }
        }

        Ok(Self {
            op,
            htype,
            hlen,
            hops,
            xid,
            secs,
            flags,
            ciaddr,
            yiaddr,
            siaddr,
            giaddr,
            chaddr,
            sname,
            file,
            magic_cookie,
            options,
        })
    }

    /// Build a DHCP packet into bytes
    pub fn build(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(576); // Minimum DHCP packet size

        // Fixed header (236 bytes)
        bytes.push(self.op);
        bytes.push(self.htype);
        bytes.push(self.hlen);
        bytes.push(self.hops);

        bytes.extend_from_slice(&self.xid.to_be_bytes());
        bytes.extend_from_slice(&self.secs.to_be_bytes());
        bytes.extend_from_slice(&self.flags.to_be_bytes());

        bytes.extend_from_slice(&self.ciaddr.octets());
        bytes.extend_from_slice(&self.yiaddr.octets());
        bytes.extend_from_slice(&self.siaddr.octets());
        bytes.extend_from_slice(&self.giaddr.octets());

        bytes.extend_from_slice(&self.chaddr);
        bytes.extend_from_slice(&self.sname);
        bytes.extend_from_slice(&self.file);

        // Magic cookie
        bytes.extend_from_slice(&self.magic_cookie.to_be_bytes());

        // Options
        for option in &self.options {
            bytes.extend_from_slice(&option.build());
        }

        // Ensure End option is present
        if !self.options.iter().any(|o| matches!(o, DhcpOption::End)) {
            bytes.push(255); // End option
        }

        bytes
    }

    /// Get the message type from options
    pub fn message_type(&self) -> Option<DhcpMessageType> {
        self.options.iter().find_map(|opt| {
            if let DhcpOption::MessageType(msg_type) = opt {
                Some(*msg_type)
            } else {
                None
            }
        })
    }

    /// Get server ID from options
    pub fn server_id(&self) -> Option<Ipv4Addr> {
        self.options.iter().find_map(|opt| {
            if let DhcpOption::ServerId(addr) = opt {
                Some(*addr)
            } else {
                None
            }
        })
    }

    /// Get requested IP from options
    pub fn requested_ip(&self) -> Option<Ipv4Addr> {
        self.options.iter().find_map(|opt| {
            if let DhcpOption::RequestedIpAddress(addr) = opt {
                Some(*addr)
            } else {
                None
            }
        })
    }

    /// Get lease time from options
    pub fn lease_time(&self) -> Option<u32> {
        self.options.iter().find_map(|opt| {
            if let DhcpOption::LeaseTime(time) = opt {
                Some(*time)
            } else {
                None
            }
        })
    }

    /// Get client MAC address
    pub fn client_mac(&self) -> [u8; 6] {
        let mut mac = [0u8; 6];
        mac.copy_from_slice(&self.chaddr[..6]);
        mac
    }
}

impl Default for DhcpPacket {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dhcp_message_type_conversion() {
        assert_eq!(DhcpMessageType::from_u8(1), Some(DhcpMessageType::Discover));
        assert_eq!(DhcpMessageType::from_u8(2), Some(DhcpMessageType::Offer));
        assert_eq!(DhcpMessageType::from_u8(3), Some(DhcpMessageType::Request));
        assert_eq!(DhcpMessageType::from_u8(7), Some(DhcpMessageType::Release));
        assert_eq!(DhcpMessageType::from_u8(99), None);
    }

    #[test]
    fn test_dhcp_message_type_display() {
        assert_eq!(DhcpMessageType::Discover.to_string(), "DISCOVER");
        assert_eq!(DhcpMessageType::Offer.to_string(), "OFFER");
        assert_eq!(DhcpMessageType::Release.to_string(), "RELEASE");
    }

    #[test]
    fn test_option_code_from_u8() {
        assert_eq!(OptionCode::from_u8(0), Some(OptionCode::Pad));
        assert_eq!(OptionCode::from_u8(53), Some(OptionCode::MessageType));
        assert_eq!(OptionCode::from_u8(54), Some(OptionCode::ServerId));
        assert_eq!(OptionCode::from_u8(255), Some(OptionCode::End));
        assert_eq!(OptionCode::from_u8(200), None);
    }

    #[test]
    fn test_option_parse_message_type() {
        let data = [1u8]; // DISCOVER
        let option = DhcpOption::parse(53, &data).unwrap();
        assert_eq!(option, DhcpOption::MessageType(DhcpMessageType::Discover));
    }

    #[test]
    fn test_option_parse_server_id() {
        let data = [192, 168, 1, 1];
        let option = DhcpOption::parse(54, &data).unwrap();
        assert_eq!(option, DhcpOption::ServerId(Ipv4Addr::new(192, 168, 1, 1)));
    }

    #[test]
    fn test_option_parse_lease_time() {
        let data = [0x00, 0x01, 0x51, 0x80]; // 86400 seconds (1 day)
        let option = DhcpOption::parse(51, &data).unwrap();
        assert_eq!(option, DhcpOption::LeaseTime(86400));
    }

    #[test]
    fn test_option_parse_hostname() {
        let data = b"testhost";
        let option = DhcpOption::parse(12, data).unwrap();
        assert_eq!(option, DhcpOption::Hostname("testhost".to_string()));
    }

    #[test]
    fn test_option_build_message_type() {
        let option = DhcpOption::MessageType(DhcpMessageType::Discover);
        let bytes = option.build();
        assert_eq!(bytes, vec![53, 1, 1]);
    }

    #[test]
    fn test_option_build_server_id() {
        let option = DhcpOption::ServerId(Ipv4Addr::new(192, 168, 1, 1));
        let bytes = option.build();
        assert_eq!(bytes, vec![54, 4, 192, 168, 1, 1]);
    }

    #[test]
    fn test_option_build_lease_time() {
        let option = DhcpOption::LeaseTime(86400);
        let bytes = option.build();
        assert_eq!(bytes, vec![51, 4, 0x00, 0x01, 0x51, 0x80]);
    }

    #[test]
    fn test_option_build_end() {
        let option = DhcpOption::End;
        let bytes = option.build();
        assert_eq!(bytes, vec![255]);
    }

    #[test]
    fn test_dhcp_packet_new() {
        let packet = DhcpPacket::new();
        assert_eq!(packet.op, BOOTREQUEST);
        assert_eq!(packet.htype, HTYPE_ETHERNET);
        assert_eq!(packet.hlen, HLEN_ETHERNET);
        assert_eq!(packet.magic_cookie, DHCP_MAGIC_COOKIE);
    }

    #[test]
    fn test_dhcp_packet_new_discover() {
        let mac = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66];
        let packet = DhcpPacket::new_discover(0x12345678, mac);

        assert_eq!(packet.op, BOOTREQUEST);
        assert_eq!(packet.xid, 0x12345678);
        assert_eq!(packet.flags, DHCP_BROADCAST_FLAG);
        assert_eq!(&packet.chaddr[..6], &mac);
        assert_eq!(packet.message_type(), Some(DhcpMessageType::Discover));
    }

    #[test]
    fn test_dhcp_packet_new_request() {
        let mac = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66];
        let requested = Ipv4Addr::new(192, 168, 1, 100);
        let server = Ipv4Addr::new(192, 168, 1, 1);
        let packet = DhcpPacket::new_request(0x12345678, mac, requested, server);

        assert_eq!(packet.op, BOOTREQUEST);
        assert_eq!(packet.xid, 0x12345678);
        assert_eq!(packet.message_type(), Some(DhcpMessageType::Request));
        assert_eq!(packet.requested_ip(), Some(requested));
        assert_eq!(packet.server_id(), Some(server));
    }

    #[test]
    fn test_dhcp_packet_new_release() {
        let mac = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66];
        let client_ip = Ipv4Addr::new(192, 168, 1, 100);
        let server = Ipv4Addr::new(192, 168, 1, 1);
        let packet = DhcpPacket::new_release(0x12345678, mac, client_ip, server);

        assert_eq!(packet.op, BOOTREQUEST);
        assert_eq!(packet.xid, 0x12345678);
        assert_eq!(packet.ciaddr, client_ip);
        assert_eq!(packet.message_type(), Some(DhcpMessageType::Release));
        assert_eq!(packet.server_id(), Some(server));
    }

    #[test]
    fn test_dhcp_packet_build_and_parse() {
        let mac = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66];
        let original = DhcpPacket::new_discover(0x12345678, mac);
        let bytes = original.build();

        let parsed = DhcpPacket::parse(&bytes).unwrap();

        assert_eq!(parsed.op, original.op);
        assert_eq!(parsed.xid, original.xid);
        assert_eq!(parsed.flags, original.flags);
        assert_eq!(&parsed.chaddr[..6], &mac);
        assert_eq!(parsed.magic_cookie, DHCP_MAGIC_COOKIE);
        assert_eq!(parsed.message_type(), Some(DhcpMessageType::Discover));
    }

    #[test]
    fn test_dhcp_packet_parse_too_short() {
        let data = vec![0u8; 100]; // Too short
        let result = DhcpPacket::parse(&data);
        assert!(result.is_err());
    }

    #[test]
    fn test_dhcp_packet_client_mac() {
        let mac = [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF];
        let packet = DhcpPacket::new_discover(0x12345678, mac);
        assert_eq!(packet.client_mac(), mac);
    }

    #[test]
    fn test_dhcp_packet_with_multiple_options() {
        let mut packet = DhcpPacket::new();
        packet.options = vec![
            DhcpOption::MessageType(DhcpMessageType::Request),
            DhcpOption::RequestedIpAddress(Ipv4Addr::new(192, 168, 1, 100)),
            DhcpOption::ServerId(Ipv4Addr::new(192, 168, 1, 1)),
            DhcpOption::Hostname("testhost".to_string()),
            DhcpOption::End,
        ];

        let bytes = packet.build();
        let parsed = DhcpPacket::parse(&bytes).unwrap();

        assert_eq!(parsed.message_type(), Some(DhcpMessageType::Request));
        assert_eq!(parsed.requested_ip(), Some(Ipv4Addr::new(192, 168, 1, 100)));
        assert_eq!(parsed.server_id(), Some(Ipv4Addr::new(192, 168, 1, 1)));
    }

    #[test]
    fn test_option_parse_router() {
        let data = [192, 168, 1, 1];
        let option = DhcpOption::parse(3, &data).unwrap();
        assert_eq!(
            option,
            DhcpOption::Router(vec![Ipv4Addr::new(192, 168, 1, 1)])
        );
    }

    #[test]
    fn test_option_parse_dns() {
        let data = [8, 8, 8, 8, 8, 8, 4, 4];
        let option = DhcpOption::parse(6, &data).unwrap();
        assert_eq!(
            option,
            DhcpOption::DnsServer(vec![Ipv4Addr::new(8, 8, 8, 8), Ipv4Addr::new(8, 8, 4, 4)])
        );
    }

    #[test]
    fn test_option_build_router() {
        let option = DhcpOption::Router(vec![Ipv4Addr::new(192, 168, 1, 1)]);
        let bytes = option.build();
        assert_eq!(bytes, vec![3, 4, 192, 168, 1, 1]);
    }

    #[test]
    fn test_option_build_hostname() {
        let option = DhcpOption::Hostname("test".to_string());
        let bytes = option.build();
        assert_eq!(bytes, vec![12, 4, b't', b'e', b's', b't']);
    }

    #[test]
    fn test_dhcp_constants() {
        assert_eq!(DHCP_MAGIC_COOKIE, 0x63825363);
        assert_eq!(DHCP_SERVER_PORT, 67);
        assert_eq!(DHCP_CLIENT_PORT, 68);
        assert_eq!(DHCP_BROADCAST_FLAG, 0x8000);
        assert_eq!(BOOTREQUEST, 1);
        assert_eq!(BOOTREPLY, 2);
        assert_eq!(HTYPE_ETHERNET, 1);
        assert_eq!(HLEN_ETHERNET, 6);
    }

    #[test]
    fn test_option_code() {
        assert_eq!(DhcpOption::Pad.code(), 0);
        assert_eq!(
            DhcpOption::MessageType(DhcpMessageType::Discover).code(),
            53
        );
        assert_eq!(
            DhcpOption::ServerId(Ipv4Addr::new(192, 168, 1, 1)).code(),
            54
        );
        assert_eq!(DhcpOption::End.code(), 255);
    }

    #[test]
    fn test_dhcp_packet_new_inform() {
        let mac = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66];
        let client_ip = Ipv4Addr::new(192, 168, 1, 100);
        let packet = DhcpPacket::new_inform(0x12345678, mac, client_ip);

        assert_eq!(packet.op, BOOTREQUEST);
        assert_eq!(packet.ciaddr, client_ip);
        assert_eq!(packet.message_type(), Some(DhcpMessageType::Inform));
    }
}
