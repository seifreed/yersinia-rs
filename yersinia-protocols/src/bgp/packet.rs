//! BGP Packet Structures and Parsing

use std::net::Ipv4Addr;

pub const BGP_PORT: u16 = 179;
pub const BGP_VERSION: u8 = 4;
pub const BGP_HEADER_SIZE: usize = 19;
pub const BGP_MARKER: [u8; 16] = [0xFF; 16];

/// BGP Message Types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum BgpMessageType {
    Open = 1,
    Update = 2,
    Notification = 3,
    Keepalive = 4,
    RouteRefresh = 5, // RFC 2918
}

impl BgpMessageType {
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            1 => Some(Self::Open),
            2 => Some(Self::Update),
            3 => Some(Self::Notification),
            4 => Some(Self::Keepalive),
            5 => Some(Self::RouteRefresh),
            _ => None,
        }
    }
}

/// BGP Path Attribute Types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum BgpPathAttributeType {
    Origin = 1,
    AsPath = 2,
    NextHop = 3,
    MultiExitDisc = 4, // MED
    LocalPref = 5,
    AtomicAggregate = 6,
    Aggregator = 7,
    Communities = 8,          // RFC 1997
    OriginatorId = 9,         // RFC 4456
    ClusterList = 10,         // RFC 4456
    MpReachNlri = 14,         // RFC 4760 (Multiprotocol)
    MpUnreachNlri = 15,       // RFC 4760
    ExtendedCommunities = 16, // RFC 4360
    As4Path = 17,             // RFC 6793 (4-byte AS)
    As4Aggregator = 18,       // RFC 6793
    LargeCommunities = 32,    // RFC 8092
}

impl BgpPathAttributeType {
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            1 => Some(Self::Origin),
            2 => Some(Self::AsPath),
            3 => Some(Self::NextHop),
            4 => Some(Self::MultiExitDisc),
            5 => Some(Self::LocalPref),
            6 => Some(Self::AtomicAggregate),
            7 => Some(Self::Aggregator),
            8 => Some(Self::Communities),
            9 => Some(Self::OriginatorId),
            10 => Some(Self::ClusterList),
            14 => Some(Self::MpReachNlri),
            15 => Some(Self::MpUnreachNlri),
            16 => Some(Self::ExtendedCommunities),
            17 => Some(Self::As4Path),
            18 => Some(Self::As4Aggregator),
            32 => Some(Self::LargeCommunities),
            _ => None,
        }
    }
}

/// BGP Origin Codes
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum BgpOrigin {
    Igp = 0,        // Interior Gateway Protocol
    Egp = 1,        // Exterior Gateway Protocol
    Incomplete = 2, // Incomplete
}

/// BGP AS Path Segment Types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum BgpAsPathSegmentType {
    AsSet = 1,
    AsSequence = 2,
}

/// BGP Path Attribute
#[derive(Debug, Clone)]
pub struct BgpPathAttribute {
    pub flags: u8,
    pub type_code: BgpPathAttributeType,
    pub value: Vec<u8>,
}

impl BgpPathAttribute {
    pub fn new(type_code: BgpPathAttributeType, flags: u8, value: Vec<u8>) -> Self {
        Self {
            flags,
            type_code,
            value,
        }
    }

    /// Origin attribute
    pub fn origin(origin: BgpOrigin) -> Self {
        Self {
            flags: 0x40, // Well-known mandatory
            type_code: BgpPathAttributeType::Origin,
            value: vec![origin as u8],
        }
    }

    /// AS_PATH attribute (2-byte AS numbers)
    pub fn as_path(as_sequence: Vec<u16>) -> Self {
        let mut value = Vec::new();
        value.push(BgpAsPathSegmentType::AsSequence as u8);
        value.push(as_sequence.len() as u8);
        for as_num in as_sequence {
            value.extend_from_slice(&as_num.to_be_bytes());
        }
        Self {
            flags: 0x40, // Well-known mandatory
            type_code: BgpPathAttributeType::AsPath,
            value,
        }
    }

    /// AS4_PATH attribute (4-byte AS numbers)
    pub fn as4_path(as_sequence: Vec<u32>) -> Self {
        let mut value = Vec::new();
        value.push(BgpAsPathSegmentType::AsSequence as u8);
        value.push(as_sequence.len() as u8);
        for as_num in as_sequence {
            value.extend_from_slice(&as_num.to_be_bytes());
        }
        Self {
            flags: 0xC0, // Optional transitive
            type_code: BgpPathAttributeType::As4Path,
            value,
        }
    }

    /// NEXT_HOP attribute
    pub fn next_hop(ip: Ipv4Addr) -> Self {
        Self {
            flags: 0x40, // Well-known mandatory
            type_code: BgpPathAttributeType::NextHop,
            value: ip.octets().to_vec(),
        }
    }

    /// LOCAL_PREF attribute
    pub fn local_pref(pref: u32) -> Self {
        Self {
            flags: 0x40, // Well-known mandatory (iBGP only)
            type_code: BgpPathAttributeType::LocalPref,
            value: pref.to_be_bytes().to_vec(),
        }
    }

    /// MED (Multi-Exit Discriminator) attribute
    pub fn med(metric: u32) -> Self {
        Self {
            flags: 0x80, // Optional non-transitive
            type_code: BgpPathAttributeType::MultiExitDisc,
            value: metric.to_be_bytes().to_vec(),
        }
    }

    /// Communities attribute
    pub fn communities(communities: Vec<u32>) -> Self {
        let mut value = Vec::new();
        for community in communities {
            value.extend_from_slice(&community.to_be_bytes());
        }
        Self {
            flags: 0xC0, // Optional transitive
            type_code: BgpPathAttributeType::Communities,
            value,
        }
    }

    /// Encode attribute to bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.push(self.flags);
        bytes.push(self.type_code as u8);

        // Extended length flag (bit 4)
        if self.flags & 0x10 != 0 || self.value.len() > 255 {
            bytes.extend_from_slice(&(self.value.len() as u16).to_be_bytes());
        } else {
            bytes.push(self.value.len() as u8);
        }

        bytes.extend_from_slice(&self.value);
        bytes
    }

    /// Parse attribute from bytes
    pub fn from_bytes(data: &[u8]) -> Option<(Self, usize)> {
        if data.len() < 3 {
            return None;
        }

        let flags = data[0];
        let type_code = BgpPathAttributeType::from_u8(data[1])?;

        let (length, value_offset) = if flags & 0x10 != 0 {
            // Extended length
            if data.len() < 4 {
                return None;
            }
            (u16::from_be_bytes([data[2], data[3]]) as usize, 4)
        } else {
            (data[2] as usize, 3)
        };

        if data.len() < value_offset + length {
            return None;
        }

        let value = data[value_offset..value_offset + length].to_vec();
        Some((
            Self {
                flags,
                type_code,
                value,
            },
            value_offset + length,
        ))
    }
}

/// BGP OPEN Message
#[derive(Debug, Clone)]
pub struct BgpOpenMessage {
    pub version: u8,
    pub my_as: u16,
    pub hold_time: u16,
    pub bgp_identifier: Ipv4Addr,
    pub optional_parameters: Vec<u8>,
}

impl BgpOpenMessage {
    pub fn new(my_as: u16, bgp_identifier: Ipv4Addr) -> Self {
        Self {
            version: BGP_VERSION,
            my_as,
            hold_time: 180,
            bgp_identifier,
            optional_parameters: vec![],
        }
    }

    pub fn with_hold_time(mut self, hold_time: u16) -> Self {
        self.hold_time = hold_time;
        self
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.push(self.version);
        bytes.extend_from_slice(&self.my_as.to_be_bytes());
        bytes.extend_from_slice(&self.hold_time.to_be_bytes());
        bytes.extend_from_slice(&self.bgp_identifier.octets());
        bytes.push(self.optional_parameters.len() as u8);
        bytes.extend_from_slice(&self.optional_parameters);
        bytes
    }

    pub fn from_bytes(data: &[u8]) -> Option<Self> {
        if data.len() < 10 {
            return None;
        }

        let version = data[0];
        let my_as = u16::from_be_bytes([data[1], data[2]]);
        let hold_time = u16::from_be_bytes([data[3], data[4]]);
        let bgp_identifier = Ipv4Addr::new(data[5], data[6], data[7], data[8]);
        let opt_param_len = data[9] as usize;

        if data.len() < 10 + opt_param_len {
            return None;
        }

        let optional_parameters = data[10..10 + opt_param_len].to_vec();

        Some(Self {
            version,
            my_as,
            hold_time,
            bgp_identifier,
            optional_parameters,
        })
    }
}

/// BGP UPDATE Message
#[derive(Debug, Clone)]
pub struct BgpUpdateMessage {
    pub withdrawn_routes: Vec<(Ipv4Addr, u8)>, // (prefix, prefix_len)
    pub path_attributes: Vec<BgpPathAttribute>,
    pub nlri: Vec<(Ipv4Addr, u8)>, // Network Layer Reachability Info
}

impl Default for BgpUpdateMessage {
    fn default() -> Self {
        Self::new()
    }
}

impl BgpUpdateMessage {
    pub fn new() -> Self {
        Self {
            withdrawn_routes: vec![],
            path_attributes: vec![],
            nlri: vec![],
        }
    }

    pub fn with_nlri(mut self, prefix: Ipv4Addr, prefix_len: u8) -> Self {
        self.nlri.push((prefix, prefix_len));
        self
    }

    pub fn add_attribute(mut self, attr: BgpPathAttribute) -> Self {
        self.path_attributes.push(attr);
        self
    }

    pub fn with_withdrawn(mut self, prefix: Ipv4Addr, prefix_len: u8) -> Self {
        self.withdrawn_routes.push((prefix, prefix_len));
        self
    }

    fn encode_prefix(prefix: Ipv4Addr, prefix_len: u8) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.push(prefix_len);
        let octets_needed = prefix_len.div_ceil(8) as usize;
        bytes.extend_from_slice(&prefix.octets()[..octets_needed]);
        bytes
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();

        // Withdrawn routes
        let mut withdrawn_bytes = Vec::new();
        for (prefix, prefix_len) in &self.withdrawn_routes {
            withdrawn_bytes.extend_from_slice(&Self::encode_prefix(*prefix, *prefix_len));
        }
        bytes.extend_from_slice(&(withdrawn_bytes.len() as u16).to_be_bytes());
        bytes.extend_from_slice(&withdrawn_bytes);

        // Path attributes
        let mut attr_bytes = Vec::new();
        for attr in &self.path_attributes {
            attr_bytes.extend_from_slice(&attr.to_bytes());
        }
        bytes.extend_from_slice(&(attr_bytes.len() as u16).to_be_bytes());
        bytes.extend_from_slice(&attr_bytes);

        // NLRI
        for (prefix, prefix_len) in &self.nlri {
            bytes.extend_from_slice(&Self::encode_prefix(*prefix, *prefix_len));
        }

        bytes
    }
}

/// BGP NOTIFICATION Message
#[derive(Debug, Clone)]
pub struct BgpNotificationMessage {
    pub error_code: u8,
    pub error_subcode: u8,
    pub data: Vec<u8>,
}

impl BgpNotificationMessage {
    pub fn new(error_code: u8, error_subcode: u8) -> Self {
        Self {
            error_code,
            error_subcode,
            data: vec![],
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.push(self.error_code);
        bytes.push(self.error_subcode);
        bytes.extend_from_slice(&self.data);
        bytes
    }
}

/// BGP Packet (with header)
#[derive(Debug, Clone)]
pub struct BgpPacket {
    pub marker: [u8; 16],
    pub length: u16,
    pub message_type: BgpMessageType,
    pub payload: Vec<u8>,
}

impl BgpPacket {
    pub fn new(message_type: BgpMessageType, payload: Vec<u8>) -> Self {
        let length = (BGP_HEADER_SIZE + payload.len()) as u16;
        Self {
            marker: BGP_MARKER,
            length,
            message_type,
            payload,
        }
    }

    pub fn open(open_msg: BgpOpenMessage) -> Self {
        Self::new(BgpMessageType::Open, open_msg.to_bytes())
    }

    pub fn update(update_msg: BgpUpdateMessage) -> Self {
        Self::new(BgpMessageType::Update, update_msg.to_bytes())
    }

    pub fn keepalive() -> Self {
        Self::new(BgpMessageType::Keepalive, vec![])
    }

    pub fn notification(notif_msg: BgpNotificationMessage) -> Self {
        Self::new(BgpMessageType::Notification, notif_msg.to_bytes())
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&self.marker);
        bytes.extend_from_slice(&self.length.to_be_bytes());
        bytes.push(self.message_type as u8);
        bytes.extend_from_slice(&self.payload);
        bytes
    }

    pub fn from_bytes(data: &[u8]) -> Option<Self> {
        if data.len() < BGP_HEADER_SIZE {
            return None;
        }

        let mut marker = [0u8; 16];
        marker.copy_from_slice(&data[0..16]);
        let length = u16::from_be_bytes([data[16], data[17]]) as usize;
        let message_type = BgpMessageType::from_u8(data[18])?;

        if data.len() < length {
            return None;
        }

        let payload = data[BGP_HEADER_SIZE..length].to_vec();

        Some(Self {
            marker,
            length: length as u16,
            message_type,
            payload,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bgp_open() {
        let open = BgpOpenMessage::new(65001, "10.0.0.1".parse().unwrap());
        let bytes = open.to_bytes();

        assert_eq!(bytes[0], BGP_VERSION);
        assert_eq!(u16::from_be_bytes([bytes[1], bytes[2]]), 65001);

        let decoded = BgpOpenMessage::from_bytes(&bytes).unwrap();
        assert_eq!(decoded.my_as, 65001);
    }

    #[test]
    fn test_bgp_update() {
        let update = BgpUpdateMessage::new()
            .with_nlri("192.168.1.0".parse().unwrap(), 24)
            .add_attribute(BgpPathAttribute::origin(BgpOrigin::Igp))
            .add_attribute(BgpPathAttribute::next_hop("10.0.0.1".parse().unwrap()));

        let bytes = update.to_bytes();
        assert!(bytes.len() > 4); // At least headers
    }

    #[test]
    fn test_bgp_packet() {
        let packet = BgpPacket::keepalive();
        let bytes = packet.to_bytes();

        assert_eq!(bytes.len(), BGP_HEADER_SIZE);
        assert_eq!(&bytes[0..16], &BGP_MARKER);

        let decoded = BgpPacket::from_bytes(&bytes).unwrap();
        assert_eq!(decoded.message_type, BgpMessageType::Keepalive);
    }

    #[test]
    fn test_as_path_attribute() {
        let attr = BgpPathAttribute::as_path(vec![65001, 65002, 65003]);
        let bytes = attr.to_bytes();

        assert!(!bytes.is_empty());
        assert_eq!(bytes[1], BgpPathAttributeType::AsPath as u8);
    }
}
