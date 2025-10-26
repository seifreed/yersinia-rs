//! PPPoE Packet Structures

pub const PPPOE_DISCOVERY_ETHERTYPE: u16 = 0x8863;
pub const PPPOE_SESSION_ETHERTYPE: u16 = 0x8864;
pub const PPPOE_BROADCAST_MAC: [u8; 6] = [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF];

/// PPPoE Discovery/Session Codes
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum PppoeCode {
    /// PADI - PPPoE Active Discovery Initiation (client broadcast)
    PADI = 0x09,
    /// PADO - PPPoE Active Discovery Offer (server unicast)
    PADO = 0x07,
    /// PADR - PPPoE Active Discovery Request (client unicast)
    PADR = 0x19,
    /// PADS - PPPoE Active Discovery Session-confirmation (server unicast)
    PADS = 0x65,
    /// PADT - PPPoE Active Discovery Terminate (either party)
    PADT = 0xA7,
    /// Session data packet
    SessionData = 0x00,
}

impl PppoeCode {
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            0x09 => Some(Self::PADI),
            0x07 => Some(Self::PADO),
            0x19 => Some(Self::PADR),
            0x65 => Some(Self::PADS),
            0xA7 => Some(Self::PADT),
            0x00 => Some(Self::SessionData),
            _ => None,
        }
    }
}

/// PPPoE Tag Types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum PppoeTagType {
    EndOfList = 0x0000,
    ServiceName = 0x0101,
    ACName = 0x0102,   // Access Concentrator Name
    HostUniq = 0x0103, // Host unique identifier
    ACCookie = 0x0104,
    VendorSpecific = 0x0105,
    RelaySessionId = 0x0110,
    ServiceNameError = 0x0201,
    ACSystemError = 0x0202,
    GenericError = 0x0203,
}

impl PppoeTagType {
    pub fn from_u16(value: u16) -> Option<Self> {
        match value {
            0x0000 => Some(Self::EndOfList),
            0x0101 => Some(Self::ServiceName),
            0x0102 => Some(Self::ACName),
            0x0103 => Some(Self::HostUniq),
            0x0104 => Some(Self::ACCookie),
            0x0105 => Some(Self::VendorSpecific),
            0x0110 => Some(Self::RelaySessionId),
            0x0201 => Some(Self::ServiceNameError),
            0x0202 => Some(Self::ACSystemError),
            0x0203 => Some(Self::GenericError),
            _ => None,
        }
    }
}

/// PPPoE Tag (TLV structure)
#[derive(Debug, Clone)]
pub struct PppoeTag {
    pub tag_type: PppoeTagType,
    pub value: Vec<u8>,
}

impl PppoeTag {
    pub fn new(tag_type: PppoeTagType, value: Vec<u8>) -> Self {
        Self { tag_type, value }
    }

    pub fn service_name(name: &str) -> Self {
        Self {
            tag_type: PppoeTagType::ServiceName,
            value: name.as_bytes().to_vec(),
        }
    }

    pub fn ac_name(name: &str) -> Self {
        Self {
            tag_type: PppoeTagType::ACName,
            value: name.as_bytes().to_vec(),
        }
    }

    pub fn host_uniq(data: Vec<u8>) -> Self {
        Self {
            tag_type: PppoeTagType::HostUniq,
            value: data,
        }
    }

    pub fn ac_cookie(data: Vec<u8>) -> Self {
        Self {
            tag_type: PppoeTagType::ACCookie,
            value: data,
        }
    }

    pub fn end_of_list() -> Self {
        Self {
            tag_type: PppoeTagType::EndOfList,
            value: vec![],
        }
    }

    /// Encode tag to bytes (Type + Length + Value)
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&(self.tag_type as u16).to_be_bytes());
        bytes.extend_from_slice(&(self.value.len() as u16).to_be_bytes());
        bytes.extend_from_slice(&self.value);
        bytes
    }

    /// Parse tag from bytes
    pub fn from_bytes(data: &[u8]) -> Option<(Self, usize)> {
        if data.len() < 4 {
            return None;
        }

        let tag_type = u16::from_be_bytes([data[0], data[1]]);
        let length = u16::from_be_bytes([data[2], data[3]]) as usize;

        if data.len() < 4 + length {
            return None;
        }

        let tag_type = PppoeTagType::from_u16(tag_type)?;
        let value = data[4..4 + length].to_vec();

        Some((Self { tag_type, value }, 4 + length))
    }
}

/// PPPoE Packet
#[derive(Debug, Clone)]
pub struct PppoePacket {
    /// Version (always 1) and Type (always 1)
    pub version: u8,
    pub pppoe_type: u8,
    /// Code (PADI, PADO, PADR, PADS, PADT, or 0x00 for session)
    pub code: PppoeCode,
    /// Session ID (0x0000 for discovery, assigned for session)
    pub session_id: u16,
    /// Payload length
    pub length: u16,
    /// Tags (for discovery) or PPP payload (for session)
    pub tags: Vec<PppoeTag>,
    /// Session payload (for session packets)
    pub payload: Vec<u8>,
}

impl PppoePacket {
    /// Create new discovery packet
    pub fn new_discovery(code: PppoeCode, tags: Vec<PppoeTag>) -> Self {
        let length = tags.iter().map(|t| t.to_bytes().len()).sum::<usize>() as u16;
        Self {
            version: 1,
            pppoe_type: 1,
            code,
            session_id: 0x0000,
            length,
            tags,
            payload: vec![],
        }
    }

    /// Create new session packet
    pub fn new_session(session_id: u16, payload: Vec<u8>) -> Self {
        Self {
            version: 1,
            pppoe_type: 1,
            code: PppoeCode::SessionData,
            session_id,
            length: payload.len() as u16,
            tags: vec![],
            payload,
        }
    }

    /// Create PADI (initiation) packet
    pub fn padi(service_name: Option<&str>, host_uniq: Vec<u8>) -> Self {
        let mut tags = vec![PppoeTag::host_uniq(host_uniq)];
        if let Some(name) = service_name {
            tags.insert(0, PppoeTag::service_name(name));
        } else {
            tags.insert(0, PppoeTag::service_name(""));
        }
        Self::new_discovery(PppoeCode::PADI, tags)
    }

    /// Create PADO (offer) packet
    pub fn pado(service_name: &str, ac_name: &str, ac_cookie: Vec<u8>) -> Self {
        let tags = vec![
            PppoeTag::service_name(service_name),
            PppoeTag::ac_name(ac_name),
            PppoeTag::ac_cookie(ac_cookie),
        ];
        Self::new_discovery(PppoeCode::PADO, tags)
    }

    /// Create PADR (request) packet
    pub fn padr(service_name: &str, host_uniq: Vec<u8>, ac_cookie: Option<Vec<u8>>) -> Self {
        let mut tags = vec![
            PppoeTag::service_name(service_name),
            PppoeTag::host_uniq(host_uniq),
        ];
        if let Some(cookie) = ac_cookie {
            tags.push(PppoeTag::ac_cookie(cookie));
        }
        Self::new_discovery(PppoeCode::PADR, tags)
    }

    /// Create PADS (session confirmation) packet
    pub fn pads(session_id: u16, service_name: &str) -> Self {
        let mut packet =
            Self::new_discovery(PppoeCode::PADS, vec![PppoeTag::service_name(service_name)]);
        packet.session_id = session_id;
        packet
    }

    /// Create PADT (terminate) packet
    pub fn padt(session_id: u16) -> Self {
        let mut packet = Self::new_discovery(PppoeCode::PADT, vec![]);
        packet.session_id = session_id;
        packet.length = 0;
        packet
    }

    /// Encode packet to bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();

        // Version (4 bits) and Type (4 bits)
        bytes.push((self.version << 4) | self.pppoe_type);

        // Code
        bytes.push(self.code as u8);

        // Session ID
        bytes.extend_from_slice(&self.session_id.to_be_bytes());

        // Length
        bytes.extend_from_slice(&self.length.to_be_bytes());

        // Tags or payload
        if self.code == PppoeCode::SessionData {
            bytes.extend_from_slice(&self.payload);
        } else {
            for tag in &self.tags {
                bytes.extend_from_slice(&tag.to_bytes());
            }
        }

        bytes
    }

    /// Parse packet from bytes
    pub fn from_bytes(data: &[u8]) -> Option<Self> {
        if data.len() < 6 {
            return None;
        }

        let version = (data[0] >> 4) & 0x0F;
        let pppoe_type = data[0] & 0x0F;
        let code = PppoeCode::from_u8(data[1])?;
        let session_id = u16::from_be_bytes([data[2], data[3]]);
        let length = u16::from_be_bytes([data[4], data[5]]) as usize;

        if data.len() < 6 + length {
            return None;
        }

        let mut tags = vec![];
        let mut payload = vec![];

        if code == PppoeCode::SessionData {
            payload = data[6..6 + length].to_vec();
        } else {
            let mut offset = 6;
            while offset < 6 + length {
                if let Some((tag, consumed)) = PppoeTag::from_bytes(&data[offset..]) {
                    tags.push(tag);
                    offset += consumed;
                } else {
                    break;
                }
            }
        }

        Some(Self {
            version,
            pppoe_type,
            code,
            session_id,
            length: length as u16,
            tags,
            payload,
        })
    }

    /// Check if this is a discovery packet
    pub fn is_discovery(&self) -> bool {
        self.code != PppoeCode::SessionData
    }

    /// Check if this is a session packet
    pub fn is_session(&self) -> bool {
        self.code == PppoeCode::SessionData
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_padi_encoding() {
        let packet = PppoePacket::padi(Some("MyService"), vec![0x12, 0x34, 0x56, 0x78]);
        let bytes = packet.to_bytes();

        assert_eq!(bytes[0], 0x11); // version 1, type 1
        assert_eq!(bytes[1], 0x09); // PADI code
        assert_eq!(u16::from_be_bytes([bytes[2], bytes[3]]), 0x0000); // session ID 0

        let decoded = PppoePacket::from_bytes(&bytes).unwrap();
        assert_eq!(decoded.code, PppoeCode::PADI);
        assert_eq!(decoded.session_id, 0);
        assert_eq!(decoded.tags.len(), 2);
    }

    #[test]
    fn test_padt_encoding() {
        let packet = PppoePacket::padt(0x1234);
        let bytes = packet.to_bytes();

        assert_eq!(bytes[1], 0xA7); // PADT code
        assert_eq!(u16::from_be_bytes([bytes[2], bytes[3]]), 0x1234); // session ID

        let decoded = PppoePacket::from_bytes(&bytes).unwrap();
        assert_eq!(decoded.code, PppoeCode::PADT);
        assert_eq!(decoded.session_id, 0x1234);
    }

    #[test]
    fn test_tag_encoding() {
        let tag = PppoeTag::service_name("TestService");
        let bytes = tag.to_bytes();

        assert_eq!(u16::from_be_bytes([bytes[0], bytes[1]]), 0x0101);
        assert_eq!(u16::from_be_bytes([bytes[2], bytes[3]]), 11); // "TestService".len()

        let (decoded, consumed) = PppoeTag::from_bytes(&bytes).unwrap();
        assert_eq!(consumed, 4 + 11);
        assert_eq!(decoded.value, b"TestService");
    }
}
