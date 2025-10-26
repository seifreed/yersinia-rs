//! EAPOL and EAP Packet Structures
//!
//! This module implements parsing and building of 802.1X EAPOL and EAP packets.
//!
//! ## EAPOL Frame Structure
//!
//! ```text
//! +------------------+
//! | Protocol Version | 1 byte
//! +------------------+
//! | Packet Type      | 1 byte
//! +------------------+
//! | Body Length      | 2 bytes (network order)
//! +------------------+
//! | Body             | Variable (0-65535 bytes)
//! +------------------+
//! ```
//!
//! ## EAP Packet Structure (when EAPOL Type = EAP-Packet)
//!
//! ```text
//! +------------------+
//! | Code             | 1 byte
//! +------------------+
//! | Identifier       | 1 byte
//! +------------------+
//! | Length           | 2 bytes (network order)
//! +------------------+
//! | Type             | 1 byte (optional, for Request/Response)
//! +------------------+
//! | Data             | Variable (optional)
//! +------------------+
//! ```

use yersinia_core::{Error, Result};

use super::constants::*;

/// EAPOL Packet Type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EapolType {
    /// EAP-Packet (contains EAP frame)
    EapPacket,
    /// EAPOL-Start (supplicant initiates)
    Start,
    /// EAPOL-Logoff
    Logoff,
    /// EAPOL-Key (WPA/WPA2)
    Key,
    /// EAPOL-Encapsulated-ASF-Alert
    AsfAlert,
}

impl EapolType {
    /// Convert to byte value
    pub fn to_byte(&self) -> u8 {
        match self {
            EapolType::EapPacket => EAPOL_TYPE_EAP_PACKET,
            EapolType::Start => EAPOL_TYPE_START,
            EapolType::Logoff => EAPOL_TYPE_LOGOFF,
            EapolType::Key => EAPOL_TYPE_KEY,
            EapolType::AsfAlert => EAPOL_TYPE_ASF_ALERT,
        }
    }

    /// Parse from byte value
    pub fn from_byte(byte: u8) -> Result<Self> {
        match byte {
            EAPOL_TYPE_EAP_PACKET => Ok(EapolType::EapPacket),
            EAPOL_TYPE_START => Ok(EapolType::Start),
            EAPOL_TYPE_LOGOFF => Ok(EapolType::Logoff),
            EAPOL_TYPE_KEY => Ok(EapolType::Key),
            EAPOL_TYPE_ASF_ALERT => Ok(EapolType::AsfAlert),
            _ => Err(Error::protocol(format!(
                "Unknown EAPOL type: 0x{:02x}",
                byte
            ))),
        }
    }
}

/// EAP Code
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EapCode {
    /// EAP Request
    Request,
    /// EAP Response
    Response,
    /// EAP Success
    Success,
    /// EAP Failure
    Failure,
}

impl EapCode {
    /// Convert to byte value
    pub fn to_byte(&self) -> u8 {
        match self {
            EapCode::Request => EAP_CODE_REQUEST,
            EapCode::Response => EAP_CODE_RESPONSE,
            EapCode::Success => EAP_CODE_SUCCESS,
            EapCode::Failure => EAP_CODE_FAILURE,
        }
    }

    /// Parse from byte value
    pub fn from_byte(byte: u8) -> Result<Self> {
        match byte {
            EAP_CODE_REQUEST => Ok(EapCode::Request),
            EAP_CODE_RESPONSE => Ok(EapCode::Response),
            EAP_CODE_SUCCESS => Ok(EapCode::Success),
            EAP_CODE_FAILURE => Ok(EapCode::Failure),
            _ => Err(Error::protocol(format!("Unknown EAP code: 0x{:02x}", byte))),
        }
    }
}

/// EAP Type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EapType {
    /// Identity
    Identity,
    /// Notification
    Notification,
    /// NAK (Response only)
    Nak,
    /// MD5-Challenge
    Md5Challenge,
    /// OTP
    Otp,
    /// Generic Token Card
    Gtc,
    /// TLS
    Tls,
    /// Cisco LEAP
    Leap,
    /// SIM
    Sim,
    /// TTLS
    Ttls,
    /// AKA
    Aka,
    /// PEAP
    Peap,
    /// MS-CHAPv2
    MsChapV2,
    /// TLV
    Tlv,
    /// FAST
    Fast,
}

impl EapType {
    /// Convert to byte value
    pub fn to_byte(&self) -> u8 {
        match self {
            EapType::Identity => EAP_TYPE_IDENTITY,
            EapType::Notification => EAP_TYPE_NOTIFICATION,
            EapType::Nak => EAP_TYPE_NAK,
            EapType::Md5Challenge => EAP_TYPE_MD5_CHALLENGE,
            EapType::Otp => EAP_TYPE_OTP,
            EapType::Gtc => EAP_TYPE_GTC,
            EapType::Tls => EAP_TYPE_TLS,
            EapType::Leap => EAP_TYPE_LEAP,
            EapType::Sim => EAP_TYPE_SIM,
            EapType::Ttls => EAP_TYPE_TTLS,
            EapType::Aka => EAP_TYPE_AKA,
            EapType::Peap => EAP_TYPE_PEAP,
            EapType::MsChapV2 => EAP_TYPE_MSCHAPV2,
            EapType::Tlv => EAP_TYPE_TLV,
            EapType::Fast => EAP_TYPE_FAST,
        }
    }

    /// Parse from byte value
    pub fn from_byte(byte: u8) -> Result<Self> {
        match byte {
            EAP_TYPE_IDENTITY => Ok(EapType::Identity),
            EAP_TYPE_NOTIFICATION => Ok(EapType::Notification),
            EAP_TYPE_NAK => Ok(EapType::Nak),
            EAP_TYPE_MD5_CHALLENGE => Ok(EapType::Md5Challenge),
            EAP_TYPE_OTP => Ok(EapType::Otp),
            EAP_TYPE_GTC => Ok(EapType::Gtc),
            EAP_TYPE_TLS => Ok(EapType::Tls),
            EAP_TYPE_LEAP => Ok(EapType::Leap),
            EAP_TYPE_SIM => Ok(EapType::Sim),
            EAP_TYPE_TTLS => Ok(EapType::Ttls),
            EAP_TYPE_AKA => Ok(EapType::Aka),
            EAP_TYPE_PEAP => Ok(EapType::Peap),
            EAP_TYPE_MSCHAPV2 => Ok(EapType::MsChapV2),
            EAP_TYPE_TLV => Ok(EapType::Tlv),
            EAP_TYPE_FAST => Ok(EapType::Fast),
            _ => Err(Error::protocol(format!("Unknown EAP type: 0x{:02x}", byte))),
        }
    }
}

/// EAP Packet
#[derive(Debug, Clone, PartialEq)]
pub struct EapPacket {
    /// EAP Code (Request, Response, Success, Failure)
    pub code: EapCode,
    /// Identifier (for matching requests/responses)
    pub identifier: u8,
    /// EAP Type (only for Request/Response)
    pub eap_type: Option<EapType>,
    /// EAP Data (type-specific data)
    pub data: Vec<u8>,
}

impl EapPacket {
    /// Create a new EAP packet
    pub fn new(code: EapCode, identifier: u8) -> Self {
        Self {
            code,
            identifier,
            eap_type: None,
            data: Vec::new(),
        }
    }

    /// Create EAP Response/Identity packet
    pub fn response_identity(identifier: u8, identity: &str) -> Self {
        Self {
            code: EapCode::Response,
            identifier,
            eap_type: Some(EapType::Identity),
            data: identity.as_bytes().to_vec(),
        }
    }

    /// Create EAP Request/Identity packet
    pub fn request_identity(identifier: u8) -> Self {
        Self {
            code: EapCode::Request,
            identifier,
            eap_type: Some(EapType::Identity),
            data: Vec::new(),
        }
    }

    /// Create EAP Success packet
    pub fn success(identifier: u8) -> Self {
        Self {
            code: EapCode::Success,
            identifier,
            eap_type: None,
            data: Vec::new(),
        }
    }

    /// Create EAP Failure packet
    pub fn failure(identifier: u8) -> Self {
        Self {
            code: EapCode::Failure,
            identifier,
            eap_type: None,
            data: Vec::new(),
        }
    }

    /// Set EAP type
    pub fn with_type(mut self, eap_type: EapType) -> Self {
        self.eap_type = Some(eap_type);
        self
    }

    /// Set EAP data
    pub fn with_data(mut self, data: Vec<u8>) -> Self {
        self.data = data;
        self
    }

    /// Parse EAP packet from bytes
    pub fn parse(data: &[u8]) -> Result<Self> {
        if data.len() < EAP_HEADER_SIZE {
            return Err(Error::protocol(format!(
                "EAP packet too short: {} bytes (need at least {})",
                data.len(),
                EAP_HEADER_SIZE
            )));
        }

        let code = EapCode::from_byte(data[0])?;
        let identifier = data[1];
        let length = u16::from_be_bytes([data[2], data[3]]) as usize;

        if data.len() < length {
            return Err(Error::protocol(format!(
                "EAP packet truncated: got {} bytes, expected {}",
                data.len(),
                length
            )));
        }

        // For Request and Response, parse Type and Data
        let (eap_type, payload_data) = match code {
            EapCode::Request | EapCode::Response => {
                if length > EAP_HEADER_SIZE {
                    let eap_type = EapType::from_byte(data[4])?;
                    let payload_data = if length > EAP_HEADER_SIZE + 1 {
                        data[5..length].to_vec()
                    } else {
                        Vec::new()
                    };
                    (Some(eap_type), payload_data)
                } else {
                    (None, Vec::new())
                }
            }
            EapCode::Success | EapCode::Failure => (None, Vec::new()),
        };

        Ok(Self {
            code,
            identifier,
            eap_type,
            data: payload_data,
        })
    }

    /// Build EAP packet to bytes
    pub fn build(&self) -> Vec<u8> {
        // Calculate total length
        let length = match self.code {
            EapCode::Request | EapCode::Response => {
                if self.eap_type.is_some() {
                    EAP_HEADER_SIZE + 1 + self.data.len()
                } else {
                    EAP_HEADER_SIZE
                }
            }
            EapCode::Success | EapCode::Failure => EAP_HEADER_SIZE,
        };

        let mut bytes = Vec::with_capacity(length);

        // Code
        bytes.push(self.code.to_byte());
        // Identifier
        bytes.push(self.identifier);
        // Length (2 bytes, network order)
        bytes.extend_from_slice(&(length as u16).to_be_bytes());

        // Type and Data (only for Request/Response)
        match self.code {
            EapCode::Request | EapCode::Response => {
                if let Some(eap_type) = self.eap_type {
                    bytes.push(eap_type.to_byte());
                    bytes.extend_from_slice(&self.data);
                }
            }
            EapCode::Success | EapCode::Failure => {
                // No type or data
            }
        }

        bytes
    }
}

/// EAPOL Packet
#[derive(Debug, Clone, PartialEq)]
pub struct EapolPacket {
    /// Protocol version (1, 2, or 3)
    pub version: u8,
    /// Packet type
    pub packet_type: EapolType,
    /// Body (can be EAP packet or other data)
    pub body: Vec<u8>,
}

impl EapolPacket {
    /// Create a new EAPOL packet
    pub fn new(version: u8, packet_type: EapolType) -> Self {
        Self {
            version,
            packet_type,
            body: Vec::new(),
        }
    }

    /// Create EAPOL-Start packet
    pub fn start() -> Self {
        Self {
            version: DEFAULT_EAPOL_VERSION,
            packet_type: EapolType::Start,
            body: Vec::new(),
        }
    }

    /// Create EAPOL-Logoff packet
    pub fn logoff() -> Self {
        Self {
            version: DEFAULT_EAPOL_VERSION,
            packet_type: EapolType::Logoff,
            body: Vec::new(),
        }
    }

    /// Create EAPOL packet containing an EAP packet
    pub fn eap_packet(eap: EapPacket) -> Self {
        Self {
            version: DEFAULT_EAPOL_VERSION,
            packet_type: EapolType::EapPacket,
            body: eap.build(),
        }
    }

    /// Set version
    pub fn with_version(mut self, version: u8) -> Self {
        self.version = version;
        self
    }

    /// Set body
    pub fn with_body(mut self, body: Vec<u8>) -> Self {
        self.body = body;
        self
    }

    /// Parse EAPOL packet from bytes
    pub fn parse(data: &[u8]) -> Result<Self> {
        if data.len() < MIN_EAPOL_SIZE {
            return Err(Error::protocol(format!(
                "EAPOL packet too short: {} bytes (need at least {})",
                data.len(),
                MIN_EAPOL_SIZE
            )));
        }

        let version = data[0];
        let packet_type = EapolType::from_byte(data[1])?;
        let body_length = u16::from_be_bytes([data[2], data[3]]) as usize;

        if data.len() < EAPOL_HEADER_SIZE + body_length {
            return Err(Error::protocol(format!(
                "EAPOL packet truncated: got {} bytes, expected {}",
                data.len(),
                EAPOL_HEADER_SIZE + body_length
            )));
        }

        let body = if body_length > 0 {
            data[EAPOL_HEADER_SIZE..EAPOL_HEADER_SIZE + body_length].to_vec()
        } else {
            Vec::new()
        };

        Ok(Self {
            version,
            packet_type,
            body,
        })
    }

    /// Build EAPOL packet to bytes
    pub fn build(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(EAPOL_HEADER_SIZE + self.body.len());

        // Version
        bytes.push(self.version);
        // Packet Type
        bytes.push(self.packet_type.to_byte());
        // Body Length (2 bytes, network order)
        bytes.extend_from_slice(&(self.body.len() as u16).to_be_bytes());
        // Body
        bytes.extend_from_slice(&self.body);

        bytes
    }

    /// Parse the body as an EAP packet (if packet_type is EapPacket)
    pub fn parse_eap_body(&self) -> Result<EapPacket> {
        if self.packet_type != EapolType::EapPacket {
            return Err(Error::protocol(format!(
                "Not an EAP packet, type is {:?}",
                self.packet_type
            )));
        }

        EapPacket::parse(&self.body)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_eapol_type_conversion() {
        assert_eq!(EapolType::Start.to_byte(), 0x01);
        assert_eq!(EapolType::Logoff.to_byte(), 0x02);
        assert_eq!(EapolType::EapPacket.to_byte(), 0x00);

        assert_eq!(EapolType::from_byte(0x01).unwrap(), EapolType::Start);
        assert_eq!(EapolType::from_byte(0x02).unwrap(), EapolType::Logoff);
    }

    #[test]
    fn test_eap_code_conversion() {
        assert_eq!(EapCode::Request.to_byte(), 0x01);
        assert_eq!(EapCode::Response.to_byte(), 0x02);
        assert_eq!(EapCode::Success.to_byte(), 0x03);
        assert_eq!(EapCode::Failure.to_byte(), 0x04);

        assert_eq!(EapCode::from_byte(0x01).unwrap(), EapCode::Request);
        assert_eq!(EapCode::from_byte(0x02).unwrap(), EapCode::Response);
    }

    #[test]
    fn test_eap_type_conversion() {
        assert_eq!(EapType::Identity.to_byte(), 0x01);
        assert_eq!(EapType::Md5Challenge.to_byte(), 0x04);
        assert_eq!(EapType::Tls.to_byte(), 0x0D);

        assert_eq!(EapType::from_byte(0x01).unwrap(), EapType::Identity);
        assert_eq!(EapType::from_byte(0x04).unwrap(), EapType::Md5Challenge);
    }

    #[test]
    fn test_eapol_start_packet() {
        let packet = EapolPacket::start();
        assert_eq!(packet.version, EAPOL_VERSION_1);
        assert_eq!(packet.packet_type, EapolType::Start);
        assert_eq!(packet.body.len(), 0);

        let bytes = packet.build();
        assert_eq!(bytes.len(), 4); // Header only
        assert_eq!(bytes[0], EAPOL_VERSION_1);
        assert_eq!(bytes[1], EAPOL_TYPE_START);
        assert_eq!(bytes[2], 0x00); // Body length high byte
        assert_eq!(bytes[3], 0x00); // Body length low byte
    }

    #[test]
    fn test_eapol_logoff_packet() {
        let packet = EapolPacket::logoff();
        assert_eq!(packet.packet_type, EapolType::Logoff);

        let bytes = packet.build();
        assert_eq!(bytes[1], EAPOL_TYPE_LOGOFF);
    }

    #[test]
    fn test_eap_response_identity() {
        let packet = EapPacket::response_identity(1, "testuser");
        assert_eq!(packet.code, EapCode::Response);
        assert_eq!(packet.identifier, 1);
        assert_eq!(packet.eap_type, Some(EapType::Identity));
        assert_eq!(packet.data, b"testuser");

        let bytes = packet.build();
        // Length = 4 (header) + 1 (type) + 8 (data) = 13
        assert_eq!(bytes.len(), 13);
        assert_eq!(bytes[0], EAP_CODE_RESPONSE);
        assert_eq!(bytes[1], 1); // identifier
        assert_eq!(u16::from_be_bytes([bytes[2], bytes[3]]), 13); // length
        assert_eq!(bytes[4], EAP_TYPE_IDENTITY);
        assert_eq!(&bytes[5..], b"testuser");
    }

    #[test]
    fn test_eap_success() {
        let packet = EapPacket::success(5);
        assert_eq!(packet.code, EapCode::Success);
        assert_eq!(packet.identifier, 5);
        assert_eq!(packet.eap_type, None);

        let bytes = packet.build();
        assert_eq!(bytes.len(), 4); // Header only
        assert_eq!(bytes[0], EAP_CODE_SUCCESS);
        assert_eq!(bytes[1], 5);
    }

    #[test]
    fn test_eap_failure() {
        let packet = EapPacket::failure(10);
        assert_eq!(packet.code, EapCode::Failure);

        let bytes = packet.build();
        assert_eq!(bytes[0], EAP_CODE_FAILURE);
    }

    #[test]
    fn test_eapol_eap_packet() {
        let eap = EapPacket::response_identity(2, "admin");
        let eapol = EapolPacket::eap_packet(eap.clone());

        assert_eq!(eapol.packet_type, EapolType::EapPacket);
        assert_eq!(eapol.body, eap.build());

        let bytes = eapol.build();
        // Parse it back
        let parsed = EapolPacket::parse(&bytes).unwrap();
        assert_eq!(parsed, eapol);
    }

    #[test]
    fn test_eapol_parse_build_roundtrip() {
        let original = EapolPacket::start();
        let bytes = original.build();
        let parsed = EapolPacket::parse(&bytes).unwrap();
        assert_eq!(parsed, original);
    }

    #[test]
    fn test_eap_parse_build_roundtrip() {
        let original = EapPacket::response_identity(3, "user@example.com");
        let bytes = original.build();
        let parsed = EapPacket::parse(&bytes).unwrap();
        assert_eq!(parsed, original);
    }

    #[test]
    fn test_eapol_too_short() {
        let data = vec![0x01, 0x00]; // Only 2 bytes
        assert!(EapolPacket::parse(&data).is_err());
    }

    #[test]
    fn test_eap_too_short() {
        let data = vec![0x01, 0x00, 0x00]; // Only 3 bytes
        assert!(EapPacket::parse(&data).is_err());
    }

    #[test]
    fn test_eapol_parse_eap_body() {
        let eap = EapPacket::request_identity(7);
        let eapol = EapolPacket::eap_packet(eap.clone());

        let parsed_eap = eapol.parse_eap_body().unwrap();
        assert_eq!(parsed_eap, eap);
    }

    #[test]
    fn test_eapol_parse_eap_body_wrong_type() {
        let eapol = EapolPacket::start();
        assert!(eapol.parse_eap_body().is_err());
    }
}
