//! HSRP Packet Parser and Builder
//!
//! This module provides complete parsing and construction of Hot Standby Router Protocol packets
//! for both HSRPv1 and HSRPv2, with 100% parity to the original Yersinia implementation.

use bytes::{BufMut, BytesMut};
use std::net::Ipv4Addr;
use yersinia_core::{Error, Result};

/// HSRP Protocol versions
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HsrpVersion {
    /// HSRPv1 (version 0)
    V1,
    /// HSRPv2 (version 1) - Extended for IPv6 and larger group numbers
    V2,
}

impl HsrpVersion {
    pub fn to_u8(self) -> u8 {
        match self {
            HsrpVersion::V1 => 0,
            HsrpVersion::V2 => 1,
        }
    }

    pub fn from_u8(val: u8) -> Self {
        if val == 1 {
            HsrpVersion::V2
        } else {
            HsrpVersion::V1
        }
    }
}

/// HSRP Opcode (message type)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HsrpOpcode {
    /// Hello message - periodic announcement
    Hello,
    /// Coup message - takeover from active router
    Coup,
    /// Resign message - giving up active role
    Resign,
}

impl HsrpOpcode {
    pub fn to_u8(self) -> u8 {
        match self {
            HsrpOpcode::Hello => 0,
            HsrpOpcode::Coup => 1,
            HsrpOpcode::Resign => 2,
        }
    }

    pub fn from_u8(val: u8) -> Self {
        match val {
            1 => HsrpOpcode::Coup,
            2 => HsrpOpcode::Resign,
            _ => HsrpOpcode::Hello,
        }
    }
}

/// HSRP State machine states
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HsrpState {
    /// Initial state
    Initial,
    /// Learning configuration
    Learn,
    /// Listening for hellos
    Listen,
    /// Participating in election
    Speak,
    /// Backup router
    Standby,
    /// Active router (forwarding)
    Active,
}

impl HsrpState {
    pub fn to_u8(self) -> u8 {
        match self {
            HsrpState::Initial => 0,
            HsrpState::Learn => 1,
            HsrpState::Listen => 2,
            HsrpState::Speak => 4,
            HsrpState::Standby => 8,
            HsrpState::Active => 16,
        }
    }

    pub fn from_u8(val: u8) -> Self {
        match val {
            1 => HsrpState::Learn,
            2 => HsrpState::Listen,
            4 => HsrpState::Speak,
            8 => HsrpState::Standby,
            16 => HsrpState::Active,
            _ => HsrpState::Initial,
        }
    }
}

/// HSRP Authentication type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HsrpAuthType {
    /// Plain text authentication (HSRPv1)
    PlainText,
    /// MD5 authentication (HSRPv2)
    Md5,
}

/// Complete HSRP packet structure
#[derive(Debug, Clone, PartialEq)]
pub struct HsrpPacket {
    /// Protocol version
    pub version: HsrpVersion,
    /// Message type
    pub opcode: HsrpOpcode,
    /// Current state of the router
    pub state: HsrpState,
    /// Hello time in seconds (default: 3)
    pub hello_time: u8,
    /// Hold time in seconds (default: 10)
    pub hold_time: u8,
    /// Priority for election (default: 100, max: 255)
    pub priority: u8,
    /// HSRP group number (0-255 for v1, 0-4095 for v2)
    pub group: u16,
    /// Reserved field
    pub reserved: u8,
    /// Authentication data (8 bytes for v1, variable for v2)
    pub auth_data: [u8; 8],
    /// Virtual IP address
    pub virtual_ip: Ipv4Addr,
}

impl HsrpPacket {
    /// Create a new HSRP packet with default values
    pub fn new() -> Self {
        Self {
            version: HsrpVersion::V1,
            opcode: HsrpOpcode::Hello,
            state: HsrpState::Initial,
            hello_time: HSRP_DEFAULT_HELLOTIME,
            hold_time: HSRP_DEFAULT_HOLDTIME,
            priority: HSRP_DEFAULT_PRIORITY,
            group: 0,
            reserved: 0,
            auth_data: *HSRP_DEFAULT_AUTH,
            virtual_ip: Ipv4Addr::new(0, 0, 0, 0),
        }
    }

    /// Create a Hello packet
    pub fn hello(
        group: u16,
        priority: u8,
        virtual_ip: Ipv4Addr,
        state: HsrpState,
        auth: Option<&[u8; 8]>,
    ) -> Self {
        Self {
            version: HsrpVersion::V1,
            opcode: HsrpOpcode::Hello,
            state,
            hello_time: HSRP_DEFAULT_HELLOTIME,
            hold_time: HSRP_DEFAULT_HOLDTIME,
            priority,
            group,
            reserved: 0,
            auth_data: auth.copied().unwrap_or(*HSRP_DEFAULT_AUTH),
            virtual_ip,
        }
    }

    /// Create a Coup packet (takeover)
    pub fn coup(group: u16, priority: u8, virtual_ip: Ipv4Addr, auth: Option<&[u8; 8]>) -> Self {
        Self {
            version: HsrpVersion::V1,
            opcode: HsrpOpcode::Coup,
            state: HsrpState::Speak,
            hello_time: HSRP_DEFAULT_HELLOTIME,
            hold_time: HSRP_DEFAULT_HOLDTIME,
            priority,
            group,
            reserved: 0,
            auth_data: auth.copied().unwrap_or(*HSRP_DEFAULT_AUTH),
            virtual_ip,
        }
    }

    /// Create a Resign packet (giving up active role)
    pub fn resign(group: u16, priority: u8, virtual_ip: Ipv4Addr, auth: Option<&[u8; 8]>) -> Self {
        Self {
            version: HsrpVersion::V1,
            opcode: HsrpOpcode::Resign,
            state: HsrpState::Speak,
            hello_time: HSRP_DEFAULT_HELLOTIME,
            hold_time: HSRP_DEFAULT_HOLDTIME,
            priority,
            group,
            reserved: 0,
            auth_data: auth.copied().unwrap_or(*HSRP_DEFAULT_AUTH),
            virtual_ip,
        }
    }

    /// Set the version
    pub fn with_version(mut self, version: HsrpVersion) -> Self {
        self.version = version;
        self
    }

    /// Set the opcode
    pub fn with_opcode(mut self, opcode: HsrpOpcode) -> Self {
        self.opcode = opcode;
        self
    }

    /// Set the state
    pub fn with_state(mut self, state: HsrpState) -> Self {
        self.state = state;
        self
    }

    /// Set the priority
    pub fn with_priority(mut self, priority: u8) -> Self {
        self.priority = priority;
        self
    }

    /// Set the group
    pub fn with_group(mut self, group: u16) -> Self {
        self.group = group;
        self
    }

    /// Set the virtual IP
    pub fn with_virtual_ip(mut self, ip: Ipv4Addr) -> Self {
        self.virtual_ip = ip;
        self
    }

    /// Set the authentication data
    pub fn with_auth(mut self, auth: &[u8; 8]) -> Self {
        self.auth_data = *auth;
        self
    }

    /// Set authentication from string (will be truncated/padded to 8 bytes)
    pub fn with_auth_string(mut self, auth: &str) -> Self {
        let bytes = auth.as_bytes();
        let len = bytes.len().min(8);
        self.auth_data[..len].copy_from_slice(&bytes[..len]);
        // Pad with zeros if needed
        for i in len..8 {
            self.auth_data[i] = 0;
        }
        self
    }

    /// Set hello and hold times
    pub fn with_timers(mut self, hello_time: u8, hold_time: u8) -> Self {
        self.hello_time = hello_time;
        self.hold_time = hold_time;
        self
    }

    /// Build the packet into bytes (HSRPv1 format)
    pub fn build_v1(&self) -> Result<Vec<u8>> {
        let mut buffer = BytesMut::with_capacity(20);

        buffer.put_u8(self.version.to_u8());
        buffer.put_u8(self.opcode.to_u8());
        buffer.put_u8(self.state.to_u8());
        buffer.put_u8(self.hello_time);
        buffer.put_u8(self.hold_time);
        buffer.put_u8(self.priority);
        buffer.put_u8((self.group & 0xFF) as u8); // v1 only supports 0-255
        buffer.put_u8(self.reserved);
        buffer.put_slice(&self.auth_data);
        buffer.put_slice(&self.virtual_ip.octets());

        Ok(buffer.to_vec())
    }

    /// Build the packet into bytes (HSRPv2 format)
    /// Note: HSRPv2 basic packet format is also 20 bytes like v1,
    /// but with 2-byte group field instead of 1-byte + reserved
    pub fn build_v2(&self) -> Result<Vec<u8>> {
        let mut buffer = BytesMut::with_capacity(20);

        buffer.put_u8(self.version.to_u8());
        buffer.put_u8(self.opcode.to_u8());
        buffer.put_u8(self.state.to_u8());
        buffer.put_u8(self.hello_time);
        buffer.put_u8(self.hold_time);
        buffer.put_u8(self.priority);
        buffer.put_u16(self.group); // v2 supports 0-4095 (2 bytes)
        buffer.put_slice(&self.auth_data);
        buffer.put_slice(&self.virtual_ip.octets());

        Ok(buffer.to_vec())
    }

    /// Build the packet (automatically selects v1 or v2 format)
    pub fn build(&self) -> Result<Vec<u8>> {
        match self.version {
            HsrpVersion::V1 => self.build_v1(),
            HsrpVersion::V2 => self.build_v2(),
        }
    }

    /// Parse an HSRPv1 packet from bytes
    pub fn parse_v1(data: &[u8]) -> Result<Self> {
        if data.len() < 20 {
            return Err(Error::protocol("HSRP packet too short (expected 20 bytes)"));
        }

        Ok(HsrpPacket {
            version: HsrpVersion::from_u8(data[0]),
            opcode: HsrpOpcode::from_u8(data[1]),
            state: HsrpState::from_u8(data[2]),
            hello_time: data[3],
            hold_time: data[4],
            priority: data[5],
            group: data[6] as u16,
            reserved: data[7],
            auth_data: {
                let mut auth = [0u8; 8];
                auth.copy_from_slice(&data[8..16]);
                auth
            },
            virtual_ip: Ipv4Addr::new(data[16], data[17], data[18], data[19]),
        })
    }

    /// Parse an HSRPv2 packet from bytes
    /// Note: HSRPv2 basic packet is also 20 bytes like v1
    pub fn parse_v2(data: &[u8]) -> Result<Self> {
        if data.len() < 20 {
            return Err(Error::protocol(
                "HSRPv2 packet too short (expected 20 bytes)",
            ));
        }

        Ok(HsrpPacket {
            version: HsrpVersion::from_u8(data[0]),
            opcode: HsrpOpcode::from_u8(data[1]),
            state: HsrpState::from_u8(data[2]),
            hello_time: data[3],
            hold_time: data[4],
            priority: data[5],
            group: u16::from_be_bytes([data[6], data[7]]), // 2-byte group in v2
            reserved: 0,
            auth_data: {
                let mut auth = [0u8; 8];
                auth.copy_from_slice(&data[8..16]);
                auth
            },
            virtual_ip: Ipv4Addr::new(data[16], data[17], data[18], data[19]),
        })
    }

    /// Parse an HSRP packet (auto-detects version)
    pub fn parse(data: &[u8]) -> Result<Self> {
        if data.is_empty() {
            return Err(Error::protocol("Empty HSRP packet"));
        }

        let version = HsrpVersion::from_u8(data[0]);
        match version {
            HsrpVersion::V1 => Self::parse_v1(data),
            HsrpVersion::V2 => Self::parse_v2(data),
        }
    }
}

impl Default for HsrpPacket {
    fn default() -> Self {
        Self::new()
    }
}

/// Generate HSRP virtual MAC address from group number
///
/// Format: 00:00:0C:07:AC:XX where XX is the group number
pub fn generate_virtual_mac(group: u8) -> [u8; 6] {
    [
        HSRP_VIRTUAL_MAC_OUI[0],
        HSRP_VIRTUAL_MAC_OUI[1],
        HSRP_VIRTUAL_MAC_OUI[2],
        HSRP_VIRTUAL_MAC_PREFIX[0],
        HSRP_VIRTUAL_MAC_PREFIX[1],
        group,
    ]
}

// Constants

/// HSRPv1 multicast destination IP
pub const HSRP_V1_MULTICAST: Ipv4Addr = Ipv4Addr::new(224, 0, 0, 2);

/// HSRPv1 multicast destination MAC
pub const HSRP_V1_MULTICAST_MAC: [u8; 6] = [0x01, 0x00, 0x5E, 0x00, 0x00, 0x02];

/// HSRPv2 multicast destination IP
pub const HSRP_V2_MULTICAST: Ipv4Addr = Ipv4Addr::new(224, 0, 0, 102);

/// HSRPv2 multicast destination MAC
pub const HSRP_V2_MULTICAST_MAC: [u8; 6] = [0x01, 0x00, 0x5E, 0x00, 0x00, 0x66];

/// HSRP UDP port (source and destination)
pub const HSRP_UDP_PORT: u16 = 1985;

/// HSRP virtual MAC OUI (Cisco)
pub const HSRP_VIRTUAL_MAC_OUI: [u8; 3] = [0x00, 0x00, 0x0C];

/// HSRP virtual MAC prefix
pub const HSRP_VIRTUAL_MAC_PREFIX: [u8; 3] = [0x07, 0xAC, 0x00];

/// Default hello time (3 seconds)
pub const HSRP_DEFAULT_HELLOTIME: u8 = 3;

/// Default hold time (10 seconds)
pub const HSRP_DEFAULT_HOLDTIME: u8 = 10;

/// Default priority (100)
pub const HSRP_DEFAULT_PRIORITY: u8 = 100;

/// Maximum priority (255)
pub const HSRP_MAX_PRIORITY: u8 = 255;

/// Default authentication data ("cisco\0\0\0")
pub const HSRP_DEFAULT_AUTH: &[u8; 8] = b"cisco\0\0\0";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hsrp_version_conversion() {
        assert_eq!(HsrpVersion::V1.to_u8(), 0);
        assert_eq!(HsrpVersion::V2.to_u8(), 1);
        assert_eq!(HsrpVersion::from_u8(0), HsrpVersion::V1);
        assert_eq!(HsrpVersion::from_u8(1), HsrpVersion::V2);
    }

    #[test]
    fn test_hsrp_opcode_conversion() {
        assert_eq!(HsrpOpcode::Hello.to_u8(), 0);
        assert_eq!(HsrpOpcode::Coup.to_u8(), 1);
        assert_eq!(HsrpOpcode::Resign.to_u8(), 2);
        assert_eq!(HsrpOpcode::from_u8(0), HsrpOpcode::Hello);
        assert_eq!(HsrpOpcode::from_u8(1), HsrpOpcode::Coup);
        assert_eq!(HsrpOpcode::from_u8(2), HsrpOpcode::Resign);
    }

    #[test]
    fn test_hsrp_state_conversion() {
        assert_eq!(HsrpState::Initial.to_u8(), 0);
        assert_eq!(HsrpState::Learn.to_u8(), 1);
        assert_eq!(HsrpState::Listen.to_u8(), 2);
        assert_eq!(HsrpState::Speak.to_u8(), 4);
        assert_eq!(HsrpState::Standby.to_u8(), 8);
        assert_eq!(HsrpState::Active.to_u8(), 16);

        assert_eq!(HsrpState::from_u8(0), HsrpState::Initial);
        assert_eq!(HsrpState::from_u8(1), HsrpState::Learn);
        assert_eq!(HsrpState::from_u8(16), HsrpState::Active);
    }

    #[test]
    fn test_hsrp_packet_creation() {
        let packet = HsrpPacket::new();
        assert_eq!(packet.version, HsrpVersion::V1);
        assert_eq!(packet.opcode, HsrpOpcode::Hello);
        assert_eq!(packet.state, HsrpState::Initial);
        assert_eq!(packet.hello_time, HSRP_DEFAULT_HELLOTIME);
        assert_eq!(packet.hold_time, HSRP_DEFAULT_HOLDTIME);
        assert_eq!(packet.priority, HSRP_DEFAULT_PRIORITY);
    }

    #[test]
    fn test_hsrp_hello_packet() {
        let ip = Ipv4Addr::new(192, 168, 1, 1);
        let packet = HsrpPacket::hello(1, 100, ip, HsrpState::Active, None);

        assert_eq!(packet.opcode, HsrpOpcode::Hello);
        assert_eq!(packet.state, HsrpState::Active);
        assert_eq!(packet.group, 1);
        assert_eq!(packet.priority, 100);
        assert_eq!(packet.virtual_ip, ip);
    }

    #[test]
    fn test_hsrp_coup_packet() {
        let ip = Ipv4Addr::new(192, 168, 1, 1);
        let packet = HsrpPacket::coup(1, 255, ip, None);

        assert_eq!(packet.opcode, HsrpOpcode::Coup);
        assert_eq!(packet.state, HsrpState::Speak);
        assert_eq!(packet.priority, 255);
    }

    #[test]
    fn test_hsrp_resign_packet() {
        let ip = Ipv4Addr::new(192, 168, 1, 1);
        let packet = HsrpPacket::resign(1, 100, ip, None);

        assert_eq!(packet.opcode, HsrpOpcode::Resign);
        assert_eq!(packet.state, HsrpState::Speak);
    }

    #[test]
    fn test_hsrp_packet_builder() {
        let ip = Ipv4Addr::new(10, 0, 0, 1);
        let packet = HsrpPacket::new()
            .with_version(HsrpVersion::V1)
            .with_opcode(HsrpOpcode::Hello)
            .with_state(HsrpState::Active)
            .with_priority(200)
            .with_group(10)
            .with_virtual_ip(ip)
            .with_auth_string("secret");

        assert_eq!(packet.version, HsrpVersion::V1);
        assert_eq!(packet.opcode, HsrpOpcode::Hello);
        assert_eq!(packet.state, HsrpState::Active);
        assert_eq!(packet.priority, 200);
        assert_eq!(packet.group, 10);
        assert_eq!(packet.virtual_ip, ip);
        assert_eq!(&packet.auth_data[..6], b"secret");
    }

    #[test]
    fn test_hsrp_v1_build() {
        let ip = Ipv4Addr::new(192, 168, 1, 1);
        let packet = HsrpPacket::hello(1, 100, ip, HsrpState::Active, None);
        let bytes = packet.build_v1().unwrap();

        assert_eq!(bytes.len(), 20);
        assert_eq!(bytes[0], 0); // version
        assert_eq!(bytes[1], 0); // opcode (hello)
        assert_eq!(bytes[2], 16); // state (active)
        assert_eq!(bytes[5], 100); // priority
        assert_eq!(bytes[6], 1); // group
    }

    #[test]
    fn test_hsrp_v1_parse() {
        let ip = Ipv4Addr::new(192, 168, 1, 1);
        let original = HsrpPacket::hello(5, 150, ip, HsrpState::Standby, None);
        let bytes = original.build_v1().unwrap();
        let parsed = HsrpPacket::parse_v1(&bytes).unwrap();

        assert_eq!(parsed.version, original.version);
        assert_eq!(parsed.opcode, original.opcode);
        assert_eq!(parsed.state, original.state);
        assert_eq!(parsed.priority, original.priority);
        assert_eq!(parsed.group, original.group);
        assert_eq!(parsed.virtual_ip, original.virtual_ip);
    }

    #[test]
    fn test_hsrp_v1_roundtrip() {
        let ip = Ipv4Addr::new(10, 20, 30, 40);
        let original = HsrpPacket::new()
            .with_version(HsrpVersion::V1)
            .with_opcode(HsrpOpcode::Coup)
            .with_state(HsrpState::Speak)
            .with_priority(255)
            .with_group(10)
            .with_virtual_ip(ip)
            .with_auth_string("test1234");

        let bytes = original.build().unwrap();
        let parsed = HsrpPacket::parse(&bytes).unwrap();

        assert_eq!(parsed.version, original.version);
        assert_eq!(parsed.opcode, original.opcode);
        assert_eq!(parsed.state, original.state);
        assert_eq!(parsed.priority, original.priority);
        assert_eq!(parsed.group, original.group);
        assert_eq!(parsed.virtual_ip, original.virtual_ip);
        assert_eq!(parsed.auth_data, original.auth_data);
    }

    #[test]
    fn test_hsrp_v2_build() {
        let ip = Ipv4Addr::new(192, 168, 1, 1);
        let packet =
            HsrpPacket::hello(1000, 100, ip, HsrpState::Active, None).with_version(HsrpVersion::V2);
        let bytes = packet.build_v2().unwrap();

        assert_eq!(bytes.len(), 20); // HSRPv2 is also 20 bytes
        assert_eq!(bytes[0], 1); // version 2
        assert_eq!(bytes[1], 0); // opcode (hello)
        assert_eq!(bytes[2], 16); // state (active)
        assert_eq!(bytes[5], 100); // priority

        // Group is 2 bytes in v2
        let group = u16::from_be_bytes([bytes[6], bytes[7]]);
        assert_eq!(group, 1000);
    }

    #[test]
    fn test_hsrp_v2_parse() {
        let ip = Ipv4Addr::new(172, 16, 0, 1);
        let original =
            HsrpPacket::hello(2048, 200, ip, HsrpState::Active, None).with_version(HsrpVersion::V2);
        let bytes = original.build_v2().unwrap();
        let parsed = HsrpPacket::parse_v2(&bytes).unwrap();

        assert_eq!(parsed.version, HsrpVersion::V2);
        assert_eq!(parsed.group, 2048);
        assert_eq!(parsed.priority, 200);
        assert_eq!(parsed.virtual_ip, ip);
    }

    #[test]
    fn test_hsrp_v2_roundtrip() {
        let ip = Ipv4Addr::new(10, 0, 0, 254);
        let original = HsrpPacket::new()
            .with_version(HsrpVersion::V2)
            .with_opcode(HsrpOpcode::Hello)
            .with_state(HsrpState::Active)
            .with_priority(255)
            .with_group(4095) // Max group for v2
            .with_virtual_ip(ip)
            .with_auth_string("password");

        let bytes = original.build().unwrap();
        let parsed = HsrpPacket::parse(&bytes).unwrap();

        assert_eq!(parsed.version, original.version);
        assert_eq!(parsed.opcode, original.opcode);
        assert_eq!(parsed.group, original.group);
        assert_eq!(parsed.priority, original.priority);
    }

    #[test]
    fn test_hsrp_auto_parse() {
        // Test v1 auto-detection
        let ip = Ipv4Addr::new(192, 168, 1, 1);
        let v1_packet = HsrpPacket::hello(1, 100, ip, HsrpState::Active, None);
        let v1_bytes = v1_packet.build().unwrap();
        let parsed_v1 = HsrpPacket::parse(&v1_bytes).unwrap();
        assert_eq!(parsed_v1.version, HsrpVersion::V1);

        // Test v2 auto-detection
        let v2_packet =
            HsrpPacket::hello(1000, 100, ip, HsrpState::Active, None).with_version(HsrpVersion::V2);
        let v2_bytes = v2_packet.build().unwrap();
        let parsed_v2 = HsrpPacket::parse(&v2_bytes).unwrap();
        assert_eq!(parsed_v2.version, HsrpVersion::V2);
    }

    #[test]
    fn test_generate_virtual_mac() {
        let mac = generate_virtual_mac(0);
        assert_eq!(mac, [0x00, 0x00, 0x0C, 0x07, 0xAC, 0x00]);

        let mac = generate_virtual_mac(10);
        assert_eq!(mac, [0x00, 0x00, 0x0C, 0x07, 0xAC, 0x0A]);

        let mac = generate_virtual_mac(255);
        assert_eq!(mac, [0x00, 0x00, 0x0C, 0x07, 0xAC, 0xFF]);
    }

    #[test]
    fn test_hsrp_constants() {
        assert_eq!(HSRP_V1_MULTICAST, Ipv4Addr::new(224, 0, 0, 2));
        assert_eq!(HSRP_V2_MULTICAST, Ipv4Addr::new(224, 0, 0, 102));
        assert_eq!(HSRP_UDP_PORT, 1985);
        assert_eq!(HSRP_DEFAULT_HELLOTIME, 3);
        assert_eq!(HSRP_DEFAULT_HOLDTIME, 10);
        assert_eq!(HSRP_DEFAULT_PRIORITY, 100);
        assert_eq!(HSRP_MAX_PRIORITY, 255);
    }

    #[test]
    fn test_hsrp_auth_string() {
        let packet = HsrpPacket::new().with_auth_string("cisco");
        assert_eq!(&packet.auth_data, b"cisco\0\0\0");

        let packet = HsrpPacket::new().with_auth_string("verylongpassword");
        assert_eq!(&packet.auth_data, b"verylong"); // Truncated to 8 bytes

        let packet = HsrpPacket::new().with_auth_string("");
        assert_eq!(&packet.auth_data, b"\0\0\0\0\0\0\0\0");
    }

    #[test]
    fn test_hsrp_packet_too_short() {
        let short_data = vec![0x00, 0x00, 0x00]; // Too short
        let result = HsrpPacket::parse_v1(&short_data);
        assert!(result.is_err());
    }

    #[test]
    fn test_hsrp_empty_packet() {
        let result = HsrpPacket::parse(&[]);
        assert!(result.is_err());
    }

    #[test]
    fn test_hsrp_timers() {
        let packet = HsrpPacket::new().with_timers(5, 15);

        assert_eq!(packet.hello_time, 5);
        assert_eq!(packet.hold_time, 15);
    }

    #[test]
    fn test_all_opcodes() {
        let ip = Ipv4Addr::new(192, 168, 1, 1);

        let hello = HsrpPacket::hello(1, 100, ip, HsrpState::Active, None);
        assert_eq!(hello.opcode, HsrpOpcode::Hello);

        let coup = HsrpPacket::coup(1, 255, ip, None);
        assert_eq!(coup.opcode, HsrpOpcode::Coup);

        let resign = HsrpPacket::resign(1, 100, ip, None);
        assert_eq!(resign.opcode, HsrpOpcode::Resign);
    }

    #[test]
    fn test_all_states() {
        let states = [
            HsrpState::Initial,
            HsrpState::Learn,
            HsrpState::Listen,
            HsrpState::Speak,
            HsrpState::Standby,
            HsrpState::Active,
        ];

        for state in &states {
            let packet = HsrpPacket::new().with_state(*state);
            let bytes = packet.build().unwrap();
            let parsed = HsrpPacket::parse(&bytes).unwrap();
            assert_eq!(parsed.state, *state);
        }
    }

    #[test]
    fn test_multicast_macs() {
        assert_eq!(HSRP_V1_MULTICAST_MAC, [0x01, 0x00, 0x5E, 0x00, 0x00, 0x02]);
        assert_eq!(HSRP_V2_MULTICAST_MAC, [0x01, 0x00, 0x5E, 0x00, 0x00, 0x66]);
    }

    #[test]
    fn test_virtual_mac_prefix() {
        assert_eq!(HSRP_VIRTUAL_MAC_OUI, [0x00, 0x00, 0x0C]);
        assert_eq!(HSRP_VIRTUAL_MAC_PREFIX, [0x07, 0xAC, 0x00]);
    }
}
