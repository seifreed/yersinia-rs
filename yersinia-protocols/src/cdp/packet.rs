//! CDP Packet Parser and Builder
//!
//! This module provides complete parsing and construction of Cisco Discovery Protocol packets,
//! including all TLV (Type-Length-Value) types found in the original Yersinia implementation.

use bytes::{BufMut, BytesMut};
use std::net::Ipv4Addr;
use yersinia_core::{Error, Result};

/// CDP Protocol version
pub const CDP_VERSION: u8 = 0x02;

/// Default TTL (Time To Live) in seconds
pub const CDP_TTL_DEFAULT: u8 = 180;

/// CDP multicast MAC address
pub const CDP_MULTICAST_MAC: [u8; 6] = [0x01, 0x00, 0x0C, 0xCC, 0xCC, 0xCC];

/// Complete CDP packet structure
#[derive(Debug, Clone, PartialEq)]
pub struct CdpPacket {
    /// Protocol version (typically 0x01 or 0x02)
    pub version: u8,
    /// Time To Live in seconds
    pub ttl: u8,
    /// Checksum (calculated automatically on build)
    pub checksum: u16,
    /// List of TLVs
    pub tlvs: Vec<CdpTlv>,
}

impl CdpPacket {
    /// Create a new CDP packet with default version and TTL
    pub fn new() -> Self {
        Self {
            version: CDP_VERSION,
            ttl: CDP_TTL_DEFAULT,
            checksum: 0,
            tlvs: Vec::new(),
        }
    }

    /// Add a TLV to the packet
    pub fn add_tlv(mut self, tlv: CdpTlv) -> Self {
        self.tlvs.push(tlv);
        self
    }

    /// Set the version
    pub fn with_version(mut self, version: u8) -> Self {
        self.version = version;
        self
    }

    /// Set the TTL
    pub fn with_ttl(mut self, ttl: u8) -> Self {
        self.ttl = ttl;
        self
    }

    /// Build the packet into bytes (calculates checksum automatically)
    pub fn build(&self) -> Result<Vec<u8>> {
        let mut buffer = BytesMut::new();

        // Reserve space for header
        buffer.put_u8(self.version);
        buffer.put_u8(self.ttl);
        buffer.put_u16(0); // Placeholder for checksum

        // Encode all TLVs
        for tlv in &self.tlvs {
            tlv.encode(&mut buffer)?;
        }

        // Calculate checksum (covers version, ttl, checksum field, and all TLVs)
        let checksum = calculate_checksum(&buffer[0..]);

        // Write checksum at offset 2
        buffer[2..4].copy_from_slice(&checksum.to_be_bytes());

        Ok(buffer.to_vec())
    }

    /// Parse a CDP packet from bytes
    pub fn parse(data: &[u8]) -> Result<Self> {
        if data.len() < 4 {
            return Err(Error::protocol("CDP packet too short"));
        }

        let version = data[0];
        let ttl = data[1];
        let checksum = u16::from_be_bytes([data[2], data[3]]);

        // Verify checksum
        let calculated = calculate_checksum(data);
        if calculated != 0 {
            // Note: A valid checksum should result in 0 when computed over the entire packet
            // We don't fail here to allow parsing packets with bad checksums for analysis
        }

        // Parse TLVs
        let mut offset = 4;
        let mut tlvs = Vec::new();

        while offset < data.len() {
            if offset + 4 > data.len() {
                break; // Not enough data for TLV header
            }

            let tlv_type = u16::from_be_bytes([data[offset], data[offset + 1]]);
            let tlv_len = u16::from_be_bytes([data[offset + 2], data[offset + 3]]);

            if tlv_len < 4 {
                break; // Invalid TLV length
            }

            if offset + tlv_len as usize > data.len() {
                break; // TLV extends beyond packet
            }

            let tlv_data = &data[offset + 4..offset + tlv_len as usize];

            match CdpTlv::decode(tlv_type, tlv_data) {
                Ok(tlv) => tlvs.push(tlv),
                Err(_) => {
                    // Skip unknown/malformed TLVs
                }
            }

            offset += tlv_len as usize;
        }

        Ok(CdpPacket {
            version,
            ttl,
            checksum,
            tlvs,
        })
    }
}

impl Default for CdpPacket {
    fn default() -> Self {
        Self::new()
    }
}

/// CDP TLV (Type-Length-Value) types
#[derive(Debug, Clone, PartialEq)]
pub enum CdpTlv {
    /// Device ID (hostname)
    DeviceId(String),
    /// List of network addresses
    Addresses(Vec<Ipv4Addr>),
    /// Port ID (interface name)
    PortId(String),
    /// Device capabilities (flags)
    Capabilities(CdpCapabilities),
    /// Software version string
    SoftwareVersion(String),
    /// Platform description
    Platform(String),
    /// IP Prefix/Gateway
    IpPrefix(Ipv4Addr, u8),
    /// Protocol Hello (rarely used)
    ProtocolHello(Vec<u8>),
    /// VTP Management Domain
    VtpMgmtDomain(String),
    /// Native VLAN ID
    NativeVlan(u16),
    /// Duplex setting
    Duplex(DuplexMode),
    /// VoIP VLAN Reply
    VoipVlanReply(u16),
    /// VoIP VLAN Query
    VoipVlanQuery(Vec<u8>),
    /// MTU size
    Mtu(u32),
    /// Trust Bitmap
    TrustBitmap(u8),
    /// Untrusted Port CoS
    UntrustedPortCoS(u8),
    /// System Name
    SystemName(String),
    /// System Object ID (SNMP OID)
    SystemObjectId(Vec<u8>),
    /// Management Address
    ManagementAddress(Ipv4Addr),
    /// Physical Location
    PhysicalLocation(String),
    /// Unknown TLV type (for future compatibility)
    Unknown(u16, Vec<u8>),
}

impl CdpTlv {
    /// Get the TLV type code
    pub fn type_code(&self) -> u16 {
        match self {
            CdpTlv::DeviceId(_) => CDP_TYPE_DEVID,
            CdpTlv::Addresses(_) => CDP_TYPE_ADDRESS,
            CdpTlv::PortId(_) => CDP_TYPE_PORTID,
            CdpTlv::Capabilities(_) => CDP_TYPE_CAPABILITY,
            CdpTlv::SoftwareVersion(_) => CDP_TYPE_VERSION,
            CdpTlv::Platform(_) => CDP_TYPE_PLATFORM,
            CdpTlv::IpPrefix(_, _) => CDP_TYPE_IPPREFIX,
            CdpTlv::ProtocolHello(_) => CDP_TYPE_PROTOCOL_HELLO,
            CdpTlv::VtpMgmtDomain(_) => CDP_TYPE_VTP_MGMT_DOMAIN,
            CdpTlv::NativeVlan(_) => CDP_TYPE_NATIVE_VLAN,
            CdpTlv::Duplex(_) => CDP_TYPE_DUPLEX,
            CdpTlv::VoipVlanReply(_) => CDP_TYPE_VOIP_VLAN_REPLY,
            CdpTlv::VoipVlanQuery(_) => CDP_TYPE_VOIP_VLAN_QUERY,
            CdpTlv::Mtu(_) => CDP_TYPE_MTU,
            CdpTlv::TrustBitmap(_) => CDP_TYPE_TRUST_BITMAP,
            CdpTlv::UntrustedPortCoS(_) => CDP_TYPE_UNTRUSTED_COS,
            CdpTlv::SystemName(_) => CDP_TYPE_SYSTEM_NAME,
            CdpTlv::SystemObjectId(_) => CDP_TYPE_SYSTEM_OID,
            CdpTlv::ManagementAddress(_) => CDP_TYPE_MANAGEMENT_ADDR,
            CdpTlv::PhysicalLocation(_) => CDP_TYPE_LOCATION,
            CdpTlv::Unknown(code, _) => *code,
        }
    }

    /// Encode TLV to bytes
    fn encode(&self, buffer: &mut BytesMut) -> Result<()> {
        let type_code = self.type_code();

        match self {
            CdpTlv::DeviceId(s)
            | CdpTlv::PortId(s)
            | CdpTlv::SoftwareVersion(s)
            | CdpTlv::Platform(s)
            | CdpTlv::VtpMgmtDomain(s)
            | CdpTlv::SystemName(s)
            | CdpTlv::PhysicalLocation(s) => {
                let data = s.as_bytes();
                buffer.put_u16(type_code);
                buffer.put_u16((4 + data.len()) as u16);
                buffer.put_slice(data);
            }
            CdpTlv::Addresses(addrs) => {
                let mut tlv_data = BytesMut::new();
                tlv_data.put_u32(addrs.len() as u32); // Number of addresses

                for addr in addrs {
                    tlv_data.put_u8(0x01); // Protocol type: NLPID
                    tlv_data.put_u8(0x01); // Length: 1
                    tlv_data.put_u8(0xCC); // Protocol: IP
                    tlv_data.put_u16(4); // Address length
                    tlv_data.put_slice(&addr.octets());
                }

                buffer.put_u16(type_code);
                buffer.put_u16((4 + tlv_data.len()) as u16);
                buffer.put_slice(&tlv_data);
            }
            CdpTlv::Capabilities(caps) => {
                buffer.put_u16(type_code);
                buffer.put_u16(8);
                buffer.put_u32(caps.bits());
            }
            CdpTlv::IpPrefix(addr, prefix_len) => {
                buffer.put_u16(type_code);
                buffer.put_u16(9);
                buffer.put_slice(&addr.octets());
                buffer.put_u8(*prefix_len);
            }
            CdpTlv::NativeVlan(vlan) | CdpTlv::VoipVlanReply(vlan) => {
                buffer.put_u16(type_code);
                buffer.put_u16(6);
                buffer.put_u16(*vlan);
            }
            CdpTlv::Duplex(mode) => {
                buffer.put_u16(type_code);
                buffer.put_u16(5);
                buffer.put_u8(mode.to_u8());
            }
            CdpTlv::Mtu(mtu) => {
                buffer.put_u16(type_code);
                buffer.put_u16(8);
                buffer.put_u32(*mtu);
            }
            CdpTlv::TrustBitmap(val) | CdpTlv::UntrustedPortCoS(val) => {
                buffer.put_u16(type_code);
                buffer.put_u16(5);
                buffer.put_u8(*val);
            }
            CdpTlv::ManagementAddress(addr) => {
                // Same format as Addresses but typically single address
                let mut tlv_data = BytesMut::new();
                tlv_data.put_u32(1); // One address
                tlv_data.put_u8(0x01); // NLPID
                tlv_data.put_u8(0x01); // Length
                tlv_data.put_u8(0xCC); // IP
                tlv_data.put_u16(4);
                tlv_data.put_slice(&addr.octets());

                buffer.put_u16(type_code);
                buffer.put_u16((4 + tlv_data.len()) as u16);
                buffer.put_slice(&tlv_data);
            }
            CdpTlv::ProtocolHello(data)
            | CdpTlv::VoipVlanQuery(data)
            | CdpTlv::SystemObjectId(data)
            | CdpTlv::Unknown(_, data) => {
                buffer.put_u16(type_code);
                buffer.put_u16((4 + data.len()) as u16);
                buffer.put_slice(data);
            }
        }

        Ok(())
    }

    /// Decode TLV from bytes
    fn decode(tlv_type: u16, data: &[u8]) -> Result<Self> {
        Ok(match tlv_type {
            CDP_TYPE_DEVID => CdpTlv::DeviceId(String::from_utf8_lossy(data).to_string()),
            CDP_TYPE_ADDRESS | CDP_TYPE_MANAGEMENT_ADDR => {
                // Parse address list
                if data.len() < 4 {
                    return Err(Error::protocol("Address TLV too short"));
                }
                let num_addrs = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
                let mut addrs = Vec::new();
                let mut offset = 4;

                for _ in 0..num_addrs {
                    if offset + 7 > data.len() {
                        break;
                    }
                    let proto_type = data[offset];
                    let proto_len = data[offset + 1];
                    let protocol = data[offset + 2];
                    let addr_len = u16::from_be_bytes([data[offset + 3], data[offset + 4]]);

                    if proto_type == 0x01
                        && proto_len == 0x01
                        && protocol == 0xCC
                        && addr_len == 4
                        && offset + 5 + 4 <= data.len()
                    {
                        let ip = Ipv4Addr::new(
                            data[offset + 5],
                            data[offset + 6],
                            data[offset + 7],
                            data[offset + 8],
                        );
                        addrs.push(ip);
                        offset += 9;
                    }
                }

                if tlv_type == CDP_TYPE_MANAGEMENT_ADDR && !addrs.is_empty() {
                    CdpTlv::ManagementAddress(addrs[0])
                } else {
                    CdpTlv::Addresses(addrs)
                }
            }
            CDP_TYPE_PORTID => CdpTlv::PortId(String::from_utf8_lossy(data).to_string()),
            CDP_TYPE_CAPABILITY => {
                if data.len() < 4 {
                    return Err(Error::protocol("Capabilities TLV too short"));
                }
                let bits = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
                CdpTlv::Capabilities(CdpCapabilities::from_bits(bits))
            }
            CDP_TYPE_VERSION => CdpTlv::SoftwareVersion(String::from_utf8_lossy(data).to_string()),
            CDP_TYPE_PLATFORM => CdpTlv::Platform(String::from_utf8_lossy(data).to_string()),
            CDP_TYPE_IPPREFIX => {
                if data.len() < 5 {
                    return Err(Error::protocol("IP Prefix TLV too short"));
                }
                let ip = Ipv4Addr::new(data[0], data[1], data[2], data[3]);
                let prefix_len = data[4];
                CdpTlv::IpPrefix(ip, prefix_len)
            }
            CDP_TYPE_VTP_MGMT_DOMAIN => {
                CdpTlv::VtpMgmtDomain(String::from_utf8_lossy(data).to_string())
            }
            CDP_TYPE_NATIVE_VLAN => {
                if data.len() < 2 {
                    return Err(Error::protocol("Native VLAN TLV too short"));
                }
                CdpTlv::NativeVlan(u16::from_be_bytes([data[0], data[1]]))
            }
            CDP_TYPE_DUPLEX => {
                if data.is_empty() {
                    return Err(Error::protocol("Duplex TLV too short"));
                }
                CdpTlv::Duplex(DuplexMode::from_u8(data[0]))
            }
            CDP_TYPE_VOIP_VLAN_REPLY => {
                if data.len() < 2 {
                    return Err(Error::protocol("VoIP VLAN Reply TLV too short"));
                }
                CdpTlv::VoipVlanReply(u16::from_be_bytes([data[0], data[1]]))
            }
            CDP_TYPE_MTU => {
                if data.len() < 4 {
                    return Err(Error::protocol("MTU TLV too short"));
                }
                CdpTlv::Mtu(u32::from_be_bytes([data[0], data[1], data[2], data[3]]))
            }
            CDP_TYPE_TRUST_BITMAP => {
                if data.is_empty() {
                    return Err(Error::protocol("Trust Bitmap TLV too short"));
                }
                CdpTlv::TrustBitmap(data[0])
            }
            CDP_TYPE_UNTRUSTED_COS => {
                if data.is_empty() {
                    return Err(Error::protocol("Untrusted CoS TLV too short"));
                }
                CdpTlv::UntrustedPortCoS(data[0])
            }
            CDP_TYPE_SYSTEM_NAME => CdpTlv::SystemName(String::from_utf8_lossy(data).to_string()),
            CDP_TYPE_SYSTEM_OID => CdpTlv::SystemObjectId(data.to_vec()),
            CDP_TYPE_LOCATION => {
                CdpTlv::PhysicalLocation(String::from_utf8_lossy(data).to_string())
            }
            CDP_TYPE_PROTOCOL_HELLO => CdpTlv::ProtocolHello(data.to_vec()),
            CDP_TYPE_VOIP_VLAN_QUERY => CdpTlv::VoipVlanQuery(data.to_vec()),
            _ => CdpTlv::Unknown(tlv_type, data.to_vec()),
        })
    }
}

/// CDP TLV type constants
pub const CDP_TYPE_DEVID: u16 = 0x0001;
pub const CDP_TYPE_ADDRESS: u16 = 0x0002;
pub const CDP_TYPE_PORTID: u16 = 0x0003;
pub const CDP_TYPE_CAPABILITY: u16 = 0x0004;
pub const CDP_TYPE_VERSION: u16 = 0x0005;
pub const CDP_TYPE_PLATFORM: u16 = 0x0006;
pub const CDP_TYPE_IPPREFIX: u16 = 0x0007;
pub const CDP_TYPE_PROTOCOL_HELLO: u16 = 0x0008;
pub const CDP_TYPE_VTP_MGMT_DOMAIN: u16 = 0x0009;
pub const CDP_TYPE_NATIVE_VLAN: u16 = 0x000A;
pub const CDP_TYPE_DUPLEX: u16 = 0x000B;
pub const CDP_TYPE_VOIP_VLAN_REPLY: u16 = 0x000E;
pub const CDP_TYPE_VOIP_VLAN_QUERY: u16 = 0x000F;
pub const CDP_TYPE_MTU: u16 = 0x0011;
pub const CDP_TYPE_TRUST_BITMAP: u16 = 0x0012;
pub const CDP_TYPE_UNTRUSTED_COS: u16 = 0x0013;
pub const CDP_TYPE_SYSTEM_NAME: u16 = 0x0014;
pub const CDP_TYPE_SYSTEM_OID: u16 = 0x0015;
pub const CDP_TYPE_MANAGEMENT_ADDR: u16 = 0x0016;
pub const CDP_TYPE_LOCATION: u16 = 0x0017;

/// CDP device capabilities bitflags
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CdpCapabilities {
    bits: u32,
}

impl CdpCapabilities {
    pub const ROUTER: u32 = 0x01;
    pub const TRANSPARENT_BRIDGE: u32 = 0x02;
    pub const SOURCE_ROUTE_BRIDGE: u32 = 0x04;
    pub const SWITCH: u32 = 0x08;
    pub const HOST: u32 = 0x10;
    pub const IGMP: u32 = 0x20;
    pub const REPEATER: u32 = 0x40;

    pub fn new() -> Self {
        Self { bits: 0 }
    }

    pub fn from_bits(bits: u32) -> Self {
        Self { bits }
    }

    pub fn bits(&self) -> u32 {
        self.bits
    }

    pub fn with_router(mut self) -> Self {
        self.bits |= Self::ROUTER;
        self
    }

    pub fn with_switch(mut self) -> Self {
        self.bits |= Self::SWITCH;
        self
    }

    pub fn with_bridge(mut self) -> Self {
        self.bits |= Self::TRANSPARENT_BRIDGE;
        self
    }

    pub fn with_host(mut self) -> Self {
        self.bits |= Self::HOST;
        self
    }

    pub fn is_router(&self) -> bool {
        self.bits & Self::ROUTER != 0
    }

    pub fn is_switch(&self) -> bool {
        self.bits & Self::SWITCH != 0
    }

    pub fn is_bridge(&self) -> bool {
        self.bits & Self::TRANSPARENT_BRIDGE != 0
    }
}

impl Default for CdpCapabilities {
    fn default() -> Self {
        Self::new()
    }
}

/// Duplex mode
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DuplexMode {
    Half,
    Full,
}

impl DuplexMode {
    pub fn to_u8(self) -> u8 {
        match self {
            DuplexMode::Half => 0x00,
            DuplexMode::Full => 0x01,
        }
    }

    pub fn from_u8(val: u8) -> Self {
        if val == 0x01 {
            DuplexMode::Full
        } else {
            DuplexMode::Half
        }
    }
}

/// Calculate CDP checksum
///
/// CDP uses the standard Internet checksum algorithm (RFC 1071)
/// The checksum is calculated over the entire CDP packet (version, TTL, checksum field, TLVs)
fn calculate_checksum(data: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut i = 0;

    // Sum 16-bit words
    while i < data.len() - 1 {
        let word = u16::from_be_bytes([data[i], data[i + 1]]);
        sum += word as u32;
        i += 2;
    }

    // Add leftover byte if odd length
    if i < data.len() {
        sum += (data[i] as u32) << 8;
    }

    // Fold 32-bit sum to 16 bits
    while (sum >> 16) != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    // Return one's complement
    !sum as u16
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cdp_packet_build() {
        let packet = CdpPacket::new()
            .with_version(CDP_VERSION)
            .with_ttl(180)
            .add_tlv(CdpTlv::DeviceId("Router1".to_string()))
            .add_tlv(CdpTlv::PortId("FastEthernet0/1".to_string()));

        let bytes = packet.build().unwrap();

        assert!(bytes.len() > 4);
        assert_eq!(bytes[0], CDP_VERSION);
        assert_eq!(bytes[1], 180);
    }

    #[test]
    fn test_cdp_packet_roundtrip() {
        let original = CdpPacket::new()
            .add_tlv(CdpTlv::DeviceId("TestDevice".to_string()))
            .add_tlv(CdpTlv::PortId("Eth0".to_string()))
            .add_tlv(CdpTlv::Capabilities(
                CdpCapabilities::new().with_router().with_switch(),
            ));

        let bytes = original.build().unwrap();
        let parsed = CdpPacket::parse(&bytes).unwrap();

        assert_eq!(original.version, parsed.version);
        assert_eq!(original.ttl, parsed.ttl);
        assert_eq!(original.tlvs.len(), parsed.tlvs.len());
    }

    #[test]
    fn test_capabilities() {
        let caps = CdpCapabilities::new().with_router().with_switch();

        assert!(caps.is_router());
        assert!(caps.is_switch());
        assert!(!caps.is_bridge());
    }

    #[test]
    fn test_address_tlv() {
        let addr = Ipv4Addr::new(192, 168, 1, 1);
        let tlv = CdpTlv::Addresses(vec![addr]);

        let mut buffer = BytesMut::new();
        tlv.encode(&mut buffer).unwrap();

        assert!(buffer.len() > 4);
    }

    #[test]
    fn test_checksum_calculation() {
        let data = vec![0x02, 0xb4, 0x00, 0x00]; // version, ttl, checksum placeholder
        let checksum = calculate_checksum(&data);

        // Checksum should be non-zero for this data
        assert_ne!(checksum, 0);
    }

    #[test]
    fn test_duplex_mode() {
        assert_eq!(DuplexMode::Full.to_u8(), 0x01);
        assert_eq!(DuplexMode::Half.to_u8(), 0x00);
        assert_eq!(DuplexMode::from_u8(0x01), DuplexMode::Full);
        assert_eq!(DuplexMode::from_u8(0x00), DuplexMode::Half);
    }
}
