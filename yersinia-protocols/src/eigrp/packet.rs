//! EIGRP Packet Structures

use std::net::Ipv4Addr;

pub const EIGRP_PROTOCOL: u8 = 88;
pub const EIGRP_MULTICAST: [u8; 4] = [224, 0, 0, 10];
pub const EIGRP_VERSION: u8 = 2;

/// EIGRP Opcodes
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum EigrpOpcode {
    Update = 1,
    Request = 2,
    Query = 3,
    Reply = 4,
    Hello = 5,
    Ack = 6,       // Hello with no data
    SiaQuery = 10, // Stuck-in-Active Query
    SiaReply = 11, // Stuck-in-Active Reply
}

impl EigrpOpcode {
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            1 => Some(Self::Update),
            2 => Some(Self::Request),
            3 => Some(Self::Query),
            4 => Some(Self::Reply),
            5 => Some(Self::Hello),
            6 => Some(Self::Ack),
            10 => Some(Self::SiaQuery),
            11 => Some(Self::SiaReply),
            _ => None,
        }
    }
}

/// EIGRP TLV Types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum EigrpTlvType {
    GeneralParameters = 0x0001,
    Authentication = 0x0002,
    Sequence = 0x0003,
    SoftwareVersion = 0x0004,
    NextMulticastSeq = 0x0005,
    PeerTermination = 0x0007,
    InternalRoute = 0x0102,
    ExternalRoute = 0x0103,
    CommunityList = 0x0104,
}

impl EigrpTlvType {
    pub fn from_u16(value: u16) -> Option<Self> {
        match value {
            0x0001 => Some(Self::GeneralParameters),
            0x0002 => Some(Self::Authentication),
            0x0003 => Some(Self::Sequence),
            0x0004 => Some(Self::SoftwareVersion),
            0x0005 => Some(Self::NextMulticastSeq),
            0x0007 => Some(Self::PeerTermination),
            0x0102 => Some(Self::InternalRoute),
            0x0103 => Some(Self::ExternalRoute),
            0x0104 => Some(Self::CommunityList),
            _ => None,
        }
    }
}

/// Route metrics for EIGRP routes
#[derive(Debug, Clone, Copy)]
pub struct RouteMetrics {
    pub delay: u32,
    pub bandwidth: u32,
    pub mtu: u32,
    pub hop_count: u8,
    pub reliability: u8,
    pub load: u8,
}

impl RouteMetrics {
    pub fn new(
        delay: u32,
        bandwidth: u32,
        mtu: u32,
        hop_count: u8,
        reliability: u8,
        load: u8,
    ) -> Self {
        Self {
            delay,
            bandwidth,
            mtu,
            hop_count,
            reliability,
            load,
        }
    }
}

/// EIGRP TLV
#[derive(Debug, Clone)]
pub struct EigrpTlv {
    pub tlv_type: EigrpTlvType,
    pub data: Vec<u8>,
}

impl EigrpTlv {
    pub fn new(tlv_type: EigrpTlvType, data: Vec<u8>) -> Self {
        Self { tlv_type, data }
    }

    /// General Parameters TLV
    pub fn general_parameters(k1: u8, k2: u8, k3: u8, k4: u8, k5: u8, hold_time: u16) -> Self {
        let mut data = vec![k1, k2, k3, k4, k5, 0];
        data.extend_from_slice(&hold_time.to_be_bytes());
        Self {
            tlv_type: EigrpTlvType::GeneralParameters,
            data,
        }
    }

    /// Software Version TLV
    pub fn software_version(major: u8, minor: u8, tlv_version: u8) -> Self {
        let data = vec![major, minor, tlv_version, 0]; // Last byte reserved
        Self {
            tlv_type: EigrpTlvType::SoftwareVersion,
            data,
        }
    }

    /// Internal Route TLV
    pub fn internal_route(network: Ipv4Addr, prefix_len: u8, metrics: RouteMetrics) -> Self {
        let mut data = Vec::new();

        // Next hop (0.0.0.0 = originator)
        data.extend_from_slice(&[0, 0, 0, 0]);

        // Delay (in 10s of microseconds)
        data.extend_from_slice(&metrics.delay.to_be_bytes());

        // Bandwidth (in units of 256 Kbps)
        data.extend_from_slice(&metrics.bandwidth.to_be_bytes());

        // MTU (24 bits)
        data.extend_from_slice(&metrics.mtu.to_be_bytes()[1..4]);

        // Hop count
        data.push(metrics.hop_count);

        // Reliability (0-255, 255 = 100%)
        data.push(metrics.reliability);

        // Load (0-255, 1 = minimally loaded)
        data.push(metrics.load);

        // Reserved
        data.push(0);
        data.push(0);

        // Prefix length
        data.push(prefix_len);

        // Network address (only significant bytes based on prefix_len)
        let bytes_needed = prefix_len.div_ceil(8) as usize;
        data.extend_from_slice(&network.octets()[..bytes_needed]);

        Self {
            tlv_type: EigrpTlvType::InternalRoute,
            data,
        }
    }

    /// External Route TLV
    pub fn external_route(
        network: Ipv4Addr,
        prefix_len: u8,
        originating_router: Ipv4Addr,
        originating_as: u32,
        external_metric: u32,
    ) -> Self {
        let mut data = Vec::new();

        // Next hop
        data.extend_from_slice(&[0, 0, 0, 0]);

        // Originating router
        data.extend_from_slice(&originating_router.octets());

        // Originating AS
        data.extend_from_slice(&originating_as.to_be_bytes());

        // External metric
        data.extend_from_slice(&external_metric.to_be_bytes());

        // Reserved fields, flags, etc. (simplified)
        data.extend_from_slice(&[0u8; 8]);

        // Prefix length
        data.push(prefix_len);

        // Network address
        let bytes_needed = prefix_len.div_ceil(8) as usize;
        data.extend_from_slice(&network.octets()[..bytes_needed]);

        Self {
            tlv_type: EigrpTlvType::ExternalRoute,
            data,
        }
    }

    /// Encode TLV to bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&(self.tlv_type as u16).to_be_bytes());
        bytes.extend_from_slice(&((self.data.len() + 4) as u16).to_be_bytes());
        bytes.extend_from_slice(&self.data);
        bytes
    }

    /// Parse TLV from bytes
    pub fn from_bytes(data: &[u8]) -> Option<(Self, usize)> {
        if data.len() < 4 {
            return None;
        }

        let tlv_type = u16::from_be_bytes([data[0], data[1]]);
        let length = u16::from_be_bytes([data[2], data[3]]) as usize;

        if data.len() < length {
            return None;
        }

        let tlv_type = EigrpTlvType::from_u16(tlv_type)?;
        let tlv_data = data[4..length].to_vec();

        Some((
            Self {
                tlv_type,
                data: tlv_data,
            },
            length,
        ))
    }
}

/// EIGRP Packet Header
#[derive(Debug, Clone)]
pub struct EigrpPacket {
    pub version: u8,
    pub opcode: EigrpOpcode,
    pub checksum: u16,
    pub flags: u32,
    pub sequence: u32,
    pub ack: u32,
    pub virtual_router_id: u16, // VRID (AS number for classic EIGRP)
    pub autonomous_system: u16, // AS number
    pub tlvs: Vec<EigrpTlv>,
}

impl EigrpPacket {
    pub fn new(opcode: EigrpOpcode, as_number: u16) -> Self {
        Self {
            version: EIGRP_VERSION,
            opcode,
            checksum: 0,
            flags: 0,
            sequence: 0,
            ack: 0,
            virtual_router_id: 0,
            autonomous_system: as_number,
            tlvs: vec![],
        }
    }

    pub fn with_sequence(mut self, seq: u32) -> Self {
        self.sequence = seq;
        self
    }

    pub fn with_ack(mut self, ack: u32) -> Self {
        self.ack = ack;
        self
    }

    pub fn add_tlv(mut self, tlv: EigrpTlv) -> Self {
        self.tlvs.push(tlv);
        self
    }

    /// Create HELLO packet
    pub fn hello(as_number: u16, hold_time: u16) -> Self {
        Self::new(EigrpOpcode::Hello, as_number)
            .add_tlv(EigrpTlv::general_parameters(1, 0, 1, 0, 0, hold_time))
            .add_tlv(EigrpTlv::software_version(12, 4, 1))
    }

    /// Create UPDATE packet
    pub fn update(as_number: u16, sequence: u32) -> Self {
        Self::new(EigrpOpcode::Update, as_number)
            .with_sequence(sequence)
            .add_tlv(EigrpTlv::general_parameters(1, 0, 1, 0, 0, 180))
    }

    /// Create QUERY packet
    pub fn query(as_number: u16, sequence: u32) -> Self {
        Self::new(EigrpOpcode::Query, as_number).with_sequence(sequence)
    }

    /// Create REPLY packet
    pub fn reply(as_number: u16, sequence: u32) -> Self {
        Self::new(EigrpOpcode::Reply, as_number).with_sequence(sequence)
    }

    /// Set Init flag (initial update)
    pub fn set_init_flag(mut self) -> Self {
        self.flags |= 0x01;
        self
    }

    /// Set CR flag (Conditional Receive)
    pub fn set_cr_flag(mut self) -> Self {
        self.flags |= 0x02;
        self
    }

    /// Calculate checksum (simplified - internet checksum over header + data)
    pub fn calculate_checksum(&mut self) {
        self.checksum = 0;
        let bytes = self.to_bytes_without_checksum();
        let checksum = Self::internet_checksum(&bytes);
        self.checksum = checksum;
    }

    fn internet_checksum(data: &[u8]) -> u16 {
        let mut sum: u32 = 0;
        let mut i = 0;

        while i < data.len() - 1 {
            sum += u16::from_be_bytes([data[i], data[i + 1]]) as u32;
            i += 2;
        }

        if i < data.len() {
            sum += (data[i] as u32) << 8;
        }

        while sum >> 16 != 0 {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }

        !sum as u16
    }

    fn to_bytes_without_checksum(&self) -> Vec<u8> {
        let mut bytes = Vec::new();

        bytes.push(self.version);
        bytes.push(self.opcode as u8);
        bytes.extend_from_slice(&0u16.to_be_bytes()); // checksum placeholder
        bytes.extend_from_slice(&self.flags.to_be_bytes());
        bytes.extend_from_slice(&self.sequence.to_be_bytes());
        bytes.extend_from_slice(&self.ack.to_be_bytes());
        bytes.extend_from_slice(&self.virtual_router_id.to_be_bytes());
        bytes.extend_from_slice(&self.autonomous_system.to_be_bytes());

        for tlv in &self.tlvs {
            bytes.extend_from_slice(&tlv.to_bytes());
        }

        bytes
    }

    /// Encode packet to bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();

        bytes.push(self.version);
        bytes.push(self.opcode as u8);
        bytes.extend_from_slice(&self.checksum.to_be_bytes());
        bytes.extend_from_slice(&self.flags.to_be_bytes());
        bytes.extend_from_slice(&self.sequence.to_be_bytes());
        bytes.extend_from_slice(&self.ack.to_be_bytes());
        bytes.extend_from_slice(&self.virtual_router_id.to_be_bytes());
        bytes.extend_from_slice(&self.autonomous_system.to_be_bytes());

        for tlv in &self.tlvs {
            bytes.extend_from_slice(&tlv.to_bytes());
        }

        bytes
    }

    /// Parse packet from bytes
    pub fn from_bytes(data: &[u8]) -> Option<Self> {
        if data.len() < 20 {
            return None;
        }

        let version = data[0];
        let opcode = EigrpOpcode::from_u8(data[1])?;
        let checksum = u16::from_be_bytes([data[2], data[3]]);
        let flags = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
        let sequence = u32::from_be_bytes([data[8], data[9], data[10], data[11]]);
        let ack = u32::from_be_bytes([data[12], data[13], data[14], data[15]]);
        let virtual_router_id = u16::from_be_bytes([data[16], data[17]]);
        let autonomous_system = u16::from_be_bytes([data[18], data[19]]);

        let mut tlvs = vec![];
        let mut offset = 20;

        while offset < data.len() {
            if let Some((tlv, consumed)) = EigrpTlv::from_bytes(&data[offset..]) {
                tlvs.push(tlv);
                offset += consumed;
            } else {
                break;
            }
        }

        Some(Self {
            version,
            opcode,
            checksum,
            flags,
            sequence,
            ack,
            virtual_router_id,
            autonomous_system,
            tlvs,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hello_packet() {
        let mut packet = EigrpPacket::hello(100, 180);
        packet.calculate_checksum();

        let bytes = packet.to_bytes();
        assert_eq!(bytes[0], EIGRP_VERSION);
        assert_eq!(bytes[1], EigrpOpcode::Hello as u8);

        let decoded = EigrpPacket::from_bytes(&bytes).unwrap();
        assert_eq!(decoded.opcode, EigrpOpcode::Hello);
        assert_eq!(decoded.autonomous_system, 100);
    }

    #[test]
    fn test_internal_route_tlv() {
        let metrics = RouteMetrics::new(100, 10000, 1500, 1, 255, 1);
        let tlv = EigrpTlv::internal_route("192.168.1.0".parse().unwrap(), 24, metrics);

        let bytes = tlv.to_bytes();
        assert_eq!(u16::from_be_bytes([bytes[0], bytes[1]]), 0x0102);

        let (decoded, _consumed) = EigrpTlv::from_bytes(&bytes).unwrap();
        assert_eq!(decoded.tlv_type, EigrpTlvType::InternalRoute);
    }
}
