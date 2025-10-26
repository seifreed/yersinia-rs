//! PIM Packet Structures
use std::net::Ipv4Addr;

pub const PIM_PROTOCOL: u8 = 103;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum PimType {
    Hello = 0,
    Register = 1,
    RegisterStop = 2,
    JoinPrune = 3,
    Bootstrap = 4,
    Assert = 5,
    Graft = 6,
    GraftAck = 7,
    CandidateRpAdvertisement = 8,
}

#[derive(Debug, Clone)]
pub struct PimPacket {
    pub version: u8,
    pub pim_type: PimType,
    pub reserved: u8,
    pub checksum: u16,
    pub payload: Vec<u8>,
}

impl PimPacket {
    pub fn new(pim_type: PimType) -> Self {
        Self {
            version: 2,
            pim_type,
            reserved: 0,
            checksum: 0,
            payload: vec![],
        }
    }

    pub fn hello() -> Self {
        Self::new(PimType::Hello)
    }
    pub fn join_prune() -> Self {
        Self::new(PimType::JoinPrune)
    }
    pub fn candidate_rp(rp_addr: Ipv4Addr, priority: u8) -> Self {
        let mut pkt = Self::new(PimType::CandidateRpAdvertisement);
        pkt.payload.extend_from_slice(&rp_addr.octets());
        pkt.payload.push(priority);
        pkt
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.push((self.version << 4) | (self.pim_type as u8));
        bytes.push(self.reserved);
        bytes.extend_from_slice(&self.checksum.to_be_bytes());
        bytes.extend_from_slice(&self.payload);
        bytes
    }
}
