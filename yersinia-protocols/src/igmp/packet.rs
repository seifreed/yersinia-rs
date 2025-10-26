//! IGMP/MLD Packet Structures

use std::net::{Ipv4Addr, Ipv6Addr};

pub const IGMP_PROTOCOL: u8 = 2;
pub const IGMP_ALL_SYSTEMS: [u8; 4] = [224, 0, 0, 1];
pub const IGMP_ALL_ROUTERS: [u8; 4] = [224, 0, 0, 2];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IgmpVersion {
    V1,
    V2,
    V3,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum IgmpType {
    MembershipQuery = 0x11,
    V1MembershipReport = 0x12,
    V2MembershipReport = 0x16,
    LeaveGroup = 0x17,
    V3MembershipReport = 0x22,
}

#[derive(Debug, Clone)]
pub struct IgmpPacket {
    pub igmp_type: IgmpType,
    pub max_resp_time: u8,
    pub checksum: u16,
    pub group_address: Ipv4Addr,
    pub data: Vec<u8>,
}

impl IgmpPacket {
    pub fn membership_query(group: Ipv4Addr, max_resp_time: u8) -> Self {
        Self {
            igmp_type: IgmpType::MembershipQuery,
            max_resp_time,
            checksum: 0,
            group_address: group,
            data: vec![],
        }
    }

    pub fn membership_report_v2(group: Ipv4Addr) -> Self {
        Self {
            igmp_type: IgmpType::V2MembershipReport,
            max_resp_time: 0,
            checksum: 0,
            group_address: group,
            data: vec![],
        }
    }

    pub fn leave_group(group: Ipv4Addr) -> Self {
        Self {
            igmp_type: IgmpType::LeaveGroup,
            max_resp_time: 0,
            checksum: 0,
            group_address: group,
            data: vec![],
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.push(self.igmp_type as u8);
        bytes.push(self.max_resp_time);
        bytes.extend_from_slice(&self.checksum.to_be_bytes());
        bytes.extend_from_slice(&self.group_address.octets());
        bytes.extend_from_slice(&self.data);
        bytes
    }

    pub fn calculate_checksum(&mut self) {
        self.checksum = 0;
        let bytes = self.to_bytes();
        let mut sum: u32 = 0;
        for i in (0..bytes.len()).step_by(2) {
            let word = if i + 1 < bytes.len() {
                u16::from_be_bytes([bytes[i], bytes[i + 1]])
            } else {
                u16::from_be_bytes([bytes[i], 0])
            };
            sum += word as u32;
        }
        while sum >> 16 != 0 {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }
        self.checksum = !sum as u16;
    }
}

// MLD (IPv6)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum MldType {
    MulticastListenerQuery = 130,
    MulticastListenerReport = 131,
    MulticastListenerDone = 132,
    MulticastListenerReportV2 = 143,
}

#[derive(Debug, Clone)]
pub struct MldPacket {
    pub mld_type: MldType,
    pub code: u8,
    pub checksum: u16,
    pub max_resp_delay: u16,
    pub multicast_address: Ipv6Addr,
}

impl MldPacket {
    pub fn query(multicast_addr: Ipv6Addr) -> Self {
        Self {
            mld_type: MldType::MulticastListenerQuery,
            code: 0,
            checksum: 0,
            max_resp_delay: 10000,
            multicast_address: multicast_addr,
        }
    }

    pub fn report(multicast_addr: Ipv6Addr) -> Self {
        Self {
            mld_type: MldType::MulticastListenerReport,
            code: 0,
            checksum: 0,
            max_resp_delay: 0,
            multicast_address: multicast_addr,
        }
    }

    pub fn done(multicast_addr: Ipv6Addr) -> Self {
        Self {
            mld_type: MldType::MulticastListenerDone,
            code: 0,
            checksum: 0,
            max_resp_delay: 0,
            multicast_address: multicast_addr,
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.push(self.mld_type as u8);
        bytes.push(self.code);
        bytes.extend_from_slice(&self.checksum.to_be_bytes());
        bytes.extend_from_slice(&self.max_resp_delay.to_be_bytes());
        bytes.extend_from_slice(&[0u8; 2]); // Reserved
        bytes.extend_from_slice(&self.multicast_address.octets());
        bytes
    }
}
