//! VTP Packet Parser and Builder
//!
//! Complete implementation of VLAN Trunking Protocol (Cisco) packet parsing and construction.
//! Supports VTP versions 1, 2, and 3 with all message types.

use bytes::{BufMut, BytesMut};
use md5::{Digest, Md5};
use std::net::Ipv4Addr;
use yersinia_core::{Error, Result};

/// VTP multicast MAC address (01:00:0C:CC:CC:CC)
pub const VTP_MULTICAST_MAC: [u8; 6] = [0x01, 0x00, 0x0C, 0xCC, 0xCC, 0xCC];

/// VTP SNAP type (used in LLC/SNAP header)
pub const VTP_SNAP_TYPE: u16 = 0x2003;

/// VTP SNAP OUI (Cisco)
pub const VTP_SNAP_OUI: [u8; 3] = [0x00, 0x00, 0x0C];

/// Maximum VTP domain name length
pub const VTP_DOMAIN_NAME_MAX: usize = 32;

/// VTP MD5 digest size
pub const VTP_MD5_DIGEST_SIZE: usize = 16;

/// VTP timestamp size
pub const VTP_TIMESTAMP_SIZE: usize = 12;

/// Maximum VLAN name size
pub const VLAN_NAME_SIZE: usize = 32;

/// VTP 802.10 SAID base value
pub const VTP_DOT10_BASE: u32 = 0x100000;

/// VTP protocol versions
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VtpVersion {
    Version1 = 0x01,
    Version2 = 0x02,
    Version3 = 0x03,
}

impl VtpVersion {
    pub fn from_u8(val: u8) -> Option<Self> {
        match val {
            0x01 => Some(VtpVersion::Version1),
            0x02 => Some(VtpVersion::Version2),
            0x03 => Some(VtpVersion::Version3),
            _ => None,
        }
    }

    pub fn to_u8(self) -> u8 {
        self as u8
    }
}

/// VTP message types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VtpMessageType {
    /// Summary Advertisement (0x01)
    SummaryAdvertisement = 0x01,
    /// Subset Advertisement (0x02)
    SubsetAdvertisement = 0x02,
    /// Advertisement Request (0x03)
    AdvertisementRequest = 0x03,
    /// Join (0x04)
    Join = 0x04,
}

impl VtpMessageType {
    pub fn from_u8(val: u8) -> Option<Self> {
        match val {
            0x01 => Some(VtpMessageType::SummaryAdvertisement),
            0x02 => Some(VtpMessageType::SubsetAdvertisement),
            0x03 => Some(VtpMessageType::AdvertisementRequest),
            0x04 => Some(VtpMessageType::Join),
            _ => None,
        }
    }

    pub fn to_u8(self) -> u8 {
        self as u8
    }
}

/// VLAN types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VlanType {
    Ethernet = 0x01,
    Fddi = 0x02,
    TokenRingCrf = 0x03,
    FddiNet = 0x04,
    TokenRingBrf = 0x05,
}

impl VlanType {
    pub fn from_u8(val: u8) -> Option<Self> {
        match val {
            0x01 => Some(VlanType::Ethernet),
            0x02 => Some(VlanType::Fddi),
            0x03 => Some(VlanType::TokenRingCrf),
            0x04 => Some(VlanType::FddiNet),
            0x05 => Some(VlanType::TokenRingBrf),
            _ => None,
        }
    }

    pub fn to_u8(self) -> u8 {
        self as u8
    }
}

/// VLAN status flags
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VlanStatus {
    Operational = 0x00,
    Suspended = 0x01,
}

impl VlanStatus {
    pub fn from_u8(val: u8) -> Self {
        if val == 0x01 {
            VlanStatus::Suspended
        } else {
            VlanStatus::Operational
        }
    }

    pub fn to_u8(self) -> u8 {
        self as u8
    }
}

/// VTP mode (server/client/transparent)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VtpMode {
    Server,
    Client,
    Transparent,
}

/// VLAN information structure
#[derive(Debug, Clone, PartialEq)]
pub struct VlanInfo {
    /// VLAN status
    pub status: VlanStatus,
    /// VLAN type
    pub vlan_type: VlanType,
    /// VLAN ID (1-4094)
    pub vlan_id: u16,
    /// MTU size
    pub mtu: u16,
    /// 802.10 SAID (Security Association Identifier)
    pub dot10_said: u32,
    /// VLAN name
    pub vlan_name: String,
}

impl VlanInfo {
    /// Create a new VLAN info with defaults
    pub fn new(vlan_id: u16, vlan_name: String) -> Self {
        Self {
            status: VlanStatus::Operational,
            vlan_type: VlanType::Ethernet,
            vlan_id,
            mtu: 1500,
            dot10_said: VTP_DOT10_BASE + vlan_id as u32,
            vlan_name,
        }
    }

    /// Calculate aligned length for encoding (4-byte aligned)
    fn aligned_name_len(&self) -> usize {
        let name_len = self.vlan_name.len();
        4 * name_len.div_ceil(4)
    }

    /// Total length when encoded
    pub fn encoded_len(&self) -> usize {
        // len(1) + status(1) + type(1) + name_len(1) + id(2) + mtu(2) + dot10(4) + name(aligned)
        12 + self.aligned_name_len()
    }

    /// Encode VLAN info to bytes
    pub fn encode(&self, buffer: &mut BytesMut) -> Result<()> {
        let name_bytes = self.vlan_name.as_bytes();
        let name_len = name_bytes.len().min(VLAN_NAME_SIZE);
        let aligned_len = self.aligned_name_len();
        let total_len = 12 + aligned_len;

        buffer.put_u8(total_len as u8);
        buffer.put_u8(self.status.to_u8());
        buffer.put_u8(self.vlan_type.to_u8());
        buffer.put_u8(name_len as u8);
        buffer.put_u16(self.vlan_id);
        buffer.put_u16(self.mtu);
        buffer.put_u32(self.dot10_said);

        // Write name (truncate if needed)
        buffer.put_slice(&name_bytes[..name_len]);

        // Pad to 4-byte alignment
        for _ in 0..(aligned_len - name_len) {
            buffer.put_u8(0);
        }

        Ok(())
    }

    /// Decode VLAN info from bytes
    pub fn decode(data: &[u8]) -> Result<(Self, usize)> {
        if data.len() < 12 {
            return Err(Error::protocol("VLAN info too short"));
        }

        let total_len = data[0] as usize;
        if total_len < 12 || data.len() < total_len {
            return Err(Error::protocol("Invalid VLAN info length"));
        }

        let status = VlanStatus::from_u8(data[1]);
        let vlan_type =
            VlanType::from_u8(data[2]).ok_or_else(|| Error::protocol("Invalid VLAN type"))?;
        let name_len = data[3] as usize;
        let vlan_id = u16::from_be_bytes([data[4], data[5]]);
        let mtu = u16::from_be_bytes([data[6], data[7]]);
        let dot10_said = u32::from_be_bytes([data[8], data[9], data[10], data[11]]);

        let name_end = 12 + name_len.min(total_len - 12);
        let vlan_name = String::from_utf8_lossy(&data[12..name_end]).to_string();

        Ok((
            VlanInfo {
                status,
                vlan_type,
                vlan_id,
                mtu,
                dot10_said,
                vlan_name,
            },
            total_len,
        ))
    }
}

/// Complete VTP packet
#[derive(Debug, Clone, PartialEq)]
pub struct VtpPacket {
    /// VTP version
    pub version: VtpVersion,
    /// Message type
    pub message_type: VtpMessageType,
    /// Management domain name
    pub domain_name: String,
    /// Configuration revision number
    pub revision: u32,
    /// Message-specific data
    pub data: VtpMessageData,
}

/// VTP message-specific data
#[derive(Debug, Clone, PartialEq)]
pub enum VtpMessageData {
    /// Summary Advertisement
    Summary {
        /// Number of subset advertisements to follow
        followers: u8,
        /// Updater identity (IP address)
        updater_identity: Ipv4Addr,
        /// Update timestamp (12 bytes)
        update_timestamp: [u8; VTP_TIMESTAMP_SIZE],
        /// MD5 digest (16 bytes)
        md5_digest: [u8; VTP_MD5_DIGEST_SIZE],
    },
    /// Subset Advertisement
    Subset {
        /// Sequence number
        sequence: u8,
        /// List of VLANs
        vlans: Vec<VlanInfo>,
    },
    /// Advertisement Request
    Request {
        /// Start value
        start_value: u16,
    },
    /// Join message
    Join {
        /// VLAN ID
        vlan: u32,
    },
}

impl VtpPacket {
    /// Create a new VTP Summary Advertisement
    pub fn new_summary(
        version: VtpVersion,
        domain_name: String,
        revision: u32,
        followers: u8,
        updater_identity: Ipv4Addr,
    ) -> Self {
        Self {
            version,
            message_type: VtpMessageType::SummaryAdvertisement,
            domain_name,
            revision,
            data: VtpMessageData::Summary {
                followers,
                updater_identity,
                update_timestamp: [0; VTP_TIMESTAMP_SIZE],
                md5_digest: [0; VTP_MD5_DIGEST_SIZE],
            },
        }
    }

    /// Create a new VTP Subset Advertisement
    pub fn new_subset(
        version: VtpVersion,
        domain_name: String,
        revision: u32,
        sequence: u8,
        vlans: Vec<VlanInfo>,
    ) -> Self {
        Self {
            version,
            message_type: VtpMessageType::SubsetAdvertisement,
            domain_name,
            revision,
            data: VtpMessageData::Subset { sequence, vlans },
        }
    }

    /// Create a new VTP Advertisement Request
    pub fn new_request(version: VtpVersion, domain_name: String, start_value: u16) -> Self {
        Self {
            version,
            message_type: VtpMessageType::AdvertisementRequest,
            domain_name,
            revision: 0,
            data: VtpMessageData::Request { start_value },
        }
    }

    /// Create a new VTP Join message
    pub fn new_join(version: VtpVersion, domain_name: String, vlan: u32) -> Self {
        Self {
            version,
            message_type: VtpMessageType::Join,
            domain_name,
            revision: 0,
            data: VtpMessageData::Join { vlan },
        }
    }

    /// Calculate and set MD5 digest for Summary Advertisement
    pub fn calculate_md5(&mut self, password: Option<&str>, vlans: &[VlanInfo]) -> Result<()> {
        if let VtpMessageData::Summary {
            ref mut md5_digest,
            updater_identity,
            ..
        } = self.data
        {
            let digest = calculate_vtp_md5(
                password,
                updater_identity,
                self.revision,
                &self.domain_name,
                vlans,
                self.version,
            )?;
            md5_digest.copy_from_slice(&digest);
            Ok(())
        } else {
            Err(Error::protocol(
                "Can only calculate MD5 for Summary Advertisement",
            ))
        }
    }

    /// Set timestamp for Summary Advertisement
    pub fn set_timestamp(&mut self, timestamp: [u8; VTP_TIMESTAMP_SIZE]) -> Result<()> {
        if let VtpMessageData::Summary {
            ref mut update_timestamp,
            ..
        } = self.data
        {
            *update_timestamp = timestamp;
            Ok(())
        } else {
            Err(Error::protocol(
                "Can only set timestamp for Summary Advertisement",
            ))
        }
    }

    /// Build the packet into bytes (without LLC/SNAP header)
    pub fn build(&self) -> Result<Vec<u8>> {
        let mut buffer = BytesMut::new();

        // Common header fields
        buffer.put_u8(self.version.to_u8());
        buffer.put_u8(self.message_type.to_u8());

        match &self.data {
            VtpMessageData::Summary {
                followers,
                updater_identity,
                update_timestamp,
                md5_digest,
            } => {
                buffer.put_u8(*followers);

                // Domain name length and domain (32 bytes max)
                let dom_bytes = self.domain_name.as_bytes();
                let dom_len = dom_bytes.len().min(VTP_DOMAIN_NAME_MAX);
                buffer.put_u8(dom_len as u8);
                buffer.put_slice(&dom_bytes[..dom_len]);
                // Pad to 32 bytes
                for _ in dom_len..VTP_DOMAIN_NAME_MAX {
                    buffer.put_u8(0);
                }

                // Revision, updater, timestamp, MD5
                buffer.put_u32(self.revision);
                buffer.put_slice(&updater_identity.octets());
                buffer.put_slice(update_timestamp);
                buffer.put_slice(md5_digest);
            }
            VtpMessageData::Subset { sequence, vlans } => {
                buffer.put_u8(*sequence);

                // Domain name
                let dom_bytes = self.domain_name.as_bytes();
                let dom_len = dom_bytes.len().min(VTP_DOMAIN_NAME_MAX);
                buffer.put_u8(dom_len as u8);
                buffer.put_slice(&dom_bytes[..dom_len]);
                for _ in dom_len..VTP_DOMAIN_NAME_MAX {
                    buffer.put_u8(0);
                }

                // Revision
                buffer.put_u32(self.revision);

                // VLAN information
                for vlan in vlans {
                    vlan.encode(&mut buffer)?;
                }
            }
            VtpMessageData::Request { start_value } => {
                buffer.put_u8(0); // Reserved

                // Domain name
                let dom_bytes = self.domain_name.as_bytes();
                let dom_len = dom_bytes.len().min(VTP_DOMAIN_NAME_MAX);
                buffer.put_u8(dom_len as u8);
                buffer.put_slice(&dom_bytes[..dom_len]);
                for _ in dom_len..VTP_DOMAIN_NAME_MAX {
                    buffer.put_u8(0);
                }

                // Start value
                buffer.put_u16(*start_value);
            }
            VtpMessageData::Join { vlan } => {
                buffer.put_u8(0); // Maybe reserved

                // Domain name
                let dom_bytes = self.domain_name.as_bytes();
                let dom_len = dom_bytes.len().min(VTP_DOMAIN_NAME_MAX);
                buffer.put_u8(dom_len as u8);
                buffer.put_slice(&dom_bytes[..dom_len]);
                for _ in dom_len..VTP_DOMAIN_NAME_MAX {
                    buffer.put_u8(0);
                }

                // VLAN
                buffer.put_u32(*vlan);

                // Unknown data (126 bytes)
                buffer.put_u8(0x40);
                for _ in 1..126 {
                    buffer.put_u8(0);
                }
            }
        }

        Ok(buffer.to_vec())
    }

    /// Build complete frame with LLC/SNAP header
    pub fn build_with_llc(&self) -> Result<Vec<u8>> {
        let mut buffer = BytesMut::new();

        // LLC header (DSAP=0xAA, SSAP=0xAA, Control=0x03)
        buffer.put_u8(0xAA);
        buffer.put_u8(0xAA);
        buffer.put_u8(0x03);

        // SNAP header (OUI + Type)
        buffer.put_slice(&VTP_SNAP_OUI);
        buffer.put_u16(VTP_SNAP_TYPE);

        // VTP packet
        let vtp_data = self.build()?;
        buffer.put_slice(&vtp_data);

        Ok(buffer.to_vec())
    }

    /// Parse a VTP packet from bytes (assumes LLC/SNAP already stripped)
    pub fn parse(data: &[u8]) -> Result<Self> {
        if data.len() < 4 {
            return Err(Error::protocol("VTP packet too short"));
        }

        let version =
            VtpVersion::from_u8(data[0]).ok_or_else(|| Error::protocol("Invalid VTP version"))?;
        let message_type = VtpMessageType::from_u8(data[1])
            .ok_or_else(|| Error::protocol("Invalid VTP message type"))?;

        let mut offset = 2;

        match message_type {
            VtpMessageType::SummaryAdvertisement => {
                if data.len() < 68 {
                    return Err(Error::protocol("VTP Summary Advertisement too short"));
                }

                let followers = data[offset];
                offset += 1;

                let dom_len = data[offset] as usize;
                offset += 1;

                let domain_name = if dom_len <= VTP_DOMAIN_NAME_MAX {
                    String::from_utf8_lossy(&data[offset..offset + dom_len]).to_string()
                } else {
                    String::from_utf8_lossy(&data[offset..offset + VTP_DOMAIN_NAME_MAX]).to_string()
                };
                offset += VTP_DOMAIN_NAME_MAX;

                let revision = u32::from_be_bytes([
                    data[offset],
                    data[offset + 1],
                    data[offset + 2],
                    data[offset + 3],
                ]);
                offset += 4;

                let updater_identity = Ipv4Addr::new(
                    data[offset],
                    data[offset + 1],
                    data[offset + 2],
                    data[offset + 3],
                );
                offset += 4;

                let mut update_timestamp = [0u8; VTP_TIMESTAMP_SIZE];
                update_timestamp.copy_from_slice(&data[offset..offset + VTP_TIMESTAMP_SIZE]);
                offset += VTP_TIMESTAMP_SIZE;

                let mut md5_digest = [0u8; VTP_MD5_DIGEST_SIZE];
                md5_digest.copy_from_slice(&data[offset..offset + VTP_MD5_DIGEST_SIZE]);

                Ok(VtpPacket {
                    version,
                    message_type,
                    domain_name,
                    revision,
                    data: VtpMessageData::Summary {
                        followers,
                        updater_identity,
                        update_timestamp,
                        md5_digest,
                    },
                })
            }
            VtpMessageType::SubsetAdvertisement => {
                if data.len() < 40 {
                    return Err(Error::protocol("VTP Subset Advertisement too short"));
                }

                let sequence = data[offset];
                offset += 1;

                let dom_len = data[offset] as usize;
                offset += 1;

                let domain_name = if dom_len <= VTP_DOMAIN_NAME_MAX {
                    String::from_utf8_lossy(&data[offset..offset + dom_len]).to_string()
                } else {
                    String::from_utf8_lossy(&data[offset..offset + VTP_DOMAIN_NAME_MAX]).to_string()
                };
                offset += VTP_DOMAIN_NAME_MAX;

                let revision = u32::from_be_bytes([
                    data[offset],
                    data[offset + 1],
                    data[offset + 2],
                    data[offset + 3],
                ]);
                offset += 4;

                // Parse VLANs
                let mut vlans = Vec::new();
                while offset < data.len() {
                    match VlanInfo::decode(&data[offset..]) {
                        Ok((vlan, len)) => {
                            vlans.push(vlan);
                            offset += len;
                        }
                        Err(_) => break,
                    }
                }

                Ok(VtpPacket {
                    version,
                    message_type,
                    domain_name,
                    revision,
                    data: VtpMessageData::Subset { sequence, vlans },
                })
            }
            VtpMessageType::AdvertisementRequest => {
                if data.len() < 38 {
                    return Err(Error::protocol("VTP Advertisement Request too short"));
                }

                offset += 1; // Skip reserved

                let dom_len = data[offset] as usize;
                offset += 1;

                let domain_name = if dom_len <= VTP_DOMAIN_NAME_MAX {
                    String::from_utf8_lossy(&data[offset..offset + dom_len]).to_string()
                } else {
                    String::from_utf8_lossy(&data[offset..offset + VTP_DOMAIN_NAME_MAX]).to_string()
                };
                offset += VTP_DOMAIN_NAME_MAX;

                let start_value = u16::from_be_bytes([data[offset], data[offset + 1]]);

                Ok(VtpPacket {
                    version,
                    message_type,
                    domain_name,
                    revision: 0,
                    data: VtpMessageData::Request { start_value },
                })
            }
            VtpMessageType::Join => {
                if data.len() < 40 {
                    return Err(Error::protocol("VTP Join message too short"));
                }

                offset += 1; // Skip maybe_reserved

                let dom_len = data[offset] as usize;
                offset += 1;

                let domain_name = if dom_len <= VTP_DOMAIN_NAME_MAX {
                    String::from_utf8_lossy(&data[offset..offset + dom_len]).to_string()
                } else {
                    String::from_utf8_lossy(&data[offset..offset + VTP_DOMAIN_NAME_MAX]).to_string()
                };
                offset += VTP_DOMAIN_NAME_MAX;

                let vlan = u32::from_be_bytes([
                    data[offset],
                    data[offset + 1],
                    data[offset + 2],
                    data[offset + 3],
                ]);

                Ok(VtpPacket {
                    version,
                    message_type,
                    domain_name,
                    revision: 0,
                    data: VtpMessageData::Join { vlan },
                })
            }
        }
    }
}

/// Calculate VTP MD5 digest for Summary Advertisement
///
/// This matches the exact MD5 calculation from Yersinia original:
/// MD5(MD5(password) + Summary + VLANs + MD5(password))
pub fn calculate_vtp_md5(
    password: Option<&str>,
    updater_identity: Ipv4Addr,
    revision: u32,
    domain_name: &str,
    vlans: &[VlanInfo],
    version: VtpVersion,
) -> Result<[u8; VTP_MD5_DIGEST_SIZE]> {
    let mut data = BytesMut::new();

    // If password provided, calculate MD5 of password first
    let md5_secret = if let Some(pass) = password {
        let mut hasher = Md5::new();
        hasher.update(pass.as_bytes());
        hasher.finalize().to_vec()
    } else {
        vec![0u8; 16]
    };

    // Add MD5 secret
    data.put_slice(&md5_secret);

    // Build Summary Advertisement structure (without MD5 field)
    data.put_u8(version.to_u8());
    data.put_u8(VtpMessageType::SummaryAdvertisement.to_u8());
    data.put_u8(0); // followers (not used in MD5)

    let dom_bytes = domain_name.as_bytes();
    let dom_len = dom_bytes.len().min(VTP_DOMAIN_NAME_MAX);
    data.put_u8(dom_len as u8);
    data.put_slice(&dom_bytes[..dom_len]);
    for _ in dom_len..VTP_DOMAIN_NAME_MAX {
        data.put_u8(0);
    }

    data.put_u32(revision);
    data.put_slice(&updater_identity.octets());

    // Timestamp (zeros for MD5 calculation)
    for _ in 0..VTP_TIMESTAMP_SIZE {
        data.put_u8(0);
    }

    // Encode VLANs
    for vlan in vlans {
        vlan.encode(&mut data)?;
    }

    // Add MD5 secret again
    data.put_slice(&md5_secret);

    // Calculate final MD5
    let mut hasher = Md5::new();
    hasher.update(&data);
    let result = hasher.finalize();

    let mut digest = [0u8; VTP_MD5_DIGEST_SIZE];
    digest.copy_from_slice(&result[..]);
    Ok(digest)
}

/// Default VLANs that come with Cisco switches (for delete all attack)
pub fn default_cisco_vlans() -> Vec<VlanInfo> {
    vec![
        VlanInfo {
            status: VlanStatus::Operational,
            vlan_type: VlanType::Ethernet,
            vlan_id: 1,
            mtu: 1500,
            dot10_said: 0x0100001,
            vlan_name: "default".to_string(),
        },
        VlanInfo {
            status: VlanStatus::Operational,
            vlan_type: VlanType::FddiNet,
            vlan_id: 1002,
            mtu: 1500,
            dot10_said: 0x01003EA,
            vlan_name: "fddi-default".to_string(),
        },
        VlanInfo {
            status: VlanStatus::Operational,
            vlan_type: VlanType::TokenRingCrf,
            vlan_id: 1003,
            mtu: 1500,
            dot10_said: 0x01003EB,
            vlan_name: "token-ring-default".to_string(),
        },
        VlanInfo {
            status: VlanStatus::Operational,
            vlan_type: VlanType::FddiNet,
            vlan_id: 1004,
            mtu: 1500,
            dot10_said: 0x01003EC,
            vlan_name: "fddinet-default".to_string(),
        },
        VlanInfo {
            status: VlanStatus::Operational,
            vlan_type: VlanType::TokenRingBrf,
            vlan_id: 1005,
            mtu: 1500,
            dot10_said: 0x01003ED,
            vlan_name: "trnet-default".to_string(),
        },
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vtp_version() {
        assert_eq!(VtpVersion::from_u8(0x01), Some(VtpVersion::Version1));
        assert_eq!(VtpVersion::from_u8(0x02), Some(VtpVersion::Version2));
        assert_eq!(VtpVersion::from_u8(0x03), Some(VtpVersion::Version3));
        assert_eq!(VtpVersion::from_u8(0x99), None);
    }

    #[test]
    fn test_vtp_message_type() {
        assert_eq!(
            VtpMessageType::from_u8(0x01),
            Some(VtpMessageType::SummaryAdvertisement)
        );
        assert_eq!(
            VtpMessageType::from_u8(0x02),
            Some(VtpMessageType::SubsetAdvertisement)
        );
        assert_eq!(
            VtpMessageType::from_u8(0x03),
            Some(VtpMessageType::AdvertisementRequest)
        );
        assert_eq!(VtpMessageType::from_u8(0x04), Some(VtpMessageType::Join));
    }

    #[test]
    fn test_vlan_info_encoding() {
        let vlan = VlanInfo::new(100, "test-vlan".to_string());
        let mut buffer = BytesMut::new();
        vlan.encode(&mut buffer).unwrap();

        assert!(buffer.len() >= 12);
        assert_eq!(buffer[0] as usize, vlan.encoded_len());
    }

    #[test]
    fn test_vlan_info_roundtrip() {
        let original = VlanInfo::new(100, "test".to_string());
        let mut buffer = BytesMut::new();
        original.encode(&mut buffer).unwrap();

        let (decoded, _) = VlanInfo::decode(&buffer).unwrap();
        assert_eq!(original.vlan_id, decoded.vlan_id);
        assert_eq!(original.vlan_name, decoded.vlan_name);
    }

    #[test]
    fn test_vtp_summary_build() {
        let packet = VtpPacket::new_summary(
            VtpVersion::Version2,
            "testdomain".to_string(),
            1,
            0,
            Ipv4Addr::new(10, 0, 0, 1),
        );

        let bytes = packet.build().unwrap();
        assert!(bytes.len() >= 68);
        assert_eq!(bytes[0], VtpVersion::Version2.to_u8());
        assert_eq!(bytes[1], VtpMessageType::SummaryAdvertisement.to_u8());
    }

    #[test]
    fn test_vtp_summary_parse() {
        let packet = VtpPacket::new_summary(
            VtpVersion::Version2,
            "testdomain".to_string(),
            10,
            0,
            Ipv4Addr::new(192, 168, 1, 1),
        );

        let bytes = packet.build().unwrap();
        let parsed = VtpPacket::parse(&bytes).unwrap();

        assert_eq!(packet.version, parsed.version);
        assert_eq!(packet.message_type, parsed.message_type);
        assert_eq!(packet.domain_name, parsed.domain_name);
        assert_eq!(packet.revision, parsed.revision);
    }

    #[test]
    fn test_vtp_subset_build() {
        let vlans = vec![
            VlanInfo::new(10, "vlan10".to_string()),
            VlanInfo::new(20, "vlan20".to_string()),
        ];

        let packet =
            VtpPacket::new_subset(VtpVersion::Version2, "testdomain".to_string(), 5, 1, vlans);

        let bytes = packet.build().unwrap();
        assert!(bytes.len() > 40);
    }

    #[test]
    fn test_vtp_subset_parse() {
        let vlans = vec![VlanInfo::new(100, "test".to_string())];

        let packet = VtpPacket::new_subset(
            VtpVersion::Version2,
            "domain".to_string(),
            5,
            1,
            vlans.clone(),
        );

        let bytes = packet.build().unwrap();
        let parsed = VtpPacket::parse(&bytes).unwrap();

        if let VtpMessageData::Subset {
            vlans: parsed_vlans,
            ..
        } = parsed.data
        {
            assert_eq!(vlans.len(), parsed_vlans.len());
            assert_eq!(vlans[0].vlan_id, parsed_vlans[0].vlan_id);
        } else {
            panic!("Expected Subset message");
        }
    }

    #[test]
    fn test_vtp_request_build() {
        let packet = VtpPacket::new_request(VtpVersion::Version2, "domain".to_string(), 1);

        let bytes = packet.build().unwrap();
        assert_eq!(bytes[0], VtpVersion::Version2.to_u8());
        assert_eq!(bytes[1], VtpMessageType::AdvertisementRequest.to_u8());
    }

    #[test]
    fn test_vtp_request_parse() {
        let packet = VtpPacket::new_request(VtpVersion::Version2, "testdomain".to_string(), 5);

        let bytes = packet.build().unwrap();
        let parsed = VtpPacket::parse(&bytes).unwrap();

        if let VtpMessageData::Request { start_value } = parsed.data {
            assert_eq!(start_value, 5);
        } else {
            panic!("Expected Request message");
        }
    }

    #[test]
    fn test_vtp_join_build() {
        let packet = VtpPacket::new_join(VtpVersion::Version2, "domain".to_string(), 0x3EF);

        let bytes = packet.build().unwrap();
        assert!(bytes.len() >= 40);
    }

    #[test]
    fn test_vtp_join_parse() {
        let packet = VtpPacket::new_join(VtpVersion::Version2, "domain".to_string(), 1007);

        let bytes = packet.build().unwrap();
        let parsed = VtpPacket::parse(&bytes).unwrap();

        if let VtpMessageData::Join { vlan } = parsed.data {
            assert_eq!(vlan, 1007);
        } else {
            panic!("Expected Join message");
        }
    }

    #[test]
    fn test_vtp_with_llc() {
        let packet = VtpPacket::new_summary(
            VtpVersion::Version2,
            "test".to_string(),
            1,
            0,
            Ipv4Addr::new(10, 0, 0, 1),
        );

        let bytes = packet.build_with_llc().unwrap();

        // Check LLC header
        assert_eq!(bytes[0], 0xAA);
        assert_eq!(bytes[1], 0xAA);
        assert_eq!(bytes[2], 0x03);

        // Check SNAP
        assert_eq!(&bytes[3..6], &VTP_SNAP_OUI);
        assert_eq!(u16::from_be_bytes([bytes[6], bytes[7]]), VTP_SNAP_TYPE);
    }

    #[test]
    fn test_md5_calculation() {
        let vlans = vec![VlanInfo::new(10, "test".to_string())];

        let digest = calculate_vtp_md5(
            None,
            Ipv4Addr::new(10, 0, 0, 1),
            1,
            "testdomain",
            &vlans,
            VtpVersion::Version2,
        )
        .unwrap();

        assert_eq!(digest.len(), VTP_MD5_DIGEST_SIZE);
    }

    #[test]
    fn test_md5_with_password() {
        let vlans = vec![VlanInfo::new(10, "test".to_string())];

        let digest1 = calculate_vtp_md5(
            Some("password123"),
            Ipv4Addr::new(10, 0, 0, 1),
            1,
            "domain",
            &vlans,
            VtpVersion::Version2,
        )
        .unwrap();

        let digest2 = calculate_vtp_md5(
            Some("different"),
            Ipv4Addr::new(10, 0, 0, 1),
            1,
            "domain",
            &vlans,
            VtpVersion::Version2,
        )
        .unwrap();

        // Different passwords should produce different digests
        assert_ne!(digest1, digest2);
    }

    #[test]
    fn test_default_cisco_vlans() {
        let vlans = default_cisco_vlans();
        assert_eq!(vlans.len(), 5);
        assert_eq!(vlans[0].vlan_id, 1);
        assert_eq!(vlans[0].vlan_name, "default");
    }

    #[test]
    fn test_vlan_types() {
        assert_eq!(VlanType::from_u8(0x01), Some(VlanType::Ethernet));
        assert_eq!(VlanType::Ethernet.to_u8(), 0x01);
    }

    #[test]
    fn test_vlan_status() {
        assert_eq!(VlanStatus::from_u8(0x00), VlanStatus::Operational);
        assert_eq!(VlanStatus::from_u8(0x01), VlanStatus::Suspended);
    }

    #[test]
    fn test_domain_name_truncation() {
        let long_name = "a".repeat(50);
        let packet = VtpPacket::new_summary(
            VtpVersion::Version2,
            long_name,
            1,
            0,
            Ipv4Addr::new(10, 0, 0, 1),
        );

        let bytes = packet.build().unwrap();
        let parsed = VtpPacket::parse(&bytes).unwrap();

        assert!(parsed.domain_name.len() <= VTP_DOMAIN_NAME_MAX);
    }

    #[test]
    fn test_vlan_name_alignment() {
        // Test that VLAN names are properly 4-byte aligned
        let vlan = VlanInfo::new(10, "abc".to_string()); // 3 bytes -> should pad to 4
        assert_eq!(vlan.aligned_name_len(), 4);

        let vlan2 = VlanInfo::new(20, "abcde".to_string()); // 5 bytes -> should pad to 8
        assert_eq!(vlan2.aligned_name_len(), 8);
    }

    #[test]
    fn test_multiple_vlans_subset() {
        let vlans = vec![
            VlanInfo::new(10, "sales".to_string()),
            VlanInfo::new(20, "engineering".to_string()),
            VlanInfo::new(30, "management".to_string()),
        ];

        let packet = VtpPacket::new_subset(
            VtpVersion::Version2,
            "corporate".to_string(),
            100,
            1,
            vlans.clone(),
        );

        let bytes = packet.build().unwrap();
        let parsed = VtpPacket::parse(&bytes).unwrap();

        if let VtpMessageData::Subset {
            vlans: parsed_vlans,
            ..
        } = parsed.data
        {
            assert_eq!(parsed_vlans.len(), 3);
            assert_eq!(parsed_vlans[0].vlan_id, 10);
            assert_eq!(parsed_vlans[1].vlan_id, 20);
            assert_eq!(parsed_vlans[2].vlan_id, 30);
        } else {
            panic!("Expected Subset");
        }
    }
}
