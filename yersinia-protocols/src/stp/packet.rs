//! BPDU packet structures and parsing
//!
//! This module implements parsing and building of all BPDU types:
//! - Configuration BPDUs (STP)
//! - Topology Change Notification (TCN) BPDUs
//! - Rapid Spanning Tree (RSTP) BPDUs
//! - Multiple Spanning Tree (MSTP) BPDUs

use std::fmt;
use yersinia_core::{Error, MacAddr, Result};

use super::constants::*;

/// Bridge ID (8 bytes: 2 bytes priority + 6 bytes MAC)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BridgeId {
    /// Bridge priority (0-65535, default 32768)
    pub priority: u16,
    /// Bridge MAC address
    pub mac: MacAddr,
}

impl BridgeId {
    /// Create a new Bridge ID
    pub fn new(priority: u16, mac: MacAddr) -> Self {
        Self { priority, mac }
    }

    /// Parse Bridge ID from 8 bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < 8 {
            return Err(Error::protocol("Bridge ID requires 8 bytes"));
        }

        let priority = u16::from_be_bytes([bytes[0], bytes[1]]);
        let mac = MacAddr([bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7]]);

        Ok(Self { priority, mac })
    }

    /// Convert Bridge ID to bytes
    pub fn to_bytes(&self) -> [u8; 8] {
        let mut bytes = [0u8; 8];
        bytes[0..2].copy_from_slice(&self.priority.to_be_bytes());
        bytes[2..8].copy_from_slice(&self.mac.0);
        bytes
    }

    /// Create a Bridge ID with lowest priority (to claim root)
    pub fn lowest_priority(mac: MacAddr) -> Self {
        Self::new(0, mac)
    }
}

impl fmt::Display for BridgeId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:04x}.{}", self.priority, self.mac)
    }
}

/// STP flags (for classic STP)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct StpFlags {
    /// Topology Change flag
    pub topology_change: bool,
    /// Topology Change Acknowledgment flag
    pub topology_change_ack: bool,
}

impl StpFlags {
    pub fn from_byte(byte: u8) -> Self {
        Self {
            topology_change: (byte & 0x01) != 0,
            topology_change_ack: (byte & 0x80) != 0,
        }
    }

    pub fn to_byte(&self) -> u8 {
        let mut flags = 0u8;
        if self.topology_change {
            flags |= 0x01;
        }
        if self.topology_change_ack {
            flags |= 0x80;
        }
        flags
    }
}

/// RSTP port roles
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RstpPortRole {
    Unknown = 0,
    Backup = 1,
    Root = 2,
    Designated = 3,
}

impl RstpPortRole {
    pub fn from_flags(flags: u8) -> Self {
        match (flags >> 2) & 0x03 {
            0 => RstpPortRole::Unknown,
            1 => RstpPortRole::Backup,
            2 => RstpPortRole::Root,
            3 => RstpPortRole::Designated,
            _ => RstpPortRole::Unknown,
        }
    }

    pub fn to_flags_bits(&self) -> u8 {
        (*self as u8) << 2
    }
}

/// RSTP flags (for RSTP/MSTP)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct RstpFlags {
    /// Topology Change flag
    pub topology_change: bool,
    /// Proposal flag
    pub proposal: bool,
    /// Port role (2 bits)
    pub port_role: Option<RstpPortRole>,
    /// Learning flag
    pub learning: bool,
    /// Forwarding flag
    pub forwarding: bool,
    /// Agreement flag
    pub agreement: bool,
    /// Topology Change Acknowledgment (legacy)
    pub topology_change_ack: bool,
}

impl RstpFlags {
    pub fn from_byte(byte: u8) -> Self {
        Self {
            topology_change: (byte & 0x01) != 0,
            proposal: (byte & 0x02) != 0,
            port_role: Some(RstpPortRole::from_flags(byte)),
            learning: (byte & 0x10) != 0,
            forwarding: (byte & 0x20) != 0,
            agreement: (byte & 0x40) != 0,
            topology_change_ack: (byte & 0x80) != 0,
        }
    }

    pub fn to_byte(&self) -> u8 {
        let mut flags = 0u8;
        if self.topology_change {
            flags |= 0x01;
        }
        if self.proposal {
            flags |= 0x02;
        }
        if let Some(role) = self.port_role {
            flags |= role.to_flags_bits();
        }
        if self.learning {
            flags |= 0x10;
        }
        if self.forwarding {
            flags |= 0x20;
        }
        if self.agreement {
            flags |= 0x40;
        }
        if self.topology_change_ack {
            flags |= 0x80;
        }
        flags
    }

    /// Create default RSTP flags for root bridge
    pub fn root_bridge() -> Self {
        Self {
            topology_change: false,
            proposal: false,
            port_role: Some(RstpPortRole::Designated),
            learning: true,
            forwarding: true,
            agreement: true,
            topology_change_ack: false,
        }
    }
}

/// BPDU Type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BpduType {
    /// Configuration BPDU (STP)
    Config,
    /// Topology Change Notification
    Tcn,
    /// Rapid Spanning Tree
    Rst,
    /// Multiple Spanning Tree
    Mst,
}

impl BpduType {
    pub fn to_byte(&self) -> u8 {
        match self {
            BpduType::Config => BPDU_TYPE_CONFIG,
            BpduType::Tcn => BPDU_TYPE_TCN,
            BpduType::Rst => BPDU_TYPE_RST,
            BpduType::Mst => BPDU_TYPE_RST, // MSTP uses same type as RST
        }
    }

    pub fn from_byte(byte: u8) -> Result<Self> {
        match byte {
            BPDU_TYPE_CONFIG => Ok(BpduType::Config),
            BPDU_TYPE_TCN => Ok(BpduType::Tcn),
            BPDU_TYPE_RST => Ok(BpduType::Rst),
            _ => Err(Error::protocol(format!(
                "Unknown BPDU type: 0x{:02x}",
                byte
            ))),
        }
    }
}

/// Configuration BPDU (STP/RSTP/MSTP)
#[derive(Debug, Clone, PartialEq)]
pub struct ConfigBpdu {
    /// Protocol identifier (always 0x0000)
    pub protocol_id: u16,
    /// Protocol version (0=STP, 2=RSTP, 3=MSTP)
    pub version: u8,
    /// BPDU type
    pub bpdu_type: u8,
    /// Flags
    pub flags: u8,
    /// Root bridge identifier
    pub root_id: BridgeId,
    /// Root path cost
    pub root_path_cost: u32,
    /// Bridge identifier
    pub bridge_id: BridgeId,
    /// Port identifier
    pub port_id: u16,
    /// Message age (in 1/256 seconds)
    pub message_age: u16,
    /// Max age (in 1/256 seconds)
    pub max_age: u16,
    /// Hello time (in 1/256 seconds)
    pub hello_time: u16,
    /// Forward delay (in 1/256 seconds)
    pub forward_delay: u16,
    /// Additional data for RSTP/MSTP
    pub additional_data: Vec<u8>,
}

impl ConfigBpdu {
    /// Create a new Config BPDU with defaults
    pub fn new(bridge_id: BridgeId, root_id: BridgeId) -> Self {
        Self {
            protocol_id: STP_PROTOCOL_ID,
            version: STP_VERSION_STP,
            bpdu_type: BPDU_TYPE_CONFIG,
            flags: 0,
            root_id,
            root_path_cost: 0,
            bridge_id,
            port_id: DEFAULT_PORT_ID,
            message_age: DEFAULT_MESSAGE_AGE,
            max_age: DEFAULT_MAX_AGE,
            hello_time: DEFAULT_HELLO_TIME,
            forward_delay: DEFAULT_FORWARD_DELAY,
            additional_data: Vec::new(),
        }
    }

    /// Create a Config BPDU claiming to be root
    pub fn claim_root(mac: MacAddr) -> Self {
        let bridge_id = BridgeId::lowest_priority(mac);
        Self::new(bridge_id, bridge_id)
    }

    /// Parse Config BPDU from bytes
    pub fn parse(data: &[u8]) -> Result<Self> {
        if data.len() < CONFIG_BPDU_SIZE {
            return Err(Error::protocol(format!(
                "Config BPDU too short: {} bytes (need {})",
                data.len(),
                CONFIG_BPDU_SIZE
            )));
        }

        let protocol_id = u16::from_be_bytes([data[0], data[1]]);
        let version = data[2];
        let bpdu_type = data[3];
        let flags = data[4];
        let root_id = BridgeId::from_bytes(&data[5..13])?;
        let root_path_cost = u32::from_be_bytes([data[13], data[14], data[15], data[16]]);
        let bridge_id = BridgeId::from_bytes(&data[17..25])?;
        let port_id = u16::from_be_bytes([data[25], data[26]]);
        let message_age = u16::from_be_bytes([data[27], data[28]]);
        let max_age = u16::from_be_bytes([data[29], data[30]]);
        let hello_time = u16::from_be_bytes([data[31], data[32]]);
        let forward_delay = u16::from_be_bytes([data[33], data[34]]);

        let additional_data = if data.len() > CONFIG_BPDU_SIZE {
            data[CONFIG_BPDU_SIZE..].to_vec()
        } else {
            Vec::new()
        };

        Ok(Self {
            protocol_id,
            version,
            bpdu_type,
            flags,
            root_id,
            root_path_cost,
            bridge_id,
            port_id,
            message_age,
            max_age,
            hello_time,
            forward_delay,
            additional_data,
        })
    }

    /// Build Config BPDU to bytes
    pub fn build(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(CONFIG_BPDU_SIZE + self.additional_data.len());

        // Protocol ID (2 bytes)
        bytes.extend_from_slice(&self.protocol_id.to_be_bytes());
        // Version (1 byte)
        bytes.push(self.version);
        // BPDU Type (1 byte)
        bytes.push(self.bpdu_type);
        // Flags (1 byte)
        bytes.push(self.flags);
        // Root ID (8 bytes)
        bytes.extend_from_slice(&self.root_id.to_bytes());
        // Root Path Cost (4 bytes)
        bytes.extend_from_slice(&self.root_path_cost.to_be_bytes());
        // Bridge ID (8 bytes)
        bytes.extend_from_slice(&self.bridge_id.to_bytes());
        // Port ID (2 bytes)
        bytes.extend_from_slice(&self.port_id.to_be_bytes());
        // Message Age (2 bytes)
        bytes.extend_from_slice(&self.message_age.to_be_bytes());
        // Max Age (2 bytes)
        bytes.extend_from_slice(&self.max_age.to_be_bytes());
        // Hello Time (2 bytes)
        bytes.extend_from_slice(&self.hello_time.to_be_bytes());
        // Forward Delay (2 bytes)
        bytes.extend_from_slice(&self.forward_delay.to_be_bytes());
        // Additional data (for RSTP/MSTP)
        bytes.extend_from_slice(&self.additional_data);

        bytes
    }

    /// Get STP flags
    pub fn stp_flags(&self) -> StpFlags {
        StpFlags::from_byte(self.flags)
    }

    /// Get RSTP flags
    pub fn rstp_flags(&self) -> RstpFlags {
        RstpFlags::from_byte(self.flags)
    }

    /// Set flags from StpFlags
    pub fn with_stp_flags(mut self, flags: StpFlags) -> Self {
        self.flags = flags.to_byte();
        self
    }

    /// Set flags from RstpFlags
    pub fn with_rstp_flags(mut self, flags: RstpFlags) -> Self {
        self.flags = flags.to_byte();
        self
    }

    /// Convert to RSTP version
    pub fn as_rstp(mut self) -> Self {
        self.version = STP_VERSION_RSTP;
        self.bpdu_type = BPDU_TYPE_RST;
        // Add version 1 length field (0)
        if self.additional_data.is_empty() {
            self.additional_data.push(0);
        }
        self
    }

    /// Convert to MSTP version
    pub fn as_mstp(mut self) -> Self {
        self.version = STP_VERSION_MSTP;
        self.bpdu_type = BPDU_TYPE_RST;
        // MSTP requires extensive additional fields - simplified here
        if self.additional_data.is_empty() {
            self.additional_data = vec![0; 64]; // Minimal MSTP extension
        }
        self
    }
}

/// Topology Change Notification (TCN) BPDU
#[derive(Debug, Clone, PartialEq)]
pub struct TcnBpdu {
    /// Protocol identifier (always 0x0000)
    pub protocol_id: u16,
    /// Protocol version (always 0x00 for TCN)
    pub version: u8,
    /// BPDU type (always 0x80 for TCN)
    pub bpdu_type: u8,
}

impl TcnBpdu {
    /// Create a new TCN BPDU
    pub fn new() -> Self {
        Self {
            protocol_id: STP_PROTOCOL_ID,
            version: STP_VERSION_STP,
            bpdu_type: BPDU_TYPE_TCN,
        }
    }

    /// Parse TCN BPDU from bytes
    pub fn parse(data: &[u8]) -> Result<Self> {
        if data.len() < TCN_BPDU_SIZE {
            return Err(Error::protocol(format!(
                "TCN BPDU too short: {} bytes (need {})",
                data.len(),
                TCN_BPDU_SIZE
            )));
        }

        let protocol_id = u16::from_be_bytes([data[0], data[1]]);
        let version = data[2];
        let bpdu_type = data[3];

        Ok(Self {
            protocol_id,
            version,
            bpdu_type,
        })
    }

    /// Build TCN BPDU to bytes
    pub fn build(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(TCN_BPDU_SIZE);
        bytes.extend_from_slice(&self.protocol_id.to_be_bytes());
        bytes.push(self.version);
        bytes.push(self.bpdu_type);
        bytes
    }
}

impl Default for TcnBpdu {
    fn default() -> Self {
        Self::new()
    }
}

/// RSTP BPDU (version 2)
pub type RstBpdu = ConfigBpdu;

/// MSTP BPDU (version 3)
#[derive(Debug, Clone, PartialEq)]
pub struct MstBpdu {
    /// Base Config BPDU
    pub config: ConfigBpdu,
    /// MST Configuration Identifier (32 bytes)
    pub mst_config_id: [u8; 32],
    /// CIST Internal Root Path Cost
    pub cist_internal_root_path_cost: u32,
    /// CIST Bridge Identifier
    pub cist_bridge_id: BridgeId,
    /// CIST Remaining Hops
    pub cist_remaining_hops: u8,
    /// MST Configuration Messages (variable)
    pub mst_config_messages: Vec<u8>,
}

impl MstBpdu {
    /// Create a new MSTP BPDU
    pub fn new(bridge_id: BridgeId, root_id: BridgeId) -> Self {
        let mut config = ConfigBpdu::new(bridge_id, root_id);
        config.version = STP_VERSION_MSTP;
        config.bpdu_type = BPDU_TYPE_RST;

        Self {
            config,
            mst_config_id: [0; 32],
            cist_internal_root_path_cost: 0,
            cist_bridge_id: bridge_id,
            cist_remaining_hops: 20,
            mst_config_messages: Vec::new(),
        }
    }

    /// Parse MSTP BPDU from bytes
    pub fn parse(data: &[u8]) -> Result<Self> {
        if data.len() < MST_BPDU_MIN_SIZE {
            return Err(Error::protocol(format!(
                "MSTP BPDU too short: {} bytes (need {})",
                data.len(),
                MST_BPDU_MIN_SIZE
            )));
        }

        let config = ConfigBpdu::parse(&data[0..CONFIG_BPDU_SIZE])?;

        let mut offset = CONFIG_BPDU_SIZE + 1; // Skip version 1 length

        let mut mst_config_id = [0u8; 32];
        mst_config_id.copy_from_slice(&data[offset..offset + 32]);
        offset += 32;

        let cist_internal_root_path_cost = u32::from_be_bytes([
            data[offset],
            data[offset + 1],
            data[offset + 2],
            data[offset + 3],
        ]);
        offset += 4;

        let cist_bridge_id = BridgeId::from_bytes(&data[offset..offset + 8])?;
        offset += 8;

        let cist_remaining_hops = data[offset];
        offset += 1;

        let mst_config_messages = if data.len() > offset {
            data[offset..].to_vec()
        } else {
            Vec::new()
        };

        Ok(Self {
            config,
            mst_config_id,
            cist_internal_root_path_cost,
            cist_bridge_id,
            cist_remaining_hops,
            mst_config_messages,
        })
    }

    /// Build MSTP BPDU to bytes
    pub fn build(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(MST_BPDU_MIN_SIZE + self.mst_config_messages.len());

        // Base Config BPDU (35 bytes)
        bytes.extend_from_slice(&self.config.build());

        // Version 1 Length (1 byte) - always 0
        bytes.push(0);

        // MST Configuration Identifier (32 bytes)
        bytes.extend_from_slice(&self.mst_config_id);

        // CIST Internal Root Path Cost (4 bytes)
        bytes.extend_from_slice(&self.cist_internal_root_path_cost.to_be_bytes());

        // CIST Bridge Identifier (8 bytes)
        bytes.extend_from_slice(&self.cist_bridge_id.to_bytes());

        // CIST Remaining Hops (1 byte)
        bytes.push(self.cist_remaining_hops);

        // MST Configuration Messages
        bytes.extend_from_slice(&self.mst_config_messages);

        bytes
    }
}

/// Generic BPDU packet (can be any type)
#[derive(Debug, Clone, PartialEq)]
pub enum BpduPacket {
    Config(ConfigBpdu),
    Tcn(TcnBpdu),
    Rst(RstBpdu),
    Mst(MstBpdu),
}

impl BpduPacket {
    /// Parse a BPDU packet from bytes
    pub fn parse(data: &[u8]) -> Result<Self> {
        if data.len() < 4 {
            return Err(Error::protocol("BPDU too short"));
        }

        let version = data[2];
        let bpdu_type = data[3];

        match (version, bpdu_type) {
            (STP_VERSION_STP, BPDU_TYPE_CONFIG) => Ok(BpduPacket::Config(ConfigBpdu::parse(data)?)),
            (STP_VERSION_STP, BPDU_TYPE_TCN) => Ok(BpduPacket::Tcn(TcnBpdu::parse(data)?)),
            (STP_VERSION_RSTP, BPDU_TYPE_RST) => Ok(BpduPacket::Rst(ConfigBpdu::parse(data)?)),
            (STP_VERSION_MSTP, BPDU_TYPE_RST) => Ok(BpduPacket::Mst(MstBpdu::parse(data)?)),
            _ => Err(Error::protocol(format!(
                "Unknown BPDU version/type: version={}, type={}",
                version, bpdu_type
            ))),
        }
    }

    /// Build a BPDU packet to bytes
    pub fn build(&self) -> Vec<u8> {
        match self {
            BpduPacket::Config(bpdu) => bpdu.build(),
            BpduPacket::Tcn(bpdu) => bpdu.build(),
            BpduPacket::Rst(bpdu) => bpdu.build(),
            BpduPacket::Mst(bpdu) => bpdu.build(),
        }
    }

    /// Get the BPDU type
    pub fn bpdu_type(&self) -> BpduType {
        match self {
            BpduPacket::Config(_) => BpduType::Config,
            BpduPacket::Tcn(_) => BpduType::Tcn,
            BpduPacket::Rst(_) => BpduType::Rst,
            BpduPacket::Mst(_) => BpduType::Mst,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bridge_id() {
        let mac = MacAddr([0x00, 0x1a, 0x2b, 0x3c, 0x4d, 0x5e]);
        let bridge_id = BridgeId::new(32768, mac);

        let bytes = bridge_id.to_bytes();
        let parsed = BridgeId::from_bytes(&bytes).unwrap();

        assert_eq!(bridge_id, parsed);
    }

    #[test]
    fn test_stp_flags() {
        let flags = StpFlags {
            topology_change: true,
            topology_change_ack: false,
        };

        let byte = flags.to_byte();
        assert_eq!(byte, 0x01);

        let parsed = StpFlags::from_byte(byte);
        assert_eq!(flags, parsed);
    }

    #[test]
    fn test_rstp_flags() {
        let flags = RstpFlags {
            topology_change: true,
            proposal: true,
            port_role: Some(RstpPortRole::Designated),
            learning: true,
            forwarding: true,
            agreement: true,
            topology_change_ack: false,
        };

        let byte = flags.to_byte();
        let parsed = RstpFlags::from_byte(byte);

        assert_eq!(flags, parsed);
    }

    #[test]
    fn test_config_bpdu_parse_build() {
        let mac = MacAddr([0x00, 0x1a, 0x2b, 0x3c, 0x4d, 0x5e]);

        let bpdu = ConfigBpdu::claim_root(mac);
        let bytes = bpdu.build();

        assert_eq!(bytes.len(), CONFIG_BPDU_SIZE);

        let parsed = ConfigBpdu::parse(&bytes).unwrap();
        assert_eq!(bpdu, parsed);
    }

    #[test]
    fn test_tcn_bpdu_parse_build() {
        let bpdu = TcnBpdu::new();
        let bytes = bpdu.build();

        assert_eq!(bytes.len(), TCN_BPDU_SIZE);

        let parsed = TcnBpdu::parse(&bytes).unwrap();
        assert_eq!(bpdu, parsed);
    }

    #[test]
    fn test_rstp_bpdu() {
        let mac = MacAddr([0x00, 0x1a, 0x2b, 0x3c, 0x4d, 0x5e]);
        let bpdu = ConfigBpdu::claim_root(mac)
            .as_rstp()
            .with_rstp_flags(RstpFlags::root_bridge());

        assert_eq!(bpdu.version, STP_VERSION_RSTP);
        assert_eq!(bpdu.bpdu_type, BPDU_TYPE_RST);

        let bytes = bpdu.build();
        let parsed = ConfigBpdu::parse(&bytes).unwrap();
        assert_eq!(bpdu.version, parsed.version);
    }

    #[test]
    fn test_bpdu_packet_parse() {
        let mac = MacAddr([0x00, 0x1a, 0x2b, 0x3c, 0x4d, 0x5e]);
        let bpdu = ConfigBpdu::claim_root(mac);
        let bytes = bpdu.build();

        let packet = BpduPacket::parse(&bytes).unwrap();
        match packet {
            BpduPacket::Config(parsed) => assert_eq!(bpdu, parsed),
            _ => panic!("Wrong BPDU type"),
        }
    }
}
