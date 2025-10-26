//! Spanning Tree Protocol (STP/RSTP/MSTP) implementation
//!
//! This module provides complete support for:
//! - STP (IEEE 802.1D) - Spanning Tree Protocol
//! - RSTP (IEEE 802.1w) - Rapid Spanning Tree Protocol
//! - MSTP (IEEE 802.1s) - Multiple Spanning Tree Protocol
//!
//! ## Supported Attacks
//!
//! 1. **Claim Root Attack** - Become the root bridge
//! 2. **Claim Other Attack** - Impersonate a specific bridge
//! 3. **DoS Config Attack** - Flood with config BPDUs causing reconvergence
//! 4. **DoS TCN Attack** - Flood with TCN BPDUs to flush MAC tables
//! 5. **RSTP Attack** - Exploit RSTP fast transitions
//! 6. **MITM Attack** - Position as root for man-in-the-middle
//!
//! ## Packet Format
//!
//! All STP variants use 802.3 Ethernet frames with LLC headers:
//! - Destination: 01:80:C2:00:00:00 (Bridge Group Address)
//! - LLC DSAP/SSAP: 0x42 (STP)
//! - BPDU structure depends on type (Config/TCN/RST/MST)

pub mod attack;
pub mod packet;
pub mod protocol;

pub use attack::{
    StpClaimOtherAttack, StpClaimRootAttack, StpDosConfAttack, StpDosTcnAttack, StpMitmAttack,
    StpSendConfAttack, StpSendTcnAttack,
};
pub use packet::{
    BpduPacket, BpduType, BridgeId, ConfigBpdu, MstBpdu, RstBpdu, RstpFlags, RstpPortRole,
    StpFlags, TcnBpdu,
};
pub use protocol::StpProtocol;

/// STP Protocol constants
pub mod constants {
    use yersinia_core::MacAddr;

    /// STP multicast destination MAC address
    pub const STP_MULTICAST_MAC: MacAddr = MacAddr([0x01, 0x80, 0xC2, 0x00, 0x00, 0x00]);

    /// LLC DSAP and SSAP for STP
    pub const STP_LLC_DSAP: u8 = 0x42;
    pub const STP_LLC_SSAP: u8 = 0x42;
    pub const STP_LLC_CONTROL: u8 = 0x03;

    /// Protocol ID (always 0x0000)
    pub const STP_PROTOCOL_ID: u16 = 0x0000;

    /// Protocol versions
    pub const STP_VERSION_STP: u8 = 0x00;
    pub const STP_VERSION_RSTP: u8 = 0x02;
    pub const STP_VERSION_MSTP: u8 = 0x03;

    /// BPDU Types
    pub const BPDU_TYPE_CONFIG: u8 = 0x00;
    pub const BPDU_TYPE_TCN: u8 = 0x80;
    pub const BPDU_TYPE_RST: u8 = 0x02;

    /// Default timing values (in 1/256 seconds for wire format)
    pub const DEFAULT_HELLO_TIME: u16 = 2 * 256; // 2 seconds
    pub const DEFAULT_MAX_AGE: u16 = 20 * 256; // 20 seconds
    pub const DEFAULT_FORWARD_DELAY: u16 = 15 * 256; // 15 seconds
    pub const DEFAULT_MESSAGE_AGE: u16 = 0;

    /// Default port ID (priority 0x80, port number 2)
    pub const DEFAULT_PORT_ID: u16 = 0x8002;

    /// Packet sizes
    pub const CONFIG_BPDU_SIZE: usize = 35;
    pub const TCN_BPDU_SIZE: usize = 4;
    pub const RST_BPDU_SIZE: usize = 36; // Config + 1 byte version
    pub const MST_BPDU_MIN_SIZE: usize = 102;

    /// Attack timing defaults
    pub const DEFAULT_ATTACK_INTERVAL_MS: u64 = 2000; // 2 seconds
    pub const DOS_ATTACK_INTERVAL_MS: u64 = 100; // 100ms for DoS
}
