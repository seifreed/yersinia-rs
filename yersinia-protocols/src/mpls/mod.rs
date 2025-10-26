//! MPLS (Multiprotocol Label Switching) Protocol implementation
//!
//! This module provides complete MPLS protocol support including:
//! - MPLS header parsing and construction (label, exp, bottom-of-stack, TTL)
//! - Support for label stacking (double headers)
//! - Attack implementations (send TCP/UDP/ICMP with single/double MPLS headers)
//!
//! ## MPLS Header Format
//! ```text
//!  0                   1                   2                   3
//!  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                Label                  | Exp |S|       TTL     |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! ```

pub mod attack;
pub mod packet;
pub mod protocol;

pub use attack::{MplsPayloadType, MplsSendAttack};
pub use packet::{MplsHeader, MplsPacket};
pub use protocol::MplsProtocol;
