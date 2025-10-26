//! ARP (Address Resolution Protocol) Enhanced Implementation
//!
//! This module provides complete ARP protocol support including:
//! - ARP packet parsing and construction (Request, Reply, RARP)
//! - Attack implementations (Spoofing/Poisoning, Flooding, Gratuitous ARP)
//! - ARP cache tracking
//!
//! ## Note
//! This is an enhanced implementation beyond the original Yersinia,
//! which had basic ARP support but no attacks implemented.
//!
//! ## ARP Packet Format
//! ```text
//!  0                   1                   2                   3
//!  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |      Hardware Type (HTYPE)    |       Protocol Type (PTYPE)   |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |  HW Addr Len  |Proto Addr Len |         Operation (OPER)      |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                   Sender Hardware Address (SHA)               |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |       SHA (cont.)             |  Sender Protocol Address (SPA)|
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |       SPA (cont.)             |  Target Hardware Address (THA)|
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                        THA (cont.)                            |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                   Target Protocol Address (TPA)               |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! ```

pub mod attack;
pub mod packet;
pub mod protocol;

pub use attack::{ArpFloodingAttack, ArpGratuitousAttack, ArpSpoofingAttack};
pub use packet::{ArpOpcode, ArpPacket};
pub use protocol::ArpProtocol;
