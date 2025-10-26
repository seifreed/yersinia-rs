//! DHCP (Dynamic Host Configuration Protocol) implementation
//!
//! This module provides complete DHCP protocol support including:
//! - Packet parsing and building
//! - DHCP message types (DISCOVER, OFFER, REQUEST, ACK, NAK, RELEASE, INFORM, DECLINE)
//! - DHCP options handling
//! - Protocol statistics and tracking
//! - Attack implementations (Starvation, Release spoofing)

pub mod attack;
pub mod packet;
pub mod protocol;

pub use attack::{DhcpReleaseAttack, DhcpStarvationAttack};
pub use packet::{DhcpMessageType, DhcpOption, DhcpPacket, OptionCode};
pub use protocol::DhcpProtocol;
