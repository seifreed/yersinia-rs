//! Virtual Router Redundancy Protocol (VRRP) Implementation - RFC 5798
//!
//! VRRP provides automatic assignment of available routers to participating hosts,
//! increasing availability and reliability of routing paths.

pub mod attack;
pub mod packet;
pub mod protocol;

pub use attack::{VrrpDosAttack, VrrpMasterAttack};
pub use packet::{VrrpPacket, VrrpVersion, VRRP_MULTICAST_V2, VRRP_MULTICAST_V3};
pub use protocol::VrrpProtocol;
