//! BGP (Border Gateway Protocol) - RFC 4271
//!
//! BGP is the protocol that makes the Internet work - it's used to exchange
//! routing information between autonomous systems (AS). Critical for ISP
//! and large enterprise network security testing.

pub mod attack;
pub mod packet;
pub mod protocol;

pub use attack::{
    BgpAsPathManipulationAttack, BgpRouteHijackAttack, BgpRouteLeakAttack, BgpSessionHijackAttack,
    BgpTtlSecurityBypassAttack,
};
pub use packet::{
    BgpMessageType, BgpOpenMessage, BgpPacket, BgpPathAttribute, BgpPathAttributeType,
    BgpUpdateMessage, BGP_PORT, BGP_VERSION,
};
pub use protocol::BgpProtocol;
