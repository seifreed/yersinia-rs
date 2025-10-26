//! PPPoE (Point-to-Point Protocol over Ethernet) - RFC 2516
//!
//! PPPoE enables traditional PPP connections over Ethernet networks,
//! commonly used by ISPs for DSL/broadband connections.

pub mod attack;
pub mod packet;
pub mod protocol;

pub use attack::{
    PppoeDiscoveryDosAttack, PppoeMacExhaustionAttack, PppoeRogueAcAttack, PppoeSessionHijackAttack,
};
pub use packet::{
    PppoeCode, PppoePacket, PppoeTag, PppoeTagType, PPPOE_DISCOVERY_ETHERTYPE,
    PPPOE_SESSION_ETHERTYPE,
};
pub use protocol::PppoeProtocol;
