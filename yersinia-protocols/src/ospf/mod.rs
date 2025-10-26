//! OSPF (Open Shortest Path First) - RFC 2328
//!
//! OSPF is a link-state routing protocol that uses Dijkstra's algorithm
//! to calculate shortest paths in IP networks.

pub mod attack;
pub mod packet;
pub mod protocol;

pub use attack::{
    OspfLsaInjectionAttack, OspfMaxAgeDosAttack, OspfNeighborHijackAttack,
    OspfRouteManipulationAttack,
};
pub use packet::{
    OspfLsa, OspfLsaType, OspfPacket, OspfPacketType, OSPF_MULTICAST_ALL_DR,
    OSPF_MULTICAST_ALL_SPF, OSPF_PROTOCOL,
};
pub use protocol::OspfProtocol;
