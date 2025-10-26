//! GVRP/MVRP Dynamic VLAN Registration Protocol
pub mod attack;
pub mod packet;
pub mod protocol;

pub use attack::{GarpPoisoningAttack, VlanDeregistrationAttack, VlanFloodingAttack};
pub use packet::{GvrpPacket, MvrpPacket, GVRP_ETHERTYPE, GVRP_MULTICAST, MVRP_MULTICAST};
pub use protocol::GvrpProtocol;
