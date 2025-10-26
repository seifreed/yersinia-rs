//! Unidirectional Link Detection Protocol (Cisco)
pub mod attack;
pub mod packet;
pub mod protocol;

pub use attack::{EchoManipulationAttack, NeighborImpersonationAttack, UdldSpoofingAttack};
pub use packet::{UdldOpcode, UdldPacket, UDLD_MULTICAST};
pub use protocol::UdldProtocol;
