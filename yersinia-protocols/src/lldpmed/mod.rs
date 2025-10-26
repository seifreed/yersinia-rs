//! LLDP-MED Media Endpoint Discovery Protocol
pub mod attack;
pub mod packet;
pub mod protocol;

pub use attack::{DeviceImpersonationAttack, PoEManipulationAttack, VoiceVlanManipulationAttack};
pub use packet::{LldpMedPacket, LldpMedTlv, LLDP_ETHERTYPE, LLDP_MULTICAST};
pub use protocol::LldpMedProtocol;
