//! GLBP (Gateway Load Balancing Protocol) - Cisco Proprietary
pub mod attack;
pub mod packet;
pub mod protocol;
pub use attack::GlbpAttack;
pub use packet::{GlbpPacket, GLBP_MULTICAST};
pub use protocol::GlbpProtocol;
