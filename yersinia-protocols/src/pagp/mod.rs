//! PAgP (Port Aggregation Protocol) - Cisco Proprietary
pub mod attack;
pub mod packet;
pub mod protocol;
pub use attack::PagpHijackAttack;
pub use packet::{PagpPacket, PAGP_DST_MAC, PAGP_MULTICAST_MAC};
pub use protocol::PagpProtocol;
