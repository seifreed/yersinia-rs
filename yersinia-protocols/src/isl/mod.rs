//! ISL (Inter-Switch Link) Protocol Implementation
//!
//! Legacy Cisco proprietary VLAN trunking protocol, now largely replaced by 802.1Q.
//! ISL encapsulates frames with a 26-byte header and 4-byte CRC trailer.

mod attack;
mod packet;
mod protocol;

pub use attack::{IslSpoofingAttack, IslTaggingAttack};
pub use packet::{IslFrame, IslFrameType, ISL_HEADER_SIZE, ISL_TOTAL_OVERHEAD, ISL_TRAILER_SIZE};
pub use protocol::IslProtocol;
