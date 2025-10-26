//! VXLAN (Virtual Extensible LAN) - RFC 7348
//!
//! VXLAN is a network virtualization technology that encapsulates
//! Layer 2 Ethernet frames in Layer 4 UDP packets for overlay networks.

pub mod attack;
pub mod packet;
pub mod protocol;

pub use attack::{VxlanTenantBypassAttack, VxlanVniManipulationAttack, VxlanVtepSpoofingAttack};
pub use packet::{VxlanHeader, VxlanPacket, VXLAN_FLAG_VNI_VALID, VXLAN_UDP_PORT};
pub use protocol::VxlanProtocol;
