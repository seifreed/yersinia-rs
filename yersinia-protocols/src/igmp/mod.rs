//! IGMP/MLD (Internet Group Management Protocol / Multicast Listener Discovery)
//! RFC 3376 (IGMPv3), RFC 2710/3810 (MLD)
//!
//! IGMP manages IPv4 multicast group memberships.
//! MLD is the IPv6 equivalent.

pub mod attack;
pub mod packet;
pub mod protocol;

pub use attack::{
    IgmpFloodingAttack, IgmpSnoopingBypassAttack, MldPoisoningAttack, MulticastGroupHijackAttack,
};
pub use packet::{
    IgmpPacket, IgmpType, IgmpVersion, MldPacket, MldType, IGMP_ALL_ROUTERS, IGMP_ALL_SYSTEMS,
    IGMP_PROTOCOL,
};
pub use protocol::IgmpProtocol;
