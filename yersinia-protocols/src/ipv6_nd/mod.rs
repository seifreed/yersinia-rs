//! IPv6 Neighbor Discovery / Router Advertisement - RFC 4861
//!
//! IPv6 ND protocol replaces ARP and provides router discovery,
//! address autoconfiguration (SLAAC), and neighbor reachability.

pub mod attack;
pub mod packet;
pub mod protocol;

pub use attack::{DadDosAttack, NdpPoisoningAttack, RogueRouterAdvertisementAttack, SlaacAttack};
pub use packet::{
    Ipv6NdOption, Ipv6NdOptionType, Ipv6NdPacket, Ipv6NdType, ICMPV6_NS_MULTICAST_PREFIX,
    ICMPV6_RA_MULTICAST,
};
pub use protocol::Ipv6NdProtocol;
