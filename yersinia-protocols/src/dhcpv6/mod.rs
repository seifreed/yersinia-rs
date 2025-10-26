//! DHCPv6 (Dynamic Host Configuration Protocol for IPv6) - RFC 8415
//!
//! DHCPv6 provides configuration information to IPv6 nodes, including
//! addresses, DNS servers, and other network parameters.

pub mod attack;
pub mod packet;
pub mod protocol;

pub use attack::{Dhcpv6DosAttack, Dhcpv6RogueServerAttack, Dhcpv6StarvationAttack};
pub use packet::{
    Dhcpv6MessageType, Dhcpv6Option, Dhcpv6OptionType, Dhcpv6Packet, DHCPV6_CLIENT_PORT,
    DHCPV6_MULTICAST, DHCPV6_SERVER_PORT,
};
pub use protocol::Dhcpv6Protocol;
