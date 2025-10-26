//! Protocol implementations for Yersinia-RS
//!
//! This crate contains complete protocol implementations for network security testing.
//! Each protocol module includes:
//! - Packet parsing and construction
//! - Attack implementations
//! - Statistics tracking
//!
//! ## Available Protocols
//!
//! ### CDP (Cisco Discovery Protocol)
//! Full implementation with flooding and spoofing attacks.
//! See [`cdp`] module for details.
//!
//! ### HSRP (Hot Standby Router Protocol)
//! Full implementation with active router takeover attack.
//! See [`hsrp`] module for details.
//!
//! ### VTP (VLAN Trunking Protocol)
//! Complete implementation with delete VLAN, spoofing, and poisoning attacks.
//! See [`vtp`] module for details.
//!
//! ### DTP (Dynamic Trunking Protocol)
//! Complete DTP implementation with trunk negotiation attacks for VLAN hopping.
//! See [`dtp`] module for details.
//!
//! ### 802.1Q (VLAN Tagging)
//! IEEE 802.1Q implementation with double tagging and VLAN hopping attacks.
//! See [`dot1q`] module for details.
//!
//! ### ISL (Inter-Switch Link)
//! Legacy Cisco VLAN trunking protocol implementation with VLAN hopping attacks.
//! See [`isl`] module for details.
//!
//! ### 802.1X (Port-based Network Access Control)
//! IEEE 802.1X implementation with EAPOL/EAP parsing and authentication attacks.
//! See [`dot1x`] module for details.
//!
pub mod arp;
pub mod bfd;
pub mod bgp;
pub mod cam;
pub mod cdp;
pub mod dhcp;
pub mod dhcpv6;
pub mod dot1q;
pub mod dot1x;
pub mod dtp;
pub mod eigrp;
pub mod erspan;
pub mod glbp;
pub mod gre;
pub mod gvrp;
pub mod hsrp;
pub mod icmp;
pub mod igmp;
pub mod ipv6_nd;
pub mod isis;
pub mod isl;
pub mod lacp;
pub mod lldp;
pub mod lldpmed;
pub mod mpls;
pub mod ospf;
pub mod pagp;
pub mod pim;
pub mod pppoe;
pub mod qinq;
pub mod qos;
pub mod ripv2;
pub mod storm;
pub mod stp;
pub mod udld;
pub mod vrrp;
pub mod vtp;
pub mod vxlan;

// Re-export protocol implementations for convenience
pub use arp::ArpProtocol;
pub use bfd::BfdProtocol;
pub use bgp::BgpProtocol;
pub use cam::CamProtocol;
pub use cdp::CdpProtocol;
pub use dhcp::DhcpProtocol;
pub use dhcpv6::Dhcpv6Protocol;
pub use dot1q::Dot1qProtocol;
pub use dot1x::Dot1xProtocol;
pub use dtp::DtpProtocol;
pub use eigrp::EigrpProtocol;
pub use erspan::ErspanProtocol;
pub use glbp::GlbpProtocol;
pub use gre::GreProtocol;
pub use gvrp::GvrpProtocol;
pub use hsrp::HsrpProtocol;
pub use icmp::IcmpProtocol;
pub use igmp::IgmpProtocol;
pub use ipv6_nd::Ipv6NdProtocol;
pub use isis::IsisProtocol;
pub use isl::IslProtocol;
pub use lacp::LacpProtocol;
pub use lldp::LldpProtocol;
pub use lldpmed::LldpMedProtocol;
pub use mpls::MplsProtocol;
pub use ospf::OspfProtocol;
pub use pagp::PagpProtocol;
pub use pim::PimProtocol;
pub use pppoe::PppoeProtocol;
pub use qinq::QinQProtocol;
pub use qos::QosProtocol;
pub use ripv2::RipProtocol;
pub use storm::StormProtocol;
pub use stp::StpProtocol;
pub use udld::UdldProtocol;
pub use vrrp::VrrpProtocol;
pub use vtp::VtpProtocol;
pub use vxlan::VxlanProtocol;
