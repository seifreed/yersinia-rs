//! Hot Standby Router Protocol (HSRP) Implementation
//!
//! This module provides complete HSRP support for Cisco's router redundancy protocol including:
//! - Full packet parsing and construction for HSRPv1 and HSRPv2
//! - Active router takeover attack (becoming the active router)
//! - Statistics tracking for discovered HSRP groups
//!
//! ## Packet Structure
//!
//! HSRP uses UDP encapsulation:
//! - UDP Port: 1985 (source and destination)
//! - Destination IP: 224.0.0.2 (HSRPv1) or 224.0.0.102 (HSRPv2)
//! - Destination MAC: 01:00:5E:00:00:02 (HSRPv1) or 01:00:5E:00:00:66 (HSRPv2)
//!
//! ## Protocol States
//!
//! HSRP routers go through these states:
//! - Initial (0): Starting state
//! - Learn (1): Learning configuration from active router
//! - Listen (2): Listening for hellos
//! - Speak (4): Participating in election
//! - Standby (8): Backup router
//! - Active (16): Forwarding packets
//!
//! ## Attacks
//!
//! ### Active Router Takeover (Attack ID 0)
//! Sends a Coup message followed by periodic Hellos to become the active router
//! for an HSRP group, allowing the attacker to intercept traffic destined for
//! the virtual IP address.
//!
//! **Parameters:**
//! - `group_id`: HSRP group number (0-255 for v1, 0-4095 for v2, default: 0)
//! - `virtual_ip`: Virtual IP address to claim (required)
//! - `priority`: Router priority (0-255, default: 255 = maximum)
//! - `virtual_mac`: Virtual MAC address (optional, auto-generated from group)
//! - `authentication`: Authentication string (default: "cisco")
//! - `version`: HSRP version (1 or 2, default: 1)
//! - `interval_ms`: Hello interval in milliseconds (default: 3000)
//!
//! ## Example Usage
//!
//! ```rust
//! use yersinia_protocols::hsrp::HsrpProtocol;
//! use yersinia_core::{AttackId, protocol::AttackParams};
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! let hsrp = HsrpProtocol::new();
//!
//! // Launch active router takeover attack
//! let params = AttackParams::new()
//!     .set("group_id", 0u32)
//!     .set("virtual_ip", "192.168.1.1")
//!     .set("priority", 255u32)
//!     .set("authentication", "cisco")
//!     .set("version", 1u32)
//!     .set("interval_ms", 3000u32);
//!
//! // let handle = manager.launch(&hsrp, AttackId(0), params, &interface).await?;
//! # Ok(())
//! # }
//! ```

pub mod attack;
pub mod packet;
pub mod protocol;

pub use attack::HsrpActiveRouterAttack;
pub use packet::{
    HsrpAuthType, HsrpOpcode, HsrpPacket, HsrpState, HsrpVersion, HSRP_DEFAULT_AUTH,
    HSRP_DEFAULT_HELLOTIME, HSRP_DEFAULT_HOLDTIME, HSRP_DEFAULT_PRIORITY, HSRP_MAX_PRIORITY,
    HSRP_UDP_PORT, HSRP_V1_MULTICAST, HSRP_V1_MULTICAST_MAC, HSRP_V2_MULTICAST,
    HSRP_V2_MULTICAST_MAC, HSRP_VIRTUAL_MAC_OUI, HSRP_VIRTUAL_MAC_PREFIX,
};
pub use protocol::HsrpProtocol;
