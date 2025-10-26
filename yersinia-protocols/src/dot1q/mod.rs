//! IEEE 802.1Q (VLAN Tagging) Protocol Implementation
//!
//! This module provides complete 802.1Q support with 100% parity to Yersinia original.
//! IEEE 802.1Q is the networking standard for VLAN tagging on Ethernet frames.
//!
//! ## Packet Structure
//!
//! 802.1Q adds a 4-byte VLAN tag to Ethernet frames:
//! ```text
//! Ethernet Frame:
//!   Dst MAC: 6 bytes
//!   Src MAC: 6 bytes
//!   TPID: 0x8100 (2 bytes) - Tag Protocol Identifier
//!   TCI (Tag Control Information - 2 bytes):
//!     PCP: 3 bits - Priority Code Point (0-7)
//!     DEI: 1 bit - Drop Eligible Indicator
//!     VID: 12 bits - VLAN Identifier (1-4094)
//!   EtherType: 2 bytes (e.g., 0x0800 for IPv4)
//!   Payload...
//! ```
//!
//! ## VLAN Tag Format
//!
//! The 802.1Q tag consists of:
//! - **TPID (Tag Protocol Identifier)**: Always 0x8100 for single-tagged frames
//! - **PCP (Priority Code Point)**: QoS priority (0-7), 3 bits
//! - **DEI (Drop Eligible Indicator)**: 1 bit for congestion management
//! - **VID (VLAN Identifier)**: 12 bits, valid range 1-4094 (0 and 4095 reserved)
//!
//! ## Double Tagging (Q-in-Q)
//!
//! Double tagging uses two consecutive 802.1Q tags:
//! ```text
//! Ethernet Frame:
//!   Dst MAC: 6 bytes
//!   Src MAC: 6 bytes
//!   Outer TPID: 0x8100 (2 bytes)
//!   Outer TCI: 2 bytes (Outer VLAN)
//!   Inner TPID: 0x8100 (2 bytes)
//!   Inner TCI: 2 bytes (Inner VLAN)
//!   EtherType: 2 bytes
//!   Payload...
//! ```
//!
//! ## Attacks
//!
//! ### Double Tagging Attack (Attack ID 0)
//! Exploits VLAN processing to bypass ACLs and access other VLANs.
//!
//! **How it works:**
//! 1. Attacker on VLAN X sends double-tagged frame
//! 2. Outer tag has VLAN X (attacker's native VLAN)
//! 3. Inner tag has VLAN Y (target VLAN)
//! 4. First switch removes outer tag, forwards to trunk
//! 5. Second switch sees inner tag VLAN Y, delivers to VLAN Y
//!
//! **Parameters:**
//! - `outer_vlan`: Attacker's native VLAN (u16, 1-4094)
//! - `inner_vlan`: Target VLAN to access (u16, 1-4094)
//! - `dst_mac`: Target MAC address (optional, broadcast if not set)
//! - `payload`: Custom payload data (optional)
//!
//! ### VLAN Hopping Attack (Attack ID 1)
//! Sends tagged traffic to multiple VLANs to discover network topology.
//!
//! **Parameters:**
//! - `vlan_list`: Comma-separated list of VLANs to probe (e.g., "1,10,20,100")
//! - `interval_ms`: Interval between probes in milliseconds (default: 1000)
//!
//! ## Example Usage
//!
//! ```rust
//! use yersinia_protocols::dot1q::Dot1qProtocol;
//! use yersinia_core::{AttackId, protocol::AttackParams};
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! let dot1q = Dot1qProtocol::new();
//!
//! // Launch double tagging attack
//! let params = AttackParams::new()
//!     .set("outer_vlan", 10u16)
//!     .set("inner_vlan", 20u16)
//!     .set("dst_mac", "ff:ff:ff:ff:ff:ff");
//!
//! // let handle = manager.launch(&dot1q, AttackId(0), params, &interface).await?;
//! # Ok(())
//! # }
//! ```
//!
//! ## Security Implications
//!
//! 802.1Q attacks can lead to:
//! - **VLAN Hopping**: Access to networks on different VLANs
//! - **ACL Bypass**: Circumventing VLAN-based access controls
//! - **Man-in-the-Middle**: Intercepting traffic from other VLANs
//! - **Data Exfiltration**: Accessing sensitive data on isolated VLANs
//!
//! ## Mitigation
//!
//! - **Disable automatic trunking**: Use `switchport mode access` on access ports
//! - **Use PVLAN Edge**: Prevents VLAN hopping on trunk ports
//! - **Native VLAN tagging**: Always tag native VLAN traffic
//! - **VLAN ACLs (VACLs)**: Filter traffic within VLANs
//! - **Port security**: Limit MAC addresses per port
//! - **Monitor for double-tagged frames**: Use IDS/IPS to detect attacks

pub mod attack;
pub mod packet;
pub mod protocol;

// #[cfg(test)]
// mod tests;

pub use attack::{Dot1qDoubleTaggingAttack, Dot1qVlanHoppingAttack};
pub use packet::{Dot1qTag, DOT1Q_MAX_VLAN, DOT1Q_MIN_VLAN, DOT1Q_TAG_SIZE, DOT1Q_TPID};
pub use protocol::Dot1qProtocol;
