//! Dynamic Trunking Protocol (DTP) Implementation
//!
//! This module provides complete DTP support with 100% parity to Yersinia original.
//! DTP is Cisco's proprietary protocol for automatic trunk negotiation between switches.
//!
//! ## Packet Structure
//!
//! DTP uses LLC/SNAP encapsulation over Ethernet:
//! ```text
//! Ethernet Header (14 bytes)
//!   Dst: 01:00:0C:CC:CC:CC (DTP multicast)
//!   Src: Interface MAC
//!   Length: payload length
//! LLC/SNAP Header (8 bytes)
//!   DSAP: 0xAA
//!   SSAP: 0xAA
//!   Control: 0x03
//!   OUI: 0x00000C (Cisco)
//!   Type: 0x2004 (DTP)
//! DTP Data:
//!   Version: 0x01
//!   TLVs...
//! ```
//!
//! ## TLV Types
//!
//! - **Domain (0x0001)**: VTP domain name (variable length)
//! - **Status (0x0002)**: Port status (1 byte)
//!   - Trunk Operating Status (TOS): 0x00=Access, 0x80=Trunk
//!   - Trunk Administrative Status (TAS): 0x01=On, 0x02=Off, 0x03=Desirable, 0x04=Auto
//! - **Type (0x0003)**: Trunk type (1 byte)
//!   - Trunk Operating Type (TOT): 0x20=Native, 0x40=ISL, 0xA0=802.1Q
//!   - Trunk Administrative Type (TAT): 0x00=Negotiated, 0x01=Native, 0x02=ISL, 0x05=802.1Q
//! - **Neighbor (0x0004)**: Neighbor MAC address (6 bytes)
//!
//! ## DTP Status Values
//!
//! DTP status byte combines Trunk Operating Status (TOS) and Trunk Administrative Status (TAS):
//! - **ACCESS/DESIRABLE** (0x03): Access mode, will negotiate if peer is desirable
//! - **ACCESS/AUTO** (0x04): Access mode, respond to desirable
//! - **ACCESS/ON** (0x01): Forced access mode
//! - **ACCESS/OFF** (0x02): Trunking disabled
//! - **TRUNK/DESIRABLE** (0x83): Trunk mode, actively negotiate
//! - **TRUNK/AUTO** (0x84): Trunk mode, passively negotiate
//! - **TRUNK/ON** (0x81): Forced trunk mode
//! - **TRUNK/OFF** (0x82): Trunk mode disabled
//!
//! ## DTP Type Values
//!
//! DTP type byte combines Trunk Operating Type (TOT) and Trunk Administrative Type (TAT):
//! - **802.1Q/802.1Q** (0xA5): Prefer 802.1Q encapsulation
//! - **ISL/ISL** (0x42): Prefer ISL encapsulation
//! - **NATIVE/NATIVE** (0x21): Native VLAN only
//! - **802.1Q/NEGOTIATED** (0xA0): Negotiate encapsulation type
//!
//! ## Attacks
//!
//! ### DTP Negotiation Attack (Attack ID 0)
//! Forces trunk negotiation on access ports to enable VLAN hopping attacks.
//!
//! **Parameters:**
//! - `mode`: DTP mode - "trunk", "desirable", or "auto" (default: "trunk")
//! - `trunk_type`: Encapsulation - "isl", "dot1q", or "negotiate" (default: "dot1q")
//! - `vtp_domain`: VTP domain name (optional, defaults to null domain)
//! - `src_mac`: Source MAC address (optional, random if not set)
//! - `interval_ms`: DTP hello interval in ms (default: 30000 = 30s like Cisco)
//!
//! ## Example Usage
//!
//! ```rust
//! use yersinia_protocols::dtp::DtpProtocol;
//! use yersinia_core::{AttackId, protocol::AttackParams};
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! let dtp = DtpProtocol::new();
//!
//! // Launch trunk negotiation attack with 802.1Q
//! let params = AttackParams::new()
//!     .set("mode", "trunk")
//!     .set("trunk_type", "dot1q")
//!     .set("vtp_domain", "")
//!     .set("interval_ms", 30000u32);
//!
//! // let handle = manager.launch(&dtp, AttackId(0), params, &interface).await?;
//! # Ok(())
//! # }
//! ```
//!
//! ## Security Implications
//!
//! DTP negotiation attacks can convert an access port to a trunk port, allowing:
//! - **VLAN Hopping**: Access to multiple VLANs through a single port
//! - **Double Tagging**: Sending packets to other VLANs
//! - **Traffic Interception**: Capturing traffic from multiple VLANs
//!
//! ## Mitigation
//!
//! - Disable DTP on access ports: `switchport mode access` + `switchport nonegotiate`
//! - Use trunk mode explicitly: `switchport mode trunk` (prevents negotiation)
//! - Never use `switchport mode dynamic auto` or `dynamic desirable` in production

pub mod attack;
pub mod packet;
pub mod protocol;

#[cfg(test)]
mod tests;

pub use attack::DtpNegotiationAttack;
pub use packet::{DtpPacket, DtpStatus, DtpTlv, DtpType, DTP_MULTICAST_MAC, DTP_VERSION};
pub use protocol::DtpProtocol;
