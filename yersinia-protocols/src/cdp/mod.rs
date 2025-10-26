//! Cisco Discovery Protocol (CDP) Implementation
//!
//! This module provides complete CDP support including:
//! - Full packet parsing and construction with all TLV types
//! - CDP flooding attack
//! - CDP spoofing/virtual device attack
//! - Statistics tracking for discovered devices
//!
//! ## Packet Structure
//!
//! CDP uses LLC/SNAP encapsulation over Ethernet:
//! - Destination MAC: 01:00:0C:CC:CC:CC (CDP multicast)
//! - LLC: DSAP=0xAA, SSAP=0xAA, Control=0x03
//! - SNAP: OUI=0x00000C (Cisco), Type=0x2000 (CDP)
//!
//! ## Attacks
//!
//! ### CDP Flooding (Attack ID 0)
//! Sends numerous CDP packets with randomized source MACs and device IDs
//! to exhaust the switch's CAM table and CDP neighbor table.
//!
//! **Parameters:**
//! - `device_id_prefix`: Prefix for generated device IDs (default: "yersinia")
//! - `interval_ms`: Milliseconds between packets (default: 100)
//! - `count`: Number of packets to send (optional, unlimited if not set)
//! - `randomize_mac`: Use random MACs vs Cisco OUI (default: true)
//!
//! ### CDP Spoofing/Virtual Device (Attack ID 1)
//! Impersonates a specific Cisco device by sending periodic CDP beacons.
//! Mimics real Cisco behavior with configurable parameters.
//!
//! **Parameters:**
//! - `device_id`: Device hostname (required)
//! - `ip_address`: Management IP address (required)
//! - `platform`: Platform string (default: "cisco WS-C2960-24TT-L")
//! - `software_version`: IOS version (default: "12.2(55)SE")
//! - `port_id`: Interface name (default: "FastEthernet0/1")
//! - `capabilities`: Capability flags (default: 0x08 = switch)
//! - `vlan`: Native VLAN ID (optional)
//! - `vtp_domain`: VTP domain name (optional)
//! - `interval_ms`: Hello interval in ms (default: 60000 = 60s)
//! - `src_mac`: Source MAC address (optional, random Cisco MAC if not set)
//!
//! ## Example Usage
//!
//! ```rust
//! use yersinia_protocols::cdp::CdpProtocol;
//! use yersinia_core::{AttackId, protocol::AttackParams};
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! let cdp = CdpProtocol::new();
//!
//! // Launch flooding attack
//! let flood_params = AttackParams::new()
//!     .set("device_id_prefix", "Evil")
//!     .set("interval_ms", 100u32)
//!     .set("randomize_mac", true);
//!
//! // let handle = manager.launch(&cdp, AttackId(0), flood_params, &interface).await?;
//!
//! // Launch spoofing attack
//! let spoof_params = AttackParams::new()
//!     .set("device_id", "Router-Evil")
//!     .set("ip_address", "192.168.1.254")
//!     .set("platform", "Cisco 3750")
//!     .set("software_version", "12.2(55)SE10")
//!     .set("capabilities", 0x28u32); // Router + Switch
//!
//! // let handle = manager.launch(&cdp, AttackId(1), spoof_params, &interface).await?;
//! # Ok(())
//! # }
//! ```

pub mod attack;
pub mod packet;
pub mod protocol;

pub use attack::{CdpFloodingAttack, CdpSpoofingAttack};
pub use packet::{
    CdpCapabilities, CdpPacket, CdpTlv, DuplexMode, CDP_MULTICAST_MAC, CDP_TTL_DEFAULT, CDP_VERSION,
};
pub use protocol::CdpProtocol;
