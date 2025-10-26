//! Link Layer Discovery Protocol (LLDP) Implementation - IEEE 802.1AB
//!
//! This module provides complete LLDP support including:
//! - Full packet parsing and construction with all TLV types
//! - LLDP flooding attack
//! - LLDP device spoofing attack
//! - TLV fuzzing attack
//! - Statistics tracking for discovered neighbors
//!
//! ## Packet Structure
//!
//! LLDP frames have the following structure:
//! - Destination MAC: 01:80:C2:00:00:0E (nearest bridge multicast)
//! - Ethertype: 0x88CC
//! - TLVs: Type-Length-Value format
//!
//! Mandatory TLVs:
//! - Chassis ID (Type 1)
//! - Port ID (Type 2)
//! - TTL (Type 3)
//! - End of LLDPDU (Type 0)
//!
//! Optional TLVs:
//! - Port Description (Type 4)
//! - System Name (Type 5)
//! - System Description (Type 6)
//! - System Capabilities (Type 7)
//! - Management Address (Type 8)
//!
//! ## Attacks
//!
//! ### LLDP Flooding (Attack ID 0)
//! Sends numerous LLDP packets with randomized chassis IDs and port IDs
//! to exhaust the switch's neighbor table and potentially CAM table.
//!
//! **Parameters:**
//! - `system_name_prefix`: Prefix for generated system names (default: "yersinia")
//! - `interval_ms`: Milliseconds between packets (default: 100)
//! - `count`: Number of packets to send (optional, unlimited if not set)
//! - `randomize_mac`: Use random MACs (default: true)
//!
//! ### LLDP Device Spoofing (Attack ID 1)
//! Impersonates a specific network device by sending periodic LLDP beacons.
//!
//! **Parameters:**
//! - `chassis_id`: Chassis identifier (required)
//! - `port_id`: Port identifier (required)
//! - `system_name`: System hostname (required)
//! - `system_description`: System description (default: "Yersinia LLDP")
//! - `port_description`: Port description (default: "eth0")
//! - `capabilities`: System capabilities (default: 0x14 = bridge + router)
//! - `ttl`: Time to live in seconds (default: 120)
//! - `interval_ms`: Hello interval in ms (default: 30000 = 30s)
//! - `src_mac`: Source MAC address (optional)
//!
//! ### LLDP TLV Fuzzing (Attack ID 2)
//! Sends malformed LLDP packets with invalid TLVs to test device robustness.
//!
//! **Parameters:**
//! - `tlv_type`: TLV type to fuzz (default: random)
//! - `tlv_length`: TLV length override (default: random)
//! - `interval_ms`: Milliseconds between packets (default: 100)

pub mod attack;
pub mod packet;
pub mod protocol;

pub use attack::{LldpFloodingAttack, LldpFuzzingAttack, LldpSpoofingAttack};
pub use packet::{LldpCapabilities, LldpPacket, LldpTlv, LLDP_MULTICAST_MAC, LLDP_TTL_DEFAULT};
pub use protocol::LldpProtocol;
