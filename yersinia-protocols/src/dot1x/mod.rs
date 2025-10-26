//! IEEE 802.1X (Port-based Network Access Control) Implementation
//!
//! This module provides complete 802.1X support with 100% parity to Yersinia original.
//! 802.1X is the IEEE standard for port-based network access control, providing
//! authentication for devices attempting to attach to a LAN/WLAN.
//!
//! ## Protocol Overview
//!
//! 802.1X uses three components:
//! - **Supplicant**: The client device seeking network access
//! - **Authenticator**: The network device (switch/AP) controlling access
//! - **Authentication Server**: RADIUS server that validates credentials
//!
//! ## EAPOL Frame Structure
//!
//! EAPOL (EAP over LAN) frames are used to transport authentication messages:
//!
//! ```text
//! Ethernet Header (14 bytes)
//!   Dst: 01:80:C2:00:00:03 (PAE multicast address)
//!   Src: Supplicant or Authenticator MAC
//!   EtherType: 0x888E (EAPOL)
//! EAPOL Header (4 bytes)
//!   Protocol Version: 0x01, 0x02, or 0x03
//!   Packet Type: 0x00-0x04
//!   Body Length: 2 bytes (network order)
//! EAPOL Body (variable)
//!   EAP packet or other data
//! ```
//!
//! ## EAPOL Packet Types
//!
//! - **EAP-Packet (0x00)**: Contains an EAP frame
//! - **EAPOL-Start (0x01)**: Supplicant initiates authentication
//! - **EAPOL-Logoff (0x02)**: Supplicant logs off
//! - **EAPOL-Key (0x03)**: Key exchange (WPA/WPA2)
//! - **EAPOL-Encapsulated-ASF-Alert (0x04)**: Alert messages
//!
//! ## EAP Packet Structure
//!
//! When EAPOL packet type is EAP-Packet (0x00), the body contains an EAP packet:
//!
//! ```text
//! EAP Header (4+ bytes)
//!   Code: 1 byte (Request=1, Response=2, Success=3, Failure=4)
//!   Identifier: 1 byte (for matching requests/responses)
//!   Length: 2 bytes (network order, total EAP packet length)
//!   Type: 1 byte (only for Request/Response)
//!   Data: variable (type-specific data)
//! ```
//!
//! ## EAP Codes
//!
//! - **Request (1)**: Authenticator requests information
//! - **Response (2)**: Supplicant responds with requested information
//! - **Success (3)**: Authentication succeeded
//! - **Failure (4)**: Authentication failed
//!
//! ## EAP Types (Common)
//!
//! - **Identity (1)**: Username/identity
//! - **Notification (2)**: Informational message
//! - **NAK (3)**: Negative acknowledgment (Response only)
//! - **MD5-Challenge (4)**: MD5 password challenge
//! - **OTP (5)**: One-Time Password
//! - **GTC (6)**: Generic Token Card
//! - **TLS (13)**: EAP-TLS (certificate-based)
//! - **LEAP (17)**: Cisco LEAP
//! - **SIM (18)**: GSM SIM authentication
//! - **TTLS (21)**: Tunneled TLS
//! - **AKA (23)**: UMTS authentication
//! - **PEAP (25)**: Protected EAP
//! - **MS-CHAPv2 (26)**: Microsoft CHAP version 2
//! - **FAST (43)**: Flexible Authentication via Secure Tunneling
//!
//! ## Authentication Flow
//!
//! 1. **Initialization**: Supplicant connects to authenticator port
//! 2. **Initiation**: Supplicant sends EAPOL-Start
//! 3. **Negotiation**: Authenticator sends EAP-Request/Identity
//! 4. **Identity**: Supplicant sends EAP-Response/Identity
//! 5. **Challenge**: Authenticator forwards to RADIUS, which sends challenge
//! 6. **Credentials**: Supplicant responds with credentials
//! 7. **Verification**: RADIUS verifies credentials
//! 8. **Success/Failure**: RADIUS responds with Accept/Reject
//! 9. **Port Control**: Authenticator opens/closes port based on result
//!
//! ## Attacks Implemented
//!
//! ### 802.1X DoS Attack (Attack ID 0)
//! Floods the authenticator with EAPOL-Start packets to exhaust resources.
//!
//! **Parameters:**
//! - `rate_pps`: Packets per second (default: 100, max: 10000)
//! - `mac_mode`: "random", "pool", or "list" (default: "random")
//! - `pool_size`: Size of MAC pool if mac_mode="pool" (default: 100)
//! - `mac_list`: Comma-separated MAC addresses if mac_mode="list"
//!
//! **Impact:**
//! - Exhausts authenticator's port state table
//! - Overloads RADIUS server with authentication requests
//! - Consumes network bandwidth
//! - Can cause denial of service for legitimate clients
//!
//! ### 802.1X Identity Spoofing Attack (Attack ID 1)
//! Sends EAP-Response/Identity with spoofed identity.
//!
//! **Parameters:**
//! - `identity`: Identity string to spoof (default: "anonymous")
//! - `src_mac`: Source MAC address (optional, random if not set)
//! - `eap_identifier`: EAP identifier value (default: 0)
//! - `continuous`: Send continuously (default: false)
//! - `interval_ms`: Interval if continuous (default: 1000ms)
//!
//! **Impact:**
//! - Test RADIUS server responses to different identities
//! - Attempt authentication bypass with known valid identities
//! - Trigger specific authentication flows for testing
//!
//! ## Example Usage
//!
//! ```rust
//! use yersinia_protocols::dot1x::Dot1xProtocol;
//! use yersinia_core::{AttackId, protocol::AttackParams};
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! let dot1x = Dot1xProtocol::new();
//!
//! // Launch EAPOL-Start DoS attack with random MACs
//! let params = AttackParams::new()
//!     .set("rate_pps", 500u32)
//!     .set("mac_mode", "random");
//!
//! // let handle = manager.launch(&dot1x, AttackId(0), params, &interface).await?;
//!
//! // Launch identity spoofing attack
//! let params2 = AttackParams::new()
//!     .set("identity", "admin@corp.com")
//!     .set("continuous", true)
//!     .set("interval_ms", 1000u32);
//!
//! // let handle2 = manager.launch(&dot1x, AttackId(1), params2, &interface).await?;
//! # Ok(())
//! # }
//! ```
//!
//! ## Security Implications
//!
//! 802.1X attacks can:
//! - **DoS**: Prevent legitimate devices from authenticating
//! - **Reconnaissance**: Discover valid usernames and authentication methods
//! - **Bypass**: Exploit weak configurations or credential databases
//! - **MitM**: In combination with other attacks, intercept traffic
//!
//! ## Mitigation
//!
//! - **Rate Limiting**: Limit authentication attempts per port
//! - **Port Security**: Limit MAC addresses per port
//! - **Strong EAP**: Use EAP-TLS or PEAP with certificates
//! - **Monitoring**: Monitor for unusual authentication patterns
//! - **Network Segmentation**: Isolate untrusted networks
//!
//! ## References
//!
//! - IEEE 802.1X-2010: Port-Based Network Access Control
//! - RFC 3748: Extensible Authentication Protocol (EAP)
//! - RFC 2284: PPP Extensible Authentication Protocol (EAP) [obsolete]
//! - Original Yersinia C implementation: `src/dot1x.c`

pub mod attack;
pub mod constants;
pub mod packet;
pub mod protocol;

#[cfg(test)]
mod tests;

pub use attack::{Dot1xDosAttack, Dot1xSpoofingAttack, MacMode};
pub use constants::{
    DOT1X_ETHERTYPE, DOT1X_PAE_MULTICAST, EAPOL_VERSION_1, EAPOL_VERSION_2, EAPOL_VERSION_3,
    EAP_CODE_FAILURE, EAP_CODE_REQUEST, EAP_CODE_RESPONSE, EAP_CODE_SUCCESS, EAP_TYPE_IDENTITY,
    EAP_TYPE_MD5_CHALLENGE, EAP_TYPE_TLS,
};
pub use packet::{EapCode, EapPacket, EapType, EapolPacket, EapolType};
pub use protocol::Dot1xProtocol;
