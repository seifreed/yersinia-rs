//! 802.1X Protocol Constants
//!
//! This module defines all constants for IEEE 802.1X (Port-based Network Access Control).

use yersinia_core::MacAddr;

/// 802.1X PAE (Port Access Entity) Multicast MAC Address
/// Used as destination for EAPOL frames
pub const DOT1X_PAE_MULTICAST: MacAddr = MacAddr([0x01, 0x80, 0xC2, 0x00, 0x00, 0x03]);

/// EtherType for EAPOL frames (0x888E)
pub const DOT1X_ETHERTYPE: u16 = 0x888E;

// ===== EAPOL Protocol Versions =====

/// EAPOL Version 1 (802.1X-2001)
pub const EAPOL_VERSION_1: u8 = 0x01;

/// EAPOL Version 2 (802.1X-2004)
pub const EAPOL_VERSION_2: u8 = 0x02;

/// EAPOL Version 3 (802.1X-2010)
pub const EAPOL_VERSION_3: u8 = 0x03;

// ===== EAPOL Packet Types =====

/// EAPOL-Packet (contains EAP data)
pub const EAPOL_TYPE_EAP_PACKET: u8 = 0x00;

/// EAPOL-Start (supplicant initiates authentication)
pub const EAPOL_TYPE_START: u8 = 0x01;

/// EAPOL-Logoff (supplicant logs off)
pub const EAPOL_TYPE_LOGOFF: u8 = 0x02;

/// EAPOL-Key (key exchange for WPA/WPA2)
pub const EAPOL_TYPE_KEY: u8 = 0x03;

/// EAPOL-Encapsulated-ASF-Alert
pub const EAPOL_TYPE_ASF_ALERT: u8 = 0x04;

// ===== EAP Codes =====

/// EAP Request
pub const EAP_CODE_REQUEST: u8 = 0x01;

/// EAP Response
pub const EAP_CODE_RESPONSE: u8 = 0x02;

/// EAP Success
pub const EAP_CODE_SUCCESS: u8 = 0x03;

/// EAP Failure
pub const EAP_CODE_FAILURE: u8 = 0x04;

// ===== EAP Types =====

/// EAP Identity
pub const EAP_TYPE_IDENTITY: u8 = 0x01;

/// EAP Notification
pub const EAP_TYPE_NOTIFICATION: u8 = 0x02;

/// EAP NAK (Response only)
pub const EAP_TYPE_NAK: u8 = 0x03;

/// EAP MD5-Challenge
pub const EAP_TYPE_MD5_CHALLENGE: u8 = 0x04;

/// EAP One-Time Password (OTP)
pub const EAP_TYPE_OTP: u8 = 0x05;

/// EAP Generic Token Card (GTC)
pub const EAP_TYPE_GTC: u8 = 0x06;

/// EAP TLS
pub const EAP_TYPE_TLS: u8 = 0x0D;

/// Cisco LEAP (Lightweight EAP)
pub const EAP_TYPE_LEAP: u8 = 0x11;

/// EAP SIM (GSM Subscriber Identity Module)
pub const EAP_TYPE_SIM: u8 = 0x12;

/// EAP TTLS (Tunneled TLS)
pub const EAP_TYPE_TTLS: u8 = 0x15;

/// EAP AKA (UMTS Authentication and Key Agreement)
pub const EAP_TYPE_AKA: u8 = 0x17;

/// PEAP (Protected EAP)
pub const EAP_TYPE_PEAP: u8 = 0x19;

/// EAP MS-CHAPv2
pub const EAP_TYPE_MSCHAPV2: u8 = 0x1A;

/// EAP TLV (Type-Length-Value)
pub const EAP_TYPE_TLV: u8 = 0x21;

/// EAP FAST (Flexible Authentication via Secure Tunneling)
pub const EAP_TYPE_FAST: u8 = 0x2B;

// ===== Default Values =====

/// Default EAPOL version (Version 1)
pub const DEFAULT_EAPOL_VERSION: u8 = EAPOL_VERSION_1;

/// Default EAP identifier (starts at 0)
pub const DEFAULT_EAP_IDENTIFIER: u8 = 0x00;

/// Default identity string
pub const DEFAULT_IDENTITY: &str = "anonymous";

/// Maximum EAP data length (MTU considerations)
pub const MAX_EAP_DATA_LEN: usize = 1500;

/// Minimum EAPOL packet size (header only)
pub const MIN_EAPOL_SIZE: usize = 4;

/// EAPOL header size (Version + Type + Body Length)
pub const EAPOL_HEADER_SIZE: usize = 4;

/// EAP header size (Code + Identifier + Length)
pub const EAP_HEADER_SIZE: usize = 4;

// ===== Attack-related Constants =====

/// Default DoS attack rate (packets per second)
pub const DEFAULT_DOS_RATE_PPS: u32 = 100;

/// Maximum DoS attack rate (packets per second)
pub const MAX_DOS_RATE_PPS: u32 = 10000;

/// Number of random MACs to generate for MAC flooding attacks
pub const DEFAULT_MAC_POOL_SIZE: usize = 100;

/// EAPOL-Start flood interval (milliseconds between bursts)
pub const EAPOL_START_FLOOD_INTERVAL_MS: u64 = 10;
