//! ICMP (Internet Control Message Protocol) Advanced Attacks
//!
//! This module provides ICMP attack capabilities including:
//! - ICMP Redirect attacks (MITM)
//! - ICMP Flood/DoS
//! - ICMP Amplification (Smurf attack)
//! - Router Discovery manipulation

pub mod attack;
pub mod packet;
pub mod protocol;

pub use attack::{IcmpAmplificationAttack, IcmpFloodAttack, IcmpRedirectAttack};
pub use packet::{IcmpPacket, IcmpType, ICMP_PROTOCOL};
pub use protocol::IcmpProtocol;
