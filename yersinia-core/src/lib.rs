//! Yersinia-RS Core Library
//!
//! This crate provides the fundamental traits, types, and error handling
//! for the Yersinia-RS network protocol testing framework.

pub mod attack;
pub mod error;
pub mod interface;
pub mod packet;
pub mod parameter;
pub mod protocol;
pub mod types;

// Re-export commonly used types
pub use attack::{
    Attack, AttackContext, AttackDescriptor, AttackHandle, AttackId, AttackStats,
    AttackStatsCounters,
};
pub use error::{Error, Result};
pub use interface::Interface;
pub use packet::Packet;
pub use parameter::{Parameter, ParameterType, ParameterValue};
pub use protocol::Protocol;
pub use types::*;
