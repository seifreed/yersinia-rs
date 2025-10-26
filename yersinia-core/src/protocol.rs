//! Protocol trait and related types

use crate::{AttackDescriptor, AttackHandle, AttackId, Error, Interface, Packet, Parameter};
use async_trait::async_trait;
use std::collections::HashMap;

/// Main trait that all protocol implementations must implement
#[async_trait]
pub trait Protocol: Send + Sync {
    /// Full name of the protocol (e.g., "Cisco Discovery Protocol")
    fn name(&self) -> &'static str;

    /// Short name used in CLI (e.g., "cdp")
    fn shortname(&self) -> &'static str;

    /// Protocol ID
    fn id(&self) -> crate::ProtocolId;

    /// List of attacks available for this protocol
    fn attacks(&self) -> &[AttackDescriptor];

    /// Parameters that can be configured for this protocol
    fn parameters(&self) -> Vec<Box<dyn Parameter>>;

    /// Process a captured packet (passive mode)
    ///
    /// This is called when a packet matching the protocol filter is captured.
    /// The protocol should parse the packet and update internal statistics.
    fn handle_packet(&mut self, packet: &Packet) -> Result<(), Error>;

    /// Launch a specific attack
    ///
    /// Returns an AttackHandle that can be used to control the attack.
    async fn launch_attack(
        &self,
        attack_id: AttackId,
        params: AttackParams,
        interface: &Interface,
    ) -> Result<AttackHandle, Error>;

    /// Get current protocol statistics
    fn stats(&self) -> ProtocolStats;

    /// Reset protocol statistics
    fn reset_stats(&mut self);
}

/// Parameters for launching an attack
#[derive(Debug, Clone, Default)]
pub struct AttackParams {
    params: HashMap<String, ParamValue>,
}

impl AttackParams {
    /// Create a new empty parameter set
    pub fn new() -> Self {
        Self::default()
    }

    /// Set a parameter value
    pub fn set<K: Into<String>, V: Into<ParamValue>>(mut self, key: K, value: V) -> Self {
        self.params.insert(key.into(), value.into());
        self
    }

    /// Get a parameter value
    pub fn get(&self, key: &str) -> Option<&ParamValue> {
        self.params.get(key)
    }

    /// Get a string parameter
    pub fn get_string(&self, key: &str) -> Option<&str> {
        self.params.get(key).and_then(|v| v.as_string())
    }

    /// Get a u32 parameter
    pub fn get_u32(&self, key: &str) -> Option<u32> {
        self.params.get(key).and_then(|v| v.as_u32())
    }

    /// Get a boolean parameter
    pub fn get_bool(&self, key: &str) -> Option<bool> {
        self.params.get(key).and_then(|v| v.as_bool())
    }

    /// Get a u8 parameter
    pub fn get_u8(&self, key: &str) -> Option<u8> {
        self.params.get(key).and_then(|v| v.as_u8())
    }

    /// Get a u16 parameter
    pub fn get_u16(&self, key: &str) -> Option<u16> {
        self.params.get(key).and_then(|v| v.as_u16())
    }

    /// Get a u64 parameter
    pub fn get_u64(&self, key: &str) -> Option<u64> {
        self.params.get(key).and_then(|v| v.as_u64())
    }

    /// Get a usize parameter
    pub fn get_usize(&self, key: &str) -> Option<usize> {
        self.params.get(key).and_then(|v| v.as_usize())
    }
}

/// Parameter value types
#[derive(Debug, Clone)]
pub enum ParamValue {
    String(String),
    U64(u64),
    U32(u32),
    U16(u16),
    U8(u8),
    Usize(usize),
    Bool(bool),
    MacAddr(crate::MacAddr),
    IpAddr(std::net::IpAddr),
}

impl ParamValue {
    pub fn as_string(&self) -> Option<&str> {
        match self {
            ParamValue::String(s) => Some(s),
            _ => None,
        }
    }

    pub fn as_u32(&self) -> Option<u32> {
        match self {
            ParamValue::U32(v) => Some(*v),
            _ => None,
        }
    }

    pub fn as_bool(&self) -> Option<bool> {
        match self {
            ParamValue::Bool(v) => Some(*v),
            _ => None,
        }
    }

    pub fn as_u8(&self) -> Option<u8> {
        match self {
            ParamValue::U8(v) => Some(*v),
            ParamValue::U16(v) if *v <= u8::MAX as u16 => Some(*v as u8),
            ParamValue::U32(v) if *v <= u8::MAX as u32 => Some(*v as u8),
            ParamValue::U64(v) if *v <= u8::MAX as u64 => Some(*v as u8),
            ParamValue::Usize(v) if *v <= u8::MAX as usize => Some(*v as u8),
            _ => None,
        }
    }

    pub fn as_u16(&self) -> Option<u16> {
        match self {
            ParamValue::U16(v) => Some(*v),
            ParamValue::U8(v) => Some(*v as u16),
            ParamValue::U32(v) if *v <= u16::MAX as u32 => Some(*v as u16),
            ParamValue::U64(v) if *v <= u16::MAX as u64 => Some(*v as u16),
            ParamValue::Usize(v) if *v <= u16::MAX as usize => Some(*v as u16),
            _ => None,
        }
    }

    pub fn as_u64(&self) -> Option<u64> {
        match self {
            ParamValue::U64(v) => Some(*v),
            ParamValue::U8(v) => Some(*v as u64),
            ParamValue::U16(v) => Some(*v as u64),
            ParamValue::U32(v) => Some(*v as u64),
            ParamValue::Usize(v) => Some(*v as u64),
            _ => None,
        }
    }

    pub fn as_usize(&self) -> Option<usize> {
        match self {
            ParamValue::Usize(v) => Some(*v),
            ParamValue::U8(v) => Some(*v as usize),
            ParamValue::U16(v) => Some(*v as usize),
            ParamValue::U32(v) => Some(*v as usize),
            ParamValue::U64(v) if *v <= usize::MAX as u64 => Some(*v as usize),
            _ => None,
        }
    }
}

impl From<String> for ParamValue {
    fn from(s: String) -> Self {
        ParamValue::String(s)
    }
}

impl From<&str> for ParamValue {
    fn from(s: &str) -> Self {
        ParamValue::String(s.to_string())
    }
}

impl From<u32> for ParamValue {
    fn from(v: u32) -> Self {
        ParamValue::U32(v)
    }
}

impl From<bool> for ParamValue {
    fn from(v: bool) -> Self {
        ParamValue::Bool(v)
    }
}

impl From<u8> for ParamValue {
    fn from(v: u8) -> Self {
        ParamValue::U8(v)
    }
}

impl From<u16> for ParamValue {
    fn from(v: u16) -> Self {
        ParamValue::U16(v)
    }
}

impl From<u64> for ParamValue {
    fn from(v: u64) -> Self {
        ParamValue::U64(v)
    }
}

impl From<usize> for ParamValue {
    fn from(v: usize) -> Self {
        ParamValue::Usize(v)
    }
}

/// Statistics for a protocol
#[derive(Debug, Clone, Default)]
pub struct ProtocolStats {
    /// Number of packets received
    pub packets_received: u64,
    /// Number of packets parsed successfully
    pub packets_parsed: u64,
    /// Number of packets with errors
    pub packets_errors: u64,
    /// Total bytes received
    pub bytes_received: u64,
    /// Protocol-specific stats
    pub custom: HashMap<String, u64>,
}
