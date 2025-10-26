//! Packet types

use std::time::SystemTime;

/// A captured or constructed packet
#[derive(Debug, Clone)]
pub struct Packet {
    /// When the packet was captured/created
    pub timestamp: SystemTime,
    /// Interface the packet was received on
    pub interface: String,
    /// Packet data (including all headers)
    pub data: Vec<u8>,
    /// Actual length (may differ from data.len() if truncated)
    pub len: usize,
}

impl Packet {
    /// Create a new packet
    pub fn new(interface: String, data: Vec<u8>) -> Self {
        let len = data.len();
        Self {
            timestamp: SystemTime::now(),
            interface,
            data,
            len,
        }
    }

    /// Get packet data as slice
    pub fn data(&self) -> &[u8] {
        &self.data
    }

    /// Get packet length
    pub fn len(&self) -> usize {
        self.len
    }

    /// Check if packet is empty
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }
}
