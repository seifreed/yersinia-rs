//! Attack traits and types

use crate::{Interface, Result};
use async_trait::async_trait;
use std::sync::atomic::{AtomicBool, AtomicU64};
use std::sync::Arc;
use std::time::SystemTime;

/// Attack identifier
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct AttackId(pub u8);

/// Attack trait that all attacks must implement
#[async_trait]
pub trait Attack: Send + Sync {
    /// Execute the attack
    ///
    /// This is the main attack logic. It runs asynchronously and should
    /// respect the running flag to allow clean shutdown.
    async fn execute(&self, ctx: AttackContext) -> Result<()>;

    /// Pause the attack
    fn pause(&self);

    /// Resume the attack
    fn resume(&self);

    /// Stop the attack
    fn stop(&self);

    /// Get current attack statistics
    fn stats(&self) -> AttackStats;

    /// Get attack name
    fn name(&self) -> &str;
}

/// Attack descriptor (metadata about an attack)
#[derive(Debug, Clone)]
pub struct AttackDescriptor {
    /// Attack ID
    pub id: AttackId,
    /// Human-readable name
    pub name: &'static str,
    /// Description of what the attack does
    pub description: &'static str,
    /// Parameters this attack accepts
    pub parameters: Vec<ParamDescriptor>,
}

/// Parameter descriptor
#[derive(Debug, Clone)]
pub struct ParamDescriptor {
    /// Parameter name
    pub name: &'static str,
    /// Parameter description
    pub description: &'static str,
    /// Parameter type
    pub param_type: crate::ParameterType,
    /// Default value
    pub default: Option<String>,
    /// Is this parameter required?
    pub required: bool,
}

impl ParamDescriptor {
    pub fn new(name: &'static str, param_type: crate::ParameterType) -> Self {
        Self {
            name,
            description: "",
            param_type,
            default: None,
            required: false,
        }
    }

    pub fn with_description(mut self, description: &'static str) -> Self {
        self.description = description;
        self
    }

    pub fn with_default(mut self, default: String) -> Self {
        self.default = Some(default);
        self
    }

    pub fn required(mut self) -> Self {
        self.required = true;
        self
    }
}

/// Attack statistics
#[derive(Debug, Clone, Default)]
pub struct AttackStats {
    /// Packets sent
    pub packets_sent: u64,
    /// Bytes sent
    pub bytes_sent: u64,
    /// Packets received (if applicable)
    pub packets_received: u64,
    /// Errors encountered
    pub errors: u64,
    /// When the attack started
    pub started_at: Option<SystemTime>,
    /// Duration in seconds (if finished)
    pub duration_secs: Option<u64>,
    /// Is the attack currently running?
    pub is_running: bool,
    /// Is the attack paused?
    pub is_paused: bool,
}

/// Attack context passed to the execute method
pub struct AttackContext {
    /// Interface to send packets on
    pub interface: Interface,
    /// Running flag (attack should stop when this is false)
    pub running: Arc<AtomicBool>,
    /// Paused flag
    pub paused: Arc<AtomicBool>,
    /// Statistics counters
    pub stats: Arc<AttackStatsCounters>,
}

/// Thread-safe attack statistics counters
#[derive(Default)]
pub struct AttackStatsCounters {
    pub packets_sent: AtomicU64,
    pub bytes_sent: AtomicU64,
    pub packets_received: AtomicU64,
    pub errors: AtomicU64,
}

impl AttackStatsCounters {
    pub fn increment_packets_sent(&self) {
        self.packets_sent
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }

    pub fn add_bytes_sent(&self, bytes: u64) {
        self.bytes_sent
            .fetch_add(bytes, std::sync::atomic::Ordering::Relaxed);
    }

    pub fn increment_errors(&self) {
        self.errors
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }

    pub fn to_stats(&self, started_at: SystemTime, running: bool, paused: bool) -> AttackStats {
        let duration_secs = if !running {
            SystemTime::now()
                .duration_since(started_at)
                .ok()
                .map(|d| d.as_secs())
        } else {
            None
        };

        AttackStats {
            packets_sent: self.packets_sent.load(std::sync::atomic::Ordering::Relaxed),
            bytes_sent: self.bytes_sent.load(std::sync::atomic::Ordering::Relaxed),
            packets_received: self
                .packets_received
                .load(std::sync::atomic::Ordering::Relaxed),
            errors: self.errors.load(std::sync::atomic::Ordering::Relaxed),
            started_at: Some(started_at),
            duration_secs,
            is_running: running,
            is_paused: paused,
        }
    }
}

/// Handle to a running attack
pub struct AttackHandle {
    /// Attack ID (UUID v7 for time-ordered tracking)
    pub id: uuid::Uuid,
    /// Protocol name
    pub protocol: String,
    /// Attack name
    pub attack_name: String,
    /// Running flag
    pub running: Arc<AtomicBool>,
    /// Paused flag
    pub paused: Arc<AtomicBool>,
    /// Statistics
    pub stats: Arc<AttackStatsCounters>,
    /// Start time
    pub started_at: SystemTime,
    /// Task handle (for async runtime)
    pub task_handle: Option<tokio::task::JoinHandle<Result<()>>>,
}

impl AttackHandle {
    /// Stop the attack
    pub fn stop(&self) {
        self.running
            .store(false, std::sync::atomic::Ordering::Relaxed);
    }

    /// Pause the attack
    pub fn pause(&self) {
        self.paused
            .store(true, std::sync::atomic::Ordering::Relaxed);
    }

    /// Resume the attack
    pub fn resume(&self) {
        self.paused
            .store(false, std::sync::atomic::Ordering::Relaxed);
    }

    /// Get current statistics
    pub fn stats(&self) -> AttackStats {
        let running = self.running.load(std::sync::atomic::Ordering::Relaxed);
        let paused = self.paused.load(std::sync::atomic::Ordering::Relaxed);
        self.stats.to_stats(self.started_at, running, paused)
    }
}
