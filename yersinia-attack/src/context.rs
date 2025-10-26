//! Enhanced attack context with additional features
//!
//! This module provides an enhanced version of the attack context
//! with support for:
//! - Real packet sending
//! - Rate limiting
//! - Logging integration
//! - Resource management

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::time::sleep;
use tracing::{debug, error, warn};
use yersinia_core::{AttackStatsCounters, Error, Interface, Result};

/// Enhanced attack context with additional features
pub struct EnhancedAttackContext {
    /// Interface to send packets on
    pub interface: Interface,
    /// Running flag (attack should stop when this is false)
    pub running: Arc<AtomicBool>,
    /// Paused flag
    pub paused: Arc<AtomicBool>,
    /// Statistics counters
    pub stats: Arc<AttackStatsCounters>,
    /// Rate limiter (optional)
    pub rate_limiter: Option<RateLimiter>,
    /// Attack name (for logging)
    pub attack_name: String,
}

impl EnhancedAttackContext {
    /// Create a new enhanced attack context
    pub fn new(
        interface: Interface,
        running: Arc<AtomicBool>,
        paused: Arc<AtomicBool>,
        stats: Arc<AttackStatsCounters>,
        attack_name: String,
    ) -> Self {
        Self {
            interface,
            running,
            paused,
            stats,
            rate_limiter: None,
            attack_name,
        }
    }

    /// Set a rate limiter for this attack
    pub fn with_rate_limiter(mut self, packets_per_second: u64) -> Self {
        self.rate_limiter = Some(RateLimiter::new(packets_per_second));
        self
    }

    /// Check if the attack should continue running
    #[inline]
    pub fn is_running(&self) -> bool {
        self.running.load(Ordering::Relaxed)
    }

    /// Check if the attack is paused
    #[inline]
    pub fn is_paused(&self) -> bool {
        self.paused.load(Ordering::Relaxed)
    }

    /// Wait while the attack is paused
    pub async fn wait_if_paused(&self) {
        while self.is_paused() && self.is_running() {
            debug!(
                attack = %self.attack_name,
                "Attack paused, waiting..."
            );
            sleep(Duration::from_millis(100)).await;
        }
    }

    /// Apply rate limiting if configured
    pub async fn apply_rate_limit(&mut self) {
        if let Some(limiter) = &mut self.rate_limiter {
            limiter.wait().await;
        }
    }

    /// Send a raw packet (placeholder for actual implementation)
    ///
    /// In a real implementation, this would use pnet or similar
    /// to send the packet on the interface.
    pub async fn send_packet(&self, packet: &[u8]) -> Result<()> {
        // Apply rate limiting before sending
        if let Some(limiter) = &self.rate_limiter {
            limiter.wait().await;
        }

        // Wait if paused
        self.wait_if_paused().await;

        // Check if still running
        if !self.is_running() {
            return Err(Error::Interrupted("Attack stopped".to_string()));
        }

        // Send packet using interface
        self.interface.send_raw(packet)?;

        debug!(
            attack = %self.attack_name,
            interface = %self.interface.name,
            size = packet.len(),
            "Packet sent"
        );

        // Update statistics
        self.stats.increment_packets_sent();
        self.stats.add_bytes_sent(packet.len() as u64);

        Ok(())
    }

    /// Send multiple packets with rate limiting
    pub async fn send_packets(&self, packets: &[Vec<u8>]) -> Result<usize> {
        let mut sent = 0;

        for packet in packets {
            match self.send_packet(packet).await {
                Ok(_) => sent += 1,
                Err(e) => {
                    error!(
                        attack = %self.attack_name,
                        error = %e,
                        "Failed to send packet"
                    );
                    self.stats.increment_errors();
                    return Err(e);
                }
            }
        }

        Ok(sent)
    }

    /// Log an error and update error counter
    pub fn log_error(&self, error: &Error) {
        error!(
            attack = %self.attack_name,
            error = %error,
            "Attack error"
        );
        self.stats.increment_errors();
    }

    /// Log a warning
    pub fn log_warning(&self, message: &str) {
        warn!(
            attack = %self.attack_name,
            message = message,
            "Attack warning"
        );
    }

    /// Log debug information
    pub fn log_debug(&self, message: &str) {
        debug!(
            attack = %self.attack_name,
            message = message,
            "Attack debug"
        );
    }
}

/// Rate limiter for controlling packet send rate
pub struct RateLimiter {
    /// Maximum packets per second
    packets_per_second: u64,
    /// Nanoseconds between packets
    interval_nanos: u64,
    /// Last packet send time
    last_send: Arc<parking_lot::Mutex<Instant>>,
    /// Total packets sent (for tracking)
    total_packets: AtomicU64,
}

impl RateLimiter {
    /// Create a new rate limiter
    pub fn new(packets_per_second: u64) -> Self {
        let packets_per_second = packets_per_second.max(1); // Minimum 1 pps
        let interval_nanos = 1_000_000_000 / packets_per_second;

        Self {
            packets_per_second,
            interval_nanos,
            last_send: Arc::new(parking_lot::Mutex::new(Instant::now())),
            total_packets: AtomicU64::new(0),
        }
    }

    /// Wait until it's time to send the next packet
    pub async fn wait(&self) {
        let sleep_duration = {
            let mut last = self.last_send.lock();
            let now = Instant::now();
            let elapsed = now.duration_since(*last);
            let required = Duration::from_nanos(self.interval_nanos);

            if elapsed < required {
                Some(required - elapsed)
            } else {
                *last = now;
                None
            }
        };

        if let Some(duration) = sleep_duration {
            sleep(duration).await;
            *self.last_send.lock() = Instant::now();
        }

        self.total_packets.fetch_add(1, Ordering::Relaxed);
    }

    /// Get the configured rate
    pub fn packets_per_second(&self) -> u64 {
        self.packets_per_second
    }

    /// Get total packets processed
    pub fn total_packets(&self) -> u64 {
        self.total_packets.load(Ordering::Relaxed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use yersinia_core::MacAddr;

    fn create_test_interface() -> Interface {
        Interface::new(
            "lo0".to_string(),
            0,
            MacAddr([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]),
        )
    }

    #[tokio::test]
    async fn test_context_creation() {
        let interface = create_test_interface();
        let running = Arc::new(AtomicBool::new(true));
        let paused = Arc::new(AtomicBool::new(false));
        let stats = Arc::new(AttackStatsCounters::default());

        let ctx = EnhancedAttackContext::new(
            interface,
            running.clone(),
            paused.clone(),
            stats,
            "test_attack".to_string(),
        );

        assert!(ctx.is_running());
        assert!(!ctx.is_paused());
    }

    #[tokio::test]
    async fn test_pause_resume() {
        let interface = create_test_interface();
        let running = Arc::new(AtomicBool::new(true));
        let paused = Arc::new(AtomicBool::new(false));
        let stats = Arc::new(AttackStatsCounters::default());

        let ctx = EnhancedAttackContext::new(
            interface,
            running.clone(),
            paused.clone(),
            stats,
            "test_attack".to_string(),
        );

        assert!(!ctx.is_paused());

        paused.store(true, Ordering::Relaxed);
        assert!(ctx.is_paused());

        paused.store(false, Ordering::Relaxed);
        assert!(!ctx.is_paused());
    }

    #[tokio::test]
    async fn test_rate_limiter() {
        let limiter = RateLimiter::new(10); // 10 packets per second
        assert_eq!(limiter.packets_per_second(), 10);

        let start = Instant::now();
        for _ in 0..3 {
            limiter.wait().await;
        }
        let elapsed = start.elapsed();

        // Should take at least 200ms for 3 packets at 10 pps
        assert!(elapsed >= Duration::from_millis(190));
        assert_eq!(limiter.total_packets(), 3);
    }

    #[tokio::test]
    async fn test_send_packet_updates_stats() {
        let interface = create_test_interface();
        let running = Arc::new(AtomicBool::new(true));
        let paused = Arc::new(AtomicBool::new(false));
        let stats = Arc::new(AttackStatsCounters::default());

        let ctx = EnhancedAttackContext::new(
            interface,
            running.clone(),
            paused.clone(),
            stats.clone(),
            "test_attack".to_string(),
        );

        let packet = vec![0u8; 100];
        ctx.send_packet(&packet).await.unwrap();

        assert_eq!(stats.packets_sent.load(Ordering::Relaxed), 1);
        assert_eq!(stats.bytes_sent.load(Ordering::Relaxed), 100);
    }

    #[tokio::test]
    async fn test_send_packet_respects_stop() {
        let interface = create_test_interface();
        let running = Arc::new(AtomicBool::new(false)); // Already stopped
        let paused = Arc::new(AtomicBool::new(false));
        let stats = Arc::new(AttackStatsCounters::default());

        let ctx = EnhancedAttackContext::new(
            interface,
            running.clone(),
            paused.clone(),
            stats.clone(),
            "test_attack".to_string(),
        );

        let packet = vec![0u8; 100];
        let result = ctx.send_packet(&packet).await;

        assert!(result.is_err());
        assert_eq!(stats.packets_sent.load(Ordering::Relaxed), 0);
    }
}
