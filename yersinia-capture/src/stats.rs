//! Capture statistics and metrics

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Statistics for packet capture operations
#[derive(Debug, Clone)]
pub struct CaptureStats {
    /// Number of packets received by the filter
    pub packets_received: u64,
    /// Number of packets dropped by the kernel
    pub packets_dropped: u64,
    /// Number of packets dropped by the interface
    pub packets_if_dropped: u64,
    /// Total bytes received
    pub bytes_received: u64,
    /// Capture duration
    pub duration: Duration,
    /// Packets per second
    pub packets_per_second: f64,
    /// Bytes per second
    pub bytes_per_second: f64,
}

impl CaptureStats {
    /// Create new empty statistics
    pub fn new() -> Self {
        Self {
            packets_received: 0,
            packets_dropped: 0,
            packets_if_dropped: 0,
            bytes_received: 0,
            duration: Duration::from_secs(0),
            packets_per_second: 0.0,
            bytes_per_second: 0.0,
        }
    }

    /// Create statistics from pcap stats
    pub fn from_pcap_stats(stats: pcap::Stat, duration: Duration) -> Self {
        let secs = duration.as_secs_f64();
        let packets_per_second = if secs > 0.0 {
            stats.received as f64 / secs
        } else {
            0.0
        };

        Self {
            packets_received: stats.received as u64,
            packets_dropped: stats.dropped as u64,
            packets_if_dropped: stats.if_dropped as u64,
            bytes_received: 0, // pcap doesn't provide this directly
            duration,
            packets_per_second,
            bytes_per_second: 0.0,
        }
    }

    /// Calculate drop rate as percentage
    pub fn drop_rate(&self) -> f64 {
        if self.packets_received == 0 {
            return 0.0;
        }
        (self.packets_dropped as f64 / self.packets_received as f64) * 100.0
    }

    /// Check if there are significant drops
    pub fn has_significant_drops(&self, threshold_percent: f64) -> bool {
        self.drop_rate() > threshold_percent
    }

    /// Get total packets (received + dropped)
    pub fn total_packets(&self) -> u64 {
        self.packets_received + self.packets_dropped
    }

    /// Format statistics as human-readable string
    pub fn format(&self) -> String {
        format!(
            "Received: {} packets ({} bytes)\n\
             Dropped: {} packets ({:.2}%)\n\
             IF Dropped: {} packets\n\
             Duration: {:.2}s\n\
             Rate: {:.2} pps, {:.2} KB/s",
            self.packets_received,
            self.bytes_received,
            self.packets_dropped,
            self.drop_rate(),
            self.packets_if_dropped,
            self.duration.as_secs_f64(),
            self.packets_per_second,
            self.bytes_per_second / 1024.0
        )
    }
}

impl Default for CaptureStats {
    fn default() -> Self {
        Self::new()
    }
}

/// Thread-safe statistics accumulator for live capture
#[derive(Debug, Clone)]
pub struct StatsAccumulator {
    packets_received: Arc<AtomicU64>,
    packets_dropped: Arc<AtomicU64>,
    bytes_received: Arc<AtomicU64>,
    start_time: Instant,
}

impl StatsAccumulator {
    /// Create a new statistics accumulator
    pub fn new() -> Self {
        Self {
            packets_received: Arc::new(AtomicU64::new(0)),
            packets_dropped: Arc::new(AtomicU64::new(0)),
            bytes_received: Arc::new(AtomicU64::new(0)),
            start_time: Instant::now(),
        }
    }

    /// Record a received packet
    pub fn record_packet(&self, size: usize) {
        self.packets_received.fetch_add(1, Ordering::Relaxed);
        self.bytes_received
            .fetch_add(size as u64, Ordering::Relaxed);
    }

    /// Record dropped packets
    pub fn record_drops(&self, count: u64) {
        self.packets_dropped.fetch_add(count, Ordering::Relaxed);
    }

    /// Get current statistics snapshot
    pub fn snapshot(&self) -> CaptureStats {
        let packets_received = self.packets_received.load(Ordering::Relaxed);
        let packets_dropped = self.packets_dropped.load(Ordering::Relaxed);
        let bytes_received = self.bytes_received.load(Ordering::Relaxed);
        let duration = self.start_time.elapsed();

        let secs = duration.as_secs_f64();
        let packets_per_second = if secs > 0.0 {
            packets_received as f64 / secs
        } else {
            0.0
        };
        let bytes_per_second = if secs > 0.0 {
            bytes_received as f64 / secs
        } else {
            0.0
        };

        CaptureStats {
            packets_received,
            packets_dropped,
            packets_if_dropped: 0,
            bytes_received,
            duration,
            packets_per_second,
            bytes_per_second,
        }
    }

    /// Reset all statistics
    pub fn reset(&self) {
        self.packets_received.store(0, Ordering::Relaxed);
        self.packets_dropped.store(0, Ordering::Relaxed);
        self.bytes_received.store(0, Ordering::Relaxed);
    }

    /// Get packets received count
    pub fn packets_received(&self) -> u64 {
        self.packets_received.load(Ordering::Relaxed)
    }

    /// Get packets dropped count
    pub fn packets_dropped(&self) -> u64 {
        self.packets_dropped.load(Ordering::Relaxed)
    }

    /// Get bytes received count
    pub fn bytes_received(&self) -> u64 {
        self.bytes_received.load(Ordering::Relaxed)
    }

    /// Get elapsed time since start
    pub fn elapsed(&self) -> Duration {
        self.start_time.elapsed()
    }
}

impl Default for StatsAccumulator {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;
    use std::time::Duration as StdDuration;

    #[test]
    fn test_capture_stats_new() {
        let stats = CaptureStats::new();
        assert_eq!(stats.packets_received, 0);
        assert_eq!(stats.packets_dropped, 0);
        assert_eq!(stats.bytes_received, 0);
    }

    #[test]
    fn test_drop_rate() {
        let stats = CaptureStats {
            packets_received: 100,
            packets_dropped: 10,
            packets_if_dropped: 0,
            bytes_received: 0,
            duration: Duration::from_secs(1),
            packets_per_second: 0.0,
            bytes_per_second: 0.0,
        };

        assert_eq!(stats.drop_rate(), 10.0);
        assert!(stats.has_significant_drops(5.0));
        assert!(!stats.has_significant_drops(15.0));
    }

    #[test]
    fn test_drop_rate_zero_packets() {
        let stats = CaptureStats::new();
        assert_eq!(stats.drop_rate(), 0.0);
    }

    #[test]
    fn test_total_packets() {
        let stats = CaptureStats {
            packets_received: 100,
            packets_dropped: 10,
            packets_if_dropped: 5,
            bytes_received: 0,
            duration: Duration::from_secs(1),
            packets_per_second: 0.0,
            bytes_per_second: 0.0,
        };

        assert_eq!(stats.total_packets(), 110);
    }

    #[test]
    fn test_stats_format() {
        let stats = CaptureStats {
            packets_received: 1000,
            packets_dropped: 50,
            packets_if_dropped: 10,
            bytes_received: 64000,
            duration: Duration::from_secs(10),
            packets_per_second: 100.0,
            bytes_per_second: 6400.0,
        };

        let formatted = stats.format();
        assert!(formatted.contains("1000"));
        assert!(formatted.contains("50"));
        assert!(formatted.contains("64000"));
    }

    #[test]
    fn test_stats_accumulator_basic() {
        let acc = StatsAccumulator::new();

        acc.record_packet(64);
        acc.record_packet(128);
        acc.record_packet(256);

        assert_eq!(acc.packets_received(), 3);
        assert_eq!(acc.bytes_received(), 448);

        acc.record_drops(5);
        assert_eq!(acc.packets_dropped(), 5);
    }

    #[test]
    fn test_stats_accumulator_snapshot() {
        let acc = StatsAccumulator::new();

        acc.record_packet(100);
        acc.record_packet(200);

        let snapshot = acc.snapshot();
        assert_eq!(snapshot.packets_received, 2);
        assert_eq!(snapshot.bytes_received, 300);
        // Duration should be positive but we can't assert on exact value in tests
    }

    #[test]
    fn test_stats_accumulator_reset() {
        let acc = StatsAccumulator::new();

        acc.record_packet(100);
        acc.record_drops(5);

        assert_eq!(acc.packets_received(), 1);
        assert_eq!(acc.packets_dropped(), 5);

        acc.reset();

        assert_eq!(acc.packets_received(), 0);
        assert_eq!(acc.packets_dropped(), 0);
        assert_eq!(acc.bytes_received(), 0);
    }

    #[test]
    fn test_stats_accumulator_thread_safety() {
        let acc = StatsAccumulator::new();
        let acc_clone = acc.clone();

        let handle = thread::spawn(move || {
            for _ in 0..100 {
                acc_clone.record_packet(64);
            }
        });

        for _ in 0..100 {
            acc.record_packet(64);
        }

        handle.join().unwrap();

        assert_eq!(acc.packets_received(), 200);
        assert_eq!(acc.bytes_received(), 12800);
    }

    #[test]
    fn test_stats_accumulator_rates() {
        let acc = StatsAccumulator::new();

        // Wait a bit to ensure non-zero duration
        thread::sleep(StdDuration::from_millis(10));

        acc.record_packet(1000);
        acc.record_packet(2000);

        let snapshot = acc.snapshot();
        assert!(snapshot.packets_per_second > 0.0);
        assert!(snapshot.bytes_per_second > 0.0);
    }

    #[test]
    fn test_default_implementations() {
        let stats = CaptureStats::default();
        assert_eq!(stats.packets_received, 0);

        let acc = StatsAccumulator::default();
        assert_eq!(acc.packets_received(), 0);
    }
}
