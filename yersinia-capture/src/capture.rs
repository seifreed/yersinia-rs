//! Packet capture wrapper around pcap

use parking_lot::{Mutex, RwLock};
use pcap::{Active, Capture, Device, Linktype};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, SystemTime};
use tracing::{debug, error, info};
use yersinia_core::{Error, Packet, Result};

use crate::interface::{get_interface, InterfaceInfo};
use crate::stats::{CaptureStats, StatsAccumulator};

/// Default snapshot length (maximum bytes per packet)
const DEFAULT_SNAPLEN: i32 = 65535;

/// Default timeout for packet capture (milliseconds)
const DEFAULT_TIMEOUT_MS: i32 = 1000;

/// Configuration for packet capture
#[derive(Debug, Clone)]
pub struct CaptureConfig {
    /// Maximum bytes to capture per packet
    pub snaplen: i32,
    /// Timeout in milliseconds
    pub timeout_ms: i32,
    /// Enable promiscuous mode
    pub promiscuous: bool,
    /// Buffer size (0 = default)
    pub buffer_size: i32,
    /// Enable immediate mode (deliver packets immediately)
    pub immediate_mode: bool,
}

impl Default for CaptureConfig {
    fn default() -> Self {
        Self {
            snaplen: DEFAULT_SNAPLEN,
            timeout_ms: DEFAULT_TIMEOUT_MS,
            promiscuous: true,
            buffer_size: 0,
            immediate_mode: true,
        }
    }
}

/// State of packet capture
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CaptureState {
    /// Capture is not running
    Stopped,
    /// Capture is actively running
    Running,
    /// Capture is paused
    Paused,
}

/// Main packet capture interface
pub struct PacketCapture {
    /// Interface name
    interface: String,
    /// Interface information
    interface_info: InterfaceInfo,
    /// Capture configuration
    config: CaptureConfig,
    /// Active pcap capture (when running)
    capture: Arc<Mutex<Option<Capture<Active>>>>,
    /// Current BPF filter
    filter: Arc<RwLock<Option<String>>>,
    /// Current capture state
    state: Arc<RwLock<CaptureState>>,
    /// Statistics accumulator
    stats: StatsAccumulator,
}

impl PacketCapture {
    /// Create a new packet capture on the specified interface
    pub fn new(interface: &str) -> Result<Self> {
        let interface_info = get_interface(interface)?;

        if !interface_info.is_up {
            return Err(Error::Capture(format!(
                "Interface '{}' is not up",
                interface
            )));
        }

        info!("Created packet capture on interface: {}", interface);

        Ok(Self {
            interface: interface.to_string(),
            interface_info,
            config: CaptureConfig::default(),
            capture: Arc::new(Mutex::new(None)),
            filter: Arc::new(RwLock::new(None)),
            state: Arc::new(RwLock::new(CaptureState::Stopped)),
            stats: StatsAccumulator::new(),
        })
    }

    /// Create a new packet capture with custom configuration
    pub fn with_config(interface: &str, config: CaptureConfig) -> Result<Self> {
        let mut capture = Self::new(interface)?;
        capture.config = config;
        Ok(capture)
    }

    /// Set BPF filter for packet capture
    pub fn set_filter(&mut self, bpf: &str) -> Result<()> {
        debug!("Setting BPF filter: {}", bpf);

        // Validate filter by trying to compile it
        let device = Device::from(self.interface.as_str());
        let mut test_capture = Capture::from_device(device)
            .map_err(|e| Error::Capture(format!("Failed to open device: {}", e)))?
            .open()
            .map_err(|e| Error::Capture(format!("Failed to open capture: {}", e)))?;

        test_capture
            .filter(bpf, true)
            .map_err(|e| Error::Capture(format!("Invalid BPF filter: {}", e)))?;

        // Store filter for later use
        *self.filter.write() = Some(bpf.to_string());

        // If capture is running, apply filter to active capture
        let mut capture_guard = self.capture.lock();
        if let Some(capture) = capture_guard.as_mut() {
            capture
                .filter(bpf, true)
                .map_err(|e| Error::Capture(format!("Failed to apply filter: {}", e)))?;
        }

        info!("BPF filter set: {}", bpf);
        Ok(())
    }

    /// Set promiscuous mode
    pub fn set_promiscuous(&mut self, enable: bool) {
        self.config.promiscuous = enable;
        debug!("Promiscuous mode: {}", enable);
    }

    /// Set snapshot length
    pub fn set_snaplen(&mut self, snaplen: i32) {
        self.config.snaplen = snaplen;
        debug!("Snapshot length: {}", snaplen);
    }

    /// Set capture timeout
    pub fn set_timeout(&mut self, timeout_ms: i32) {
        self.config.timeout_ms = timeout_ms;
        debug!("Timeout: {}ms", timeout_ms);
    }

    /// Get interface information
    pub fn interface_info(&self) -> &InterfaceInfo {
        &self.interface_info
    }

    /// Get current capture state
    pub fn state(&self) -> CaptureState {
        *self.state.read()
    }

    /// Get current statistics
    pub fn stats(&self) -> CaptureStats {
        self.stats.snapshot()
    }

    /// Get statistics from pcap
    pub fn pcap_stats(&self) -> Result<CaptureStats> {
        let mut capture_guard = self.capture.lock();
        if let Some(capture) = capture_guard.as_mut() {
            let stats = capture
                .stats()
                .map_err(|e| Error::Capture(format!("Failed to get stats: {}", e)))?;
            let duration = self.stats.elapsed();
            Ok(CaptureStats::from_pcap_stats(stats, duration))
        } else {
            Err(Error::Capture("Capture not active".to_string()))
        }
    }

    /// Initialize pcap capture
    fn init_capture(&self) -> Result<Capture<Active>> {
        debug!("Initializing pcap capture on {}", self.interface);

        let device = Device::from(self.interface.as_str());
        let mut capture = Capture::from_device(device)
            .map_err(|e| Error::Capture(format!("Failed to create capture: {}", e)))?
            .promisc(self.config.promiscuous)
            .snaplen(self.config.snaplen)
            .timeout(self.config.timeout_ms)
            .immediate_mode(self.config.immediate_mode);

        if self.config.buffer_size > 0 {
            capture = capture.buffer_size(self.config.buffer_size);
        }

        let mut capture = capture
            .open()
            .map_err(|e| Error::Capture(format!("Failed to open capture: {}", e)))?;

        // Apply filter if set
        if let Some(filter) = self.filter.read().as_ref() {
            capture
                .filter(filter, true)
                .map_err(|e| Error::Capture(format!("Failed to apply filter: {}", e)))?;
            debug!("Applied filter: {}", filter);
        }

        info!("Capture initialized on {}", self.interface);
        Ok(capture)
    }

    /// Start packet capture with callback
    pub fn start<F>(&mut self, mut callback: F) -> Result<()>
    where
        F: FnMut(Packet) + Send + 'static,
    {
        let current_state = *self.state.read();
        if current_state != CaptureState::Stopped {
            return Err(Error::Capture("Capture already running".to_string()));
        }

        let capture = self.init_capture()?;
        *self.capture.lock() = Some(capture);
        *self.state.write() = CaptureState::Running;

        info!("Starting packet capture on {}", self.interface);

        let capture_arc = Arc::clone(&self.capture);
        let state_arc = Arc::clone(&self.state);
        let stats = self.stats.clone();
        let interface = self.interface.clone();

        thread::spawn(move || {
            let mut capture_guard = capture_arc.lock();
            if let Some(capture) = capture_guard.as_mut() {
                loop {
                    // Check if we should stop
                    let state = *state_arc.read();
                    if state == CaptureState::Stopped {
                        debug!("Capture stopped");
                        break;
                    }

                    if state == CaptureState::Paused {
                        thread::sleep(Duration::from_millis(100));
                        continue;
                    }

                    // Capture next packet
                    match capture.next_packet() {
                        Ok(packet) => {
                            let packet_data = packet.data.to_vec();
                            let packet_len = packet_data.len();

                            // Update statistics
                            stats.record_packet(packet_len);

                            // Create Packet struct
                            let pkt = Packet {
                                timestamp: SystemTime::now(),
                                interface: interface.clone(),
                                data: packet_data,
                                len: packet_len,
                            };

                            // Call user callback
                            callback(pkt);
                        }
                        Err(pcap::Error::TimeoutExpired) => {
                            // Timeout is normal, just continue
                            continue;
                        }
                        Err(e) => {
                            error!("Packet capture error: {}", e);
                            break;
                        }
                    }
                }
            }

            *state_arc.write() = CaptureState::Stopped;
            info!("Capture thread finished");
        });

        Ok(())
    }

    /// Start capture and collect packets into a vector (for testing)
    pub fn start_collect(&mut self, max_packets: usize) -> Result<Vec<Packet>> {
        let packets = Arc::new(Mutex::new(Vec::new()));
        let packets_clone = Arc::clone(&packets);

        let mut count = 0;
        self.start(move |packet| {
            let mut packets = packets_clone.lock();
            packets.push(packet);
            count += 1;
            if count >= max_packets {
                // This is a simple way to stop, but not the cleanest
                // In production, you'd want better control
            }
        })?;

        // Wait for packets or timeout
        for _ in 0..100 {
            thread::sleep(Duration::from_millis(100));
            let count = packets.lock().len();
            if count >= max_packets {
                break;
            }
        }

        self.stop()?;

        let result = packets.lock().clone();
        Ok(result)
    }

    /// Stop packet capture
    pub fn stop(&mut self) -> Result<()> {
        let current_state = *self.state.read();
        if current_state == CaptureState::Stopped {
            return Ok(());
        }

        info!("Stopping packet capture on {}", self.interface);
        *self.state.write() = CaptureState::Stopped;

        // Give the thread time to finish
        thread::sleep(Duration::from_millis(100));

        // Clear capture
        *self.capture.lock() = None;

        Ok(())
    }

    /// Pause packet capture
    pub fn pause(&mut self) -> Result<()> {
        let current_state = *self.state.read();
        if current_state != CaptureState::Running {
            return Err(Error::Capture("Capture not running".to_string()));
        }

        *self.state.write() = CaptureState::Paused;
        info!("Paused packet capture on {}", self.interface);
        Ok(())
    }

    /// Resume packet capture
    pub fn resume(&mut self) -> Result<()> {
        let current_state = *self.state.read();
        if current_state != CaptureState::Paused {
            return Err(Error::Capture("Capture not paused".to_string()));
        }

        *self.state.write() = CaptureState::Running;
        info!("Resumed packet capture on {}", self.interface);
        Ok(())
    }

    /// Get the datalink type
    pub fn datalink(&self) -> Result<Linktype> {
        let capture_guard = self.capture.lock();
        if let Some(capture) = capture_guard.as_ref() {
            Ok(capture.get_datalink())
        } else {
            Err(Error::Capture("Capture not active".to_string()))
        }
    }

    /// Check if capture is running
    pub fn is_running(&self) -> bool {
        *self.state.read() == CaptureState::Running
    }

    /// Reset statistics
    pub fn reset_stats(&self) {
        self.stats.reset();
    }
}

impl Drop for PacketCapture {
    fn drop(&mut self) {
        // Ensure capture is stopped when dropped
        let _ = self.stop();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::filters;

    #[test]
    fn test_capture_config_default() {
        let config = CaptureConfig::default();
        assert_eq!(config.snaplen, DEFAULT_SNAPLEN);
        assert_eq!(config.timeout_ms, DEFAULT_TIMEOUT_MS);
        assert!(config.promiscuous);
        assert!(config.immediate_mode);
    }

    #[test]
    fn test_capture_state() {
        assert_eq!(CaptureState::Stopped, CaptureState::Stopped);
        assert_ne!(CaptureState::Running, CaptureState::Stopped);
    }

    #[test]
    fn test_new_capture() {
        // Try to create capture on loopback (should exist on most systems)
        let result = PacketCapture::new("lo0")
            .or_else(|_| PacketCapture::new("lo"))
            .or_else(|_| PacketCapture::new("\\Device\\NPF_Loopback"));

        // This might fail if not running with permissions
        // or if loopback naming is different
        match result {
            Ok(capture) => {
                assert!(!capture.interface.is_empty());
                assert_eq!(capture.state(), CaptureState::Stopped);
            }
            Err(e) => {
                // Log the error but don't fail the test
                println!("Could not create capture (may need privileges): {}", e);
            }
        }
    }

    #[test]
    fn test_set_config() {
        let result = PacketCapture::new("lo0")
            .or_else(|_| PacketCapture::new("lo"))
            .or_else(|_| PacketCapture::new("\\Device\\NPF_Loopback"));

        if let Ok(mut capture) = result {
            capture.set_promiscuous(false);
            assert!(!capture.config.promiscuous);

            capture.set_snaplen(1024);
            assert_eq!(capture.config.snaplen, 1024);

            capture.set_timeout(500);
            assert_eq!(capture.config.timeout_ms, 500);
        }
    }

    #[test]
    fn test_set_filter() {
        let result = PacketCapture::new("lo0")
            .or_else(|_| PacketCapture::new("lo"))
            .or_else(|_| PacketCapture::new("\\Device\\NPF_Loopback"));

        if let Ok(mut capture) = result {
            // Test valid filter
            let result = capture.set_filter(&filters::arp_filter());
            match result {
                Ok(_) => {
                    assert!(capture.filter.read().is_some());
                }
                Err(e) => {
                    println!("Could not set filter (may need privileges): {}", e);
                }
            }

            // Test invalid filter
            let result = capture.set_filter("invalid filter syntax !!!");
            assert!(result.is_err());
        }
    }

    #[test]
    fn test_stats_accumulator() {
        let result = PacketCapture::new("lo0")
            .or_else(|_| PacketCapture::new("lo"))
            .or_else(|_| PacketCapture::new("\\Device\\NPF_Loopback"));

        if let Ok(capture) = result {
            let stats = capture.stats();
            assert_eq!(stats.packets_received, 0);
            assert_eq!(stats.bytes_received, 0);
        }
    }

    #[test]
    fn test_capture_lifecycle() {
        let result = PacketCapture::new("lo0")
            .or_else(|_| PacketCapture::new("lo"))
            .or_else(|_| PacketCapture::new("\\Device\\NPF_Loopback"));

        if let Ok(capture) = result {
            assert_eq!(capture.state(), CaptureState::Stopped);
            assert!(!capture.is_running());

            // Note: Actually starting capture requires privileges
            // and may not work in all test environments
        }
    }
}
