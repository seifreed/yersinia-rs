//! Packet capture library for Yersinia-RS
//!
//! This crate provides a robust, type-safe wrapper around pcap for packet capture operations.
//!
//! ## Features
//!
//! - **Interface Management**: List, query, and select network interfaces
//! - **BPF Filters**: Pre-built filters for common protocols (CDP, STP, DHCP, etc.)
//! - **Statistics**: Real-time capture statistics and metrics
//! - **Thread-Safe**: Safe concurrent access to capture state and statistics
//! - **Type-Safe**: Strong typing for capture configuration and state
//!
//! ## Example
//!
//! ```no_run
//! use yersinia_capture::{PacketCapture, filters};
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! // Create capture on eth0 with CDP filter
//! let mut capture = PacketCapture::new("eth0")?;
//! capture.set_filter(&filters::cdp_filter())?;
//!
//! // Start capturing packets
//! capture.start(|packet| {
//!     println!("Got packet: {} bytes", packet.len());
//! })?;
//!
//! // Later, stop the capture
//! capture.stop()?;
//! # Ok(())
//! # }
//! ```

pub mod capture;
pub mod filters;
pub mod interface;
pub mod stats;

// Re-export main types
pub use capture::{CaptureConfig, CaptureState, PacketCapture};
pub use interface::{
    default_interface, get_interface, list_capture_interfaces, list_interfaces, InterfaceInfo,
};
pub use stats::{CaptureStats, StatsAccumulator};
