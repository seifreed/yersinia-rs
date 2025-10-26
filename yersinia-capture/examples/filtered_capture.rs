//! Example: Filtered packet capture
//!
//! This example demonstrates using BPF filters to capture specific protocols.
//! Note: Requires root/administrator privileges to run.
//!
//! Run with: sudo cargo run --example filtered_capture

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;
use yersinia_capture::{default_interface, filters, PacketCapture};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Find default interface
    let iface = default_interface()?;
    println!("Capturing on: {} ({})", iface.name, iface.description);

    // Create packet capture
    let mut capture = PacketCapture::new(&iface.name)?;

    // Build a filter to capture Layer 2 discovery protocols
    let filter = filters::combine_filters_or(&[
        &filters::cdp_filter(),
        &filters::lldp_filter(),
        &filters::stp_filter(),
    ]);

    println!("BPF Filter: {}", filter);
    println!();

    // Set the filter
    capture.set_filter(&filter)?;

    println!("Capturing Layer 2 discovery protocols...");
    println!("(CDP, LLDP, STP)");
    println!("Will capture for 30 seconds or 10 packets");
    println!();

    // Start capture
    let count = Arc::new(AtomicUsize::new(0));
    let c = count.clone();

    capture.start(move |packet| {
        let n = c.fetch_add(1, Ordering::SeqCst) + 1;

        println!("[{}] Discovery packet captured!", n);
        println!("  Interface: {}", packet.interface);
        println!("  Length: {} bytes", packet.len());

        // Print first few bytes in hex
        let preview = packet
            .data()
            .iter()
            .take(32)
            .map(|b| format!("{:02x}", b))
            .collect::<Vec<_>>()
            .join(" ");
        println!("  Data: {}", preview);
        println!();
    })?;

    // Wait for 30 seconds or 10 packets
    let start = std::time::Instant::now();
    while start.elapsed() < Duration::from_secs(30) {
        thread::sleep(Duration::from_millis(100));

        if count.load(Ordering::SeqCst) >= 10 {
            break;
        }
    }

    // Stop capture
    capture.stop()?;

    // Print final statistics
    println!("\n=== Capture Complete ===");
    println!("Total packets: {}", count.load(Ordering::SeqCst));

    let stats = capture.stats();
    println!("\nStatistics:");
    println!("{}", stats.format());

    Ok(())
}
