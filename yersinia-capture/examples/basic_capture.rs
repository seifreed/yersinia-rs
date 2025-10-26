//! Example: Basic packet capture
//!
//! This example demonstrates basic packet capture without filters.
//! Note: Requires root/administrator privileges to run.
//!
//! Run with: sudo cargo run --example basic_capture

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;
use yersinia_capture::{default_interface, PacketCapture};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Find default interface
    let iface = default_interface()?;
    println!("Capturing on: {} ({})", iface.name, iface.description);

    // Create packet capture
    let mut capture = PacketCapture::new(&iface.name)?;

    println!("Starting packet capture... (will capture 20 packets)");
    println!();

    // Start capture with callback
    let count = Arc::new(AtomicUsize::new(0));
    let c = count.clone();

    capture.start(move |packet| {
        let n = c.fetch_add(1, Ordering::SeqCst) + 1;
        println!(
            "[{}] Packet: {} bytes from {}",
            n,
            packet.len(),
            packet.interface
        );
    })?;

    // Capture for 10 seconds or 20 packets
    let start = std::time::Instant::now();
    while start.elapsed() < Duration::from_secs(10) {
        thread::sleep(Duration::from_millis(100));

        if count.load(Ordering::SeqCst) >= 20 {
            break;
        }

        // Print statistics every 2 seconds
        if start.elapsed().as_secs() % 2 == 0 && start.elapsed().as_millis() % 2000 < 100 {
            let stats = capture.stats();
            println!(
                "\n[Stats] Packets: {}, Bytes: {}, Rate: {:.2} pps\n",
                stats.packets_received, stats.bytes_received, stats.packets_per_second
            );
        }
    }

    // Stop capture
    capture.stop()?;

    // Print final statistics
    let stats = capture.stats();
    println!("\n=== Final Statistics ===");
    println!("{}", stats.format());

    Ok(())
}
