//! Example: Building a CDP packet
//!
//! This example demonstrates how to use the yersinia-packet crate to build
//! a complete CDP packet using the fluent API.

use yersinia_packet::ethernet::{EtherType, MacAddress};
use yersinia_packet::llc::{Oui, SnapProtocolId};
use yersinia_packet::PacketBuilder;

fn main() {
    // Source MAC address (your device)
    let src_mac = MacAddress([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);

    // CDP uses a specific multicast address
    let dst_mac = MacAddress::CDP_MULTICAST; // 01:00:0C:CC:CC:CC

    // Minimal CDP payload (version 2, TTL 180 seconds)
    let cdp_payload = vec![
        0x02, // CDP version 2
        0xb4, // TTL: 180 seconds
        0x00, 0x00, // Checksum (placeholder)
    ];

    // Build the packet using the fluent API
    let packet = PacketBuilder::new()
        .ethernet(src_mac, dst_mac, EtherType::LLC)
        .llc_snap(Oui::CISCO, SnapProtocolId::CDP)
        .payload(cdp_payload)
        .build()
        .expect("Failed to build CDP packet");

    println!("CDP packet built successfully!");
    println!("Total size: {} bytes", packet.len());
    println!("First 20 bytes: {:02X?}", &packet[..20.min(packet.len())]);

    // In a real application, you would send this packet using pnet or similar
    // Example (conceptual):
    // tx.send_to(&packet, None).unwrap();
}
