//! Example: Building a UDP packet
//!
//! This example demonstrates how to use the yersinia-packet crate to build
//! a complete UDP packet with Ethernet, IP, and UDP layers.

use std::net::Ipv4Addr;
use yersinia_packet::ethernet::{EtherType, MacAddress};
use yersinia_packet::PacketBuilder;

fn main() {
    // Network addresses
    let src_mac = MacAddress([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
    let dst_mac = MacAddress([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]);
    let src_ip = Ipv4Addr::new(192, 168, 1, 100);
    let dst_ip = Ipv4Addr::new(192, 168, 1, 1);

    // DNS query payload (simplified)
    let dns_query = vec![
        0x12, 0x34, // Transaction ID
        0x01, 0x00, // Flags: standard query
        0x00, 0x01, // Questions: 1
        0x00, 0x00, // Answer RRs: 0
        0x00, 0x00, // Authority RRs: 0
        0x00, 0x00, // Additional RRs: 0
    ];

    // Build the complete packet
    let packet = PacketBuilder::new()
        .ethernet(src_mac, dst_mac, EtherType::IPv4)
        .ipv4(src_ip, dst_ip)
        .ttl(64)
        .udp(54321, 53) // Source port 54321, DNS port 53
        .payload(dns_query)
        .build()
        .expect("Failed to build UDP packet");

    println!("UDP packet built successfully!");
    println!("Total size: {} bytes", packet.len());
    println!("Ethernet header: {:02X?}", &packet[..14]);
    println!("IP version and header length: 0x{:02X}", packet[14]);
    println!("IP protocol: {} (UDP)", packet[23]);
    println!(
        "UDP source port: {}",
        u16::from_be_bytes([packet[34], packet[35]])
    );
    println!(
        "UDP dest port: {}",
        u16::from_be_bytes([packet[36], packet[37]])
    );
}
