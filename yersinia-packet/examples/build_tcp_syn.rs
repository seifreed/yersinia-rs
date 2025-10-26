//! Example: Building a TCP SYN packet
//!
//! This example demonstrates how to use the yersinia-packet crate to build
//! a TCP SYN packet for connection establishment.

use std::net::Ipv4Addr;
use yersinia_packet::ethernet::{EtherType, MacAddress};
use yersinia_packet::tcp::TcpFlags;
use yersinia_packet::PacketBuilder;

fn main() {
    // Network addresses
    let src_mac = MacAddress([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
    let dst_mac = MacAddress([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]);
    let src_ip = Ipv4Addr::new(192, 168, 1, 100);
    let dst_ip = Ipv4Addr::new(192, 168, 1, 1);

    // Build TCP SYN packet
    let packet = PacketBuilder::new()
        .ethernet(src_mac, dst_mac, EtherType::IPv4)
        .ipv4(src_ip, dst_ip)
        .ttl(64)
        .tcp(
            54321, // Source port
            80,    // Destination port (HTTP)
            1000,  // Initial sequence number
            0,     // Acknowledgment number (0 for SYN)
            TcpFlags::SYN,
        )
        .window(65535) // Maximum window size
        .payload(vec![]) // No data in SYN packet
        .build()
        .expect("Failed to build TCP SYN packet");

    println!("TCP SYN packet built successfully!");
    println!("Total size: {} bytes", packet.len());
    println!("TCP flags: SYN");
    println!("Sequence number: 1000");
    println!("Window size: 65535");

    // Parse the flags byte to verify
    let tcp_flags_byte = packet[47]; // Offset to TCP flags
    println!("TCP flags byte: 0x{:02X}", tcp_flags_byte);
    println!("  SYN flag set: {}", (tcp_flags_byte & 0x02) != 0);
}
