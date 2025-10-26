//! Packet construction and parsing library for Yersinia-RS
//!
//! This crate provides a comprehensive, type-safe packet builder for constructing
//! network packets from layer 2 (Ethernet) to layer 4 (TCP/UDP). It includes
//! support for:
//!
//! - **Ethernet II frames** with common EtherTypes
//! - **LLC/SNAP** encapsulation for CDP, VTP, DTP, STP, and other protocols
//! - **IPv4** packets with header construction and checksum calculation
//! - **UDP** datagrams with pseudo-header checksum
//! - **TCP** segments with flags, options, and checksum
//!
//! # Architecture
//!
//! The library is organized into several modules:
//!
//! - [`builder`] - High-level fluent API for packet construction
//! - [`ethernet`] - Ethernet II frame construction and parsing
//! - [`llc`] - LLC and SNAP support for layer 2 protocols
//! - [`ip`] - IPv4 packet construction
//! - [`udp`] - UDP datagram construction
//! - [`tcp`] - TCP segment construction
//! - [`checksum`] - Internet checksum calculation utilities
//!
//! # Quick Start
//!
//! ## Building a CDP packet
//!
//! ```rust
//! use yersinia_packet::PacketBuilder;
//! use yersinia_packet::ethernet::{MacAddress, EtherType};
//! use yersinia_packet::llc::{Oui, SnapProtocolId};
//!
//! let src_mac = MacAddress([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
//! let cdp_payload = vec![0x02, 0x00, 0x00, 0x01]; // CDP version 2
//!
//! let packet = PacketBuilder::new()
//!     .ethernet(src_mac, MacAddress::CDP_MULTICAST, EtherType::LLC)
//!     .llc_snap(Oui::CISCO, SnapProtocolId::CDP)
//!     .payload(cdp_payload)
//!     .build()
//!     .unwrap();
//! ```
//!
//! ## Building a UDP packet
//!
//! ```rust
//! use std::net::Ipv4Addr;
//! use yersinia_packet::PacketBuilder;
//! use yersinia_packet::ethernet::{MacAddress, EtherType};
//!
//! let src_mac = MacAddress([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
//! let dst_mac = MacAddress([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]);
//! let src_ip = Ipv4Addr::new(192, 168, 1, 1);
//! let dst_ip = Ipv4Addr::new(192, 168, 1, 2);
//!
//! let packet = PacketBuilder::new()
//!     .ethernet(src_mac, dst_mac, EtherType::IPv4)
//!     .ipv4(src_ip, dst_ip)
//!     .udp(12345, 53) // DNS query
//!     .payload(vec![/* DNS query data */])
//!     .build()
//!     .unwrap();
//! ```
//!
//! ## Building a TCP SYN packet
//!
//! ```rust
//! use std::net::Ipv4Addr;
//! use yersinia_packet::PacketBuilder;
//! use yersinia_packet::ethernet::{MacAddress, EtherType};
//! use yersinia_packet::tcp::TcpFlags;
//!
//! let src_mac = MacAddress([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
//! let dst_mac = MacAddress([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]);
//! let src_ip = Ipv4Addr::new(192, 168, 1, 1);
//! let dst_ip = Ipv4Addr::new(192, 168, 1, 2);
//!
//! let packet = PacketBuilder::new()
//!     .ethernet(src_mac, dst_mac, EtherType::IPv4)
//!     .ipv4(src_ip, dst_ip)
//!     .tcp(54321, 80, 1000, 0, TcpFlags::SYN)
//!     .payload(vec![])
//!     .build()
//!     .unwrap();
//! ```
//!
//! # Low-Level API
//!
//! For more control, you can use the individual packet construction types:
//!
//! ```rust
//! use yersinia_packet::ethernet::{EthernetFrame, MacAddress, EtherType};
//!
//! let src = MacAddress([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
//! let dst = MacAddress::BROADCAST;
//! let payload = vec![0x01, 0x02, 0x03, 0x04];
//!
//! let frame = EthernetFrame::new(dst, src, EtherType::IPv4, payload);
//! let bytes = frame.to_bytes();
//! ```
//!
//! # Features
//!
//! - **Type Safety**: Uses newtype patterns for ports, MAC addresses, etc.
//! - **Zero Unsafe**: Pure Rust implementation with no unsafe code
//! - **Automatic Checksums**: IP, TCP, and UDP checksums calculated automatically
//! - **Fluent API**: Builder pattern for easy packet construction
//! - **Parsing**: Bidirectional - can both build and parse packets
//! - **Well Tested**: Comprehensive test coverage with roundtrip tests

pub mod builder;
pub mod checksum;
pub mod ethernet;
pub mod ip;
pub mod llc;
pub mod tcp;
pub mod udp;

// Re-export commonly used types for convenience
pub use builder::PacketBuilder;
pub use checksum::{internet_checksum, transport_checksum};
pub use ethernet::{EtherType, EthernetFrame, MacAddress};
pub use ip::{IpProtocol, Ipv4Packet};
pub use llc::{LlcSnapFrame, Oui, SnapProtocolId};
pub use tcp::{TcpFlags, TcpPort, TcpSegment};
pub use udp::{UdpDatagram, UdpPort};
