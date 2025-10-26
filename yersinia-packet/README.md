# yersinia-packet

A comprehensive, type-safe packet builder for constructing network packets from Layer 2 (Ethernet) to Layer 4 (TCP/UDP) in pure Rust.

## Features

- **Type Safety**: Uses newtype patterns for ports, MAC addresses, IP addresses, etc.
- **Zero Unsafe**: Pure Rust implementation with no unsafe code
- **Automatic Checksums**: IP, TCP, and UDP checksums calculated automatically
- **Fluent API**: Builder pattern for easy packet construction
- **Bidirectional**: Can both build and parse packets
- **Well Tested**: Comprehensive test coverage (60+ unit tests, 100% passing)
- **Well Documented**: Complete inline documentation with examples

## Supported Protocols

### Layer 2
- **Ethernet II** frames with all common EtherTypes
- **LLC/SNAP** encapsulation for CDP, VTP, DTP, STP, and other protocols

### Layer 3
- **IPv4** packets with full header support and checksum calculation

### Layer 4
- **UDP** datagrams with pseudo-header checksum
- **TCP** segments with flags, options, and checksum

## Quick Start

Add this to your `Cargo.toml`:

```toml
[dependencies]
yersinia-packet = { path = "../yersinia-packet" }
```

### Building a CDP Packet

```rust
use yersinia_packet::PacketBuilder;
use yersinia_packet::ethernet::{MacAddress, EtherType};
use yersinia_packet::llc::{Oui, SnapProtocolId};

let src_mac = MacAddress([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
let cdp_payload = vec![0x02, 0xb4, 0x00, 0x00]; // CDP version 2

let packet = PacketBuilder::new()
    .ethernet(src_mac, MacAddress::CDP_MULTICAST, EtherType::LLC)
    .llc_snap(Oui::CISCO, SnapProtocolId::CDP)
    .payload(cdp_payload)
    .build()
    .unwrap();
```

### Building a UDP Packet

```rust
use std::net::Ipv4Addr;
use yersinia_packet::PacketBuilder;
use yersinia_packet::ethernet::{MacAddress, EtherType};

let packet = PacketBuilder::new()
    .ethernet(src_mac, dst_mac, EtherType::IPv4)
    .ipv4(Ipv4Addr::new(192, 168, 1, 1), Ipv4Addr::new(192, 168, 1, 2))
    .udp(54321, 53) // DNS query
    .payload(dns_data)
    .build()
    .unwrap();
```

### Building a TCP SYN Packet

```rust
use yersinia_packet::tcp::TcpFlags;

let packet = PacketBuilder::new()
    .ethernet(src_mac, dst_mac, EtherType::IPv4)
    .ipv4(src_ip, dst_ip)
    .tcp(54321, 80, 1000, 0, TcpFlags::SYN)
    .window(65535)
    .payload(vec![])
    .build()
    .unwrap();
```

## Architecture

The crate is organized into several modules:

- **`builder`**: High-level fluent API for packet construction
- **`ethernet`**: Ethernet II frame construction and parsing
- **`llc`**: LLC and SNAP support for layer 2 protocols
- **`ip`**: IPv4 packet construction
- **`udp`**: UDP datagram construction
- **`tcp`**: TCP segment construction
- **`checksum`**: Internet checksum calculation utilities

## Examples

The crate includes several complete examples:

- `build_cdp_packet`: Building a CDP (Cisco Discovery Protocol) packet
- `build_udp_packet`: Building a complete UDP packet with DNS query
- `build_tcp_syn`: Building a TCP SYN packet for connection establishment

Run an example with:

```bash
cargo run --example build_cdp_packet
```

## Testing

Run the test suite:

```bash
cargo test -p yersinia-packet
```

Test results: **60 unit tests + 8 doc tests = 68 tests, 100% passing**

## Documentation

Generate and view the documentation:

```bash
cargo doc -p yersinia-packet --open
```

## Implementation Details

### Checksums

All checksums are calculated automatically:

- **IP checksum**: RFC 791 Internet Checksum over IP header
- **UDP checksum**: RFC 768 with pseudo-header (includes src/dst IP)
- **TCP checksum**: RFC 793 with pseudo-header (includes src/dst IP)

### Padding

Ethernet frames are automatically padded to the minimum frame size (60 bytes without FCS).

### Type Safety

The crate uses newtype patterns for type safety:

- `MacAddress`: 6-byte MAC address
- `EtherType`: Ethernet type or protocol
- `Ipv4Addr`: IPv4 address (from `std::net`)
- `UdpPort`/`TcpPort`: 16-bit port numbers
- `TcpFlags`: TCP flags with named constants
- `Oui`: Organizationally Unique Identifier (3 bytes)
- `SnapProtocolId`: SNAP protocol identifier

### Performance

The implementation uses:

- `BytesMut` from the `bytes` crate for efficient buffer management
- Pre-allocated buffers with capacity hints
- Zero-copy operations where possible

## Code Statistics

- **Total lines of code**: ~3,500 lines
- **Modules**: 7 main modules
- **Tests**: 60 unit tests + 8 documentation tests
- **Examples**: 3 complete examples

## License

GPL-2.0-or-later (inherited from Yersinia project)

## Contributing

This crate is part of the Yersinia-RS project, a Rust rewrite of the classic Yersinia network vulnerability testing tool.
