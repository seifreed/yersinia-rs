# yersinia-capture

Robust, type-safe packet capture library for Yersinia-RS, providing a high-level wrapper around libpcap.

## Features

- **Interface Management**: List, query, and select network interfaces
- **BPF Filters**: Pre-built filters for common network protocols
- **Statistics**: Real-time capture statistics and metrics
- **Thread-Safe**: Safe concurrent access to capture state and statistics
- **Type-Safe**: Strong typing for capture configuration and state
- **Pause/Resume**: Control packet capture flow dynamically

## Usage

### Basic Packet Capture

```rust
use yersinia_capture::PacketCapture;

// Create capture on network interface
let mut capture = PacketCapture::new("eth0")?;

// Start capturing packets
capture.start(|packet| {
    println!("Captured packet: {} bytes from {}",
             packet.len(),
             packet.interface);
})?;

// Later, stop the capture
capture.stop()?;
```

### Using BPF Filters

```rust
use yersinia_capture::{PacketCapture, filters};

let mut capture = PacketCapture::new("eth0")?;

// Capture only CDP packets
capture.set_filter(&filters::cdp_filter())?;

// Or combine multiple filters
let filter = filters::combine_filters(&[
    &filters::cdp_filter(),
    &filters::stp_filter(),
]);
capture.set_filter(&filter)?;

capture.start(|packet| {
    // Handle CDP or STP packets
})?;
```

### Interface Discovery

```rust
use yersinia_capture::{list_interfaces, default_interface};

// List all available interfaces
let interfaces = list_interfaces()?;
for iface in interfaces {
    println!("{}: {} ({})",
             iface.name,
             iface.description,
             if iface.is_up { "UP" } else { "DOWN" });
}

// Get default capture-capable interface
let default = default_interface()?;
println!("Using: {}", default.name);
```

### Capture Statistics

```rust
use yersinia_capture::PacketCapture;
use std::thread;
use std::time::Duration;

let mut capture = PacketCapture::new("eth0")?;
capture.start(|_packet| { /* process */ })?;

thread::sleep(Duration::from_secs(10));

// Get statistics
let stats = capture.stats();
println!("Packets: {}, Bytes: {}, Rate: {:.2} pps",
         stats.packets_received,
         stats.bytes_received,
         stats.packets_per_second);

// Check for packet drops
if stats.has_significant_drops(5.0) {
    println!("Warning: {:.2}% packet drops", stats.drop_rate());
}
```

### Custom Configuration

```rust
use yersinia_capture::{PacketCapture, CaptureConfig};

let config = CaptureConfig {
    snaplen: 65535,           // Maximum bytes per packet
    timeout_ms: 1000,         // Read timeout
    promiscuous: true,        // Promiscuous mode
    buffer_size: 2 * 1024 * 1024,  // 2MB buffer
    immediate_mode: true,     // Immediate packet delivery
};

let mut capture = PacketCapture::with_config("eth0", config)?;
```

### Pause and Resume

```rust
let mut capture = PacketCapture::new("eth0")?;
capture.start(|_| {})?;

// Temporarily pause capture
capture.pause()?;

// Do some processing...

// Resume capture
capture.resume()?;
```

## Available BPF Filters

The `filters` module provides pre-built BPF filters for common protocols:

### Layer 2 Protocols
- `cdp_filter()` - Cisco Discovery Protocol
- `lldp_filter()` - Link Layer Discovery Protocol
- `stp_filter()` - Spanning Tree Protocol
- `vtp_filter()` - VLAN Trunking Protocol
- `dtp_filter()` - Dynamic Trunking Protocol
- `dot1x_filter()` - 802.1X authentication

### Layer 3 Protocols
- `arp_filter()` - Address Resolution Protocol
- `ipv4_filter()` - IPv4 packets
- `ipv6_filter()` - IPv6 packets
- `icmp_filter()` - ICMP packets
- `icmpv6_filter()` - ICMPv6 packets

### Layer 4 Protocols
- `tcp_filter()` - TCP packets
- `udp_filter()` - UDP packets
- `dhcp_filter()` - DHCP traffic
- `dhcpv6_filter()` - DHCPv6 traffic

### Cisco Proprietary
- `hsrp_filter()` - Hot Standby Router Protocol
- `cisco_protocols_filter()` - All Cisco protocols

### Custom Filters
- `vlan_id_filter(id)` - Specific VLAN ID
- `host_filter(ip)` - Specific IP address
- `tcp_port_filter(port)` - TCP port
- `udp_port_filter(port)` - UDP port
- `src_mac_filter(mac)` - Source MAC address
- `dst_mac_filter(mac)` - Destination MAC address

### Filter Combinators
- `combine_filters(&[...])` - AND logic
- `combine_filters_or(&[...])` - OR logic
- `not_filter(filter)` - Negation

## Requirements

- libpcap or WinPcap/Npcap (on Windows)
- Appropriate privileges for packet capture (typically root/administrator)

## Platform Support

- Linux (libpcap)
- macOS (libpcap)
- Windows (WinPcap/Npcap)
- BSD (libpcap)

## Examples

See the `examples/` directory for more complete examples:

- `basic_capture.rs` - Simple packet capture
- `filtered_capture.rs` - Using BPF filters
- `interface_list.rs` - Interface enumeration
- `statistics.rs` - Working with capture statistics

## License

GPL-2.0-or-later
