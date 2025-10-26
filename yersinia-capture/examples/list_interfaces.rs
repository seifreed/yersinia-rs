//! Example: List all network interfaces
//!
//! Run with: cargo run --example list_interfaces

use yersinia_capture::{default_interface, list_capture_interfaces, list_interfaces};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== All Network Interfaces ===\n");

    let interfaces = list_interfaces()?;

    for iface in &interfaces {
        println!("Interface: {}", iface.name);
        println!("  Description: {}", iface.description);

        if let Some(ref mac) = iface.mac {
            println!("  MAC Address: {}", mac);
        }

        println!("  IP Addresses:");
        for ip in &iface.ips {
            println!("    - {}", ip);
        }

        println!("  Status:");
        println!("    Up: {}", iface.is_up);
        println!("    Loopback: {}", iface.is_loopback);
        println!("    Multicast: {}", iface.is_multicast);
        println!("    Capture Capable: {}", iface.is_capture_capable());

        println!();
    }

    println!("=== Capture-Capable Interfaces ===\n");

    let capture_interfaces = list_capture_interfaces()?;
    for iface in &capture_interfaces {
        println!("  {} - {}", iface.name, iface.description);
    }

    println!("\n=== Default Interface ===\n");

    match default_interface() {
        Ok(iface) => {
            println!("Default: {} ({})", iface.name, iface.description);
            if let Some(ipv4) = iface.primary_ipv4() {
                println!("Primary IPv4: {}", ipv4);
            }
        }
        Err(e) => {
            println!("No default interface found: {}", e);
        }
    }

    Ok(())
}
