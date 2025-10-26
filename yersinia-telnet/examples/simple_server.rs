//! Simple Telnet Server Example
//!
//! This example demonstrates how to start a basic telnet server
//! for remote Yersinia-RS management.
//!
//! Usage:
//!   cargo run --example simple_server
//!
//! Then connect with:
//!   telnet localhost 12000

use std::collections::HashMap;
use std::sync::Arc;
use yersinia_core::Protocol;
use yersinia_telnet::server::ProtocolRegistry;
use yersinia_telnet::TelnetServer;

/// Example protocol registry implementation
struct SimpleRegistry {
    protocols: HashMap<String, Box<dyn Protocol>>,
}

impl SimpleRegistry {
    fn new() -> Self {
        Self {
            protocols: HashMap::new(),
        }
    }

    #[allow(dead_code)]
    fn register(&mut self, protocol: Box<dyn Protocol>) {
        let name = protocol.shortname().to_lowercase();
        self.protocols.insert(name, protocol);
    }
}

impl ProtocolRegistry for SimpleRegistry {
    fn get(&self, name: &str) -> Option<&dyn Protocol> {
        self.protocols.get(&name.to_lowercase()).map(|b| b.as_ref())
    }

    fn list_names(&self) -> Vec<String> {
        let mut names: Vec<_> = self.protocols.keys().cloned().collect();
        names.sort();
        names
    }

    fn count(&self) -> usize {
        self.protocols.len()
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize tracing
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .init();

    println!("===========================================");
    println!("Yersinia-RS Telnet Server - Simple Example");
    println!("===========================================");
    println!();
    println!("Starting telnet server on port 12000...");
    println!();
    println!("Connect with: telnet localhost 12000");
    println!();
    println!("SECURITY WARNING:");
    println!("  - Telnet transmits in PLAIN TEXT");
    println!("  - Only use on trusted networks");
    println!("  - This is a DEMONSTRATION - not for production");
    println!();

    // Create protocol registry
    let registry = SimpleRegistry::new();

    // Note: In a real implementation, you would register protocols here:
    // registry.register(Box::new(CdpProtocol::new()));
    // registry.register(Box::new(StpProtocol::new()));
    // etc.

    // Create telnet server
    let server = TelnetServer::new(12000)
        .with_bind_addr("127.0.0.1".to_string()); // Localhost only for safety

    // Set protocol registry
    server.set_protocols(Arc::new(registry)).await;

    println!("Server ready! Press Ctrl+C to stop.");
    println!();

    // Start server (blocks until error or shutdown)
    if let Err(e) = server.start().await {
        eprintln!("Server error: {}", e);
        std::process::exit(1);
    }

    Ok(())
}
