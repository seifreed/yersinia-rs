//! Telnet server for remote administration

use crate::attack_manager::{AttackInfo, AttackManager};
use crate::command::{Command, CommandParser};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::RwLock;
use tracing::{debug, error, info, warn};
use uuid::Uuid;
use yersinia_core::{Interface, Protocol, Result};

/// Protocol registry trait
///
/// This trait allows the telnet server to work with any protocol registry
/// implementation without tight coupling.
pub trait ProtocolRegistry: Send + Sync {
    /// Get a protocol by name
    fn get(&self, name: &str) -> Option<&dyn Protocol>;

    /// List all protocol names
    fn list_names(&self) -> Vec<String>;

    /// Get protocol count
    fn count(&self) -> usize;
}

/// Telnet server for remote administration
pub struct TelnetServer {
    /// Port to listen on
    port: u16,
    /// Bind address (default: 0.0.0.0 for all interfaces)
    bind_addr: String,
    /// Attack manager
    attack_manager: Arc<AttackManager>,
    /// Protocol registry
    protocols: Arc<RwLock<Option<Arc<dyn ProtocolRegistry>>>>,
    /// Connected client count
    client_count: Arc<parking_lot::RwLock<usize>>,
}

impl TelnetServer {
    /// Create a new telnet server
    ///
    /// # Arguments
    ///
    /// * `port` - Port to listen on (default: 12000)
    pub fn new(port: u16) -> Self {
        Self {
            port,
            bind_addr: "0.0.0.0".to_string(),
            attack_manager: Arc::new(AttackManager::new()),
            protocols: Arc::new(RwLock::new(None)),
            client_count: Arc::new(parking_lot::RwLock::new(0)),
        }
    }

    /// Set the bind address
    pub fn with_bind_addr(mut self, addr: String) -> Self {
        self.bind_addr = addr;
        self
    }

    /// Set the protocol registry
    pub async fn set_protocols(&self, registry: Arc<dyn ProtocolRegistry>) {
        *self.protocols.write().await = Some(registry);
    }

    /// Get the attack manager
    pub fn attack_manager(&self) -> Arc<AttackManager> {
        self.attack_manager.clone()
    }

    /// Start the telnet server
    pub async fn start(&self) -> Result<()> {
        let addr = format!("{}:{}", self.bind_addr, self.port);
        let listener = TcpListener::bind(&addr).await?;

        info!("Yersinia Telnet server listening on {}", addr);
        warn!("WARNING: Telnet transmits in plain text. Use only on trusted networks!");

        loop {
            match listener.accept().await {
                Ok((socket, peer_addr)) => {
                    info!("New connection from: {}", peer_addr);
                    *self.client_count.write() += 1;

                    let attack_manager = self.attack_manager.clone();
                    let protocols = self.protocols.clone();
                    let client_count = self.client_count.clone();

                    tokio::spawn(async move {
                        if let Err(e) = Self::handle_client(
                            socket,
                            peer_addr,
                            attack_manager,
                            protocols,
                        )
                        .await
                        {
                            error!("Error handling client {}: {}", peer_addr, e);
                        }
                        *client_count.write() -= 1;
                        info!("Client {} disconnected", peer_addr);
                    });
                }
                Err(e) => {
                    error!("Failed to accept connection: {}", e);
                }
            }
        }
    }

    /// Handle a client connection
    async fn handle_client(
        socket: TcpStream,
        peer_addr: SocketAddr,
        attack_manager: Arc<AttackManager>,
        protocols: Arc<RwLock<Option<Arc<dyn ProtocolRegistry>>>>,
    ) -> Result<()> {
        let (reader, mut writer) = socket.into_split();
        let mut reader = BufReader::new(reader);

        // Send welcome banner with security warning
        Self::send_banner(&mut writer).await?;

        let mut line = String::new();

        // Command loop
        loop {
            // Send prompt
            writer.write_all(b"yersinia> ").await?;
            writer.flush().await?;

            // Read line
            line.clear();
            match reader.read_line(&mut line).await {
                Ok(0) => {
                    // Connection closed
                    debug!("Client {} closed connection", peer_addr);
                    break;
                }
                Ok(_) => {
                    let command_str = line.trim();

                    if command_str.is_empty() {
                        continue;
                    }

                    debug!("Client {} command: {}", peer_addr, command_str);

                    // Parse command
                    match CommandParser::parse(command_str) {
                        Ok(command) => {
                            // Execute command
                            match Self::execute_command(
                                command,
                                &mut writer,
                                &attack_manager,
                                &protocols,
                            )
                            .await
                            {
                                Ok(should_exit) => {
                                    if should_exit {
                                        break;
                                    }
                                }
                                Err(e) => {
                                    Self::write_error(&mut writer, &e.to_string()).await?;
                                }
                            }
                        }
                        Err(e) => {
                            Self::write_error(&mut writer, &e).await?;
                        }
                    }
                }
                Err(e) => {
                    error!("Error reading from client {}: {}", peer_addr, e);
                    break;
                }
            }
        }

        Ok(())
    }

    /// Send welcome banner
    async fn send_banner(writer: &mut tokio::net::tcp::OwnedWriteHalf) -> Result<()> {
        writer.write_all(b"\r\n").await?;
        writer
            .write_all(b"================================================================\r\n")
            .await?;
        writer
            .write_all(b"                                                                \r\n")
            .await?;
        writer
            .write_all(b"    Yersinia-RS - Network Protocol Security Testing Tool       \r\n")
            .await?;
        writer
            .write_all(b"    Telnet Remote Administration Interface                     \r\n")
            .await?;
        writer
            .write_all(b"                                                                \r\n")
            .await?;
        writer
            .write_all(b"    WARNING: This interface transmits in PLAIN TEXT!           \r\n")
            .await?;
        writer
            .write_all(b"             Use only on trusted networks!                     \r\n")
            .await?;
        writer
            .write_all(b"             Unauthorized access is prohibited!                \r\n")
            .await?;
        writer
            .write_all(b"                                                                \r\n")
            .await?;
        writer
            .write_all(b"================================================================\r\n")
            .await?;
        writer.write_all(b"\r\n").await?;
        writer
            .write_all(b"Type 'help' for available commands.\r\n")
            .await?;
        writer.write_all(b"\r\n").await?;
        writer.flush().await?;
        Ok(())
    }

    /// Execute a command
    async fn execute_command(
        command: Command,
        writer: &mut tokio::net::tcp::OwnedWriteHalf,
        attack_manager: &Arc<AttackManager>,
        protocols: &Arc<RwLock<Option<Arc<dyn ProtocolRegistry>>>>,
    ) -> Result<bool> {
        match command {
            Command::Help => {
                writer.write_all(CommandParser::help_text().as_bytes()).await?;
            }
            Command::ListProtocols => {
                Self::cmd_list_protocols(writer, protocols).await?;
            }
            Command::ListAttacks { protocol } => {
                Self::cmd_list_attacks(writer, protocols, &protocol).await?;
            }
            Command::Launch {
                protocol,
                attack_id,
                interface,
                params,
            } => {
                Self::cmd_launch(
                    writer,
                    attack_manager,
                    protocols,
                    &protocol,
                    attack_id,
                    &interface,
                    params,
                )
                .await?;
            }
            Command::ListRunning => {
                Self::cmd_list_running(writer, attack_manager).await?;
            }
            Command::ListAll => {
                Self::cmd_list_all(writer, attack_manager).await?;
            }
            Command::Stop { attack_id } => {
                Self::cmd_stop(writer, attack_manager, attack_id).await?;
            }
            Command::Pause { attack_id } => {
                Self::cmd_pause(writer, attack_manager, attack_id).await?;
            }
            Command::Resume { attack_id } => {
                Self::cmd_resume(writer, attack_manager, attack_id).await?;
            }
            Command::Info { attack_id } => {
                Self::cmd_info(writer, attack_manager, attack_id).await?;
            }
            Command::Status => {
                Self::cmd_status(writer, attack_manager, protocols).await?;
            }
            Command::Cleanup => {
                Self::cmd_cleanup(writer, attack_manager).await?;
            }
            Command::StopAll => {
                Self::cmd_stop_all(writer, attack_manager).await?;
            }
            Command::Exit => {
                writer.write_all(b"Goodbye!\r\n").await?;
                writer.flush().await?;
                return Ok(true); // Signal to exit
            }
        }

        writer.write_all(b"\r\n").await?;
        writer.flush().await?;
        Ok(false)
    }

    /// List protocols command
    async fn cmd_list_protocols(
        writer: &mut tokio::net::tcp::OwnedWriteHalf,
        protocols: &Arc<RwLock<Option<Arc<dyn ProtocolRegistry>>>>,
    ) -> Result<()> {
        let (names, count, has_registry) = {
            let registry_lock = protocols.read().await;
            if let Some(registry) = registry_lock.as_ref() {
                (registry.list_names(), registry.count(), true)
            } else {
                (Vec::new(), 0, false)
            }
        };

        if has_registry {
            writer
                .write_all(format!("Available Protocols ({}):\r\n", count).as_bytes())
                .await?;
            writer.write_all(b"==================\r\n").await?;
            for name in names {
                writer.write_all(format!("  - {}\r\n", name).as_bytes()).await?;
            }
            writer
                .write_all(b"\r\nUse 'list-attacks <protocol>' to see attacks for a protocol.\r\n")
                .await?;
        } else {
            writer
                .write_all(b"Protocol registry not initialized.\r\n")
                .await?;
        }
        Ok(())
    }

    /// List attacks command
    async fn cmd_list_attacks(
        writer: &mut tokio::net::tcp::OwnedWriteHalf,
        protocols: &Arc<RwLock<Option<Arc<dyn ProtocolRegistry>>>>,
        protocol_name: &str,
    ) -> Result<()> {
        // Collect all data before any await to avoid holding lock
        let attack_data = {
            let registry_lock = protocols.read().await;
            if let Some(registry) = registry_lock.as_ref() {
                if let Some(protocol) = registry.get(protocol_name) {
                    let attacks = protocol.attacks();
                    let proto_name = protocol.name().to_string();
                    let proto_short = protocol.shortname().to_string();

                    // Collect attack info
                    let attack_infos: Vec<_> = attacks.iter().map(|a| {
                        let params: Vec<_> = a.parameters.iter().map(|p| {
                            (p.name.to_string(), format!("{:?}", p.param_type), p.required)
                        }).collect();
                        (a.id.0, a.name.to_string(), a.description.to_string(), params)
                    }).collect();

                    Some((proto_name, proto_short, attack_infos))
                } else {
                    None
                }
            } else {
                None
            }
        };

        match attack_data {
            Some((proto_name, proto_short, attacks)) => {
                writer
                    .write_all(format!("Protocol: {} ({})\r\n", proto_name, proto_short).as_bytes())
                    .await?;
                writer
                    .write_all(format!("Available Attacks ({}):\r\n", attacks.len()).as_bytes())
                    .await?;
                writer.write_all(b"==================\r\n").await?;

                if attacks.is_empty() {
                    writer
                        .write_all(b"No attacks available for this protocol.\r\n")
                        .await?;
                } else {
                    for (id, name, desc, params) in attacks {
                        writer
                            .write_all(format!("\r\nID: {}\r\n", id).as_bytes())
                            .await?;
                        writer
                            .write_all(format!("Name: {}\r\n", name).as_bytes())
                            .await?;
                        writer
                            .write_all(format!("Description: {}\r\n", desc).as_bytes())
                            .await?;

                        if !params.is_empty() {
                            writer.write_all(b"Parameters:\r\n").await?;
                            for (param_name, param_type, required) in params {
                                let req_str = if required { " [required]" } else { "" };
                                writer
                                    .write_all(
                                        format!("  - {} ({}){}\r\n", param_name, param_type, req_str)
                                        .as_bytes(),
                                    )
                                    .await?;
                            }
                        }
                    }
                }
            }
            None => {
                let registry_lock = protocols.read().await;
                if registry_lock.is_none() {
                    writer
                        .write_all(b"Protocol registry not initialized.\r\n")
                        .await?;
                } else {
                    writer
                        .write_all(format!("Protocol '{}' not found.\r\n", protocol_name).as_bytes())
                        .await?;
                }
            }
        }
        Ok(())
    }

    /// Launch attack command
    #[allow(clippy::too_many_arguments)]
    async fn cmd_launch(
        writer: &mut tokio::net::tcp::OwnedWriteHalf,
        attack_manager: &Arc<AttackManager>,
        protocols: &Arc<RwLock<Option<Arc<dyn ProtocolRegistry>>>>,
        protocol_name: &str,
        attack_id: u8,
        interface_name: &str,
        params: HashMap<String, String>,
    ) -> Result<()> {
        let registry_lock = protocols.read().await;
        if let Some(registry) = registry_lock.as_ref() {
            if let Some(protocol) = registry.get(protocol_name) {
                // Find attack descriptor
                let attacks = protocol.attacks();
                if let Some(attack_desc) = attacks.iter().find(|a| a.id.0 == attack_id) {
                    let attack_name = attack_desc.name.to_string();
                    writer
                        .write_all(
                            format!(
                                "Launching attack: {} (ID: {}) on {}\r\n",
                                attack_name, attack_id, interface_name
                            )
                            .as_bytes(),
                        )
                        .await?;

                    // Convert params to AttackParams
                    let mut attack_params = yersinia_core::protocol::AttackParams::new();
                    for (key, value) in &params {
                        attack_params = attack_params.set(key.clone(), value.clone());
                    }

                    // Create interface (simplified - in production, query system)
                    let interface = Interface::new(
                        interface_name.to_string(),
                        0,
                        yersinia_core::MacAddr::new([0, 0, 0, 0, 0, 0]),
                    );

                    // Launch attack
                    match protocol
                        .launch_attack(
                            yersinia_core::AttackId(attack_id),
                            attack_params,
                            &interface,
                        )
                        .await
                    {
                        Ok(handle) => {
                            let attack_uuid = handle.id;
                            attack_manager.register(
                                handle,
                                protocol_name.to_string(),
                                attack_name,
                                interface_name.to_string(),
                            );

                            writer
                                .write_all(b"Attack launched successfully!\r\n")
                                .await?;
                            writer
                                .write_all(format!("Attack UUID: {}\r\n", attack_uuid).as_bytes())
                                .await?;
                        }
                        Err(e) => {
                            writer
                                .write_all(format!("Failed to launch attack: {}\r\n", e).as_bytes())
                                .await?;
                        }
                    }
                } else {
                    writer
                        .write_all(
                            format!("Attack ID {} not found for protocol '{}'.\r\n", attack_id, protocol_name)
                                .as_bytes(),
                        )
                        .await?;
                }
            } else {
                writer
                    .write_all(format!("Protocol '{}' not found.\r\n", protocol_name).as_bytes())
                    .await?;
            }
        } else {
            writer
                .write_all(b"Protocol registry not initialized.\r\n")
                .await?;
        }
        Ok(())
    }

    /// List running attacks command
    async fn cmd_list_running(
        writer: &mut tokio::net::tcp::OwnedWriteHalf,
        attack_manager: &Arc<AttackManager>,
    ) -> Result<()> {
        let running = attack_manager.list_running();
        writer
            .write_all(format!("Running Attacks ({}):\r\n", running.len()).as_bytes())
            .await?;
        writer.write_all(b"==================\r\n").await?;

        if running.is_empty() {
            writer.write_all(b"No attacks currently running.\r\n").await?;
        } else {
            for attack in running {
                Self::write_attack_info(writer, &attack).await?;
            }
        }
        Ok(())
    }

    /// List all attacks command
    async fn cmd_list_all(
        writer: &mut tokio::net::tcp::OwnedWriteHalf,
        attack_manager: &Arc<AttackManager>,
    ) -> Result<()> {
        let all = attack_manager.list_all();
        writer
            .write_all(format!("All Attacks ({}):\r\n", all.len()).as_bytes())
            .await?;
        writer.write_all(b"==================\r\n").await?;

        if all.is_empty() {
            writer.write_all(b"No attacks tracked.\r\n").await?;
        } else {
            for attack in all {
                Self::write_attack_info(writer, &attack).await?;
            }
        }
        Ok(())
    }

    /// Stop attack command
    async fn cmd_stop(
        writer: &mut tokio::net::tcp::OwnedWriteHalf,
        attack_manager: &Arc<AttackManager>,
        attack_id: Uuid,
    ) -> Result<()> {
        match attack_manager.stop(attack_id) {
            Ok(_) => {
                writer
                    .write_all(format!("Attack {} stopped.\r\n", attack_id).as_bytes())
                    .await?;
            }
            Err(e) => {
                writer.write_all(format!("Error: {}\r\n", e).as_bytes()).await?;
            }
        }
        Ok(())
    }

    /// Pause attack command
    async fn cmd_pause(
        writer: &mut tokio::net::tcp::OwnedWriteHalf,
        attack_manager: &Arc<AttackManager>,
        attack_id: Uuid,
    ) -> Result<()> {
        match attack_manager.pause(attack_id) {
            Ok(_) => {
                writer
                    .write_all(format!("Attack {} paused.\r\n", attack_id).as_bytes())
                    .await?;
            }
            Err(e) => {
                writer.write_all(format!("Error: {}\r\n", e).as_bytes()).await?;
            }
        }
        Ok(())
    }

    /// Resume attack command
    async fn cmd_resume(
        writer: &mut tokio::net::tcp::OwnedWriteHalf,
        attack_manager: &Arc<AttackManager>,
        attack_id: Uuid,
    ) -> Result<()> {
        match attack_manager.resume(attack_id) {
            Ok(_) => {
                writer
                    .write_all(format!("Attack {} resumed.\r\n", attack_id).as_bytes())
                    .await?;
            }
            Err(e) => {
                writer.write_all(format!("Error: {}\r\n", e).as_bytes()).await?;
            }
        }
        Ok(())
    }

    /// Info attack command
    async fn cmd_info(
        writer: &mut tokio::net::tcp::OwnedWriteHalf,
        attack_manager: &Arc<AttackManager>,
        attack_id: Uuid,
    ) -> Result<()> {
        if let Some(info) = attack_manager.get_info(attack_id) {
            writer.write_all(b"Attack Information:\r\n").await?;
            writer.write_all(b"==================\r\n").await?;
            Self::write_attack_info(writer, &info).await?;
        } else {
            writer
                .write_all(format!("Attack {} not found.\r\n", attack_id).as_bytes())
                .await?;
        }
        Ok(())
    }

    /// Status command
    async fn cmd_status(
        writer: &mut tokio::net::tcp::OwnedWriteHalf,
        attack_manager: &Arc<AttackManager>,
        protocols: &Arc<RwLock<Option<Arc<dyn ProtocolRegistry>>>>,
    ) -> Result<()> {
        writer.write_all(b"Yersinia-RS Server Status:\r\n").await?;
        writer.write_all(b"==================\r\n").await?;
        writer
            .write_all(format!("Version: {}\r\n", env!("CARGO_PKG_VERSION")).as_bytes())
            .await?;

        let protocol_count = {
            let registry_lock = protocols.read().await;
            registry_lock.as_ref().map(|r| r.count()).unwrap_or(0)
        };

        if protocol_count > 0 {
            writer
                .write_all(format!("Protocols Loaded: {}\r\n", protocol_count).as_bytes())
                .await?;
        } else {
            writer.write_all(b"Protocols Loaded: 0 (not initialized)\r\n").await?;
        }

        let running_count = attack_manager.running_count();
        writer
            .write_all(format!("Running Attacks: {}\r\n", running_count).as_bytes())
            .await?;
        writer
            .write_all(format!("Total Attacks: {}\r\n", attack_manager.list_all().len()).as_bytes())
            .await?;

        Ok(())
    }

    /// Cleanup command
    async fn cmd_cleanup(
        writer: &mut tokio::net::tcp::OwnedWriteHalf,
        attack_manager: &Arc<AttackManager>,
    ) -> Result<()> {
        let before = attack_manager.list_all().len();
        attack_manager.cleanup_stopped();
        let after = attack_manager.list_all().len();
        let removed = before - after;

        writer
            .write_all(format!("Cleaned up {} stopped attack(s).\r\n", removed).as_bytes())
            .await?;
        Ok(())
    }

    /// Stop all command
    async fn cmd_stop_all(
        writer: &mut tokio::net::tcp::OwnedWriteHalf,
        attack_manager: &Arc<AttackManager>,
    ) -> Result<()> {
        let count = attack_manager.running_count();
        attack_manager.stop_all();
        writer
            .write_all(format!("Stopped {} attack(s).\r\n", count).as_bytes())
            .await?;
        Ok(())
    }

    /// Write attack information
    async fn write_attack_info(
        writer: &mut tokio::net::tcp::OwnedWriteHalf,
        info: &AttackInfo,
    ) -> Result<()> {
        writer.write_all(b"\r\n").await?;
        writer
            .write_all(format!("UUID:      {}\r\n", info.id).as_bytes())
            .await?;
        writer
            .write_all(format!("Protocol:  {}\r\n", info.protocol).as_bytes())
            .await?;
        writer
            .write_all(format!("Attack:    {}\r\n", info.attack_name).as_bytes())
            .await?;
        writer
            .write_all(format!("Interface: {}\r\n", info.interface).as_bytes())
            .await?;
        writer
            .write_all(format!("Started:   {}\r\n", info.started_at.format("%Y-%m-%d %H:%M:%S UTC")).as_bytes())
            .await?;
        writer
            .write_all(
                format!(
                    "Status:    {}\r\n",
                    if info.stats.is_running {
                        if info.stats.is_paused {
                            "PAUSED"
                        } else {
                            "RUNNING"
                        }
                    } else {
                        "STOPPED"
                    }
                )
                .as_bytes(),
            )
            .await?;
        writer
            .write_all(format!("Packets:   {}\r\n", info.stats.packets_sent).as_bytes())
            .await?;
        writer
            .write_all(format!("Bytes:     {}\r\n", info.stats.bytes_sent).as_bytes())
            .await?;
        writer
            .write_all(format!("Errors:    {}\r\n", info.stats.errors).as_bytes())
            .await?;

        Ok(())
    }

    /// Write error message
    async fn write_error(writer: &mut tokio::net::tcp::OwnedWriteHalf, error: &str) -> Result<()> {
        writer
            .write_all(format!("Error: {}\r\n", error).as_bytes())
            .await?;
        writer.write_all(b"\r\n").await?;
        writer.flush().await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_telnet_server_new() {
        let server = TelnetServer::new(12000);
        assert_eq!(server.port, 12000);
        assert_eq!(server.bind_addr, "0.0.0.0");
    }

    #[test]
    fn test_with_bind_addr() {
        let server = TelnetServer::new(12000).with_bind_addr("127.0.0.1".to_string());
        assert_eq!(server.bind_addr, "127.0.0.1");
    }
}
