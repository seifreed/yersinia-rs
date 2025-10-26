//! DTP Protocol Implementation
//!
//! Implements the Protocol trait for Dynamic Trunking Protocol with full support
//! for packet parsing, neighbor tracking, statistics, and attack launching.

use async_trait::async_trait;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::SystemTime;
use tokio::sync::RwLock;
use yersinia_core::{
    protocol::{AttackParams, Protocol, ProtocolStats},
    Attack, AttackDescriptor, AttackHandle, AttackId, Error, Interface, MacAddr, Packet, Parameter,
    ProtocolId, Result,
};

use super::attack::DtpNegotiationAttack;
use super::packet::{DtpPacket, DtpStatus, DtpType};

/// DTP Protocol Implementation
pub struct DtpProtocol {
    stats: Arc<RwLock<DtpStats>>,
    neighbor_ports: Arc<RwLock<HashMap<MacAddr, DtpNeighborInfo>>>,
}

/// Internal statistics for DTP protocol
#[derive(Debug, Clone, Default)]
struct DtpStats {
    /// Base protocol stats
    pub base: ProtocolStats,
    /// Number of trunk negotiation successes
    pub _trunk_negotiations_success: u64,
    /// Number of trunk negotiation failures
    pub _trunk_negotiations_failed: u64,
    /// Number of access mode advertisements seen
    pub access_mode_seen: u64,
    /// Number of trunk mode advertisements seen
    pub trunk_mode_seen: u64,
    /// Number of desirable mode advertisements seen
    pub desirable_mode_seen: u64,
    /// Number of auto mode advertisements seen
    pub auto_mode_seen: u64,
}

/// Information about a DTP neighbor
#[derive(Debug, Clone)]
pub struct DtpNeighborInfo {
    /// MAC address of the neighbor
    pub mac_address: MacAddr,
    /// DTP status advertised by neighbor
    pub status: DtpStatus,
    /// DTP trunk type advertised by neighbor
    pub trunk_type: DtpType,
    /// VTP domain name
    pub domain: String,
    /// Last time we saw this neighbor
    pub last_seen: SystemTime,
}

impl DtpProtocol {
    /// Create a new DTP protocol instance
    pub fn new() -> Self {
        Self {
            stats: Arc::new(RwLock::new(DtpStats::default())),
            neighbor_ports: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Get the number of discovered DTP neighbors
    pub async fn neighbor_count(&self) -> usize {
        self.neighbor_ports.read().await.len()
    }

    /// Get statistics for a specific neighbor
    pub async fn get_neighbor(&self, mac: &MacAddr) -> Option<DtpNeighborInfo> {
        self.neighbor_ports.read().await.get(mac).cloned()
    }

    /// Extract neighbor information from a DTP packet
    fn extract_neighbor_info(
        &self,
        packet: &DtpPacket,
        src_mac: MacAddr,
    ) -> Option<DtpNeighborInfo> {
        let status = packet.status()?;
        let trunk_type = packet.trunk_type()?;
        let domain = packet.domain().unwrap_or("").to_string();

        Some(DtpNeighborInfo {
            mac_address: src_mac,
            status,
            trunk_type,
            domain,
            last_seen: SystemTime::now(),
        })
    }
}

impl Default for DtpProtocol {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Protocol for DtpProtocol {
    fn name(&self) -> &'static str {
        "Dynamic Trunking Protocol"
    }

    fn shortname(&self) -> &'static str {
        "dtp"
    }

    fn id(&self) -> ProtocolId {
        ProtocolId::DTP
    }

    fn attacks(&self) -> &[AttackDescriptor] {
        static ATTACKS: [AttackDescriptor; 1] = [AttackDescriptor {
            id: AttackId(0),
            name: "DTP Trunk Negotiation",
            description: "Force trunk negotiation on access ports to enable VLAN hopping attacks",
            parameters: vec![],
        }];

        &ATTACKS
    }

    fn parameters(&self) -> Vec<Box<dyn Parameter>> {
        vec![]
    }

    fn handle_packet(&mut self, packet: &Packet) -> Result<()> {
        // Update basic stats
        let mut stats = self
            .stats
            .try_write()
            .map_err(|_| Error::protocol("Failed to acquire stats lock"))?;

        stats.base.packets_received += 1;
        stats.base.bytes_received += packet.data.len() as u64;

        // Parse Ethernet header to get source MAC
        if packet.data.len() < 14 {
            stats.base.packets_errors += 1;
            return Ok(());
        }

        let src_mac = MacAddr([
            packet.data[6],
            packet.data[7],
            packet.data[8],
            packet.data[9],
            packet.data[10],
            packet.data[11],
        ]);

        // Try to parse as DTP packet
        // Skip Ethernet (14 bytes) + LLC/SNAP (8 bytes) headers
        if packet.data.len() > 22 {
            let dtp_data = &packet.data[22..];
            match DtpPacket::parse(dtp_data) {
                Ok(dtp_packet) => {
                    stats.base.packets_parsed += 1;

                    // Update mode-specific stats
                    if let Some(status) = dtp_packet.status() {
                        if status.is_trunk() {
                            stats.trunk_mode_seen += 1;
                        } else if status.is_access() {
                            stats.access_mode_seen += 1;
                        }

                        if status.is_desirable() {
                            stats.desirable_mode_seen += 1;
                        } else if status.is_auto() {
                            stats.auto_mode_seen += 1;
                        }
                    }

                    // Extract and store neighbor information
                    if let Some(neighbor_info) = self.extract_neighbor_info(&dtp_packet, src_mac) {
                        drop(stats); // Release stats lock

                        let mut neighbors = self
                            .neighbor_ports
                            .try_write()
                            .map_err(|_| Error::protocol("Failed to acquire neighbors lock"))?;

                        neighbors.insert(src_mac, neighbor_info);

                        // Re-acquire stats lock to update custom stats
                        let mut stats = self
                            .stats
                            .try_write()
                            .map_err(|_| Error::protocol("Failed to acquire stats lock"))?;

                        let trunk_count = stats.trunk_mode_seen;
                        let access_count = stats.access_mode_seen;
                        let desirable_count = stats.desirable_mode_seen;
                        let auto_count = stats.auto_mode_seen;

                        stats
                            .base
                            .custom
                            .insert("dtp_neighbors".to_string(), neighbors.len() as u64);
                        stats
                            .base
                            .custom
                            .insert("trunk_mode_seen".to_string(), trunk_count);
                        stats
                            .base
                            .custom
                            .insert("access_mode_seen".to_string(), access_count);
                        stats
                            .base
                            .custom
                            .insert("desirable_mode_seen".to_string(), desirable_count);
                        stats
                            .base
                            .custom
                            .insert("auto_mode_seen".to_string(), auto_count);
                    }
                }
                Err(_) => {
                    stats.base.packets_errors += 1;
                }
            }
        } else {
            stats.base.packets_errors += 1;
        }

        Ok(())
    }

    async fn launch_attack(
        &self,
        attack_id: AttackId,
        params: AttackParams,
        interface: &Interface,
    ) -> Result<AttackHandle> {
        match attack_id.0 {
            // DTP Negotiation Attack
            0 => {
                // Parse mode parameter
                let mode_str = params.get_string("mode").unwrap_or("trunk");
                let status = match mode_str.to_lowercase().as_str() {
                    "trunk" => DtpStatus::trunk_desirable(),
                    "desirable" => DtpStatus::access_desirable(),
                    "auto" => DtpStatus::new(DtpStatus::ACCESS_AUTO),
                    _ => DtpStatus::trunk_desirable(),
                };

                // Parse trunk_type parameter
                let trunk_type_str = params.get_string("trunk_type").unwrap_or("dot1q");
                let trunk_type = match trunk_type_str.to_lowercase().as_str() {
                    "isl" => DtpType::isl(),
                    "dot1q" | "802.1q" => DtpType::dot1q(),
                    "negotiate" => DtpType::negotiate(),
                    _ => DtpType::dot1q(),
                };

                // Get VTP domain (optional, defaults to null domain)
                let vtp_domain = params
                    .get_string("vtp_domain")
                    .unwrap_or("\x00\x00\x00\x00\x00\x00\x00\x00")
                    .to_string();

                // Get source MAC (optional)
                let src_mac = if let Some(mac_str) = params.get_string("src_mac") {
                    mac_str.parse::<MacAddr>().map_err(|_| {
                        Error::invalid_parameter("src_mac", "Invalid source MAC address")
                    })?
                } else {
                    // Generate random Cisco MAC if not specified
                    let mut mac = [0u8; 6];
                    use rand::Rng;
                    let mut rng = rand::thread_rng();
                    rng.fill(&mut mac);
                    mac[0] &= 0xFE; // Ensure unicast
                    mac[0] &= 0x0E; // Use Cisco OUI range
                    MacAddr(mac)
                };

                // Get interval (default 30 seconds like Cisco)
                let interval_ms = params.get_u32("interval_ms").unwrap_or(30000) as u64;

                let attack =
                    DtpNegotiationAttack::new(status, trunk_type, vtp_domain, src_mac, interval_ms);

                // Create attack context
                let running = Arc::new(std::sync::atomic::AtomicBool::new(true));
                let paused = Arc::new(std::sync::atomic::AtomicBool::new(false));
                let stats = Arc::new(yersinia_core::AttackStatsCounters::default());

                let ctx = yersinia_core::AttackContext {
                    interface: interface.clone(),
                    running: running.clone(),
                    paused: paused.clone(),
                    stats: stats.clone(),
                };

                // Spawn attack task
                let task_handle = tokio::spawn(async move { attack.execute(ctx).await });

                Ok(AttackHandle {
                    id: uuid::Uuid::now_v7(),
                    protocol: "DTP".to_string(),
                    attack_name: "Trunk Negotiation".to_string(),
                    running,
                    paused,
                    stats,
                    started_at: SystemTime::now(),
                    task_handle: Some(task_handle),
                })
            }
            _ => Err(Error::InvalidAttackId(attack_id.0)),
        }
    }

    fn stats(&self) -> ProtocolStats {
        // Try to get stats without blocking
        if let Ok(stats) = self.stats.try_read() {
            stats.base.clone()
        } else {
            ProtocolStats::default()
        }
    }

    fn reset_stats(&mut self) {
        if let Ok(mut stats) = self.stats.try_write() {
            *stats = DtpStats::default();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_protocol_metadata() {
        let dtp = DtpProtocol::new();
        assert_eq!(dtp.name(), "Dynamic Trunking Protocol");
        assert_eq!(dtp.shortname(), "dtp");
        assert_eq!(dtp.id(), ProtocolId::DTP);
    }

    #[test]
    fn test_protocol_attacks() {
        let dtp = DtpProtocol::new();
        let attacks = dtp.attacks();
        assert_eq!(attacks.len(), 1);
        assert_eq!(attacks[0].id.0, 0);
        assert_eq!(attacks[0].name, "DTP Trunk Negotiation");
    }

    #[test]
    fn test_stats_initialization() {
        let dtp = DtpProtocol::new();
        let stats = dtp.stats();
        assert_eq!(stats.packets_received, 0);
        assert_eq!(stats.packets_parsed, 0);
        assert_eq!(stats.packets_errors, 0);
    }

    #[tokio::test]
    async fn test_neighbor_count_empty() {
        let dtp = DtpProtocol::new();
        assert_eq!(dtp.neighbor_count().await, 0);
    }

    #[test]
    fn test_extract_neighbor_info() {
        let dtp = DtpProtocol::new();
        let mac = MacAddr([0x00, 0x01, 0x02, 0x03, 0x04, 0x05]);

        let packet = DtpPacket::new()
            .with_domain("testdomain")
            .with_status(DtpStatus::trunk_desirable())
            .with_type(DtpType::dot1q())
            .with_neighbor(mac);

        let info = dtp.extract_neighbor_info(&packet, mac);
        assert!(info.is_some());

        let info = info.unwrap();
        assert_eq!(info.mac_address, mac);
        assert_eq!(info.status, DtpStatus::trunk_desirable());
        assert_eq!(info.trunk_type, DtpType::dot1q());
        assert_eq!(info.domain, "testdomain");
    }
}
