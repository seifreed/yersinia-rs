//! ISL Protocol Implementation
//!
//! Implements the Protocol trait for Inter-Switch Link with packet parsing,
//! VLAN traffic tracking, statistics, and attack launching.

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

use super::attack::{IslSpoofingAttack, IslTaggingAttack};
use super::packet::IslFrame;

/// ISL Protocol Implementation
pub struct IslProtocol {
    stats: Arc<RwLock<IslStats>>,
    vlan_traffic: Arc<RwLock<HashMap<u16, IslVlanInfo>>>,
}

/// Internal statistics for ISL protocol
#[derive(Debug, Clone, Default)]
struct IslStats {
    /// Base protocol stats
    pub base: ProtocolStats,
    /// Number of valid ISL frames parsed
    pub valid_frames: u64,
    /// Number of CRC errors
    pub crc_errors: u64,
    /// Number of different VLANs seen
    pub unique_vlans: u64,
    /// Total number of BPDU frames
    pub bpdu_frames: u64,
}

/// Information about VLAN traffic
#[derive(Debug, Clone)]
pub struct IslVlanInfo {
    /// VLAN ID
    pub vlan_id: u16,
    /// Number of frames for this VLAN
    pub frame_count: u64,
    /// Total bytes for this VLAN
    pub byte_count: u64,
    /// Source MACs seen on this VLAN
    pub source_macs: Vec<MacAddr>,
    /// Last time we saw traffic on this VLAN
    pub last_seen: SystemTime,
}

impl IslProtocol {
    /// Create a new ISL protocol instance
    pub fn new() -> Self {
        Self {
            stats: Arc::new(RwLock::new(IslStats::default())),
            vlan_traffic: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Get the number of unique VLANs seen
    pub async fn vlan_count(&self) -> usize {
        self.vlan_traffic.read().await.len()
    }

    /// Get statistics for a specific VLAN
    pub async fn get_vlan_info(&self, vlan_id: u16) -> Option<IslVlanInfo> {
        self.vlan_traffic.read().await.get(&vlan_id).cloned()
    }

    /// Update VLAN traffic statistics
    async fn _update_vlan_stats(&self, frame: &IslFrame) -> Result<()> {
        let mut vlan_traffic = self.vlan_traffic.write().await;

        let entry = vlan_traffic
            .entry(frame.vlan_id)
            .or_insert_with(|| IslVlanInfo {
                vlan_id: frame.vlan_id,
                frame_count: 0,
                byte_count: 0,
                source_macs: Vec::new(),
                last_seen: SystemTime::now(),
            });

        entry.frame_count += 1;
        entry.byte_count += frame.payload.len() as u64;
        entry.last_seen = SystemTime::now();

        // Track source MAC if not already in list (limit to 100 MACs per VLAN)
        if !entry.source_macs.contains(&frame.src_mac) && entry.source_macs.len() < 100 {
            entry.source_macs.push(frame.src_mac);
        }

        Ok(())
    }
}

impl Default for IslProtocol {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Protocol for IslProtocol {
    fn name(&self) -> &'static str {
        "Inter-Switch Link Protocol"
    }

    fn shortname(&self) -> &'static str {
        "isl"
    }

    fn id(&self) -> ProtocolId {
        ProtocolId::ISL
    }

    fn attacks(&self) -> &[AttackDescriptor] {
        static ATTACKS: [AttackDescriptor; 2] = [
            AttackDescriptor {
                id: AttackId(0),
                name: "ISL Tagging Attack",
                description:
                    "Send ISL-encapsulated frames to perform VLAN hopping on legacy ISL trunks",
                parameters: vec![],
            },
            AttackDescriptor {
                id: AttackId(1),
                name: "ISL Spoofing Attack",
                description: "Spoof ISL frames from other VLANs for double-encapsulation attacks",
                parameters: vec![],
            },
        ];

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

        // Try to parse as ISL frame
        match IslFrame::parse(&packet.data) {
            Ok(isl_frame) => {
                stats.base.packets_parsed += 1;

                // Verify CRC
                if !isl_frame.verify_crc() {
                    stats.crc_errors += 1;
                    stats.base.packets_errors += 1;
                    return Ok(());
                }

                stats.valid_frames += 1;

                // Count BPDU frames
                if isl_frame.bpdu {
                    stats.bpdu_frames += 1;
                }

                // Update custom stats
                let vlan_count = stats.unique_vlans;
                let valid_frames = stats.valid_frames;
                let crc_errors = stats.crc_errors;
                let bpdu_frames = stats.bpdu_frames;

                stats
                    .base
                    .custom
                    .insert("unique_vlans".to_string(), vlan_count);
                stats
                    .base
                    .custom
                    .insert("valid_frames".to_string(), valid_frames);
                stats
                    .base
                    .custom
                    .insert("crc_errors".to_string(), crc_errors);
                stats
                    .base
                    .custom
                    .insert("bpdu_frames".to_string(), bpdu_frames);

                drop(stats); // Release lock before async call

                // Update VLAN statistics (this needs async)
                // We'll spawn a task to avoid blocking
                let vlan_traffic = self.vlan_traffic.clone();
                let frame_vlan = isl_frame.vlan_id;
                let frame_mac = isl_frame.src_mac;
                let frame_len = isl_frame.payload.len();

                tokio::spawn(async move {
                    let mut vlan_traffic = vlan_traffic.write().await;

                    let entry = vlan_traffic
                        .entry(frame_vlan)
                        .or_insert_with(|| IslVlanInfo {
                            vlan_id: frame_vlan,
                            frame_count: 0,
                            byte_count: 0,
                            source_macs: Vec::new(),
                            last_seen: SystemTime::now(),
                        });

                    entry.frame_count += 1;
                    entry.byte_count += frame_len as u64;
                    entry.last_seen = SystemTime::now();

                    if !entry.source_macs.contains(&frame_mac) && entry.source_macs.len() < 100 {
                        entry.source_macs.push(frame_mac);
                    }
                });

                // Update unique VLAN count
                let mut stats = self
                    .stats
                    .try_write()
                    .map_err(|_| Error::protocol("Failed to acquire stats lock"))?;
                stats.unique_vlans = self
                    .vlan_traffic
                    .try_read()
                    .map(|vt| vt.len() as u64)
                    .unwrap_or(stats.unique_vlans);
            }
            Err(_) => {
                stats.base.packets_errors += 1;
            }
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
            // ISL Tagging Attack
            0 => {
                // Parse VLAN ID parameter
                let vlan_id = params.get_u32("vlan_id").unwrap_or(1) as u16;

                // Parse target MAC (optional)
                let target_mac = if let Some(mac_str) = params.get_string("target_mac") {
                    mac_str.parse::<MacAddr>().map_err(|_| {
                        Error::invalid_parameter("target_mac", "Invalid target MAC address")
                    })?
                } else {
                    MacAddr([0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]) // Broadcast
                };

                // Parse source MAC (optional, generate random Cisco MAC if not specified)
                let src_mac = if let Some(mac_str) = params.get_string("src_mac") {
                    mac_str.parse::<MacAddr>().map_err(|_| {
                        Error::invalid_parameter("src_mac", "Invalid source MAC address")
                    })?
                } else {
                    let mut mac = [0u8; 6];
                    use rand::Rng;
                    let mut rng = rand::thread_rng();
                    rng.fill(&mut mac);
                    mac[0] = 0x00;
                    mac[1] = 0x0C; // Cisco OUI
                    mac[2] = 0x0C;
                    MacAddr(mac)
                };

                // Parse payload (hex string, optional)
                let payload = if let Some(payload_str) = params.get_string("payload") {
                    hex::decode(payload_str.replace(":", "").replace(" ", ""))
                        .map_err(|_| Error::invalid_parameter("payload", "Invalid hex payload"))?
                } else {
                    // Default: ARP request payload
                    vec![
                        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, // Dest MAC
                        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Src MAC
                        0x08, 0x06, // EtherType: ARP
                        0x00, 0x01, 0x08, 0x00, 0x06, 0x04, 0x00, 0x01, // ARP header
                        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Sender MAC
                        0x0A, 0x00, 0x00, 0x01, // Sender IP
                        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Target MAC
                        0x0A, 0x00, 0x00, 0x02, // Target IP
                    ]
                };

                // Get interval (default 1000ms)
                let interval_ms = params.get_u32("interval_ms").unwrap_or(1000) as u64;

                let attack =
                    IslTaggingAttack::new(vlan_id, payload, target_mac, src_mac, interval_ms);

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
                    protocol: "ISL".to_string(),
                    attack_name: "ISL Tagging".to_string(),
                    running,
                    paused,
                    stats,
                    started_at: SystemTime::now(),
                    task_handle: Some(task_handle),
                })
            }
            // ISL Spoofing Attack
            1 => {
                // Parse inner VLAN ID
                let inner_vlan = params.get_u32("inner_vlan").unwrap_or(1) as u16;

                // Parse outer VLAN ID
                let outer_vlan = params.get_u32("outer_vlan").unwrap_or(2) as u16;

                // Parse target MAC
                let target_mac = if let Some(mac_str) = params.get_string("target_mac") {
                    mac_str.parse::<MacAddr>().map_err(|_| {
                        Error::invalid_parameter("target_mac", "Invalid target MAC address")
                    })?
                } else {
                    MacAddr([0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF])
                };

                // Parse source MAC
                let src_mac = if let Some(mac_str) = params.get_string("src_mac") {
                    mac_str.parse::<MacAddr>().map_err(|_| {
                        Error::invalid_parameter("src_mac", "Invalid source MAC address")
                    })?
                } else {
                    let mut mac = [0u8; 6];
                    use rand::Rng;
                    let mut rng = rand::thread_rng();
                    rng.fill(&mut mac);
                    mac[0] = 0x00;
                    mac[1] = 0x0C;
                    mac[2] = 0x0C;
                    MacAddr(mac)
                };

                // Get interval
                let interval_ms = params.get_u32("interval_ms").unwrap_or(1000) as u64;

                let attack = IslSpoofingAttack::new(
                    inner_vlan,
                    outer_vlan,
                    target_mac,
                    src_mac,
                    interval_ms,
                );

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
                    protocol: "ISL".to_string(),
                    attack_name: "ISL Spoofing".to_string(),
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
            *stats = IslStats::default();
        }
        if let Ok(mut vlan_traffic) = self.vlan_traffic.try_write() {
            vlan_traffic.clear();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_protocol_metadata() {
        let isl = IslProtocol::new();
        assert_eq!(isl.name(), "Inter-Switch Link Protocol");
        assert_eq!(isl.shortname(), "isl");
        assert_eq!(isl.id(), ProtocolId::ISL);
    }

    #[test]
    fn test_protocol_attacks() {
        let isl = IslProtocol::new();
        let attacks = isl.attacks();
        assert_eq!(attacks.len(), 2);
        assert_eq!(attacks[0].id.0, 0);
        assert_eq!(attacks[0].name, "ISL Tagging Attack");
        assert_eq!(attacks[1].id.0, 1);
        assert_eq!(attacks[1].name, "ISL Spoofing Attack");
    }

    #[test]
    fn test_stats_initialization() {
        let isl = IslProtocol::new();
        let stats = isl.stats();
        assert_eq!(stats.packets_received, 0);
        assert_eq!(stats.packets_parsed, 0);
        assert_eq!(stats.packets_errors, 0);
    }

    #[tokio::test]
    async fn test_vlan_count_empty() {
        let isl = IslProtocol::new();
        assert_eq!(isl.vlan_count().await, 0);
    }

    #[tokio::test]
    async fn test_get_vlan_info_empty() {
        let isl = IslProtocol::new();
        assert!(isl.get_vlan_info(100).await.is_none());
    }
}
