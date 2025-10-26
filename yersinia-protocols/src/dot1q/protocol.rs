//! 802.1Q Protocol Implementation
//!
//! Implements the Protocol trait for IEEE 802.1Q with full support for packet
//! parsing, VLAN tracking, statistics, and attack launching.

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

use super::attack::{Dot1qDoubleTaggingAttack, Dot1qVlanHoppingAttack};
use super::packet::{Dot1qTag, DOT1Q_TPID};

/// 802.1Q Protocol Implementation
pub struct Dot1qProtocol {
    stats: Arc<RwLock<Dot1qStats>>,
    tagged_vlans_seen: Arc<RwLock<HashMap<u16, VlanTraffic>>>,
}

/// Internal statistics for 802.1Q protocol
#[derive(Debug, Clone, Default)]
struct Dot1qStats {
    /// Base protocol stats
    pub base: ProtocolStats,
    /// Number of single-tagged packets seen
    pub single_tagged: u64,
    /// Number of double-tagged packets seen
    pub double_tagged: u64,
    /// Number of malformed packets
    pub malformed: u64,
    /// Number of unique VLANs discovered
    pub unique_vlans: u64,
}

/// Traffic statistics for a specific VLAN
#[derive(Debug, Clone)]
pub struct VlanTraffic {
    /// VLAN ID
    pub vlan_id: u16,
    /// Number of packets seen on this VLAN
    pub packet_count: u64,
    /// Total bytes seen on this VLAN
    pub byte_count: u64,
    /// MAC addresses seen on this VLAN
    pub mac_addresses: Vec<MacAddr>,
    /// First time this VLAN was seen
    pub first_seen: SystemTime,
    /// Last time this VLAN was seen
    pub last_seen: SystemTime,
}

impl VlanTraffic {
    /// Create new VLAN traffic tracker
    fn new(vlan_id: u16) -> Self {
        let now = SystemTime::now();
        Self {
            vlan_id,
            packet_count: 0,
            byte_count: 0,
            mac_addresses: Vec::new(),
            first_seen: now,
            last_seen: now,
        }
    }

    /// Update traffic stats for this VLAN
    fn update(&mut self, bytes: u64, src_mac: MacAddr) {
        self.packet_count += 1;
        self.byte_count += bytes;
        self.last_seen = SystemTime::now();

        // Add MAC if not already seen
        if !self.mac_addresses.contains(&src_mac) {
            self.mac_addresses.push(src_mac);
        }
    }
}

impl Dot1qProtocol {
    /// Create a new 802.1Q protocol instance
    pub fn new() -> Self {
        Self {
            stats: Arc::new(RwLock::new(Dot1qStats::default())),
            tagged_vlans_seen: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Get the number of unique VLANs discovered
    pub async fn vlan_count(&self) -> usize {
        self.tagged_vlans_seen.read().await.len()
    }

    /// Get traffic statistics for a specific VLAN
    pub async fn get_vlan_traffic(&self, vlan_id: u16) -> Option<VlanTraffic> {
        self.tagged_vlans_seen.read().await.get(&vlan_id).cloned()
    }

    /// Get all discovered VLANs
    pub async fn get_all_vlans(&self) -> Vec<u16> {
        let vlans = self.tagged_vlans_seen.read().await;
        let mut vlan_ids: Vec<u16> = vlans.keys().copied().collect();
        vlan_ids.sort_unstable();
        vlan_ids
    }

    /// Parse and track VLAN information from packet
    fn process_vlan_packet(
        &self,
        packet_data: &[u8],
        stats: &mut Dot1qStats,
        vlans: &mut HashMap<u16, VlanTraffic>,
    ) -> Result<()> {
        // Minimum Ethernet frame with 802.1Q: 14 (Ethernet) + 4 (802.1Q tag) = 18 bytes
        if packet_data.len() < 18 {
            stats.malformed += 1;
            return Ok(());
        }

        // Extract source MAC (bytes 6-11)
        let src_mac = MacAddr([
            packet_data[6],
            packet_data[7],
            packet_data[8],
            packet_data[9],
            packet_data[10],
            packet_data[11],
        ]);

        // Check for 802.1Q TPID at byte 12-13
        let tpid = u16::from_be_bytes([packet_data[12], packet_data[13]]);
        if tpid != DOT1Q_TPID {
            // Not an 802.1Q packet
            return Ok(());
        }

        // Parse outer tag
        match Dot1qTag::parse(&packet_data[12..16]) {
            Ok(outer_tag) => {
                stats.single_tagged += 1;

                // Update VLAN traffic stats
                let vlan_entry = vlans
                    .entry(outer_tag.vlan_id)
                    .or_insert_with(|| VlanTraffic::new(outer_tag.vlan_id));

                vlan_entry.update(packet_data.len() as u64, src_mac);

                // Check for double tagging (inner TPID at byte 16-17)
                if packet_data.len() >= 22 {
                    let inner_tpid = u16::from_be_bytes([packet_data[16], packet_data[17]]);
                    if inner_tpid == DOT1Q_TPID {
                        stats.double_tagged += 1;

                        // Parse inner tag
                        if let Ok(inner_tag) = Dot1qTag::parse(&packet_data[16..20]) {
                            // Track inner VLAN too
                            let inner_vlan_entry = vlans
                                .entry(inner_tag.vlan_id)
                                .or_insert_with(|| VlanTraffic::new(inner_tag.vlan_id));

                            inner_vlan_entry.update(packet_data.len() as u64, src_mac);
                        }
                    }
                }
            }
            Err(_) => {
                stats.malformed += 1;
            }
        }

        Ok(())
    }
}

impl Default for Dot1qProtocol {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Protocol for Dot1qProtocol {
    fn name(&self) -> &'static str {
        "IEEE 802.1Q"
    }

    fn shortname(&self) -> &'static str {
        "dot1q"
    }

    fn id(&self) -> ProtocolId {
        ProtocolId::DOT1Q
    }

    fn attacks(&self) -> &[AttackDescriptor] {
        static ATTACKS: [AttackDescriptor; 2] = [
            AttackDescriptor {
                id: AttackId(0),
                name: "802.1Q Double Tagging",
                description:
                    "Send double-tagged frames to bypass VLAN security and access other VLANs",
                parameters: vec![],
            },
            AttackDescriptor {
                id: AttackId(1),
                name: "802.1Q VLAN Hopping",
                description: "Send tagged packets to multiple VLANs to discover network topology",
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

        // Try to get write lock on VLAN tracking
        let mut vlans = self
            .tagged_vlans_seen
            .try_write()
            .map_err(|_| Error::protocol("Failed to acquire VLAN tracking lock"))?;

        // Process packet to extract VLAN information
        self.process_vlan_packet(&packet.data, &mut stats, &mut vlans)?;

        // Update unique VLAN count
        stats.unique_vlans = vlans.len() as u64;

        Ok(())
    }

    async fn launch_attack(
        &self,
        attack_id: AttackId,
        params: AttackParams,
        interface: &Interface,
    ) -> Result<AttackHandle> {
        match attack_id.0 {
            0 => {
                // Double Tagging Attack
                let outer_vlan =
                    params
                        .get_u32("outer_vlan")
                        .ok_or_else(|| Error::InvalidParameter {
                            name: "outer_vlan".to_string(),
                            reason: "outer_vlan parameter required".to_string(),
                        })? as u16;

                let inner_vlan =
                    params
                        .get_u32("inner_vlan")
                        .ok_or_else(|| Error::InvalidParameter {
                            name: "inner_vlan".to_string(),
                            reason: "inner_vlan parameter required".to_string(),
                        })? as u16;

                // Default to broadcast MAC
                let dst_mac = MacAddr([0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]);

                // Default payload like original
                let payload = b"YERSINIA".to_vec();

                let src_mac = interface.mac_address;

                let attack = Dot1qDoubleTaggingAttack::new(
                    outer_vlan, inner_vlan, src_mac, dst_mac, payload,
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
                    protocol: "802.1Q".to_string(),
                    attack_name: "Double Tagging".to_string(),
                    running,
                    paused,
                    stats,
                    started_at: SystemTime::now(),
                    task_handle: Some(task_handle),
                })
            }
            1 => {
                // VLAN Hopping Attack
                let vlan_list_str =
                    params
                        .get_string("vlan_list")
                        .ok_or_else(|| Error::InvalidParameter {
                            name: "vlan_list".to_string(),
                            reason: "vlan_list parameter required".to_string(),
                        })?;

                // Parse comma-separated VLAN list
                let vlan_list: Result<Vec<u16>> = vlan_list_str
                    .split(',')
                    .map(|s| {
                        s.trim()
                            .parse::<u16>()
                            .map_err(|_| Error::InvalidParameter {
                                name: "vlan_list".to_string(),
                                reason: format!("Invalid VLAN ID: {}", s),
                            })
                    })
                    .collect();

                let vlan_list = vlan_list?;

                if vlan_list.is_empty() {
                    return Err(Error::InvalidParameter {
                        name: "vlan_list".to_string(),
                        reason: "vlan_list cannot be empty".to_string(),
                    });
                }

                let interval_ms = params.get_u32("interval_ms").unwrap_or(1000);

                let src_mac = interface.mac_address;
                let dst_mac = MacAddr([0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]); // Broadcast

                let attack =
                    Dot1qVlanHoppingAttack::new(vlan_list, src_mac, dst_mac, interval_ms as u64);

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
                    protocol: "802.1Q".to_string(),
                    attack_name: "VLAN Hopping".to_string(),
                    running,
                    paused,
                    stats,
                    started_at: SystemTime::now(),
                    task_handle: Some(task_handle),
                })
            }
            _ => Err(Error::InvalidParameter {
                name: "attack_id".to_string(),
                reason: format!("Unknown attack ID: {}", attack_id.0),
            }),
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
            *stats = Dot1qStats::default();
        }

        if let Ok(mut vlans) = self.tagged_vlans_seen.try_write() {
            vlans.clear();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_protocol_creation() {
        let protocol = Dot1qProtocol::new();
        assert_eq!(protocol.name(), "IEEE 802.1Q");
        assert_eq!(protocol.shortname(), "dot1q");
        assert_eq!(protocol.id(), ProtocolId::DOT1Q);
    }

    #[test]
    fn test_protocol_attacks() {
        let protocol = Dot1qProtocol::new();
        let attacks = protocol.attacks();
        assert_eq!(attacks.len(), 2);
        assert_eq!(attacks[0].name, "802.1Q Double Tagging");
        assert_eq!(attacks[1].name, "802.1Q VLAN Hopping");
    }

    #[test]
    fn test_vlan_traffic_new() {
        let traffic = VlanTraffic::new(100);
        assert_eq!(traffic.vlan_id, 100);
        assert_eq!(traffic.packet_count, 0);
        assert_eq!(traffic.byte_count, 0);
        assert_eq!(traffic.mac_addresses.len(), 0);
    }

    #[test]
    fn test_vlan_traffic_update() {
        let mut traffic = VlanTraffic::new(100);
        let mac = MacAddr([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]);

        traffic.update(64, mac);
        assert_eq!(traffic.packet_count, 1);
        assert_eq!(traffic.byte_count, 64);
        assert_eq!(traffic.mac_addresses.len(), 1);
        assert_eq!(traffic.mac_addresses[0], mac);

        // Update again with same MAC
        traffic.update(128, mac);
        assert_eq!(traffic.packet_count, 2);
        assert_eq!(traffic.byte_count, 192);
        assert_eq!(traffic.mac_addresses.len(), 1); // Should not duplicate

        // Update with different MAC
        let mac2 = MacAddr([0x11, 0x22, 0x33, 0x44, 0x55, 0x66]);
        traffic.update(256, mac2);
        assert_eq!(traffic.packet_count, 3);
        assert_eq!(traffic.byte_count, 448);
        assert_eq!(traffic.mac_addresses.len(), 2);
    }

    #[tokio::test]
    async fn test_vlan_count() {
        let protocol = Dot1qProtocol::new();
        assert_eq!(protocol.vlan_count().await, 0);

        // Add some VLANs manually for testing
        let mut vlans = protocol.tagged_vlans_seen.write().await;
        vlans.insert(100, VlanTraffic::new(100));
        vlans.insert(200, VlanTraffic::new(200));
        drop(vlans);

        assert_eq!(protocol.vlan_count().await, 2);
    }

    #[tokio::test]
    async fn test_get_all_vlans() {
        let protocol = Dot1qProtocol::new();

        let mut vlans = protocol.tagged_vlans_seen.write().await;
        vlans.insert(100, VlanTraffic::new(100));
        vlans.insert(10, VlanTraffic::new(10));
        vlans.insert(200, VlanTraffic::new(200));
        drop(vlans);

        let vlan_ids = protocol.get_all_vlans().await;
        assert_eq!(vlan_ids, vec![10, 100, 200]); // Should be sorted
    }

    #[tokio::test]
    async fn test_reset_stats() {
        let mut protocol = Dot1qProtocol::new();

        // Add some stats
        {
            let mut stats = protocol.stats.write().await;
            stats.base.packets_received = 100;
            stats.single_tagged = 50;
            stats.unique_vlans = 5;
        }

        // Add some VLANs
        {
            let mut vlans = protocol.tagged_vlans_seen.write().await;
            vlans.insert(100, VlanTraffic::new(100));
        }

        // Reset
        protocol.reset_stats();

        // Verify reset
        let stats = protocol.stats.read().await;
        assert_eq!(stats.base.packets_received, 0);
        assert_eq!(stats.single_tagged, 0);
        assert_eq!(stats.unique_vlans, 0);

        assert_eq!(protocol.vlan_count().await, 0);
    }
}
