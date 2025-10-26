//! VTP Protocol Implementation
//!
//! Implements the Protocol trait for VLAN Trunking Protocol with full support
//! for packet parsing, domain tracking, VLAN database management, and attack launching.

use async_trait::async_trait;
use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::sync::Arc;
use std::time::SystemTime;
use tokio::sync::RwLock;
use yersinia_core::{
    protocol::{AttackParams, Protocol, ProtocolStats},
    Attack, AttackDescriptor, AttackHandle, AttackId, Error, Interface, Packet, Parameter,
    ProtocolId, Result,
};

use super::packet::{VlanInfo, VtpMessageData, VtpMode, VtpPacket, VtpVersion};

/// VTP Protocol Implementation
pub struct VtpProtocol {
    stats: Arc<RwLock<VtpStats>>,
    domain_info: Arc<RwLock<HashMap<String, VtpDomainInfo>>>,
    vlan_database: Arc<RwLock<HashMap<String, HashMap<u16, VlanInfo>>>>,
}

/// Statistics specific to VTP protocol
#[derive(Debug, Clone, Default)]
pub struct VtpStats {
    pub packets_received: u64,
    pub packets_sent: u64,
    pub bytes_received: u64,
    pub bytes_sent: u64,
    pub packets_parsed: u64,
    pub parse_errors: u64,
    pub summary_adverts: u64,
    pub subset_adverts: u64,
    pub requests: u64,
    pub joins: u64,
    pub domains_discovered: u64,
    pub vlans_learned: u64,
}

/// Information about a VTP domain
#[derive(Debug, Clone)]
struct VtpDomainInfo {
    domain_name: String,
    revision: u32,
    updater_ip: Ipv4Addr,
    _last_update: SystemTime,
    _mode: VtpMode,
    version: VtpVersion,
}

impl VtpProtocol {
    pub fn new() -> Self {
        Self {
            stats: Arc::new(RwLock::new(VtpStats::default())),
            domain_info: Arc::new(RwLock::new(HashMap::new())),
            vlan_database: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Extract domain information from a VTP packet
    fn extract_domain_info(&self, packet: &VtpPacket) -> Option<VtpDomainInfo> {
        match &packet.data {
            VtpMessageData::Summary {
                updater_identity, ..
            } => Some(VtpDomainInfo {
                domain_name: packet.domain_name.clone(),
                revision: packet.revision,
                updater_ip: *updater_identity,
                _last_update: SystemTime::now(),
                _mode: VtpMode::Server, // Default assumption
                version: packet.version,
            }),
            VtpMessageData::Subset { .. } => Some(VtpDomainInfo {
                domain_name: packet.domain_name.clone(),
                revision: packet.revision,
                updater_ip: Ipv4Addr::new(0, 0, 0, 0),
                _last_update: SystemTime::now(),
                _mode: VtpMode::Server,
                version: packet.version,
            }),
            _ => None,
        }
    }

    /// Update VLAN database from subset advertisement
    fn update_vlan_database(&self, domain: &str, vlans: &[VlanInfo]) {
        if let Ok(mut db) = self.vlan_database.try_write() {
            let domain_vlans = db.entry(domain.to_string()).or_insert_with(HashMap::new);

            for vlan in vlans {
                domain_vlans.insert(vlan.vlan_id, vlan.clone());
            }
        }
    }

    /// Get number of VLANs in a domain
    pub fn get_vlan_count(&self, domain: &str) -> usize {
        if let Ok(db) = self.vlan_database.try_read() {
            db.get(domain).map(|v| v.len()).unwrap_or(0)
        } else {
            0
        }
    }

    /// Get all domains discovered
    pub fn get_domains(&self) -> Vec<String> {
        if let Ok(info) = self.domain_info.try_read() {
            info.keys().cloned().collect()
        } else {
            Vec::new()
        }
    }

    /// Get domain information
    pub fn get_domain_info(&self, domain: &str) -> Option<(u32, Ipv4Addr, VtpVersion)> {
        if let Ok(info) = self.domain_info.try_read() {
            info.get(domain)
                .map(|d| (d.revision, d.updater_ip, d.version))
        } else {
            None
        }
    }

    /// Get VLANs for a domain
    pub fn get_vlans(&self, domain: &str) -> Vec<VlanInfo> {
        if let Ok(db) = self.vlan_database.try_read() {
            db.get(domain)
                .map(|vlans| vlans.values().cloned().collect())
                .unwrap_or_default()
        } else {
            Vec::new()
        }
    }

    /// Get current statistics
    pub fn get_stats(&self) -> VtpStats {
        if let Ok(stats) = self.stats.try_read() {
            stats.clone()
        } else {
            VtpStats::default()
        }
    }
}

impl Default for VtpProtocol {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Protocol for VtpProtocol {
    fn name(&self) -> &'static str {
        "VLAN Trunking Protocol"
    }

    fn shortname(&self) -> &'static str {
        "vtp"
    }

    fn id(&self) -> ProtocolId {
        ProtocolId::VTP
    }

    fn attacks(&self) -> &[AttackDescriptor] {
        static ATTACKS: [AttackDescriptor; 4] = [
            AttackDescriptor {
                id: AttackId(0),
                name: "VTP Delete All VLANs",
                description: "Delete all VLANs in a domain by sending Summary + Subset with default VLANs only (except VLAN 1)",
                parameters: vec![],
            },
            AttackDescriptor {
                id: AttackId(1),
                name: "VTP VLAN Spoofing/Poisoning",
                description: "Inject fake VLAN configurations into the VTP domain",
                parameters: vec![],
            },
            AttackDescriptor {
                id: AttackId(2),
                name: "VTP Pruning Manipulation",
                description: "Manipulate VTP pruning to affect VLAN traffic flow",
                parameters: vec![],
            },
            AttackDescriptor {
                id: AttackId(3),
                name: "VTP Password Cracking",
                description: "Attempt offline cracking of VTP password from captured MD5 hash",
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

        stats.packets_received += 1;
        stats.bytes_received += packet.data.len() as u64;

        // Try to parse as VTP packet
        // Skip Ethernet (14 bytes) + LLC/SNAP (8 bytes) headers
        if packet.data.len() > 22 {
            let vtp_data = &packet.data[22..];
            match VtpPacket::parse(vtp_data) {
                Ok(vtp_packet) => {
                    stats.packets_parsed += 1;

                    // Update message type counters
                    match &vtp_packet.data {
                        VtpMessageData::Summary { .. } => stats.summary_adverts += 1,
                        VtpMessageData::Subset { .. } => stats.subset_adverts += 1,
                        VtpMessageData::Request { .. } => stats.requests += 1,
                        VtpMessageData::Join { .. } => stats.joins += 1,
                    }

                    // Extract domain information
                    if let Some(domain_info) = self.extract_domain_info(&vtp_packet) {
                        drop(stats); // Release stats lock

                        let mut domains = self
                            .domain_info
                            .try_write()
                            .map_err(|_| Error::protocol("Failed to acquire domain lock"))?;

                        let is_new_domain = !domains.contains_key(&domain_info.domain_name);

                        domains.insert(domain_info.domain_name.clone(), domain_info.clone());

                        if is_new_domain {
                            if let Ok(mut stats) = self.stats.try_write() {
                                stats.domains_discovered += 1;
                            }
                        }

                        // Update VLAN database if this is a subset advertisement
                        if let VtpMessageData::Subset { vlans, .. } = &vtp_packet.data {
                            drop(domains); // Release domain lock
                            self.update_vlan_database(&domain_info.domain_name, vlans);

                            if let Ok(mut stats) = self.stats.try_write() {
                                stats.vlans_learned += vlans.len() as u64;
                            }
                        }
                    }
                }
                Err(_) => {
                    stats.parse_errors += 1;
                }
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
        use super::attack::*;

        match attack_id.0 {
            // VTP Delete All VLANs Attack
            0 => {
                let domain_name = params.get_string("domain").unwrap_or("default");

                let revision_number = params.get_u32("revision").unwrap_or(1);
                let interval_ms = params
                    .get_u32("interval_ms")
                    .map(|v| v as u64)
                    .unwrap_or(5000);

                let attack = VtpDeleteVlanAttack::new(
                    interface.clone(),
                    domain_name,
                    revision_number,
                    interval_ms,
                );

                let running = Arc::new(std::sync::atomic::AtomicBool::new(true));
                let paused = Arc::new(std::sync::atomic::AtomicBool::new(false));
                let stats = Arc::new(yersinia_core::AttackStatsCounters::default());

                let ctx = yersinia_core::AttackContext {
                    interface: interface.clone(),
                    running: running.clone(),
                    paused: paused.clone(),
                    stats: stats.clone(),
                };

                let task_handle = tokio::spawn(async move { attack.execute(ctx).await });

                Ok(AttackHandle {
                    id: uuid::Uuid::now_v7(),
                    protocol: "VTP".to_string(),
                    attack_name: "Delete All VLANs".to_string(),
                    running,
                    paused,
                    stats,
                    started_at: std::time::SystemTime::now(),
                    task_handle: Some(task_handle),
                })
            }

            // VTP VLAN Spoofing/Poisoning Attack
            1 => {
                let domain_name = params.get_string("domain").unwrap_or("default");

                let revision_number = params.get_u32("revision").unwrap_or(1);
                let interval_ms = params
                    .get_u32("interval_ms")
                    .map(|v| v as u64)
                    .unwrap_or(5000);

                let attack = VtpSpoofingAttack::new(
                    interface.clone(),
                    domain_name,
                    revision_number,
                    interval_ms,
                );

                let running = Arc::new(std::sync::atomic::AtomicBool::new(true));
                let paused = Arc::new(std::sync::atomic::AtomicBool::new(false));
                let stats = Arc::new(yersinia_core::AttackStatsCounters::default());

                let ctx = yersinia_core::AttackContext {
                    interface: interface.clone(),
                    running: running.clone(),
                    paused: paused.clone(),
                    stats: stats.clone(),
                };

                let task_handle = tokio::spawn(async move { attack.execute(ctx).await });

                Ok(AttackHandle {
                    id: uuid::Uuid::now_v7(),
                    protocol: "VTP".to_string(),
                    attack_name: "VLAN Spoofing/Poisoning".to_string(),
                    running,
                    paused,
                    stats,
                    started_at: std::time::SystemTime::now(),
                    task_handle: Some(task_handle),
                })
            }

            // VTP Pruning Manipulation Attack
            2 => {
                let domain_name = params.get_string("domain").unwrap_or("default");

                let vlans_to_prune: Vec<u16> = params
                    .get_string("vlans")
                    .map(|s| s.split(',').filter_map(|v| v.trim().parse().ok()).collect())
                    .unwrap_or_else(|| vec![10, 20, 30]);

                let attack = VtpPruningManipulationAttack::new(
                    interface.clone(),
                    domain_name,
                    vlans_to_prune,
                );

                let running = Arc::new(std::sync::atomic::AtomicBool::new(true));
                let paused = Arc::new(std::sync::atomic::AtomicBool::new(false));
                let stats = Arc::new(yersinia_core::AttackStatsCounters::default());

                let ctx = yersinia_core::AttackContext {
                    interface: interface.clone(),
                    running: running.clone(),
                    paused: paused.clone(),
                    stats: stats.clone(),
                };

                let task_handle = tokio::spawn(async move { attack.execute(ctx).await });

                Ok(AttackHandle {
                    id: uuid::Uuid::now_v7(),
                    protocol: "VTP".to_string(),
                    attack_name: "Pruning Manipulation".to_string(),
                    running,
                    paused,
                    stats,
                    started_at: std::time::SystemTime::now(),
                    task_handle: Some(task_handle),
                })
            }

            // VTP Password Cracking Attack
            3 => {
                let domain_name = params.get_string("domain").unwrap_or("default");

                let dictionary_path = params.get_string("dictionary").map(|s| s.to_string());

                let dictionary = if let Some(path) = dictionary_path {
                    // Load dictionary from file
                    match std::fs::read_to_string(&path) {
                        Ok(content) => {
                            // Split by lines and filter out empty lines
                            content
                                .lines()
                                .map(|s| s.trim().to_string())
                                .filter(|s| !s.is_empty())
                                .collect()
                        }
                        Err(e) => {
                            eprintln!("Failed to load dictionary from {}: {}", path, e);
                            // Fallback to default dictionary
                            vec![
                                "password".to_string(),
                                "cisco".to_string(),
                                "admin".to_string(),
                            ]
                        }
                    }
                } else {
                    vec![
                        "password".to_string(),
                        "cisco".to_string(),
                        "admin".to_string(),
                    ]
                };

                let attack = VtpPasswordCrackingAttack::new(domain_name, dictionary);

                let running = Arc::new(std::sync::atomic::AtomicBool::new(true));
                let paused = Arc::new(std::sync::atomic::AtomicBool::new(false));
                let stats = Arc::new(yersinia_core::AttackStatsCounters::default());

                let ctx = yersinia_core::AttackContext {
                    interface: interface.clone(),
                    running: running.clone(),
                    paused: paused.clone(),
                    stats: stats.clone(),
                };

                let task_handle = tokio::spawn(async move { attack.execute(ctx).await });

                Ok(AttackHandle {
                    id: uuid::Uuid::now_v7(),
                    protocol: "VTP".to_string(),
                    attack_name: "Password Cracking".to_string(),
                    running,
                    paused,
                    stats,
                    started_at: std::time::SystemTime::now(),
                    task_handle: Some(task_handle),
                })
            }

            _ => Err(Error::InvalidAttackId(attack_id.0)),
        }
    }

    fn stats(&self) -> ProtocolStats {
        if let Ok(stats) = self.stats.try_read() {
            let mut proto_stats = ProtocolStats {
                packets_received: stats.packets_received,
                packets_parsed: stats.packets_parsed,
                packets_errors: stats.parse_errors,
                bytes_received: stats.bytes_received,
                ..Default::default()
            };

            // Add VTP-specific stats to custom map
            proto_stats
                .custom
                .insert("summary_adverts".to_string(), stats.summary_adverts);
            proto_stats
                .custom
                .insert("subset_adverts".to_string(), stats.subset_adverts);
            proto_stats
                .custom
                .insert("requests".to_string(), stats.requests);
            proto_stats
                .custom
                .insert("domains_discovered".to_string(), stats.domains_discovered);
            proto_stats
                .custom
                .insert("vlans_learned".to_string(), stats.vlans_learned);

            proto_stats
        } else {
            ProtocolStats::default()
        }
    }

    fn reset_stats(&mut self) {
        if let Ok(mut stats) = self.stats.try_write() {
            *stats = VtpStats::default();
        }
    }
}
