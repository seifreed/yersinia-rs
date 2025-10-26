//! ARP Protocol Implementation

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

use super::packet::ArpPacket;

/// ARP cache entry
#[derive(Debug, Clone)]
pub struct ArpCacheEntry {
    pub mac_addr: [u8; 6],
    pub ip_addr: Ipv4Addr,
    pub last_seen: SystemTime,
}

/// ARP Statistics
#[derive(Debug, Clone, Default)]
pub struct ArpStats {
    pub packets_received: u64,
    pub packets_parsed: u64,
    pub parse_errors: u64,
    pub requests_seen: u64,
    pub replies_seen: u64,
    pub gratuitous_seen: u64,
}

/// ARP Protocol Implementation
pub struct ArpProtocol {
    stats: Arc<RwLock<ArpStats>>,
    arp_cache: Arc<RwLock<HashMap<Ipv4Addr, ArpCacheEntry>>>,
}

impl ArpProtocol {
    pub fn new() -> Self {
        Self {
            stats: Arc::new(RwLock::new(ArpStats::default())),
            arp_cache: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub async fn cache_size(&self) -> usize {
        self.arp_cache.read().await.len()
    }
}

impl Default for ArpProtocol {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Protocol for ArpProtocol {
    fn name(&self) -> &'static str {
        "Address Resolution Protocol"
    }

    fn shortname(&self) -> &'static str {
        "arp"
    }

    fn id(&self) -> ProtocolId {
        ProtocolId::ARP
    }

    fn attacks(&self) -> &[AttackDescriptor] {
        static ATTACKS: [AttackDescriptor; 6] = [
            AttackDescriptor {
                id: AttackId(0),
                name: "ARP Spoofing/Poisoning",
                description: "Send fake ARP replies to poison ARP caches (MITM attack)",
                parameters: vec![],
            },
            AttackDescriptor {
                id: AttackId(1),
                name: "ARP Flooding",
                description: "Flood network with ARP requests to exhaust resources",
                parameters: vec![],
            },
            AttackDescriptor {
                id: AttackId(2),
                name: "Gratuitous ARP",
                description: "Send gratuitous ARP to announce MAC/IP mapping changes",
                parameters: vec![],
            },
            AttackDescriptor {
                id: AttackId(3),
                name: "ARP Storm",
                description: "Generate massive ARP traffic storm to overwhelm network",
                parameters: vec![],
            },
            AttackDescriptor {
                id: AttackId(4),
                name: "Gratuitous ARP Flooding",
                description: "Flood network with gratuitous ARP replies to poison all hosts",
                parameters: vec![],
            },
            AttackDescriptor {
                id: AttackId(5),
                name: "ARP Scanning",
                description: "Scan network for active hosts using ARP requests",
                parameters: vec![],
            },
        ];

        &ATTACKS
    }

    fn parameters(&self) -> Vec<Box<dyn Parameter>> {
        vec![]
    }

    fn handle_packet(&mut self, packet: &Packet) -> Result<()> {
        if packet.data.len() < 42 {
            // Ethernet(14) + ARP(28)
            return Ok(());
        }

        let arp_data = &packet.data[14..];

        match ArpPacket::parse(arp_data) {
            Ok(arp_packet) => {
                if let Ok(mut stats) = self.stats.try_write() {
                    stats.packets_received += 1;
                    stats.packets_parsed += 1;

                    if arp_packet.is_request() {
                        stats.requests_seen += 1;
                    } else if arp_packet.is_reply() {
                        stats.replies_seen += 1;
                    }

                    if arp_packet.is_gratuitous() {
                        stats.gratuitous_seen += 1;
                    }
                }

                // Update ARP cache
                if let Ok(mut cache) = self.arp_cache.try_write() {
                    let entry = ArpCacheEntry {
                        mac_addr: arp_packet.sender_hw_addr,
                        ip_addr: arp_packet.sender_proto_addr,
                        last_seen: SystemTime::now(),
                    };
                    cache.insert(arp_packet.sender_proto_addr, entry);
                }
            }
            Err(_) => {
                if let Ok(mut stats) = self.stats.try_write() {
                    stats.packets_received += 1;
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
        use crate::arp::attack::*;

        match attack_id.0 {
            // ARP Spoofing/Poisoning
            0 => {
                let target_ip = params
                    .get_string("target_ip")
                    .and_then(|s| s.parse().ok())
                    .ok_or_else(|| Error::invalid_parameter("target_ip", "Required IP address"))?;

                let spoof_ip = params
                    .get_string("spoof_ip")
                    .and_then(|s| s.parse().ok())
                    .ok_or_else(|| Error::invalid_parameter("spoof_ip", "Required IP address"))?;

                let target_mac = params.get_string("target_mac").and_then(|s| {
                    let parts: Vec<&str> = s.split(':').collect();
                    if parts.len() == 6 {
                        let bytes: std::result::Result<Vec<u8>, _> =
                            parts.iter().map(|p| u8::from_str_radix(p, 16)).collect();
                        bytes.ok().map(|b| {
                            let mut mac = [0u8; 6];
                            mac.copy_from_slice(&b);
                            mac
                        })
                    } else {
                        None
                    }
                });

                let attack = ArpSpoofingAttack::new(target_ip, spoof_ip, target_mac);

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
                    protocol: "ARP".to_string(),
                    attack_name: "Spoofing/Poisoning".to_string(),
                    running,
                    paused,
                    stats,
                    started_at: SystemTime::now(),
                    task_handle: Some(task_handle),
                })
            }

            // ARP Flooding
            1 => {
                let rate = params.get_u32("rate_pps").unwrap_or(100);
                let attack = ArpFloodingAttack::new(rate);

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
                    protocol: "ARP".to_string(),
                    attack_name: "Flooding".to_string(),
                    running,
                    paused,
                    stats,
                    started_at: SystemTime::now(),
                    task_handle: Some(task_handle),
                })
            }

            // Gratuitous ARP
            2 => {
                let ip_addr = params
                    .get_string("ip_addr")
                    .and_then(|s| s.parse().ok())
                    .ok_or_else(|| Error::invalid_parameter("ip_addr", "Required IP address"))?;

                let mac_str = params
                    .get_string("mac_addr")
                    .ok_or_else(|| Error::invalid_parameter("mac_addr", "Required MAC address"))?;

                let parts: Vec<&str> = mac_str.split(':').collect();
                let mac = if parts.len() == 6 {
                    let bytes: std::result::Result<Vec<u8>, _> =
                        parts.iter().map(|p| u8::from_str_radix(p, 16)).collect();
                    bytes
                        .ok()
                        .map(|b| {
                            let mut mac_array = [0u8; 6];
                            mac_array.copy_from_slice(&b);
                            mac_array
                        })
                        .ok_or_else(|| Error::invalid_parameter("mac_addr", "Invalid MAC format"))?
                } else {
                    return Err(Error::invalid_parameter("mac_addr", "Invalid MAC format"));
                };

                let attack = ArpGratuitousAttack::new(ip_addr, mac);

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
                    protocol: "ARP".to_string(),
                    attack_name: "Gratuitous ARP".to_string(),
                    running,
                    paused,
                    stats,
                    started_at: SystemTime::now(),
                    task_handle: Some(task_handle),
                })
            }

            // ARP Storm
            3 => {
                let packets_per_second = params.get_u32("rate_pps").unwrap_or(1000) as usize;
                let duration_seconds = params.get_u32("duration").unwrap_or(60) as u64;
                let randomize_source = params.get_bool("randomize").unwrap_or(true);

                let attack =
                    ArpStormAttack::new(packets_per_second, duration_seconds, randomize_source);

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
                    protocol: "ARP".to_string(),
                    attack_name: "Storm".to_string(),
                    running,
                    paused,
                    stats,
                    started_at: SystemTime::now(),
                    task_handle: Some(task_handle),
                })
            }

            // Gratuitous ARP Flooding
            4 => {
                let rate_pps = params.get_u32("rate_pps").unwrap_or(100);
                let randomize_ips = params.get_bool("randomize_ips").unwrap_or(true);

                let attack = GratuitousArpFloodingAttack::new(rate_pps, randomize_ips);

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
                    protocol: "ARP".to_string(),
                    attack_name: "Gratuitous ARP Flooding".to_string(),
                    running,
                    paused,
                    stats,
                    started_at: SystemTime::now(),
                    task_handle: Some(task_handle),
                })
            }

            // ARP Scanning
            5 => {
                let network = params
                    .get_string("network")
                    .ok_or_else(|| Error::invalid_parameter("network", "Required network address"))?
                    .to_string();

                let timeout_ms = params.get_u32("timeout_ms").unwrap_or(1000) as u64;

                let attack = ArpScanningAttack::new(network, timeout_ms);

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
                    protocol: "ARP".to_string(),
                    attack_name: "Scanning".to_string(),
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
        if let Ok(stats) = self.stats.try_read() {
            let mut proto_stats = ProtocolStats {
                packets_received: stats.packets_received,
                packets_parsed: stats.packets_parsed,
                packets_errors: stats.parse_errors,
                bytes_received: 0,
                ..Default::default()
            };

            proto_stats
                .custom
                .insert("requests_seen".to_string(), stats.requests_seen);
            proto_stats
                .custom
                .insert("replies_seen".to_string(), stats.replies_seen);
            proto_stats
                .custom
                .insert("gratuitous_seen".to_string(), stats.gratuitous_seen);

            proto_stats
        } else {
            ProtocolStats::default()
        }
    }

    fn reset_stats(&mut self) {
        if let Ok(mut stats) = self.stats.try_write() {
            *stats = ArpStats::default();
        }
    }
}
