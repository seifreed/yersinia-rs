//! DHCP Protocol implementation
//!
//! This module implements the Protocol trait for DHCP and provides
//! statistics tracking and server/lease information.

use super::packet::{DhcpMessageType, DhcpPacket};
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

/// MAC address type
pub type MacAddr = [u8; 6];

/// DHCP protocol statistics
#[derive(Debug, Clone, Default)]
pub struct DhcpStats {
    pub discovers_sent: u64,
    pub discovers_received: u64,
    pub offers_sent: u64,
    pub offers_received: u64,
    pub requests_sent: u64,
    pub requests_received: u64,
    pub acks_sent: u64,
    pub acks_received: u64,
    pub naks_sent: u64,
    pub naks_received: u64,
    pub releases_sent: u64,
    pub releases_received: u64,
    pub informs_sent: u64,
    pub informs_received: u64,
    pub declines_sent: u64,
    pub declines_received: u64,
    pub total_packets: u64,
    pub parse_errors: u64,
}

impl DhcpStats {
    pub fn new() -> Self {
        Self::default()
    }

    /// Increment counters based on message type
    pub fn record_sent(&mut self, msg_type: DhcpMessageType) {
        self.total_packets += 1;
        match msg_type {
            DhcpMessageType::Discover => self.discovers_sent += 1,
            DhcpMessageType::Offer => self.offers_sent += 1,
            DhcpMessageType::Request => self.requests_sent += 1,
            DhcpMessageType::Ack => self.acks_sent += 1,
            DhcpMessageType::Nak => self.naks_sent += 1,
            DhcpMessageType::Release => self.releases_sent += 1,
            DhcpMessageType::Inform => self.informs_sent += 1,
            DhcpMessageType::Decline => self.declines_sent += 1,
        }
    }

    pub fn record_received(&mut self, msg_type: DhcpMessageType) {
        self.total_packets += 1;
        match msg_type {
            DhcpMessageType::Discover => self.discovers_received += 1,
            DhcpMessageType::Offer => self.offers_received += 1,
            DhcpMessageType::Request => self.requests_received += 1,
            DhcpMessageType::Ack => self.acks_received += 1,
            DhcpMessageType::Nak => self.naks_received += 1,
            DhcpMessageType::Release => self.releases_received += 1,
            DhcpMessageType::Inform => self.informs_received += 1,
            DhcpMessageType::Decline => self.declines_received += 1,
        }
    }

    pub fn record_parse_error(&mut self) {
        self.parse_errors += 1;
    }
}

/// Information about a discovered DHCP server
#[derive(Debug, Clone)]
pub struct DhcpServerInfo {
    pub server_ip: Ipv4Addr,
    pub server_mac: MacAddr,
    pub offers_seen: u64,
    pub acks_seen: u64,
    pub naks_seen: u64,
    pub last_seen: SystemTime,
}

impl DhcpServerInfo {
    pub fn new(server_ip: Ipv4Addr, server_mac: MacAddr) -> Self {
        Self {
            server_ip,
            server_mac,
            offers_seen: 0,
            acks_seen: 0,
            naks_seen: 0,
            last_seen: SystemTime::now(),
        }
    }

    pub fn update_activity(&mut self, msg_type: DhcpMessageType) {
        self.last_seen = SystemTime::now();
        match msg_type {
            DhcpMessageType::Offer => self.offers_seen += 1,
            DhcpMessageType::Ack => self.acks_seen += 1,
            DhcpMessageType::Nak => self.naks_seen += 1,
            _ => {}
        }
    }
}

/// Information about a DHCP lease
#[derive(Debug, Clone)]
pub struct DhcpLeaseInfo {
    pub client_mac: MacAddr,
    pub client_ip: Ipv4Addr,
    pub server_ip: Ipv4Addr,
    pub server_mac: MacAddr,
    pub lease_time: u32,
    pub acquired_at: SystemTime,
    pub transaction_id: u32,
}

impl DhcpLeaseInfo {
    pub fn new(
        client_mac: MacAddr,
        client_ip: Ipv4Addr,
        server_ip: Ipv4Addr,
        server_mac: MacAddr,
        lease_time: u32,
        transaction_id: u32,
    ) -> Self {
        Self {
            client_mac,
            client_ip,
            server_ip,
            server_mac,
            lease_time,
            acquired_at: SystemTime::now(),
            transaction_id,
        }
    }

    /// Check if lease is expired
    pub fn is_expired(&self) -> bool {
        if let Ok(elapsed) = self.acquired_at.elapsed() {
            elapsed.as_secs() > self.lease_time as u64
        } else {
            false
        }
    }

    /// Get remaining lease time in seconds
    pub fn remaining_time(&self) -> u32 {
        if let Ok(elapsed) = self.acquired_at.elapsed() {
            let elapsed_secs = elapsed.as_secs() as u32;
            self.lease_time.saturating_sub(elapsed_secs)
        } else {
            0
        }
    }
}

/// DHCP Protocol implementation
pub struct DhcpProtocol {
    stats: Arc<RwLock<DhcpStats>>,
    discovered_servers: Arc<RwLock<HashMap<Ipv4Addr, DhcpServerInfo>>>,
    leases: Arc<RwLock<HashMap<MacAddr, DhcpLeaseInfo>>>,
}

impl DhcpProtocol {
    pub fn new() -> Self {
        Self {
            stats: Arc::new(RwLock::new(DhcpStats::new())),
            discovered_servers: Arc::new(RwLock::new(HashMap::new())),
            leases: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Get protocol statistics
    pub async fn get_stats(&self) -> DhcpStats {
        self.stats.read().await.clone()
    }

    /// Get discovered servers
    pub async fn discovered_servers(&self) -> HashMap<Ipv4Addr, DhcpServerInfo> {
        self.discovered_servers.read().await.clone()
    }

    /// Get active leases
    pub async fn leases(&self) -> HashMap<MacAddr, DhcpLeaseInfo> {
        self.leases.read().await.clone()
    }

    /// Process a received DHCP packet
    pub async fn process_packet(&self, packet: &DhcpPacket, source_mac: MacAddr) {
        if let Some(msg_type) = packet.message_type() {
            // Update stats
            self.stats.write().await.record_received(msg_type);

            match msg_type {
                DhcpMessageType::Offer | DhcpMessageType::Ack | DhcpMessageType::Nak => {
                    // Track server information
                    if let Some(server_ip) = packet.server_id() {
                        let mut servers = self.discovered_servers.write().await;
                        servers
                            .entry(server_ip)
                            .and_modify(|info| info.update_activity(msg_type))
                            .or_insert_with(|| {
                                let mut info = DhcpServerInfo::new(server_ip, source_mac);
                                info.update_activity(msg_type);
                                info
                            });
                    }

                    // Track lease for ACK messages
                    if msg_type == DhcpMessageType::Ack && packet.yiaddr != Ipv4Addr::UNSPECIFIED {
                        let client_mac = packet.client_mac();
                        if let Some(server_ip) = packet.server_id() {
                            let lease_time = packet.lease_time().unwrap_or(86400); // Default 1 day
                            let lease = DhcpLeaseInfo::new(
                                client_mac,
                                packet.yiaddr,
                                server_ip,
                                source_mac,
                                lease_time,
                                packet.xid,
                            );
                            self.leases.write().await.insert(client_mac, lease);
                        }
                    }
                }
                DhcpMessageType::Release => {
                    // Remove lease on release
                    let client_mac = packet.client_mac();
                    self.leases.write().await.remove(&client_mac);
                }
                _ => {}
            }
        }
    }

    /// Record a sent packet
    pub async fn record_sent(&self, msg_type: DhcpMessageType) {
        self.stats.write().await.record_sent(msg_type);
    }

    /// Get server count
    pub async fn server_count(&self) -> usize {
        self.discovered_servers.read().await.len()
    }

    /// Get active lease count
    pub async fn lease_count(&self) -> usize {
        self.leases.read().await.len()
    }

    /// Clean up expired leases
    pub async fn cleanup_expired_leases(&self) {
        self.leases
            .write()
            .await
            .retain(|_, lease| !lease.is_expired());
    }

    /// Get server by IP
    pub async fn get_server(&self, ip: Ipv4Addr) -> Option<DhcpServerInfo> {
        self.discovered_servers.read().await.get(&ip).cloned()
    }

    /// Get lease by MAC address
    pub async fn get_lease(&self, mac: &MacAddr) -> Option<DhcpLeaseInfo> {
        self.leases.read().await.get(mac).cloned()
    }

    /// Clear all statistics and tracking data
    pub async fn clear(&self) {
        *self.stats.write().await = DhcpStats::new();
        self.discovered_servers.write().await.clear();
        self.leases.write().await.clear();
    }

    /// Get protocol name
    pub fn name(&self) -> &'static str {
        "DHCP"
    }

    /// Get protocol description
    pub fn description(&self) -> &'static str {
        "Dynamic Host Configuration Protocol"
    }
}

impl Default for DhcpProtocol {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Protocol for DhcpProtocol {
    fn name(&self) -> &'static str {
        "Dynamic Host Configuration Protocol"
    }

    fn shortname(&self) -> &'static str {
        "dhcp"
    }

    fn id(&self) -> ProtocolId {
        ProtocolId::DHCP
    }

    fn attacks(&self) -> &[AttackDescriptor] {
        static ATTACKS: [AttackDescriptor; 5] = [
            AttackDescriptor {
                id: AttackId(0),
                name: "DHCP Starvation",
                description: "Exhaust DHCP server IP pool by requesting leases with random MAC addresses",
                parameters: vec![],
            },
            AttackDescriptor {
                id: AttackId(1),
                name: "DHCP Release Spoofing",
                description: "Send DHCP RELEASE messages to disconnect legitimate clients",
                parameters: vec![],
            },
            AttackDescriptor {
                id: AttackId(2),
                name: "Option 82 Manipulation",
                description: "Manipulate DHCP Option 82 (Relay Agent Information) to bypass security controls",
                parameters: vec![],
            },
            AttackDescriptor {
                id: AttackId(3),
                name: "Relay Manipulation",
                description: "Spoof DHCP relay agents to manipulate client configurations",
                parameters: vec![],
            },
            AttackDescriptor {
                id: AttackId(4),
                name: "Rogue DHCP Server",
                description: "Act as a persistent rogue DHCP server to distribute malicious network configurations",
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

        stats.total_packets += 1;

        // Parse DHCP packet (skip Ethernet 14 + IP 20 + UDP 8 = 42 bytes minimum)
        if packet.data.len() > 42 {
            let dhcp_data = &packet.data[42..];
            match DhcpPacket::parse(dhcp_data) {
                Ok(dhcp_packet) => {
                    // Drop stats lock before processing (needs async)
                    drop(stats);

                    // Process packet (this would need to be sync or we'd need to change handle_packet to async)
                    // For now, we'll just update basic stats
                    if let Some(msg_type) = dhcp_packet.message_type() {
                        if let Ok(mut stats) = self.stats.try_write() {
                            stats.record_received(msg_type);
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
            // DHCP Starvation
            0 => {
                let rate_pps = params.get_u32("rate_pps").unwrap_or(100);
                let duration_secs = params.get_u32("duration").map(|d| d as u64);
                let use_random_mac = params.get_bool("random_mac").unwrap_or(true);
                let use_random_xid = params.get_bool("random_xid").unwrap_or(true);

                let target_server = params
                    .get_string("target_server")
                    .and_then(|s| s.parse::<Ipv4Addr>().ok());

                let mut attack = DhcpStarvationAttack::new()
                    .with_rate(rate_pps)
                    .with_random_mac(use_random_mac)
                    .with_random_xid(use_random_xid)
                    .with_target_server(target_server);

                if let Some(duration) = duration_secs {
                    attack = attack.with_duration(duration);
                }

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
                    protocol: "DHCP".to_string(),
                    attack_name: "Starvation".to_string(),
                    running,
                    paused,
                    stats,
                    started_at: SystemTime::now(),
                    task_handle: Some(task_handle),
                })
            }

            // DHCP Release Spoofing
            1 => {
                let server_ip = params
                    .get_string("server_ip")
                    .and_then(|s| s.parse::<Ipv4Addr>().ok())
                    .ok_or_else(|| {
                        Error::invalid_parameter("server_ip", "Required DHCP server IP")
                    })?;

                let server_mac_str = params.get_string("server_mac").ok_or_else(|| {
                    Error::invalid_parameter("server_mac", "Required DHCP server MAC")
                })?;

                let parts: Vec<&str> = server_mac_str.split(':').collect();
                let server_mac = if parts.len() == 6 {
                    let bytes: std::result::Result<Vec<u8>, _> =
                        parts.iter().map(|p| u8::from_str_radix(p, 16)).collect();
                    bytes
                        .ok()
                        .map(|b| {
                            let mut mac = [0u8; 6];
                            mac.copy_from_slice(&b);
                            mac
                        })
                        .ok_or_else(|| {
                            Error::invalid_parameter("server_mac", "Invalid MAC format")
                        })?
                } else {
                    return Err(Error::invalid_parameter("server_mac", "Invalid MAC format"));
                };

                let mut attack = DhcpReleaseAttack::new(server_ip, server_mac);

                if let Some(target_mac_str) = params.get_string("target_mac") {
                    let parts: Vec<&str> = target_mac_str.split(':').collect();
                    if parts.len() == 6 {
                        let bytes: std::result::Result<Vec<u8>, _> =
                            parts.iter().map(|p| u8::from_str_radix(p, 16)).collect();
                        if let Ok(b) = bytes {
                            let mut mac = [0u8; 6];
                            mac.copy_from_slice(&b);
                            attack = attack.with_target_mac(mac);
                        }
                    }
                }

                if let Some(target_ip_str) = params.get_string("target_ip") {
                    if let Ok(ip) = target_ip_str.parse::<Ipv4Addr>() {
                        attack = attack.with_target_ip(ip);
                    }
                }

                let rate_pps = params.get_u32("rate_pps").unwrap_or(10);
                let randomize = params.get_bool("randomize").unwrap_or(false);

                attack = attack.with_rate(rate_pps).with_randomize(randomize);

                if let Some(range_start_str) = params.get_string("range_start") {
                    if let Some(range_end_str) = params.get_string("range_end") {
                        if let (Ok(start), Ok(end)) = (
                            range_start_str.parse::<Ipv4Addr>(),
                            range_end_str.parse::<Ipv4Addr>(),
                        ) {
                            attack = attack.with_ip_range(start, end);
                        }
                    }
                }

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
                    protocol: "DHCP".to_string(),
                    attack_name: "Release".to_string(),
                    running,
                    paused,
                    stats,
                    started_at: SystemTime::now(),
                    task_handle: Some(task_handle),
                })
            }

            // DHCP Option 82 Manipulation
            2 => {
                let circuit_id = params
                    .get_string("circuit_id")
                    .map(|s| s.as_bytes().to_vec())
                    .unwrap_or_else(|| b"malicious-circuit".to_vec());

                let remote_id = params
                    .get_string("remote_id")
                    .map(|s| s.as_bytes().to_vec())
                    .unwrap_or_else(|| b"malicious-remote".to_vec());

                let relay_ip = params
                    .get_string("relay_ip")
                    .and_then(|s| s.parse::<Ipv4Addr>().ok())
                    .unwrap_or_else(|| Ipv4Addr::new(192, 168, 1, 254));

                let attack = DhcpOption82Attack::new(circuit_id, remote_id, relay_ip);

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
                    protocol: "DHCP".to_string(),
                    attack_name: "Option 82 Manipulation".to_string(),
                    running,
                    paused,
                    stats,
                    started_at: SystemTime::now(),
                    task_handle: Some(task_handle),
                })
            }

            // DHCP Relay Manipulation
            3 => {
                let relay_ip = params
                    .get_string("relay_ip")
                    .and_then(|s| s.parse::<Ipv4Addr>().ok())
                    .ok_or_else(|| {
                        Error::invalid_parameter("relay_ip", "Required relay agent IP")
                    })?;

                let server_ip = params
                    .get_string("server_ip")
                    .and_then(|s| s.parse::<Ipv4Addr>().ok())
                    .ok_or_else(|| {
                        Error::invalid_parameter("server_ip", "Required DHCP server IP")
                    })?;

                let hop_count = params.get_u32("hop_count").unwrap_or(1) as u8;

                let attack =
                    DhcpRelayManipulationAttack::new(relay_ip, server_ip).with_hops(hop_count);

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
                    protocol: "DHCP".to_string(),
                    attack_name: "Relay Manipulation".to_string(),
                    running,
                    paused,
                    stats,
                    started_at: SystemTime::now(),
                    task_handle: Some(task_handle),
                })
            }

            // Rogue DHCP Server
            4 => {
                let server_ip = params
                    .get_string("server_ip")
                    .and_then(|s| s.parse::<Ipv4Addr>().ok())
                    .ok_or_else(|| {
                        Error::invalid_parameter("server_ip", "Required rogue server IP")
                    })?;

                let gateway_ip = params
                    .get_string("gateway_ip")
                    .and_then(|s| s.parse::<Ipv4Addr>().ok())
                    .ok_or_else(|| Error::invalid_parameter("gateway_ip", "Required gateway IP"))?;

                let mut attack = RogueDhcpServerAttack::new(server_ip, gateway_ip);

                if let Some(dns_str) = params.get_string("dns_servers") {
                    let dns_servers: Vec<Ipv4Addr> = dns_str
                        .split(',')
                        .filter_map(|s| s.trim().parse().ok())
                        .collect();
                    if !dns_servers.is_empty() {
                        attack = attack.with_dns(dns_servers);
                    }
                }

                let lease_time = params.get_u32("lease_time").unwrap_or(3600);
                attack = attack.with_lease_time(lease_time);

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
                    protocol: "DHCP".to_string(),
                    attack_name: "Rogue Server".to_string(),
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
                packets_received: stats.total_packets,
                packets_parsed: stats.total_packets - stats.parse_errors,
                packets_errors: stats.parse_errors,
                bytes_received: 0, // Not tracked in DhcpStats
                ..Default::default()
            };

            // Add DHCP-specific stats to custom map
            proto_stats
                .custom
                .insert("discovers_sent".to_string(), stats.discovers_sent);
            proto_stats
                .custom
                .insert("discovers_received".to_string(), stats.discovers_received);
            proto_stats
                .custom
                .insert("offers_received".to_string(), stats.offers_received);
            proto_stats
                .custom
                .insert("requests_sent".to_string(), stats.requests_sent);
            proto_stats
                .custom
                .insert("acks_received".to_string(), stats.acks_received);

            proto_stats
        } else {
            ProtocolStats::default()
        }
    }

    fn reset_stats(&mut self) {
        if let Ok(mut stats) = self.stats.try_write() {
            *stats = DhcpStats::new();
        }
    }
}
