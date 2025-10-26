//! HSRP Protocol Implementation
//!
//! Implements the Protocol trait for Hot Standby Router Protocol with full support
//! for packet parsing, statistics tracking, and attack launching.

use async_trait::async_trait;
use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::sync::Arc;
use std::time::SystemTime;
use tokio::sync::RwLock;
use yersinia_core::{
    protocol::{AttackParams, Protocol, ProtocolStats},
    Attack, AttackDescriptor, AttackHandle, AttackId, AttackStatsCounters, Error, Interface,
    MacAddr, Packet, Parameter, ProtocolId, Result,
};
use yersinia_packet::MacAddress;

use super::attack::HsrpActiveRouterAttack;
use super::packet::{HsrpPacket, HsrpState};

/// HSRP Protocol Implementation
pub struct HsrpProtocol {
    stats: Arc<RwLock<ProtocolStats>>,
    groups: Arc<RwLock<HashMap<u16, HsrpGroupInfo>>>,
}

/// Information about a discovered HSRP group
#[derive(Debug, Clone)]
struct HsrpGroupInfo {
    _group_id: u16,
    virtual_ip: Ipv4Addr,
    active_router: Option<Ipv4Addr>,
    standby_router: Option<Ipv4Addr>,
    priority: u8,
    state: HsrpState,
    last_hello: SystemTime,
}

impl HsrpProtocol {
    pub fn new() -> Self {
        Self {
            stats: Arc::new(RwLock::new(ProtocolStats::default())),
            groups: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Extract HSRP group information from a packet
    fn extract_group_info(&self, packet: &HsrpPacket, src_ip: Option<Ipv4Addr>) -> HsrpGroupInfo {
        HsrpGroupInfo {
            _group_id: packet.group,
            virtual_ip: packet.virtual_ip,
            active_router: if packet.state == HsrpState::Active {
                src_ip
            } else {
                None
            },
            standby_router: if packet.state == HsrpState::Standby {
                src_ip
            } else {
                None
            },
            priority: packet.priority,
            state: packet.state,
            last_hello: SystemTime::now(),
        }
    }

    /// Update group information with new packet data
    fn update_group_info(
        &self,
        existing: &mut HsrpGroupInfo,
        packet: &HsrpPacket,
        src_ip: Option<Ipv4Addr>,
    ) {
        existing.virtual_ip = packet.virtual_ip;
        existing.priority = packet.priority;
        existing.state = packet.state;
        existing.last_hello = SystemTime::now();

        match packet.state {
            HsrpState::Active => {
                existing.active_router = src_ip;
            }
            HsrpState::Standby => {
                existing.standby_router = src_ip;
            }
            _ => {}
        }
    }
}

impl Default for HsrpProtocol {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Protocol for HsrpProtocol {
    fn name(&self) -> &'static str {
        "Hot Standby Router Protocol"
    }

    fn shortname(&self) -> &'static str {
        "hsrp"
    }

    fn id(&self) -> ProtocolId {
        ProtocolId::HSRP
    }

    fn attacks(&self) -> &[AttackDescriptor] {
        static ATTACKS: [AttackDescriptor; 1] = [AttackDescriptor {
            id: AttackId(0),
            name: "Become Active Router",
            description: "Take over as the active router for an HSRP group by sending Coup message followed by periodic Hellos",
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

        stats.packets_received += 1;
        stats.bytes_received += packet.data.len() as u64;

        // Try to parse as HSRP packet
        // HSRP is UDP-based, we need to skip Ethernet (14) + IP (20 min) + UDP (8) headers
        // For simplicity, we look for the HSRP signature starting at various offsets
        let result = self.try_parse_hsrp(&packet.data);

        match result {
            Some((hsrp_packet, src_ip)) => {
                stats.packets_parsed += 1;

                // Extract source IP from packet data if available
                drop(stats); // Release stats lock before acquiring groups lock

                let mut groups = self
                    .groups
                    .try_write()
                    .map_err(|_| Error::protocol("Failed to acquire groups lock"))?;

                let group_id = hsrp_packet.group;
                if let Some(existing) = groups.get_mut(&group_id) {
                    self.update_group_info(existing, &hsrp_packet, src_ip);
                } else {
                    let group_info = self.extract_group_info(&hsrp_packet, src_ip);
                    groups.insert(group_id, group_info);
                }

                // Update stats
                drop(groups); // Release groups lock
                let mut stats = self
                    .stats
                    .try_write()
                    .map_err(|_| Error::protocol("Failed to acquire stats lock"))?;

                stats.custom.insert(
                    "hsrp_groups".to_string(),
                    self.groups.try_read().map(|g| g.len()).unwrap_or(0) as u64,
                );

                // Track state transitions
                let state_key = format!("state_{}", hsrp_packet.state.to_u8());
                *stats.custom.entry(state_key).or_insert(0) += 1;
            }
            None => {
                stats.packets_errors += 1;
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
            // Become Active Router Attack
            0 => {
                let group_id = params.get_u32("group_id").unwrap_or(0) as u16;

                let virtual_ip_str = params
                    .get_string("virtual_ip")
                    .ok_or_else(|| Error::protocol("virtual_ip parameter required"))?;

                let virtual_ip: Ipv4Addr = virtual_ip_str
                    .parse()
                    .map_err(|_| Error::protocol("Invalid virtual IP address"))?;

                let priority = params.get_u32("priority").unwrap_or(255) as u8;

                let authentication = params
                    .get_string("authentication")
                    .unwrap_or("cisco")
                    .to_string();

                let version = params.get_u32("version").unwrap_or(1);
                let hsrp_version = if version == 2 {
                    super::packet::HsrpVersion::V2
                } else {
                    super::packet::HsrpVersion::V1
                };

                let interval_ms = params.get_u32("interval_ms").unwrap_or(3000) as u64;

                // Parse virtual MAC if provided
                let virtual_mac = if let Some(mac_str) = params.get_string("virtual_mac") {
                    Some(
                        mac_str
                            .parse::<MacAddr>()
                            .map(|m| MacAddress(m.octets()))
                            .map_err(|_| Error::protocol("Invalid virtual MAC address"))?,
                    )
                } else {
                    None
                };

                let attack = HsrpActiveRouterAttack::new(
                    group_id,
                    virtual_ip,
                    priority,
                    virtual_mac,
                    authentication,
                    hsrp_version,
                    interval_ms,
                );

                // Create attack context
                let running = Arc::new(std::sync::atomic::AtomicBool::new(true));
                let paused = Arc::new(std::sync::atomic::AtomicBool::new(false));
                let stats = Arc::new(AttackStatsCounters::default());

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
                    protocol: "HSRP".to_string(),
                    attack_name: "Become Active Router".to_string(),
                    running,
                    paused,
                    stats,
                    started_at: SystemTime::now(),
                    task_handle: Some(task_handle),
                })
            }

            _ => Err(Error::protocol("Unknown attack ID")),
        }
    }

    fn stats(&self) -> ProtocolStats {
        self.stats.try_read().map(|s| s.clone()).unwrap_or_default()
    }

    fn reset_stats(&mut self) {
        if let Ok(mut stats) = self.stats.try_write() {
            *stats = ProtocolStats::default();
        }

        if let Ok(mut groups) = self.groups.try_write() {
            groups.clear();
        }
    }
}

impl HsrpProtocol {
    /// Try to parse HSRP packet from raw data at various offsets
    fn try_parse_hsrp(&self, data: &[u8]) -> Option<(HsrpPacket, Option<Ipv4Addr>)> {
        // Try to locate HSRP payload in the packet
        // HSRP is typically at: Ethernet(14) + IP(20) + UDP(8) = offset 42
        // But IP header can vary, so we check multiple offsets

        let mut src_ip = None;

        // Try to extract source IP from IP header if present
        if data.len() > 26 {
            // Check for IP header (version 4)
            if data[14] >> 4 == 4 {
                src_ip = Some(Ipv4Addr::new(data[26], data[27], data[28], data[29]));
            }
        }

        // Common offsets to try
        let offsets = [42, 34, 50];

        for &offset in &offsets {
            if data.len() > offset + 20 {
                if let Ok(hsrp_packet) = HsrpPacket::parse(&data[offset..]) {
                    return Some((hsrp_packet, src_ip));
                }
            }
        }

        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hsrp::HSRP_UDP_PORT;

    #[test]
    fn test_hsrp_protocol_creation() {
        let hsrp = HsrpProtocol::new();
        assert_eq!(hsrp.name(), "Hot Standby Router Protocol");
        assert_eq!(hsrp.shortname(), "hsrp");
        assert_eq!(hsrp.id(), ProtocolId::HSRP);
    }

    #[test]
    fn test_hsrp_protocol_attacks() {
        let hsrp = HsrpProtocol::new();
        let attacks = hsrp.attacks();

        assert_eq!(attacks.len(), 1);
        assert_eq!(attacks[0].name, "Become Active Router");
    }

    #[test]
    fn test_hsrp_protocol_stats() {
        let mut hsrp = HsrpProtocol::new();
        let stats = hsrp.stats();

        assert_eq!(stats.packets_received, 0);
        assert_eq!(stats.packets_parsed, 0);
        assert_eq!(stats.packets_errors, 0);

        hsrp.reset_stats();
        let stats = hsrp.stats();
        assert_eq!(stats.packets_received, 0);
    }

    #[test]
    fn test_extract_group_info() {
        let hsrp = HsrpProtocol::new();
        let ip = Ipv4Addr::new(192, 168, 1, 1);
        let virtual_ip = Ipv4Addr::new(192, 168, 1, 254);

        let packet = HsrpPacket::hello(10, 100, virtual_ip, HsrpState::Active, None);

        let group_info = hsrp.extract_group_info(&packet, Some(ip));

        assert_eq!(group_info._group_id, 10);
        assert_eq!(group_info.virtual_ip, virtual_ip);
        assert_eq!(group_info.active_router, Some(ip));
        assert_eq!(group_info.priority, 100);
        assert_eq!(group_info.state, HsrpState::Active);
    }

    #[test]
    fn test_update_group_info() {
        let hsrp = HsrpProtocol::new();
        let ip = Ipv4Addr::new(192, 168, 1, 2);
        let virtual_ip = Ipv4Addr::new(192, 168, 1, 254);

        let mut group_info = HsrpGroupInfo {
            _group_id: 10,
            virtual_ip,
            active_router: None,
            standby_router: None,
            priority: 100,
            state: HsrpState::Listen,
            last_hello: SystemTime::now(),
        };

        let packet = HsrpPacket::hello(10, 150, virtual_ip, HsrpState::Standby, None);

        hsrp.update_group_info(&mut group_info, &packet, Some(ip));

        assert_eq!(group_info.priority, 150);
        assert_eq!(group_info.state, HsrpState::Standby);
        assert_eq!(group_info.standby_router, Some(ip));
    }

    #[tokio::test]
    async fn test_launch_active_router_attack() {
        let hsrp = HsrpProtocol::new();
        let interface = Interface::new(
            "eth0".to_string(),
            0,
            MacAddr::new([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]),
        );

        let params = AttackParams::new()
            .set("group_id", 10u32)
            .set("virtual_ip", "192.168.1.254")
            .set("priority", 255u32)
            .set("authentication", "cisco")
            .set("version", 1u32)
            .set("interval_ms", 3000u32);

        let result = hsrp.launch_attack(AttackId(0), params, &interface).await;
        assert!(result.is_ok());

        let handle = result.unwrap();
        assert_eq!(handle.protocol, "HSRP");
        assert_eq!(handle.attack_name, "Become Active Router");

        // Stop the attack
        handle.stop();
    }

    #[tokio::test]
    async fn test_launch_attack_missing_virtual_ip() {
        let hsrp = HsrpProtocol::new();
        let interface = Interface::new(
            "eth0".to_string(),
            0,
            MacAddr::new([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]),
        );

        let params = AttackParams::new()
            .set("group_id", 10u32)
            .set("priority", 255u32);

        let result = hsrp.launch_attack(AttackId(0), params, &interface).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_launch_attack_invalid_ip() {
        let hsrp = HsrpProtocol::new();
        let interface = Interface::new(
            "eth0".to_string(),
            0,
            MacAddr::new([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]),
        );

        let params = AttackParams::new()
            .set("group_id", 10u32)
            .set("virtual_ip", "invalid")
            .set("priority", 255u32);

        let result = hsrp.launch_attack(AttackId(0), params, &interface).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_launch_attack_with_custom_mac() {
        let hsrp = HsrpProtocol::new();
        let interface = Interface::new(
            "eth0".to_string(),
            0,
            MacAddr::new([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]),
        );

        let params = AttackParams::new()
            .set("group_id", 5u32)
            .set("virtual_ip", "10.0.0.1")
            .set("priority", 200u32)
            .set("virtual_mac", "00:00:0c:07:ac:05")
            .set("authentication", "secret")
            .set("version", 1u32)
            .set("interval_ms", 5000u32);

        let result = hsrp.launch_attack(AttackId(0), params, &interface).await;
        assert!(result.is_ok());

        let handle = result.unwrap();
        handle.stop();
    }

    #[tokio::test]
    async fn test_launch_attack_unknown_id() {
        let hsrp = HsrpProtocol::new();
        let interface = Interface::new(
            "eth0".to_string(),
            0,
            MacAddr::new([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]),
        );

        let params = AttackParams::new();
        let result = hsrp.launch_attack(AttackId(99), params, &interface).await;
        assert!(result.is_err());
    }

    #[test]
    fn test_hsrp_port_constant() {
        assert_eq!(HSRP_UDP_PORT, 1985);
    }
}
