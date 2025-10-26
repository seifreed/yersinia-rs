//! CDP Protocol Implementation
//!
//! Implements the Protocol trait for Cisco Discovery Protocol with full support
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

use super::attack::{
    CdpFloodingAttack, CdpNativeVlanMismatchAttack, CdpPoeManipulationAttack, CdpSpoofingAttack,
    CdpVoiceVlanHijackingAttack,
};
use super::packet::{CdpCapabilities, CdpPacket};

/// CDP Protocol Implementation
pub struct CdpProtocol {
    stats: Arc<RwLock<ProtocolStats>>,
    discovered_devices: Arc<RwLock<HashMap<String, CdpDeviceInfo>>>,
}

/// Information about a discovered CDP device
#[derive(Debug, Clone)]
struct CdpDeviceInfo {
    device_id: String,
    _ip_address: Option<Ipv4Addr>,
    _platform: Option<String>,
    _port_id: Option<String>,
    _capabilities: Option<u32>,
    _last_seen: SystemTime,
}

impl CdpProtocol {
    pub fn new() -> Self {
        Self {
            stats: Arc::new(RwLock::new(ProtocolStats::default())),
            discovered_devices: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Parse a CDP packet and extract device information
    fn extract_device_info(&self, packet: &CdpPacket) -> Option<CdpDeviceInfo> {
        let mut device_id = None;
        let mut ip_address = None;
        let mut platform = None;
        let mut port_id = None;
        let mut capabilities = None;

        for tlv in &packet.tlvs {
            match tlv {
                super::packet::CdpTlv::DeviceId(id) => device_id = Some(id.clone()),
                super::packet::CdpTlv::Addresses(addrs) if !addrs.is_empty() => {
                    ip_address = Some(addrs[0])
                }
                super::packet::CdpTlv::Platform(p) => platform = Some(p.clone()),
                super::packet::CdpTlv::PortId(p) => port_id = Some(p.clone()),
                super::packet::CdpTlv::Capabilities(caps) => capabilities = Some(caps.bits()),
                super::packet::CdpTlv::ManagementAddress(addr) => ip_address = Some(*addr),
                _ => {}
            }
        }

        device_id.map(|id| CdpDeviceInfo {
            device_id: id,
            _ip_address: ip_address,
            _platform: platform,
            _port_id: port_id,
            _capabilities: capabilities,
            _last_seen: SystemTime::now(),
        })
    }
}

impl Default for CdpProtocol {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Protocol for CdpProtocol {
    fn name(&self) -> &'static str {
        "Cisco Discovery Protocol"
    }

    fn shortname(&self) -> &'static str {
        "cdp"
    }

    fn id(&self) -> ProtocolId {
        ProtocolId::CDP
    }

    fn attacks(&self) -> &[AttackDescriptor] {
        static ATTACKS: [AttackDescriptor; 5] = [
            AttackDescriptor {
                id: AttackId(0),
                name: "CDP Flooding",
                description: "Flood the network with CDP packets to exhaust CAM table",
                parameters: vec![],
            },
            AttackDescriptor {
                id: AttackId(1),
                name: "CDP Spoofing/Virtual Device",
                description: "Impersonate a Cisco device on the network",
                parameters: vec![],
            },
            AttackDescriptor {
                id: AttackId(2),
                name: "CDP PoE Manipulation",
                description: "Manipulate Power over Ethernet allocation and priorities",
                parameters: vec![],
            },
            AttackDescriptor {
                id: AttackId(3),
                name: "CDP Native VLAN Mismatch",
                description: "Exploit native VLAN mismatch for VLAN hopping",
                parameters: vec![],
            },
            AttackDescriptor {
                id: AttackId(4),
                name: "CDP Voice VLAN Hijacking",
                description: "Gain access to voice VLAN by spoofing as VoIP phone",
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

        // Try to parse as CDP packet
        // Skip Ethernet (14 bytes) + LLC/SNAP (8 bytes) headers
        if packet.data.len() > 22 {
            let cdp_data = &packet.data[22..];
            match CdpPacket::parse(cdp_data) {
                Ok(cdp_packet) => {
                    stats.packets_parsed += 1;

                    // Extract device information
                    if let Some(device_info) = self.extract_device_info(&cdp_packet) {
                        drop(stats); // Release stats lock before acquiring devices lock

                        let mut devices = self
                            .discovered_devices
                            .try_write()
                            .map_err(|_| Error::protocol("Failed to acquire devices lock"))?;

                        devices.insert(device_info.device_id.clone(), device_info);

                        // Re-acquire stats lock to update custom stats
                        let mut stats = self
                            .stats
                            .try_write()
                            .map_err(|_| Error::protocol("Failed to acquire stats lock"))?;

                        stats
                            .custom
                            .insert("discovered_devices".to_string(), devices.len() as u64);
                    }
                }
                Err(_) => {
                    stats.packets_errors += 1;
                }
            }
        } else {
            stats.packets_errors += 1;
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
            // CDP Flooding Attack
            0 => {
                let device_id_prefix = params
                    .get_string("device_id_prefix")
                    .unwrap_or("yersinia")
                    .to_string();

                let interval_ms = params.get_u32("interval_ms").unwrap_or(100) as u64;

                let count = params.get_u32("count").map(|c| c as u64);

                let randomize_mac = params.get_bool("randomize_mac").unwrap_or(true);

                let attack =
                    CdpFloodingAttack::new(device_id_prefix, interval_ms, count, randomize_mac);

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
                    protocol: "CDP".to_string(),
                    attack_name: "Flooding".to_string(),
                    running,
                    paused,
                    stats,
                    started_at: SystemTime::now(),
                    task_handle: Some(task_handle),
                })
            }

            // CDP Spoofing/Virtual Device Attack
            1 => {
                let device_id = params
                    .get_string("device_id")
                    .ok_or_else(|| Error::protocol("device_id parameter required"))?
                    .to_string();

                let platform = params
                    .get_string("platform")
                    .unwrap_or("cisco WS-C2960-24TT-L")
                    .to_string();

                let software_version = params
                    .get_string("software_version")
                    .unwrap_or("12.2(55)SE")
                    .to_string();

                let capabilities_bits = params.get_u32("capabilities").unwrap_or(0x08); // Switch by default
                let capabilities = CdpCapabilities::from_bits(capabilities_bits);

                let port_id = params
                    .get_string("port_id")
                    .unwrap_or("FastEthernet0/1")
                    .to_string();

                let ip_str = params
                    .get_string("ip_address")
                    .ok_or_else(|| Error::protocol("ip_address parameter required"))?;

                let ip_address: Ipv4Addr = ip_str
                    .parse()
                    .map_err(|_| Error::protocol("Invalid IP address"))?;

                let vlan = params.get_u32("vlan").map(|v| v as u16);

                let vtp_domain = params.get_string("vtp_domain").map(|s| s.to_string());

                let interval_ms = params.get_u32("interval_ms").unwrap_or(60000) as u64;

                // Parse source MAC if provided
                let src_mac = if let Some(mac_str) = params.get_string("src_mac") {
                    Some(
                        mac_str
                            .parse::<MacAddr>()
                            .map(|m| MacAddress(m.octets()))
                            .map_err(|_| Error::protocol("Invalid MAC address"))?,
                    )
                } else {
                    None
                };

                let attack = CdpSpoofingAttack::new(
                    device_id,
                    platform,
                    software_version,
                    capabilities,
                    port_id,
                    ip_address,
                    vlan,
                    vtp_domain,
                    interval_ms,
                    src_mac,
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
                    protocol: "CDP".to_string(),
                    attack_name: "Spoofing".to_string(),
                    running,
                    paused,
                    stats,
                    started_at: SystemTime::now(),
                    task_handle: Some(task_handle),
                })
            }

            // CDP PoE Manipulation Attack
            2 => {
                let device_id = params
                    .get_string("device_id")
                    .unwrap_or("yersinia-poe")
                    .to_string();

                let power_request_mw = params.get_u32("power_mw").unwrap_or(15400);

                let attack = CdpPoeManipulationAttack::new(device_id, power_request_mw);

                let running = Arc::new(std::sync::atomic::AtomicBool::new(true));
                let paused = Arc::new(std::sync::atomic::AtomicBool::new(false));
                let stats = Arc::new(AttackStatsCounters::default());

                let ctx = yersinia_core::AttackContext {
                    interface: interface.clone(),
                    running: running.clone(),
                    paused: paused.clone(),
                    stats: stats.clone(),
                };

                let task_handle = tokio::spawn(async move { attack.execute(ctx).await });

                Ok(AttackHandle {
                    id: uuid::Uuid::now_v7(),
                    protocol: "CDP".to_string(),
                    attack_name: "PoE Manipulation".to_string(),
                    running,
                    paused,
                    stats,
                    started_at: SystemTime::now(),
                    task_handle: Some(task_handle),
                })
            }

            // CDP Native VLAN Mismatch Attack
            3 => {
                let device_id = params
                    .get_string("device_id")
                    .unwrap_or("yersinia-vlan")
                    .to_string();

                let advertised_native_vlan = params.get_u32("advertised_vlan").unwrap_or(1) as u16;

                let attack = CdpNativeVlanMismatchAttack::new(device_id, advertised_native_vlan);

                let running = Arc::new(std::sync::atomic::AtomicBool::new(true));
                let paused = Arc::new(std::sync::atomic::AtomicBool::new(false));
                let stats = Arc::new(AttackStatsCounters::default());

                let ctx = yersinia_core::AttackContext {
                    interface: interface.clone(),
                    running: running.clone(),
                    paused: paused.clone(),
                    stats: stats.clone(),
                };

                let task_handle = tokio::spawn(async move { attack.execute(ctx).await });

                Ok(AttackHandle {
                    id: uuid::Uuid::now_v7(),
                    protocol: "CDP".to_string(),
                    attack_name: "Native VLAN Mismatch".to_string(),
                    running,
                    paused,
                    stats,
                    started_at: SystemTime::now(),
                    task_handle: Some(task_handle),
                })
            }

            // CDP Voice VLAN Hijacking Attack
            4 => {
                let device_id = params
                    .get_string("device_id")
                    .unwrap_or("Cisco IP Phone")
                    .to_string();

                let voice_vlan = params.get_u32("voice_vlan").unwrap_or(100) as u16;

                let attack = CdpVoiceVlanHijackingAttack::new(device_id, voice_vlan);

                let running = Arc::new(std::sync::atomic::AtomicBool::new(true));
                let paused = Arc::new(std::sync::atomic::AtomicBool::new(false));
                let stats = Arc::new(AttackStatsCounters::default());

                let ctx = yersinia_core::AttackContext {
                    interface: interface.clone(),
                    running: running.clone(),
                    paused: paused.clone(),
                    stats: stats.clone(),
                };

                let task_handle = tokio::spawn(async move { attack.execute(ctx).await });

                Ok(AttackHandle {
                    id: uuid::Uuid::now_v7(),
                    protocol: "CDP".to_string(),
                    attack_name: "Voice VLAN Hijacking".to_string(),
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

        if let Ok(mut devices) = self.discovered_devices.try_write() {
            devices.clear();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cdp_protocol_creation() {
        let cdp = CdpProtocol::new();
        assert_eq!(cdp.name(), "Cisco Discovery Protocol");
        assert_eq!(cdp.shortname(), "cdp");
        assert_eq!(cdp.id(), ProtocolId::CDP);
    }

    #[test]
    fn test_cdp_protocol_attacks() {
        let cdp = CdpProtocol::new();
        let attacks = cdp.attacks();

        assert_eq!(attacks.len(), 5);
        assert_eq!(attacks[0].name, "CDP Flooding");
        assert_eq!(attacks[1].name, "CDP Spoofing/Virtual Device");
    }

    #[test]
    fn test_cdp_protocol_stats() {
        let mut cdp = CdpProtocol::new();
        let stats = cdp.stats();

        assert_eq!(stats.packets_received, 0);
        assert_eq!(stats.packets_parsed, 0);
        assert_eq!(stats.packets_errors, 0);

        cdp.reset_stats();
        let stats = cdp.stats();
        assert_eq!(stats.packets_received, 0);
    }

    #[tokio::test]
    async fn test_launch_flooding_attack() {
        let cdp = CdpProtocol::new();
        let interface = Interface::new(
            "eth0".to_string(),
            0,
            MacAddr::new([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]),
        );

        let params = AttackParams::new()
            .set("device_id_prefix", "TestDevice")
            .set("interval_ms", 1000u32)
            .set("count", 5u32)
            .set("randomize_mac", true);

        let result = cdp.launch_attack(AttackId(0), params, &interface).await;
        assert!(result.is_ok());

        let handle = result.unwrap();
        assert_eq!(handle.protocol, "CDP");
        assert_eq!(handle.attack_name, "Flooding");

        // Stop the attack
        handle.stop();
    }

    #[tokio::test]
    async fn test_launch_spoofing_attack() {
        let cdp = CdpProtocol::new();
        let interface = Interface::new(
            "eth0".to_string(),
            0,
            MacAddr::new([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]),
        );

        let params = AttackParams::new()
            .set("device_id", "Router1")
            .set("ip_address", "192.168.1.1")
            .set("platform", "Cisco 2960")
            .set("software_version", "12.2(55)SE")
            .set("port_id", "GigabitEthernet0/1")
            .set("capabilities", 0x08u32)
            .set("interval_ms", 60000u32);

        let result = cdp.launch_attack(AttackId(1), params, &interface).await;
        assert!(result.is_ok());

        let handle = result.unwrap();
        assert_eq!(handle.protocol, "CDP");
        assert_eq!(handle.attack_name, "Spoofing");

        // Stop the attack
        handle.stop();
    }

    #[test]
    fn test_extract_device_info() {
        let cdp = CdpProtocol::new();

        let packet = CdpPacket::new()
            .add_tlv(super::super::packet::CdpTlv::DeviceId(
                "Router1".to_string(),
            ))
            .add_tlv(super::super::packet::CdpTlv::Platform(
                "Cisco 2960".to_string(),
            ))
            .add_tlv(super::super::packet::CdpTlv::Addresses(vec![
                Ipv4Addr::new(192, 168, 1, 1),
            ]));

        let device_info = cdp.extract_device_info(&packet);
        assert!(device_info.is_some());

        let info = device_info.unwrap();
        assert_eq!(info.device_id, "Router1");
        assert_eq!(info._platform, Some("Cisco 2960".to_string()));
        assert_eq!(info._ip_address, Some(Ipv4Addr::new(192, 168, 1, 1)));
    }
}
