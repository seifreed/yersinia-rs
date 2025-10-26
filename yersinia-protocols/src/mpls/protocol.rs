//! MPLS Protocol Implementation
//!
//! Implements the Protocol trait for MPLS with statistics tracking and attack support.

use async_trait::async_trait;
use std::collections::HashMap;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use std::time::SystemTime;
use tokio::sync::RwLock;
use yersinia_core::{
    protocol::{AttackParams, Protocol, ProtocolStats},
    Attack, AttackContext, AttackDescriptor, AttackHandle, AttackId, AttackStatsCounters, Error,
    Interface, Packet, Parameter, ProtocolId, Result,
};

use super::packet::MplsPacket;

/// MPLS Protocol statistics
#[derive(Debug, Clone, Default)]
pub struct MplsStats {
    pub packets_received: u64,
    pub packets_parsed: u64,
    pub parse_errors: u64,
    pub bytes_received: u64,
    pub single_label_packets: u64,
    pub stacked_label_packets: u64,
    /// Track unique labels seen
    pub unique_labels: HashMap<u32, u64>,
}

impl MplsStats {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn record_packet(&mut self, packet: &MplsPacket, bytes: usize) {
        self.packets_received += 1;
        self.packets_parsed += 1;
        self.bytes_received += bytes as u64;

        if packet.is_label_stacked() {
            self.stacked_label_packets += 1;
        } else {
            self.single_label_packets += 1;
        }

        // Track label usage
        *self.unique_labels.entry(packet.label1.label).or_insert(0) += 1;
        if let Some(ref label2) = packet.label2 {
            *self.unique_labels.entry(label2.label).or_insert(0) += 1;
        }
    }

    pub fn record_parse_error(&mut self) {
        self.packets_received += 1;
        self.parse_errors += 1;
    }
}

/// MPLS Protocol Implementation
pub struct MplsProtocol {
    stats: Arc<RwLock<MplsStats>>,
}

impl MplsProtocol {
    pub fn new() -> Self {
        Self {
            stats: Arc::new(RwLock::new(MplsStats::new())),
        }
    }

    /// Get protocol statistics
    pub async fn get_stats(&self) -> MplsStats {
        self.stats.read().await.clone()
    }

    /// Clear all statistics
    pub async fn clear_stats(&self) {
        *self.stats.write().await = MplsStats::new();
    }

    /// Get number of unique labels seen
    pub async fn unique_label_count(&self) -> usize {
        self.stats.read().await.unique_labels.len()
    }
}

impl Default for MplsProtocol {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Protocol for MplsProtocol {
    fn name(&self) -> &'static str {
        "Multiprotocol Label Switching"
    }

    fn shortname(&self) -> &'static str {
        "mpls"
    }

    fn id(&self) -> ProtocolId {
        ProtocolId::MPLS
    }

    fn attacks(&self) -> &[AttackDescriptor] {
        static ATTACKS: [AttackDescriptor; 6] = [
            AttackDescriptor {
                id: AttackId(0),
                name: "Send TCP MPLS packet",
                description: "Send MPLS-encapsulated TCP packet with single label",
                parameters: vec![],
            },
            AttackDescriptor {
                id: AttackId(1),
                name: "Send TCP MPLS with double header",
                description: "Send MPLS-encapsulated TCP packet with label stacking (2 labels)",
                parameters: vec![],
            },
            AttackDescriptor {
                id: AttackId(2),
                name: "Send UDP MPLS packet",
                description: "Send MPLS-encapsulated UDP packet with single label",
                parameters: vec![],
            },
            AttackDescriptor {
                id: AttackId(3),
                name: "Send UDP MPLS with double header",
                description: "Send MPLS-encapsulated UDP packet with label stacking (2 labels)",
                parameters: vec![],
            },
            AttackDescriptor {
                id: AttackId(4),
                name: "Send ICMP MPLS packet",
                description: "Send MPLS-encapsulated ICMP packet with single label",
                parameters: vec![],
            },
            AttackDescriptor {
                id: AttackId(5),
                name: "Send ICMP MPLS with double header",
                description: "Send MPLS-encapsulated ICMP packet with label stacking (2 labels)",
                parameters: vec![],
            },
        ];

        &ATTACKS
    }

    fn parameters(&self) -> Vec<Box<dyn Parameter>> {
        vec![]
    }

    fn handle_packet(&mut self, packet: &Packet) -> Result<()> {
        // MPLS packets start after Ethernet header (14 bytes)
        if packet.data.len() < 18 {
            // Ethernet(14) + MPLS(4) minimum
            if let Ok(mut stats) = self.stats.try_write() {
                stats.record_parse_error();
            }
            return Ok(());
        }

        let mpls_data = &packet.data[14..];

        match MplsPacket::parse(mpls_data) {
            Ok(mpls_packet) => {
                if let Ok(mut stats) = self.stats.try_write() {
                    stats.record_packet(&mpls_packet, packet.data.len());
                }
            }
            Err(_) => {
                if let Ok(mut stats) = self.stats.try_write() {
                    stats.record_parse_error();
                }
            }
        }

        Ok(())
    }

    async fn launch_attack(
        &self,
        attack_id: AttackId,
        _params: AttackParams,
        interface: &Interface,
    ) -> Result<AttackHandle> {
        use super::attack::{MplsPayloadType, MplsSendAttack};

        // Determine attack type and payload based on attack_id
        let (payload_type, use_double) = match attack_id.0 {
            0 => (MplsPayloadType::Tcp, false),  // TCP single
            1 => (MplsPayloadType::Tcp, true),   // TCP double
            2 => (MplsPayloadType::Udp, false),  // UDP single
            3 => (MplsPayloadType::Udp, true),   // UDP double
            4 => (MplsPayloadType::Icmp, false), // ICMP single
            5 => (MplsPayloadType::Icmp, true),  // ICMP double
            _ => return Err(Error::InvalidAttackId(attack_id.0)),
        };

        // Create attack structure
        let attack = if use_double {
            MplsSendAttack::new_double(
                payload_type,
                100, // label1
                3,   // exp1
                64,  // ttl1
                200, // label2
                3,   // exp2
                32,  // ttl2
            )
        } else {
            MplsSendAttack::new_single(payload_type, 100, 3, 64)
        };

        let attack_name = attack.name().to_string();

        let running = Arc::new(AtomicBool::new(true));
        let paused = Arc::new(AtomicBool::new(false));
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
            protocol: "MPLS".to_string(),
            attack_name,
            running,
            paused,
            stats,
            started_at: SystemTime::now(),
            task_handle: Some(task_handle),
        })
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

            // Add MPLS-specific stats to custom map
            proto_stats.custom.insert(
                "single_label_packets".to_string(),
                stats.single_label_packets,
            );
            proto_stats.custom.insert(
                "stacked_label_packets".to_string(),
                stats.stacked_label_packets,
            );
            proto_stats.custom.insert(
                "unique_labels".to_string(),
                stats.unique_labels.len() as u64,
            );

            proto_stats
        } else {
            ProtocolStats::default()
        }
    }

    fn reset_stats(&mut self) {
        if let Ok(mut stats) = self.stats.try_write() {
            *stats = MplsStats::new();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mpls_protocol_creation() {
        let protocol = MplsProtocol::new();
        assert_eq!(protocol.name(), "Multiprotocol Label Switching");
        assert_eq!(protocol.shortname(), "mpls");
    }

    #[test]
    fn test_mpls_protocol_attacks() {
        let protocol = MplsProtocol::new();
        let attacks = protocol.attacks();
        assert_eq!(attacks.len(), 6);
        assert_eq!(attacks[0].name, "Send TCP MPLS packet");
        assert_eq!(attacks[1].name, "Send TCP MPLS with double header");
        assert_eq!(attacks[2].name, "Send UDP MPLS packet");
        assert_eq!(attacks[3].name, "Send UDP MPLS with double header");
        assert_eq!(attacks[4].name, "Send ICMP MPLS packet");
        assert_eq!(attacks[5].name, "Send ICMP MPLS with double header");
    }

    #[test]
    fn test_mpls_stats_initialization() {
        let stats = MplsStats::new();
        assert_eq!(stats.packets_received, 0);
        assert_eq!(stats.packets_parsed, 0);
        assert_eq!(stats.parse_errors, 0);
        assert_eq!(stats.single_label_packets, 0);
        assert_eq!(stats.stacked_label_packets, 0);
    }

    #[tokio::test]
    async fn test_mpls_protocol_stats() {
        let protocol = MplsProtocol::new();
        let stats = protocol.get_stats().await;
        assert_eq!(stats.packets_received, 0);
    }

    #[tokio::test]
    async fn test_mpls_protocol_clear_stats() {
        let protocol = MplsProtocol::new();
        {
            let mut stats = protocol.stats.write().await;
            stats.packets_received = 100;
        }
        protocol.clear_stats().await;
        let stats = protocol.get_stats().await;
        assert_eq!(stats.packets_received, 0);
    }
}
