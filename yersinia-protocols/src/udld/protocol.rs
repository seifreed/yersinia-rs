//! UDLD Protocol Implementation
use async_trait::async_trait;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use std::time::SystemTime;
use tokio::sync::RwLock;
use yersinia_core::{
    protocol::{AttackParams, Protocol, ProtocolStats},
    Attack, AttackContext, AttackDescriptor, AttackHandle, AttackId, AttackStatsCounters, Error,
    Interface, Packet, Parameter, ProtocolId, Result,
};

use super::attack::{EchoManipulationAttack, NeighborImpersonationAttack, UdldSpoofingAttack};
use super::packet::UdldOpcode;

pub struct UdldProtocol {
    stats: Arc<RwLock<ProtocolStats>>,
}

impl UdldProtocol {
    pub fn new() -> Self {
        Self {
            stats: Arc::new(RwLock::new(ProtocolStats::default())),
        }
    }
}

impl Default for UdldProtocol {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Protocol for UdldProtocol {
    fn name(&self) -> &'static str {
        "Unidirectional Link Detection"
    }
    fn shortname(&self) -> &'static str {
        "udld"
    }
    fn id(&self) -> ProtocolId {
        ProtocolId::UDLD
    }

    fn attacks(&self) -> &[AttackDescriptor] {
        static ATTACKS: [AttackDescriptor; 3] = [
            AttackDescriptor {
                id: AttackId(0),
                name: "UDLD Spoofing",
                description: "Spoof UDLD packets to manipulate link state detection",
                parameters: vec![],
            },
            AttackDescriptor {
                id: AttackId(1),
                name: "Neighbor Impersonation",
                description: "Impersonate legitimate UDLD neighbors",
                parameters: vec![],
            },
            AttackDescriptor {
                id: AttackId(2),
                name: "Echo Manipulation",
                description: "Manipulate echo messages to cause false unidirectional detections",
                parameters: vec![],
            },
        ];
        &ATTACKS
    }

    fn parameters(&self) -> Vec<Box<dyn Parameter>> {
        vec![]
    }

    fn handle_packet(&mut self, _packet: &Packet) -> Result<()> {
        let mut stats = self
            .stats
            .try_write()
            .map_err(|_| Error::protocol("Lock failed"))?;
        stats.packets_received += 1;
        Ok(())
    }

    async fn launch_attack(
        &self,
        attack_id: AttackId,
        params: AttackParams,
        interface: &Interface,
    ) -> Result<AttackHandle> {
        match attack_id.0 {
            // UDLD Spoofing Attack
            0 => {
                let device_id = params
                    .get_string("device_id")
                    .unwrap_or("FakeSwitch")
                    .to_string();
                let port_id = params.get_string("port_id").unwrap_or("Gi0/1").to_string();
                let opcode = params.get_u32("opcode").unwrap_or(0);

                let opcode_type = match opcode {
                    0 => UdldOpcode::Probe,
                    1 => UdldOpcode::Echo,
                    2 => UdldOpcode::Flush,
                    _ => UdldOpcode::Probe,
                };

                let attack = UdldSpoofingAttack::new(device_id, port_id).with_opcode(opcode_type);

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
                    protocol: "UDLD".to_string(),
                    attack_name: "UDLD Spoofing".to_string(),
                    running,
                    paused,
                    stats,
                    started_at: SystemTime::now(),
                    task_handle: Some(task_handle),
                })
            }
            // Neighbor Impersonation Attack
            1 => {
                let fake_device_id = params
                    .get_string("fake_device_id")
                    .unwrap_or("FakeDevice")
                    .to_string();
                let fake_port_id = params
                    .get_string("fake_port_id")
                    .unwrap_or("Gi0/1")
                    .to_string();
                let target_device = params
                    .get_string("target_device")
                    .unwrap_or("TargetDevice")
                    .to_string();
                let target_port = params
                    .get_string("target_port")
                    .unwrap_or("Gi0/2")
                    .to_string();

                let attack = NeighborImpersonationAttack::new(
                    fake_device_id,
                    fake_port_id,
                    target_device,
                    target_port,
                );

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
                    protocol: "UDLD".to_string(),
                    attack_name: "Neighbor Impersonation".to_string(),
                    running,
                    paused,
                    stats,
                    started_at: SystemTime::now(),
                    task_handle: Some(task_handle),
                })
            }
            // Echo Manipulation Attack
            2 => {
                let device_id = params
                    .get_string("device_id")
                    .unwrap_or("Device")
                    .to_string();
                let port_id = params.get_string("port_id").unwrap_or("Port").to_string();

                let mut attack = EchoManipulationAttack::new(device_id, port_id);

                // Add fake neighbor if specified
                if let (Some(neighbor_device), Some(neighbor_port)) = (
                    params.get_string("neighbor_device"),
                    params.get_string("neighbor_port"),
                ) {
                    attack = attack
                        .with_fake_neighbor(neighbor_device.to_string(), neighbor_port.to_string());
                }

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
                    protocol: "UDLD".to_string(),
                    attack_name: "Echo Manipulation".to_string(),
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
    }
}
