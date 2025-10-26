//! BFD Protocol Implementation

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

use super::attack::{BfdFastFailureAttack, BfdKeepaliveManipulationAttack, BfdSessionHijackAttack};

pub struct BfdProtocol {
    stats: Arc<RwLock<ProtocolStats>>,
}

impl BfdProtocol {
    pub fn new() -> Self {
        Self {
            stats: Arc::new(RwLock::new(ProtocolStats::default())),
        }
    }
}

impl Default for BfdProtocol {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Protocol for BfdProtocol {
    fn name(&self) -> &'static str {
        "Bidirectional Forwarding Detection"
    }

    fn shortname(&self) -> &'static str {
        "bfd"
    }

    fn id(&self) -> ProtocolId {
        ProtocolId::BFD
    }

    fn attacks(&self) -> &[AttackDescriptor] {
        static ATTACKS: [AttackDescriptor; 3] = [
            AttackDescriptor {
                id: AttackId(0),
                name: "BFD Session Hijacking",
                description: "Hijack BFD sessions to cause false failovers",
                parameters: vec![],
            },
            AttackDescriptor {
                id: AttackId(1),
                name: "BFD Fast Failure Injection",
                description: "Inject failure notifications to trigger fast failover",
                parameters: vec![],
            },
            AttackDescriptor {
                id: AttackId(2),
                name: "BFD Keepalive Manipulation",
                description: "Manipulate keepalive intervals to cause instability",
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
            .map_err(|_| Error::protocol("Failed to acquire stats lock"))?;
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
            0 => {
                let my_disc = params.get_u32("my_discriminator").unwrap_or(0x12345678);
                let your_disc = params.get_u32("your_discriminator").unwrap_or(0x87654321);

                let attack = BfdSessionHijackAttack::new(my_disc, your_disc);

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
                    protocol: "BFD".to_string(),
                    attack_name: "Session Hijacking".to_string(),
                    running,
                    paused,
                    stats,
                    started_at: SystemTime::now(),
                    task_handle: Some(task_handle),
                })
            }
            1 => {
                let my_disc = params.get_u32("my_discriminator").unwrap_or(0x12345678);
                let your_disc = params.get_u32("your_discriminator").unwrap_or(0x87654321);

                let attack = BfdFastFailureAttack::new(my_disc, your_disc);

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
                    protocol: "BFD".to_string(),
                    attack_name: "Fast Failure".to_string(),
                    running,
                    paused,
                    stats,
                    started_at: SystemTime::now(),
                    task_handle: Some(task_handle),
                })
            }
            2 => {
                let my_disc = params.get_u32("my_discriminator").unwrap_or(0x12345678);
                let your_disc = params.get_u32("your_discriminator").unwrap_or(0x87654321);

                let attack = BfdKeepaliveManipulationAttack::new(my_disc, your_disc);

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
                    protocol: "BFD".to_string(),
                    attack_name: "Keepalive Manipulation".to_string(),
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
