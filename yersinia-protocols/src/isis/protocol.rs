//! IS-IS Protocol Implementation

use async_trait::async_trait;
use std::sync::Arc;
use std::time::SystemTime;
use tokio::sync::RwLock;
use yersinia_core::{
    protocol::{AttackParams, Protocol, ProtocolStats},
    Attack, AttackContext, AttackDescriptor, AttackHandle, AttackId, AttackStatsCounters, Error,
    Interface, Packet, Parameter, ProtocolId, Result,
};

use super::attack::{
    IsisDisElectionAttack, IsisLspFloodingAttack, IsisPseudonodeManipulationAttack,
};

pub struct IsisProtocol {
    stats: Arc<RwLock<ProtocolStats>>,
}

impl IsisProtocol {
    pub fn new() -> Self {
        Self {
            stats: Arc::new(RwLock::new(ProtocolStats::default())),
        }
    }
}

impl Default for IsisProtocol {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Protocol for IsisProtocol {
    fn name(&self) -> &'static str {
        "Intermediate System to Intermediate System"
    }

    fn shortname(&self) -> &'static str {
        "isis"
    }

    fn id(&self) -> ProtocolId {
        ProtocolId::ISIS
    }

    fn attacks(&self) -> &[AttackDescriptor] {
        static ATTACKS: [AttackDescriptor; 3] = [
            AttackDescriptor {
                id: AttackId(0),
                name: "IS-IS LSP Flooding",
                description: "Flood network with Link State PDUs",
                parameters: vec![],
            },
            AttackDescriptor {
                id: AttackId(1),
                name: "IS-IS Pseudonode Manipulation",
                description: "Manipulate pseudonode LSPs to alter topology",
                parameters: vec![],
            },
            AttackDescriptor {
                id: AttackId(2),
                name: "IS-IS DIS Election Hijacking",
                description: "Hijack Designated Intermediate System election",
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
        _params: AttackParams,
        interface: &Interface,
    ) -> Result<AttackHandle> {
        let running = Arc::new(std::sync::atomic::AtomicBool::new(true));
        let paused = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let stats = Arc::new(AttackStatsCounters::default());

        let ctx = AttackContext {
            interface: interface.clone(),
            running: Arc::clone(&running),
            paused: Arc::clone(&paused),
            stats: Arc::clone(&stats),
        };

        let (attack_name, task_handle) = match attack_id.0 {
            0 => {
                let attack = IsisLspFloodingAttack::new(1, [0x49, 0x00, 0x01, 0x00, 0x00, 0x01]);
                let name = attack.name().to_string();
                let handle = tokio::spawn(async move { attack.execute(ctx).await });
                (name, handle)
            }
            1 => {
                let attack =
                    IsisPseudonodeManipulationAttack::new(1, [0x49, 0x00, 0x01, 0x00, 0x00, 0x02]);
                let name = attack.name().to_string();
                let handle = tokio::spawn(async move { attack.execute(ctx).await });
                (name, handle)
            }
            2 => {
                let attack = IsisDisElectionAttack::new(1, [0x49, 0x00, 0x01, 0x00, 0x00, 0x03]);
                let name = attack.name().to_string();
                let handle = tokio::spawn(async move { attack.execute(ctx).await });
                (name, handle)
            }
            _ => return Err(Error::protocol("Invalid attack ID")),
        };

        Ok(AttackHandle {
            id: uuid::Uuid::now_v7(),
            protocol: "IS-IS".to_string(),
            attack_name,
            running,
            paused,
            stats,
            started_at: SystemTime::now(),
            task_handle: Some(task_handle),
        })
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
