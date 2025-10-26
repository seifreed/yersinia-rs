//! GVRP/MVRP Protocol Implementation
use async_trait::async_trait;
use std::sync::Arc;
use std::time::SystemTime;
use tokio::sync::RwLock;
use yersinia_core::{
    protocol::{AttackParams, Protocol, ProtocolStats},
    Attack, AttackContext, AttackDescriptor, AttackHandle, AttackId, AttackStatsCounters, Error,
    Interface, Packet, Parameter, ProtocolId, Result,
};

use super::attack::{GarpPoisoningAttack, VlanDeregistrationAttack, VlanFloodingAttack};

pub struct GvrpProtocol {
    stats: Arc<RwLock<ProtocolStats>>,
}

impl GvrpProtocol {
    pub fn new() -> Self {
        Self {
            stats: Arc::new(RwLock::new(ProtocolStats::default())),
        }
    }
}

impl Default for GvrpProtocol {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Protocol for GvrpProtocol {
    fn name(&self) -> &'static str {
        "GVRP/MVRP Dynamic VLAN Registration"
    }
    fn shortname(&self) -> &'static str {
        "gvrp"
    }
    fn id(&self) -> ProtocolId {
        ProtocolId::GVRP
    }

    fn attacks(&self) -> &[AttackDescriptor] {
        static ATTACKS: [AttackDescriptor; 3] = [
            AttackDescriptor {
                id: AttackId(0),
                name: "VLAN Flooding",
                description: "Register all possible VLANs (1-4094) to exhaust VLAN tables",
                parameters: vec![],
            },
            AttackDescriptor {
                id: AttackId(1),
                name: "VLAN Deregistration",
                description: "Deregister legitimate VLANs to cause connectivity loss",
                parameters: vec![],
            },
            AttackDescriptor {
                id: AttackId(2),
                name: "GARP Poisoning",
                description: "Corrupt GVRP state machines with conflicting messages",
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
                let attack = VlanFloodingAttack::new(1, 100);
                let name = attack.name().to_string();
                let handle = tokio::spawn(async move { attack.execute(ctx).await });
                (name, handle)
            }
            1 => {
                let attack = VlanDeregistrationAttack::new(vec![10, 20, 30]);
                let name = attack.name().to_string();
                let handle = tokio::spawn(async move { attack.execute(ctx).await });
                (name, handle)
            }
            2 => {
                let attack = GarpPoisoningAttack::new(100);
                let name = attack.name().to_string();
                let handle = tokio::spawn(async move { attack.execute(ctx).await });
                (name, handle)
            }
            _ => return Err(Error::protocol("Invalid attack ID")),
        };

        Ok(AttackHandle {
            id: uuid::Uuid::now_v7(),
            protocol: "GVRP".to_string(),
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
