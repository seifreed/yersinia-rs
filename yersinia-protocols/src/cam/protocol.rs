//! CAM Table Exhaustion Protocol Implementation
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
    CamTableOverflowAttack, MacFloodingAttack, PersistentMacPoisoningAttack,
    SelectiveMacExhaustionAttack,
};

pub struct CamProtocol {
    stats: Arc<RwLock<ProtocolStats>>,
}

impl CamProtocol {
    pub fn new() -> Self {
        Self {
            stats: Arc::new(RwLock::new(ProtocolStats::default())),
        }
    }
}

impl Default for CamProtocol {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Protocol for CamProtocol {
    fn name(&self) -> &'static str {
        "MAC/CAM Table Exhaustion"
    }
    fn shortname(&self) -> &'static str {
        "cam"
    }
    fn id(&self) -> ProtocolId {
        ProtocolId::CAM
    }

    fn attacks(&self) -> &[AttackDescriptor] {
        static ATTACKS: [AttackDescriptor; 4] = [
            AttackDescriptor {
                id: AttackId(0),
                name: "MAC Flooding",
                description: "Flood switch with packets from many different source MACs",
                parameters: vec![],
            },
            AttackDescriptor {
                id: AttackId(1),
                name: "CAM Table Overflow",
                description: "Overflow the CAM table to force switch into fail-open mode",
                parameters: vec![],
            },
            AttackDescriptor {
                id: AttackId(2),
                name: "Selective MAC Exhaustion",
                description: "Target specific VLANs with MAC exhaustion",
                parameters: vec![],
            },
            AttackDescriptor {
                id: AttackId(3),
                name: "Persistent MAC Poisoning",
                description: "Keep CAM table full by continuously refreshing entries",
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
                let attack = MacFloodingAttack::new(10000);
                let name = attack.name().to_string();
                let handle = tokio::spawn(async move { attack.execute(ctx).await });
                (name, handle)
            }
            1 => {
                let attack = CamTableOverflowAttack::new(8192);
                let name = attack.name().to_string();
                let handle = tokio::spawn(async move { attack.execute(ctx).await });
                (name, handle)
            }
            2 => {
                let attack = SelectiveMacExhaustionAttack::new(vec![1, 10, 20]);
                let name = attack.name().to_string();
                let handle = tokio::spawn(async move { attack.execute(ctx).await });
                (name, handle)
            }
            3 => {
                let attack = PersistentMacPoisoningAttack::new(5000);
                let name = attack.name().to_string();
                let handle = tokio::spawn(async move { attack.execute(ctx).await });
                (name, handle)
            }
            _ => return Err(Error::protocol("Invalid attack ID")),
        };

        Ok(AttackHandle {
            id: uuid::Uuid::now_v7(),
            protocol: "CAM".to_string(),
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
