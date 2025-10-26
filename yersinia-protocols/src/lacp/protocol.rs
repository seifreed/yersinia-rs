//! LACP Protocol
use async_trait::async_trait;
use std::sync::Arc;
use std::time::SystemTime;
use tokio::sync::RwLock;
use yersinia_core::{
    protocol::{AttackParams, Protocol, ProtocolStats},
    Attack, AttackContext, AttackDescriptor, AttackHandle, AttackId, AttackStatsCounters, Error,
    Interface, Packet, Parameter, ProtocolId, Result,
};

use super::attack::{LacpDosAttack, LacpHijackAttack};

pub struct LacpProtocol {
    stats: Arc<RwLock<ProtocolStats>>,
}
impl LacpProtocol {
    pub fn new() -> Self {
        Self {
            stats: Arc::new(RwLock::new(ProtocolStats::default())),
        }
    }
}
impl Default for LacpProtocol {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Protocol for LacpProtocol {
    fn name(&self) -> &'static str {
        "Link Aggregation Control Protocol"
    }
    fn shortname(&self) -> &'static str {
        "lacp"
    }
    fn id(&self) -> ProtocolId {
        ProtocolId::LACP
    }
    fn attacks(&self) -> &[AttackDescriptor] {
        static ATTACKS: [AttackDescriptor; 2] = [
            AttackDescriptor {
                id: AttackId(0),
                name: "LACP Partner Hijacking",
                description: "Hijack LACP partner",
                parameters: vec![],
            },
            AttackDescriptor {
                id: AttackId(1),
                name: "LACP DoS",
                description: "DoS LACP aggregation",
                parameters: vec![],
            },
        ];
        &ATTACKS
    }
    fn parameters(&self) -> Vec<Box<dyn Parameter>> {
        vec![]
    }
    fn handle_packet(&mut self, _packet: &Packet) -> Result<()> {
        let mut stats = self.stats.try_write().map_err(|_| Error::protocol("L"))?;
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
                let attack = LacpHijackAttack::new([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF], 1);
                let name = attack.name().to_string();
                let handle = tokio::spawn(async move { attack.execute(ctx).await });
                (name, handle)
            }
            1 => {
                let attack = LacpDosAttack::new(500);
                let name = attack.name().to_string();
                let handle = tokio::spawn(async move { attack.execute(ctx).await });
                (name, handle)
            }
            _ => return Err(Error::protocol("Invalid attack ID")),
        };

        Ok(AttackHandle {
            id: uuid::Uuid::now_v7(),
            protocol: "LACP".to_string(),
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
        if let Ok(mut s) = self.stats.try_write() {
            *s = ProtocolStats::default();
        }
    }
}
