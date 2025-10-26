//! GLBP Protocol
use async_trait::async_trait;
use std::sync::Arc;
use std::time::SystemTime;
use tokio::sync::RwLock;
use yersinia_core::{
    protocol::{AttackParams, Protocol, ProtocolStats},
    Attack, AttackContext, AttackDescriptor, AttackHandle, AttackId, AttackStatsCounters, Error,
    Interface, Packet, Parameter, ProtocolId, Result,
};

use super::attack::GlbpAttack;

pub struct GlbpProtocol {
    stats: Arc<RwLock<ProtocolStats>>,
}
impl GlbpProtocol {
    pub fn new() -> Self {
        Self {
            stats: Arc::new(RwLock::new(ProtocolStats::default())),
        }
    }
}
impl Default for GlbpProtocol {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Protocol for GlbpProtocol {
    fn name(&self) -> &'static str {
        "Gateway Load Balancing Protocol"
    }
    fn shortname(&self) -> &'static str {
        "glbp"
    }
    fn id(&self) -> ProtocolId {
        ProtocolId::GLBP
    }
    fn attacks(&self) -> &[AttackDescriptor] {
        static ATTACKS: [AttackDescriptor; 2] = [
            AttackDescriptor {
                id: AttackId(0),
                name: "GLBP AVG Hijacking",
                description: "Become active virtual gateway",
                parameters: vec![],
            },
            AttackDescriptor {
                id: AttackId(1),
                name: "GLBP AVF Manipulation",
                description: "Manipulate active virtual forwarder",
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
            0 | 1 => {
                let attack = GlbpAttack::new(1, "192.168.1.254".parse().unwrap());
                let name = attack.name().to_string();
                let handle = tokio::spawn(async move { attack.execute(ctx).await });
                (name, handle)
            }
            _ => return Err(Error::protocol("Invalid attack ID")),
        };

        Ok(AttackHandle {
            id: uuid::Uuid::now_v7(),
            protocol: "GLBP".to_string(),
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
