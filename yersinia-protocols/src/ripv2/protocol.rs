//! RIPv2 Protocol Implementation

use async_trait::async_trait;
use std::sync::Arc;
use std::time::SystemTime;
use tokio::sync::RwLock;
use yersinia_core::{
    protocol::{AttackParams, Protocol, ProtocolStats},
    Attack, AttackContext, AttackDescriptor, AttackHandle, AttackId, AttackStatsCounters, Error,
    Interface, Packet, Parameter, ProtocolId, Result,
};

use super::attack::{RipAuthBypassAttack, RipFloodingAttack, RipPoisoningAttack};

pub struct RipProtocol {
    stats: Arc<RwLock<ProtocolStats>>,
}

impl RipProtocol {
    pub fn new() -> Self {
        Self {
            stats: Arc::new(RwLock::new(ProtocolStats::default())),
        }
    }
}

impl Default for RipProtocol {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Protocol for RipProtocol {
    fn name(&self) -> &'static str {
        "Routing Information Protocol v2"
    }

    fn shortname(&self) -> &'static str {
        "ripv2"
    }

    fn id(&self) -> ProtocolId {
        ProtocolId::RIPV2
    }

    fn attacks(&self) -> &[AttackDescriptor] {
        static ATTACKS: [AttackDescriptor; 3] = [
            AttackDescriptor {
                id: AttackId(0),
                name: "RIP Route Poisoning",
                description: "Inject malicious routes to redirect or blackhole traffic",
                parameters: vec![],
            },
            AttackDescriptor {
                id: AttackId(1),
                name: "RIP Flooding",
                description: "Flood network with RIP updates to exhaust routing tables",
                parameters: vec![],
            },
            AttackDescriptor {
                id: AttackId(2),
                name: "RIP Authentication Bypass",
                description: "Attempt to bypass MD5 authentication",
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
            .map_err(|_| Error::protocol("Stats lock"))?;
        stats.packets_received += 1;
        stats.bytes_received += packet.data.len() as u64;
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
                let attack = RipPoisoningAttack::new(
                    "192.168.1.0".parse().unwrap(),
                    "10.0.0.1".parse().unwrap(),
                );
                let name = attack.name().to_string();
                let handle = tokio::spawn(async move { attack.execute(ctx).await });
                (name, handle)
            }
            1 => {
                let attack = RipFloodingAttack::new(100);
                let name = attack.name().to_string();
                let handle = tokio::spawn(async move { attack.execute(ctx).await });
                (name, handle)
            }
            2 => {
                let attack = RipAuthBypassAttack::new();
                let name = attack.name().to_string();
                let handle = tokio::spawn(async move { attack.execute(ctx).await });
                (name, handle)
            }
            _ => return Err(Error::protocol("Invalid attack ID")),
        };

        Ok(AttackHandle {
            id: uuid::Uuid::now_v7(),
            protocol: "RIPv2".to_string(),
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
