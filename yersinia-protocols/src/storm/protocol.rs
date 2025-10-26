//! Storm Generator Protocol Implementation
use async_trait::async_trait;
use std::sync::Arc;
use std::time::SystemTime;
use tokio::sync::RwLock;
use yersinia_core::{
    protocol::{AttackParams, Protocol, ProtocolStats},
    Attack, AttackContext, AttackDescriptor, AttackHandle, AttackId, AttackStatsCounters, Error,
    Interface, Packet, Parameter, ProtocolId, Result,
};

use super::attack::{BroadcastStormAttack, MulticastStormAttack, UnknownUnicastStormAttack};
use super::packet::StormConfig;

pub struct StormProtocol {
    stats: Arc<RwLock<ProtocolStats>>,
}

impl StormProtocol {
    pub fn new() -> Self {
        Self {
            stats: Arc::new(RwLock::new(ProtocolStats::default())),
        }
    }
}

impl Default for StormProtocol {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Protocol for StormProtocol {
    fn name(&self) -> &'static str {
        "Broadcast/Multicast Storm Generator"
    }
    fn shortname(&self) -> &'static str {
        "storm"
    }
    fn id(&self) -> ProtocolId {
        ProtocolId::STORM
    }

    fn attacks(&self) -> &[AttackDescriptor] {
        static ATTACKS: [AttackDescriptor; 3] = [
            AttackDescriptor {
                id: AttackId(0),
                name: "Broadcast Storm",
                description: "Flood network with broadcast packets to cause DoS",
                parameters: vec![],
            },
            AttackDescriptor {
                id: AttackId(1),
                name: "Multicast Storm",
                description: "Flood network with multicast packets",
                parameters: vec![],
            },
            AttackDescriptor {
                id: AttackId(2),
                name: "Unknown Unicast Storm",
                description: "Flood with random unicast MACs to exhaust switch resources",
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

        let config = StormConfig::new().with_rate(1000).with_duration(3600);

        let (attack_name, task_handle) = match attack_id.0 {
            0 => {
                let attack = BroadcastStormAttack::new().with_config(config);
                let name = attack.name().to_string();
                let handle = tokio::spawn(async move { attack.execute(ctx).await });
                (name, handle)
            }
            1 => {
                let attack = MulticastStormAttack::new().with_config(config);
                let name = attack.name().to_string();
                let handle = tokio::spawn(async move { attack.execute(ctx).await });
                (name, handle)
            }
            2 => {
                let attack = UnknownUnicastStormAttack::new().with_config(config);
                let name = attack.name().to_string();
                let handle = tokio::spawn(async move { attack.execute(ctx).await });
                (name, handle)
            }
            _ => return Err(Error::protocol("Invalid attack ID")),
        };

        Ok(AttackHandle {
            id: uuid::Uuid::now_v7(),
            protocol: "Storm".to_string(),
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
