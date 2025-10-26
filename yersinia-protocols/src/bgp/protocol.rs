//! BGP Protocol Implementation

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
    BgpAsPathManipulationAttack, BgpRouteHijackAttack, BgpRouteLeakAttack, BgpSessionHijackAttack,
    BgpTtlSecurityBypassAttack,
};

pub struct BgpProtocol {
    stats: Arc<RwLock<ProtocolStats>>,
}

impl BgpProtocol {
    pub fn new() -> Self {
        Self {
            stats: Arc::new(RwLock::new(ProtocolStats::default())),
        }
    }
}

impl Default for BgpProtocol {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Protocol for BgpProtocol {
    fn name(&self) -> &'static str {
        "Border Gateway Protocol"
    }

    fn shortname(&self) -> &'static str {
        "bgp"
    }

    fn id(&self) -> ProtocolId {
        ProtocolId::BGP
    }

    fn attacks(&self) -> &[AttackDescriptor] {
        static ATTACKS: [AttackDescriptor; 5] = [
            AttackDescriptor {
                id: AttackId(0),
                name: "BGP Route Hijacking",
                description: "Hijack network prefixes by advertising unauthorized routes",
                parameters: vec![],
            },
            AttackDescriptor {
                id: AttackId(1),
                name: "BGP AS Path Manipulation",
                description: "Manipulate AS_PATH to bypass filters or alter routing",
                parameters: vec![],
            },
            AttackDescriptor {
                id: AttackId(2),
                name: "BGP Session Hijacking",
                description: "Hijack or tear down existing BGP sessions",
                parameters: vec![],
            },
            AttackDescriptor {
                id: AttackId(3),
                name: "BGP Route Leak",
                description: "Simulate route leaks causing traffic misdirection",
                parameters: vec![],
            },
            AttackDescriptor {
                id: AttackId(4),
                name: "BGP TTL Security Bypass",
                description: "Bypass GTSM by manipulating TTL values",
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
                let attack = BgpRouteHijackAttack::new(
                    65001,
                    "10.0.0.1".parse().unwrap(),
                    "10.0.0.1".parse().unwrap(),
                )
                .add_prefix("10.0.0.0".parse().unwrap(), 8);
                let name = attack.name().to_string();
                let handle = tokio::spawn(async move { attack.execute(ctx).await });
                (name, handle)
            }
            1 => {
                let attack = BgpAsPathManipulationAttack::new(
                    65001,
                    "10.0.0.1".parse().unwrap(),
                    "10.0.0.1".parse().unwrap(),
                )
                .with_custom_path(vec![65001, 65002, 65003]);
                let name = attack.name().to_string();
                let handle = tokio::spawn(async move { attack.execute(ctx).await });
                (name, handle)
            }
            2 => {
                let attack = BgpSessionHijackAttack::new(
                    "192.168.1.1".parse().unwrap(),
                    65001,
                    "192.168.1.2".parse().unwrap(),
                    65002,
                );
                let name = attack.name().to_string();
                let handle = tokio::spawn(async move { attack.execute(ctx).await });
                (name, handle)
            }
            3 => {
                let attack = BgpRouteLeakAttack::new(
                    65001,
                    "10.0.0.1".parse().unwrap(),
                    "10.0.0.1".parse().unwrap(),
                )
                .add_leaked_route(
                    "172.16.0.0".parse().unwrap(),
                    12,
                    vec![65002, 65003],
                );
                let name = attack.name().to_string();
                let handle = tokio::spawn(async move { attack.execute(ctx).await });
                (name, handle)
            }
            4 => {
                let attack = BgpTtlSecurityBypassAttack::new(
                    65001,
                    "10.0.0.1".parse().unwrap(),
                    "192.168.1.1".parse().unwrap(),
                );
                let name = attack.name().to_string();
                let handle = tokio::spawn(async move { attack.execute(ctx).await });
                (name, handle)
            }
            _ => return Err(Error::protocol("Invalid attack ID")),
        };

        Ok(AttackHandle {
            id: uuid::Uuid::now_v7(),
            protocol: "BGP".to_string(),
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
