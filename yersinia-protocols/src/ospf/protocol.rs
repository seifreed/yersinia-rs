//! OSPF Protocol Implementation

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
    OspfLsaInjectionAttack, OspfMaxAgeDosAttack, OspfNeighborHijackAttack,
    OspfRouteManipulationAttack,
};

pub struct OspfProtocol {
    stats: Arc<RwLock<ProtocolStats>>,
}

impl OspfProtocol {
    pub fn new() -> Self {
        Self {
            stats: Arc::new(RwLock::new(ProtocolStats::default())),
        }
    }
}

impl Default for OspfProtocol {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Protocol for OspfProtocol {
    fn name(&self) -> &'static str {
        "Open Shortest Path First"
    }

    fn shortname(&self) -> &'static str {
        "ospf"
    }

    fn id(&self) -> ProtocolId {
        ProtocolId::OSPF
    }

    fn attacks(&self) -> &[AttackDescriptor] {
        static ATTACKS: [AttackDescriptor; 4] = [
            AttackDescriptor {
                id: AttackId(0),
                name: "OSPF LSA Injection",
                description: "Inject malicious Link State Advertisements",
                parameters: vec![],
            },
            AttackDescriptor {
                id: AttackId(1),
                name: "OSPF Neighbor Hijacking",
                description: "Establish fake OSPF adjacencies",
                parameters: vec![],
            },
            AttackDescriptor {
                id: AttackId(2),
                name: "OSPF Route Manipulation",
                description: "Manipulate routing table with fake metrics",
                parameters: vec![],
            },
            AttackDescriptor {
                id: AttackId(3),
                name: "OSPF Max-Age DoS",
                description: "Flood with MaxAge LSAs to cause routing instability",
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
                let attack = OspfLsaInjectionAttack::new(
                    "1.1.1.1".parse().unwrap(),
                    "0.0.0.1".parse().unwrap(),
                );
                let name = attack.name().to_string();
                let handle = tokio::spawn(async move { attack.execute(ctx).await });
                (name, handle)
            }
            1 => {
                let attack = OspfNeighborHijackAttack::new(
                    "192.168.1.1".parse().unwrap(),
                    "0.0.0.0".parse().unwrap(),
                    "255.255.255.0".parse().unwrap(),
                );
                let name = attack.name().to_string();
                let handle = tokio::spawn(async move { attack.execute(ctx).await });
                (name, handle)
            }
            2 => {
                let attack = OspfRouteManipulationAttack::new(
                    "10.0.0.0".parse().unwrap(),
                    "0.0.0.0".parse().unwrap(),
                );
                let name = attack.name().to_string();
                let handle = tokio::spawn(async move { attack.execute(ctx).await });
                (name, handle)
            }
            3 => {
                let attack = OspfMaxAgeDosAttack::new(
                    "1.1.1.1".parse().unwrap(),
                    "0.0.0.0".parse().unwrap(),
                );
                let name = attack.name().to_string();
                let handle = tokio::spawn(async move { attack.execute(ctx).await });
                (name, handle)
            }
            _ => return Err(Error::protocol("Invalid attack ID")),
        };

        Ok(AttackHandle {
            id: uuid::Uuid::now_v7(),
            protocol: "OSPF".to_string(),
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
