//! ICMP Protocol Implementation

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
    IcmpAmplificationAttack, IcmpFloodAttack, IcmpRedirectAttack, IcmpRouterDiscoveryAttack,
};

pub struct IcmpProtocol {
    stats: Arc<RwLock<ProtocolStats>>,
}

impl IcmpProtocol {
    pub fn new() -> Self {
        Self {
            stats: Arc::new(RwLock::new(ProtocolStats::default())),
        }
    }
}

impl Default for IcmpProtocol {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Protocol for IcmpProtocol {
    fn name(&self) -> &'static str {
        "Internet Control Message Protocol"
    }

    fn shortname(&self) -> &'static str {
        "icmp"
    }

    fn id(&self) -> ProtocolId {
        ProtocolId::ICMP
    }

    fn attacks(&self) -> &[AttackDescriptor] {
        static ATTACKS: [AttackDescriptor; 4] = [
            AttackDescriptor {
                id: AttackId(0),
                name: "ICMP Redirect Attack",
                description: "MITM via ICMP redirects to manipulate routing",
                parameters: vec![],
            },
            AttackDescriptor {
                id: AttackId(1),
                name: "ICMP Flood",
                description: "Flood target with ICMP packets (ping flood)",
                parameters: vec![],
            },
            AttackDescriptor {
                id: AttackId(2),
                name: "ICMP Amplification (Smurf)",
                description: "Amplification DoS using broadcast replies",
                parameters: vec![],
            },
            AttackDescriptor {
                id: AttackId(3),
                name: "Router Discovery Manipulation",
                description: "Become default gateway via fake Router Advertisements",
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
            .map_err(|_| Error::protocol("Lock"))?;

        stats.packets_received += 1;
        stats.bytes_received += packet.data.len() as u64;

        // Basic ICMP parsing - check if it's valid
        if packet.data.len() >= 8 {
            stats.packets_parsed += 1;
        } else {
            stats.packets_errors += 1;
        }

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
                let attack = IcmpRedirectAttack::new(
                    "10.0.0.1".parse().unwrap(),
                    "192.168.1.0".parse().unwrap(),
                );
                let name = attack.name().to_string();
                let handle = tokio::spawn(async move { attack.execute(ctx).await });
                (name, handle)
            }
            1 => {
                let attack = IcmpFloodAttack::ping_flood(1000);
                let name = attack.name().to_string();
                let handle = tokio::spawn(async move { attack.execute(ctx).await });
                (name, handle)
            }
            2 => {
                let attack = IcmpAmplificationAttack::new(
                    "192.168.1.100".parse().unwrap(),
                    "192.168.1.255".parse().unwrap(),
                );
                let name = attack.name().to_string();
                let handle = tokio::spawn(async move { attack.execute(ctx).await });
                (name, handle)
            }
            3 => {
                let attack = IcmpRouterDiscoveryAttack::new("10.0.0.1".parse().unwrap());
                let name = attack.name().to_string();
                let handle = tokio::spawn(async move { attack.execute(ctx).await });
                (name, handle)
            }
            _ => return Err(Error::protocol("Invalid attack ID")),
        };

        Ok(AttackHandle {
            id: uuid::Uuid::now_v7(),
            protocol: "ICMP".to_string(),
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
