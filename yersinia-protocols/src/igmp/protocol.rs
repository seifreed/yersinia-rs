//! IGMP/MLD Protocol Implementation

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
    IgmpFloodingAttack, IgmpSnoopingBypassAttack, MldPoisoningAttack, MulticastGroupHijackAttack,
};

pub struct IgmpProtocol {
    stats: Arc<RwLock<ProtocolStats>>,
}

impl IgmpProtocol {
    pub fn new() -> Self {
        Self {
            stats: Arc::new(RwLock::new(ProtocolStats::default())),
        }
    }
}

impl Default for IgmpProtocol {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Protocol for IgmpProtocol {
    fn name(&self) -> &'static str {
        "Internet Group Management Protocol / Multicast Listener Discovery"
    }

    fn shortname(&self) -> &'static str {
        "igmp"
    }

    fn id(&self) -> ProtocolId {
        ProtocolId::IGMP
    }

    fn attacks(&self) -> &[AttackDescriptor] {
        static ATTACKS: [AttackDescriptor; 4] = [
            AttackDescriptor {
                id: AttackId(0),
                name: "IGMP Flooding",
                description: "Flood network with IGMP reports to create multicast storm",
                parameters: vec![],
            },
            AttackDescriptor {
                id: AttackId(1),
                name: "IGMP Snooping Bypass",
                description: "Bypass IGMP snooping to receive multicast traffic",
                parameters: vec![],
            },
            AttackDescriptor {
                id: AttackId(2),
                name: "Multicast Group Hijacking",
                description: "Hijack multicast groups to intercept traffic",
                parameters: vec![],
            },
            AttackDescriptor {
                id: AttackId(3),
                name: "MLD Poisoning",
                description: "Poison IPv6 Multicast Listener Discovery",
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
                let attack = IgmpFloodingAttack::new(1000);
                let name = attack.name().to_string();
                let handle = tokio::spawn(async move { attack.execute(ctx).await });
                (name, handle)
            }
            1 => {
                let attack = IgmpSnoopingBypassAttack::new("224.0.1.1".parse().unwrap());
                let name = attack.name().to_string();
                let handle = tokio::spawn(async move { attack.execute(ctx).await });
                (name, handle)
            }
            2 => {
                let attack = MulticastGroupHijackAttack::new("239.255.255.250".parse().unwrap());
                let name = attack.name().to_string();
                let handle = tokio::spawn(async move { attack.execute(ctx).await });
                (name, handle)
            }
            3 => {
                let attack = MldPoisoningAttack::new("ff02::1".parse().unwrap());
                let name = attack.name().to_string();
                let handle = tokio::spawn(async move { attack.execute(ctx).await });
                (name, handle)
            }
            _ => return Err(Error::protocol("Invalid attack ID")),
        };

        Ok(AttackHandle {
            id: uuid::Uuid::now_v7(),
            protocol: "IGMP".to_string(),
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
