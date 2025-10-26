//! DHCPv6 Protocol Implementation

use async_trait::async_trait;
use std::sync::Arc;
use std::time::SystemTime;
use tokio::sync::RwLock;
use yersinia_core::{
    protocol::{AttackParams, Protocol, ProtocolStats},
    Attack, AttackContext, AttackDescriptor, AttackHandle, AttackId, AttackStatsCounters, Error,
    Interface, Packet, Parameter, ProtocolId, Result,
};

use super::attack::{Dhcpv6DosAttack, Dhcpv6RogueServerAttack, Dhcpv6StarvationAttack};
use super::packet::Dhcpv6MessageType;

pub struct Dhcpv6Protocol {
    stats: Arc<RwLock<ProtocolStats>>,
}

impl Dhcpv6Protocol {
    pub fn new() -> Self {
        Self {
            stats: Arc::new(RwLock::new(ProtocolStats::default())),
        }
    }
}

impl Default for Dhcpv6Protocol {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Protocol for Dhcpv6Protocol {
    fn name(&self) -> &'static str {
        "Dynamic Host Configuration Protocol for IPv6"
    }

    fn shortname(&self) -> &'static str {
        "dhcpv6"
    }

    fn id(&self) -> ProtocolId {
        ProtocolId::DHCPV6
    }

    fn attacks(&self) -> &[AttackDescriptor] {
        static ATTACKS: [AttackDescriptor; 3] = [
            AttackDescriptor {
                id: AttackId(0),
                name: "DHCPv6 Starvation",
                description: "Exhaust DHCPv6 address pool by requesting all available addresses",
                parameters: vec![],
            },
            AttackDescriptor {
                id: AttackId(1),
                name: "DHCPv6 Rogue Server",
                description: "Respond to DHCPv6 requests with malicious configuration",
                parameters: vec![],
            },
            AttackDescriptor {
                id: AttackId(2),
                name: "DHCPv6 DoS",
                description: "Flood DHCPv6 servers with malformed or excessive requests",
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
                let attack = Dhcpv6StarvationAttack::new(100);
                let name = attack.name().to_string();
                let handle = tokio::spawn(async move { attack.execute(ctx).await });
                (name, handle)
            }
            1 => {
                let attack = Dhcpv6RogueServerAttack::new(
                    [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF],
                    "2001:db8::".parse().unwrap(),
                );
                let name = attack.name().to_string();
                let handle = tokio::spawn(async move { attack.execute(ctx).await });
                (name, handle)
            }
            2 => {
                let attack = Dhcpv6DosAttack::new(Dhcpv6MessageType::Solicit, 1000);
                let name = attack.name().to_string();
                let handle = tokio::spawn(async move { attack.execute(ctx).await });
                (name, handle)
            }
            _ => return Err(Error::protocol("Invalid attack ID")),
        };

        Ok(AttackHandle {
            id: uuid::Uuid::now_v7(),
            protocol: "DHCPv6".to_string(),
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
