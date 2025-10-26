//! IPv6 Neighbor Discovery Protocol Implementation

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
    DadDosAttack, ExtensionHeadersAttack, Ipv6FragmentationAttack, NdpPoisoningAttack,
    RogueRouterAdvertisementAttack, SlaacAttack, TeredoTunnelAttack,
};

pub struct Ipv6NdProtocol {
    stats: Arc<RwLock<ProtocolStats>>,
}

impl Ipv6NdProtocol {
    pub fn new() -> Self {
        Self {
            stats: Arc::new(RwLock::new(ProtocolStats::default())),
        }
    }
}

impl Default for Ipv6NdProtocol {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Protocol for Ipv6NdProtocol {
    fn name(&self) -> &'static str {
        "IPv6 Neighbor Discovery / Router Advertisement"
    }

    fn shortname(&self) -> &'static str {
        "ipv6-nd"
    }

    fn id(&self) -> ProtocolId {
        ProtocolId::IPV6_ND
    }

    fn attacks(&self) -> &[AttackDescriptor] {
        static ATTACKS: [AttackDescriptor; 7] = [
            AttackDescriptor {
                id: AttackId(0),
                name: "Rogue Router Advertisement",
                description: "Advertise fake default gateway to hijack IPv6 traffic",
                parameters: vec![],
            },
            AttackDescriptor {
                id: AttackId(1),
                name: "NDP Poisoning",
                description: "Poison neighbor cache with fake MAC-to-IPv6 mappings",
                parameters: vec![],
            },
            AttackDescriptor {
                id: AttackId(2),
                name: "DAD DoS",
                description: "Deny all IPv6 address autoconfiguration via DAD exploitation",
                parameters: vec![],
            },
            AttackDescriptor {
                id: AttackId(3),
                name: "SLAAC Attack",
                description: "Manipulate Stateless Address Autoconfiguration",
                parameters: vec![],
            },
            AttackDescriptor {
                id: AttackId(4),
                name: "IPv6 Fragmentation Attack",
                description: "Exploit IPv6 fragmentation to bypass security controls or cause resource exhaustion",
                parameters: vec![],
            },
            AttackDescriptor {
                id: AttackId(5),
                name: "Extension Headers Manipulation",
                description: "Craft malicious extension headers to evade security devices",
                parameters: vec![],
            },
            AttackDescriptor {
                id: AttackId(6),
                name: "Teredo/6to4 Tunnel Attack",
                description: "Exploit IPv6 transition mechanisms to bypass firewalls or establish covert channels",
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
                let attack = RogueRouterAdvertisementAttack::new(
                    [0x00, 0x11, 0x22, 0x33, 0x44, 0x55],
                    "fe80::1".parse().unwrap(),
                    "2001:db8::".parse().unwrap(),
                );
                let name = attack.name().to_string();
                let handle = tokio::spawn(async move { attack.execute(ctx).await });
                (name, handle)
            }
            1 => {
                let attack = NdpPoisoningAttack::new(
                    "2001:db8::1".parse().unwrap(),
                    [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF],
                );
                let name = attack.name().to_string();
                let handle = tokio::spawn(async move { attack.execute(ctx).await });
                (name, handle)
            }
            2 => {
                let attack = DadDosAttack::new([0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x01]);
                let name = attack.name().to_string();
                let handle = tokio::spawn(async move { attack.execute(ctx).await });
                (name, handle)
            }
            3 => {
                let attack = SlaacAttack::new(
                    [0x00, 0x0C, 0x29, 0xAB, 0xCD, 0xEF],
                    "2001:db8::".parse().unwrap(),
                );
                let name = attack.name().to_string();
                let handle = tokio::spawn(async move { attack.execute(ctx).await });
                (name, handle)
            }
            4 => {
                let attack = Ipv6FragmentationAttack::new(
                    "2001:db8::100".parse().unwrap(),
                    "2001:db8::200".parse().unwrap(),
                );
                let name = attack.name().to_string();
                let handle = tokio::spawn(async move { attack.execute(ctx).await });
                (name, handle)
            }
            5 => {
                let attack = ExtensionHeadersAttack::new(
                    "2001:db8::100".parse().unwrap(),
                    "2001:db8::200".parse().unwrap(),
                );
                let name = attack.name().to_string();
                let handle = tokio::spawn(async move { attack.execute(ctx).await });
                (name, handle)
            }
            6 => {
                let attack = TeredoTunnelAttack::new(
                    "2001:db8::cafe".parse().unwrap(),
                    "2001:db8::dead".parse().unwrap(),
                );
                let name = attack.name().to_string();
                let handle = tokio::spawn(async move { attack.execute(ctx).await });
                (name, handle)
            }
            _ => return Err(Error::protocol("Invalid attack ID")),
        };

        Ok(AttackHandle {
            id: uuid::Uuid::now_v7(),
            protocol: "IPv6-ND".to_string(),
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
