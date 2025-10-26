//! GRE/Tunnel Protocol Implementation
use async_trait::async_trait;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use std::time::SystemTime;
use tokio::sync::RwLock;
use yersinia_core::{
    protocol::{AttackParams, Protocol, ProtocolStats},
    Attack, AttackContext, AttackDescriptor, AttackHandle, AttackId, AttackStatsCounters, Error,
    Interface, Packet, Parameter, ProtocolId, Result,
};

use super::attack::{
    GreTunnelInjectionAttack, IkeAggressiveAttack, IpsecTunnelHijackAttack,
    TunnelEndpointSpoofingAttack,
};

pub struct GreProtocol {
    stats: Arc<RwLock<ProtocolStats>>,
}

impl GreProtocol {
    pub fn new() -> Self {
        Self {
            stats: Arc::new(RwLock::new(ProtocolStats::default())),
        }
    }
}

impl Default for GreProtocol {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Protocol for GreProtocol {
    fn name(&self) -> &'static str {
        "GRE and Layer 3 Tunneling"
    }
    fn shortname(&self) -> &'static str {
        "gre"
    }
    fn id(&self) -> ProtocolId {
        ProtocolId::GRE
    }

    fn attacks(&self) -> &[AttackDescriptor] {
        static ATTACKS: [AttackDescriptor; 4] = [
            AttackDescriptor {
                id: AttackId(0),
                name: "GRE Tunnel Injection",
                description: "Inject traffic into GRE tunnels",
                parameters: vec![],
            },
            AttackDescriptor {
                id: AttackId(1),
                name: "Tunnel Endpoint Spoofing",
                description: "Spoof tunnel endpoints for traffic interception",
                parameters: vec![],
            },
            AttackDescriptor {
                id: AttackId(2),
                name: "IKE Aggressive Mode Attack",
                description: "Exploit IKE aggressive mode weaknesses",
                parameters: vec![],
            },
            AttackDescriptor {
                id: AttackId(3),
                name: "IPsec Tunnel Hijacking",
                description: "Hijack existing IPsec tunnels",
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
        params: AttackParams,
        interface: &Interface,
    ) -> Result<AttackHandle> {
        use std::net::Ipv4Addr;

        match attack_id.0 {
            0 => {
                let tunnel_key = params.get_u32("tunnel_key");
                let attack = GreTunnelInjectionAttack {
                    tunnel_key,
                    encapsulated_payload: vec![0xCC; 64],
                };

                let running = Arc::new(AtomicBool::new(true));
                let paused = Arc::new(AtomicBool::new(false));
                let stats = Arc::new(AttackStatsCounters::default());

                let ctx = AttackContext {
                    interface: interface.clone(),
                    running: running.clone(),
                    paused: paused.clone(),
                    stats: stats.clone(),
                };

                let task_handle = tokio::spawn(async move { attack.execute(ctx).await });

                Ok(AttackHandle {
                    id: uuid::Uuid::now_v7(),
                    protocol: "GRE".to_string(),
                    attack_name: "GRE Injection".to_string(),
                    running,
                    paused,
                    stats,
                    started_at: SystemTime::now(),
                    task_handle: Some(task_handle),
                })
            }
            1 => {
                let spoofed = params
                    .get_string("spoofed_endpoint")
                    .and_then(|s| s.parse::<Ipv4Addr>().ok())
                    .unwrap_or(Ipv4Addr::new(10, 0, 0, 1));
                let target = params
                    .get_string("target_endpoint")
                    .and_then(|s| s.parse::<Ipv4Addr>().ok())
                    .unwrap_or(Ipv4Addr::new(10, 0, 0, 2));

                let attack = TunnelEndpointSpoofingAttack::new(spoofed, target);

                let running = Arc::new(AtomicBool::new(true));
                let paused = Arc::new(AtomicBool::new(false));
                let stats = Arc::new(AttackStatsCounters::default());

                let ctx = AttackContext {
                    interface: interface.clone(),
                    running: running.clone(),
                    paused: paused.clone(),
                    stats: stats.clone(),
                };

                let task_handle = tokio::spawn(async move { attack.execute(ctx).await });

                Ok(AttackHandle {
                    id: uuid::Uuid::now_v7(),
                    protocol: "GRE".to_string(),
                    attack_name: "Endpoint Spoofing".to_string(),
                    running,
                    paused,
                    stats,
                    started_at: SystemTime::now(),
                    task_handle: Some(task_handle),
                })
            }
            2 => {
                let gateway = params
                    .get_string("target_gateway")
                    .and_then(|s| s.parse::<Ipv4Addr>().ok())
                    .unwrap_or(Ipv4Addr::new(192, 168, 1, 1));

                let attack = IkeAggressiveAttack::new(gateway);

                let running = Arc::new(AtomicBool::new(true));
                let paused = Arc::new(AtomicBool::new(false));
                let stats = Arc::new(AttackStatsCounters::default());

                let ctx = AttackContext {
                    interface: interface.clone(),
                    running: running.clone(),
                    paused: paused.clone(),
                    stats: stats.clone(),
                };

                let task_handle = tokio::spawn(async move { attack.execute(ctx).await });

                Ok(AttackHandle {
                    id: uuid::Uuid::now_v7(),
                    protocol: "GRE".to_string(),
                    attack_name: "IKE Aggressive".to_string(),
                    running,
                    paused,
                    stats,
                    started_at: SystemTime::now(),
                    task_handle: Some(task_handle),
                })
            }
            3 => {
                let spi = params.get_u32("spi").unwrap_or(0x12345678);

                let attack = IpsecTunnelHijackAttack::new(spi);

                let running = Arc::new(AtomicBool::new(true));
                let paused = Arc::new(AtomicBool::new(false));
                let stats = Arc::new(AttackStatsCounters::default());

                let ctx = AttackContext {
                    interface: interface.clone(),
                    running: running.clone(),
                    paused: paused.clone(),
                    stats: stats.clone(),
                };

                let task_handle = tokio::spawn(async move { attack.execute(ctx).await });

                Ok(AttackHandle {
                    id: uuid::Uuid::now_v7(),
                    protocol: "GRE".to_string(),
                    attack_name: "IPsec Hijacking".to_string(),
                    running,
                    paused,
                    stats,
                    started_at: SystemTime::now(),
                    task_handle: Some(task_handle),
                })
            }
            _ => Err(Error::protocol("Invalid attack ID")),
        }
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
