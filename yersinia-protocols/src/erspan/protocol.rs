//! ERSPAN Protocol Implementation
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
    ErspanSessionHijackingAttack, RspanVlanHoppingAttack, SpanTrafficManipulationAttack,
};

pub struct ErspanProtocol {
    stats: Arc<RwLock<ProtocolStats>>,
}

impl ErspanProtocol {
    pub fn new() -> Self {
        Self {
            stats: Arc::new(RwLock::new(ProtocolStats::default())),
        }
    }
}

impl Default for ErspanProtocol {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Protocol for ErspanProtocol {
    fn name(&self) -> &'static str {
        "ERSPAN/RSPAN Remote SPAN"
    }
    fn shortname(&self) -> &'static str {
        "erspan"
    }
    fn id(&self) -> ProtocolId {
        ProtocolId::ERSPAN
    }

    fn attacks(&self) -> &[AttackDescriptor] {
        static ATTACKS: [AttackDescriptor; 3] = [
            AttackDescriptor {
                id: AttackId(0),
                name: "ERSPAN Session Hijacking",
                description: "Hijack ERSPAN monitoring sessions",
                parameters: vec![],
            },
            AttackDescriptor {
                id: AttackId(1),
                name: "SPAN Traffic Manipulation",
                description: "Manipulate mirrored traffic in SPAN sessions",
                parameters: vec![],
            },
            AttackDescriptor {
                id: AttackId(2),
                name: "RSPAN VLAN Hopping",
                description: "Hop between VLANs using RSPAN VLAN",
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
                let session_id = params.get_u32("session_id").unwrap_or(1) as u16;
                let src_ip = params
                    .get_string("source_ip")
                    .and_then(|s| s.parse::<Ipv4Addr>().ok())
                    .unwrap_or(Ipv4Addr::new(192, 168, 1, 1));
                let dst_ip = params
                    .get_string("destination_ip")
                    .and_then(|s| s.parse::<Ipv4Addr>().ok())
                    .unwrap_or(Ipv4Addr::new(192, 168, 1, 2));

                let attack = ErspanSessionHijackingAttack::new(session_id, src_ip, dst_ip);

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
                    protocol: "ERSPAN".to_string(),
                    attack_name: "Session Hijacking".to_string(),
                    running,
                    paused,
                    stats,
                    started_at: SystemTime::now(),
                    task_handle: Some(task_handle),
                })
            }
            1 => {
                let session_id = params.get_u32("session_id").unwrap_or(1) as u16;

                let attack =
                    SpanTrafficManipulationAttack::new(session_id).with_malicious_injection();

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
                    protocol: "ERSPAN".to_string(),
                    attack_name: "Traffic Manipulation".to_string(),
                    running,
                    paused,
                    stats,
                    started_at: SystemTime::now(),
                    task_handle: Some(task_handle),
                })
            }
            2 => {
                let source_vlan = params.get_u32("source_vlan").unwrap_or(10) as u16;
                let target_vlan = params.get_u32("target_vlan").unwrap_or(20) as u16;
                let session_id = params.get_u32("session_id").unwrap_or(1) as u16;

                let attack = RspanVlanHoppingAttack::new(source_vlan, target_vlan, session_id);

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
                    protocol: "ERSPAN".to_string(),
                    attack_name: "VLAN Hopping".to_string(),
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
