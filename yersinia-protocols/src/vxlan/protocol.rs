//! VXLAN Protocol Implementation

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
    TenantBypassMode, VxlanTenantBypassAttack, VxlanVniManipulationAttack, VxlanVtepSpoofingAttack,
};

pub struct VxlanProtocol {
    stats: Arc<RwLock<ProtocolStats>>,
}

impl VxlanProtocol {
    pub fn new() -> Self {
        Self {
            stats: Arc::new(RwLock::new(ProtocolStats::default())),
        }
    }
}

impl Default for VxlanProtocol {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Protocol for VxlanProtocol {
    fn name(&self) -> &'static str {
        "Virtual Extensible LAN"
    }

    fn shortname(&self) -> &'static str {
        "vxlan"
    }

    fn id(&self) -> ProtocolId {
        ProtocolId::VXLAN
    }

    fn attacks(&self) -> &[AttackDescriptor] {
        static ATTACKS: [AttackDescriptor; 3] = [
            AttackDescriptor {
                id: AttackId(0),
                name: "VXLAN VTEP Spoofing",
                description: "Spoof VXLAN Tunnel Endpoint to inject traffic into overlay networks",
                parameters: vec![],
            },
            AttackDescriptor {
                id: AttackId(1),
                name: "VXLAN VNI Manipulation",
                description: "Manipulate VXLAN Network Identifiers to access unauthorized segments",
                parameters: vec![],
            },
            AttackDescriptor {
                id: AttackId(2),
                name: "VXLAN Tenant Isolation Bypass",
                description: "Bypass multi-tenant isolation in VXLAN environments",
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
        params: AttackParams,
        interface: &Interface,
    ) -> Result<AttackHandle> {
        use std::net::Ipv4Addr;

        match attack_id.0 {
            0 => {
                let vtep_ip = params
                    .get_string("vtep_ip")
                    .and_then(|s| s.parse::<Ipv4Addr>().ok())
                    .unwrap_or(Ipv4Addr::new(10, 0, 0, 1));
                let vni = params.get_u32("vni").unwrap_or(100);

                let attack = VxlanVtepSpoofingAttack::new(vtep_ip, vni);

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
                    protocol: "VXLAN".to_string(),
                    attack_name: "VTEP Spoofing".to_string(),
                    running,
                    paused,
                    stats,
                    started_at: SystemTime::now(),
                    task_handle: Some(task_handle),
                })
            }
            1 => {
                let vtep_ip = params
                    .get_string("vtep_ip")
                    .and_then(|s| s.parse::<Ipv4Addr>().ok())
                    .unwrap_or(Ipv4Addr::new(10, 0, 0, 1));
                let source_vni = params.get_u32("source_vni").unwrap_or(100);

                let attack =
                    VxlanVniManipulationAttack::new(vtep_ip, source_vni).enable_scan(1, 4096);

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
                    protocol: "VXLAN".to_string(),
                    attack_name: "VNI Manipulation".to_string(),
                    running,
                    paused,
                    stats,
                    started_at: SystemTime::now(),
                    task_handle: Some(task_handle),
                })
            }
            2 => {
                let vtep_ip = params
                    .get_string("vtep_ip")
                    .and_then(|s| s.parse::<Ipv4Addr>().ok())
                    .unwrap_or(Ipv4Addr::new(10, 0, 0, 1));
                let attacker_vni = params.get_u32("attacker_vni").unwrap_or(100);
                let target_vni = params.get_u32("target_vni").unwrap_or(200);

                let attack = VxlanTenantBypassAttack::new(vtep_ip, attacker_vni, target_vni)
                    .set_mode(TenantBypassMode::DirectInjection);

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
                    protocol: "VXLAN".to_string(),
                    attack_name: "Tenant Bypass".to_string(),
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
