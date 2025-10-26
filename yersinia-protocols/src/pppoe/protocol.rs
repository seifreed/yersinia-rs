//! PPPoE Protocol Implementation

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
    PppoeDiscoveryDosAttack, PppoeMacExhaustionAttack, PppoeRogueAcAttack, PppoeSessionHijackAttack,
};

pub struct PppoeProtocol {
    stats: Arc<RwLock<ProtocolStats>>,
}

impl PppoeProtocol {
    pub fn new() -> Self {
        Self {
            stats: Arc::new(RwLock::new(ProtocolStats::default())),
        }
    }
}

impl Default for PppoeProtocol {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Protocol for PppoeProtocol {
    fn name(&self) -> &'static str {
        "Point-to-Point Protocol over Ethernet"
    }

    fn shortname(&self) -> &'static str {
        "pppoe"
    }

    fn id(&self) -> ProtocolId {
        ProtocolId::PPPOE
    }

    fn attacks(&self) -> &[AttackDescriptor] {
        static ATTACKS: [AttackDescriptor; 4] = [
            AttackDescriptor {
                id: AttackId(0),
                name: "PPPoE Discovery DoS",
                description: "Flood network with PADI packets to exhaust AC resources",
                parameters: vec![],
            },
            AttackDescriptor {
                id: AttackId(1),
                name: "PPPoE Rogue AC",
                description: "Respond to PADI with fake PADO offers to hijack sessions",
                parameters: vec![],
            },
            AttackDescriptor {
                id: AttackId(2),
                name: "PPPoE Session Hijacking",
                description: "Send PADT packets to terminate active sessions",
                parameters: vec![],
            },
            AttackDescriptor {
                id: AttackId(3),
                name: "PPPoE MAC Exhaustion",
                description:
                    "Create multiple sessions with different MACs to exhaust session table",
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
        match attack_id.0 {
            // PPPoE Discovery DoS Attack
            0 => {
                let rate_pps = params.get_u32("rate_pps").unwrap_or(100);
                let count = params.get_u32("count").map(|c| c as u64);
                let service_name = params.get_string("service_name").map(|s| s.to_string());

                let mut attack = PppoeDiscoveryDosAttack::new(rate_pps);
                if let Some(service) = service_name {
                    attack = attack.with_service(&service);
                }
                if let Some(c) = count {
                    attack = attack.with_count(c);
                }

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
                    protocol: "PPPoE".to_string(),
                    attack_name: "Discovery DoS".to_string(),
                    running,
                    paused,
                    stats,
                    started_at: SystemTime::now(),
                    task_handle: Some(task_handle),
                })
            }
            // PPPoE Rogue AC Attack
            1 => {
                let ac_name = params
                    .get_string("ac_name")
                    .unwrap_or("Rogue-AC")
                    .to_string();
                let service_name = params
                    .get_string("service_name")
                    .unwrap_or("internet")
                    .to_string();

                let attack = PppoeRogueAcAttack::new(&ac_name, &service_name);

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
                    protocol: "PPPoE".to_string(),
                    attack_name: "Rogue AC".to_string(),
                    running,
                    paused,
                    stats,
                    started_at: SystemTime::now(),
                    task_handle: Some(task_handle),
                })
            }
            // PPPoE Session Hijacking Attack
            2 => {
                let session_id = params.get_u32("session_id").unwrap_or(0x1234) as u16;
                let target_mac_str = params
                    .get_string("target_mac")
                    .ok_or_else(|| Error::protocol("target_mac parameter required"))?;

                // Parse MAC address
                let target_mac = target_mac_str
                    .parse::<yersinia_core::MacAddr>()
                    .map_err(|_| Error::protocol("Invalid MAC address"))?;

                let attack = PppoeSessionHijackAttack::new(session_id, target_mac.0);

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
                    protocol: "PPPoE".to_string(),
                    attack_name: "Session Hijacking".to_string(),
                    running,
                    paused,
                    stats,
                    started_at: SystemTime::now(),
                    task_handle: Some(task_handle),
                })
            }
            // PPPoE MAC Exhaustion Attack
            3 => {
                let service_name = params
                    .get_string("service_name")
                    .unwrap_or("internet")
                    .to_string();
                let session_count = params.get_u32("session_count").unwrap_or(100);
                let rate_sps = params.get_u32("rate_sps").unwrap_or(10);

                let attack =
                    PppoeMacExhaustionAttack::new(&service_name, session_count).with_rate(rate_sps);

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
                    protocol: "PPPoE".to_string(),
                    attack_name: "MAC Exhaustion".to_string(),
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
