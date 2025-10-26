//! QoS/CoS Protocol Implementation
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
    CosBitManipulationAttack, DscpManipulationAttack, PriorityQueueFloodingAttack, QosBypassMethod,
    QosPolicyBypassAttack,
};
use super::packet::{CosPriority, DscpValue};

pub struct QosProtocol {
    stats: Arc<RwLock<ProtocolStats>>,
}

impl QosProtocol {
    pub fn new() -> Self {
        Self {
            stats: Arc::new(RwLock::new(ProtocolStats::default())),
        }
    }
}

impl Default for QosProtocol {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Protocol for QosProtocol {
    fn name(&self) -> &'static str {
        "QoS/CoS Manipulation"
    }
    fn shortname(&self) -> &'static str {
        "qos"
    }
    fn id(&self) -> ProtocolId {
        ProtocolId::QOS
    }

    fn attacks(&self) -> &[AttackDescriptor] {
        static ATTACKS: [AttackDescriptor; 4] = [
            AttackDescriptor {
                id: AttackId(0),
                name: "CoS Bit Manipulation",
                description: "Manipulate 802.1p CoS priority bits to gain preferential treatment",
                parameters: vec![],
            },
            AttackDescriptor {
                id: AttackId(1),
                name: "DSCP Manipulation",
                description: "Manipulate DSCP values in IP headers for priority escalation",
                parameters: vec![],
            },
            AttackDescriptor {
                id: AttackId(2),
                name: "Priority Queue Flooding",
                description: "Flood high-priority queues to cause DoS",
                parameters: vec![],
            },
            AttackDescriptor {
                id: AttackId(3),
                name: "QoS Policy Bypass",
                description: "Bypass QoS policies and trust boundaries",
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
        match attack_id.0 {
            0 => {
                let priority = params.get_u8("priority").unwrap_or(5);
                let cos_priority = match priority {
                    0 => CosPriority::BestEffort,
                    1 => CosPriority::Background,
                    2 => CosPriority::ExcellentEffort,
                    3 => CosPriority::CriticalApps,
                    4 => CosPriority::Video,
                    5 => CosPriority::Voice,
                    6 => CosPriority::InternetControl,
                    7 => CosPriority::NetworkControl,
                    _ => CosPriority::BestEffort,
                };

                let attack = CosBitManipulationAttack::new(cos_priority)
                    .with_count(params.get_usize("packet_count").unwrap_or(1000))
                    .with_size(params.get_usize("payload_size").unwrap_or(1500));

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
                    protocol: "QoS".to_string(),
                    attack_name: "CoS Manipulation".to_string(),
                    running,
                    paused,
                    stats,
                    started_at: SystemTime::now(),
                    task_handle: Some(task_handle),
                })
            }
            1 => {
                let dscp = params.get_u8("dscp").unwrap_or(46); // EF by default
                let dscp_value = match dscp {
                    0 => DscpValue::Default,
                    10 => DscpValue::AF11,
                    12 => DscpValue::AF12,
                    14 => DscpValue::AF13,
                    46 => DscpValue::EF,
                    48 => DscpValue::CS6,
                    56 => DscpValue::CS7,
                    _ => DscpValue::Default,
                };

                let attack = DscpManipulationAttack::new(dscp_value)
                    .with_count(params.get_usize("packet_count").unwrap_or(1000));

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
                    protocol: "QoS".to_string(),
                    attack_name: "DSCP Manipulation".to_string(),
                    running,
                    paused,
                    stats,
                    started_at: SystemTime::now(),
                    task_handle: Some(task_handle),
                })
            }
            2 => {
                let attack = PriorityQueueFloodingAttack::new()
                    .with_rate(params.get_usize("pps").unwrap_or(10000))
                    .with_duration(params.get_u64("duration").unwrap_or(60));

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
                    protocol: "QoS".to_string(),
                    attack_name: "Priority Flooding".to_string(),
                    running,
                    paused,
                    stats,
                    started_at: SystemTime::now(),
                    task_handle: Some(task_handle),
                })
            }
            3 => {
                let method = params.get_u8("method").unwrap_or(0);
                let bypass_method = match method {
                    0 => QosBypassMethod::CosSpoofing,
                    1 => QosBypassMethod::DscpRemarkingBypass,
                    2 => QosBypassMethod::PriorityEscalation,
                    3 => QosBypassMethod::TrustBoundaryViolation,
                    _ => QosBypassMethod::CosSpoofing,
                };

                let attack = QosPolicyBypassAttack::new(bypass_method)
                    .with_priority(params.get_u8("priority").unwrap_or(7));

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
                    protocol: "QoS".to_string(),
                    attack_name: "Policy Bypass".to_string(),
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
