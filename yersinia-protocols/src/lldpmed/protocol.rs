//! LLDP-MED Protocol Implementation
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
    DeviceImpersonationAttack, PoEManipulationAttack, VoiceVlanManipulationAttack,
};

pub struct LldpMedProtocol {
    stats: Arc<RwLock<ProtocolStats>>,
}

impl LldpMedProtocol {
    pub fn new() -> Self {
        Self {
            stats: Arc::new(RwLock::new(ProtocolStats::default())),
        }
    }
}

impl Default for LldpMedProtocol {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Protocol for LldpMedProtocol {
    fn name(&self) -> &'static str {
        "LLDP-MED Media Endpoint Discovery"
    }
    fn shortname(&self) -> &'static str {
        "lldpmed"
    }
    fn id(&self) -> ProtocolId {
        ProtocolId::LLDPMED
    }

    fn attacks(&self) -> &[AttackDescriptor] {
        static ATTACKS: [AttackDescriptor; 3] = [
            AttackDescriptor {
                id: AttackId(0),
                name: "Voice VLAN Manipulation",
                description: "Manipulate voice VLAN assignments via LLDP-MED",
                parameters: vec![],
            },
            AttackDescriptor {
                id: AttackId(1),
                name: "PoE Manipulation",
                description: "Manipulate PoE power allocation via LLDP-MED",
                parameters: vec![],
            },
            AttackDescriptor {
                id: AttackId(2),
                name: "Device Impersonation",
                description: "Impersonate IP phones or other MED devices",
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
            // Voice VLAN Manipulation Attack
            0 => {
                let vlan = params.get_u32("vlan").unwrap_or(100) as u16;
                let attack = VoiceVlanManipulationAttack::new(vlan);

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
                    protocol: "LLDP-MED".to_string(),
                    attack_name: "Voice VLAN Manipulation".to_string(),
                    running,
                    paused,
                    stats,
                    started_at: SystemTime::now(),
                    task_handle: Some(task_handle),
                })
            }
            // PoE Manipulation Attack
            1 => {
                let power = params.get_u32("power").unwrap_or(15400) as u16;
                let attack = PoEManipulationAttack::new(power);

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
                    protocol: "LLDP-MED".to_string(),
                    attack_name: "PoE Manipulation".to_string(),
                    running,
                    paused,
                    stats,
                    started_at: SystemTime::now(),
                    task_handle: Some(task_handle),
                })
            }
            // Device Impersonation Attack
            2 => {
                let mut attack = DeviceImpersonationAttack::new();

                // Check if we should impersonate a phone
                if params.get_string("device_type") == Some("phone") {
                    attack = attack.as_phone();
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
                    protocol: "LLDP-MED".to_string(),
                    attack_name: "Device Impersonation".to_string(),
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
