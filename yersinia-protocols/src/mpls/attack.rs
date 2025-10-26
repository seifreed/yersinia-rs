//! MPLS Attack Implementations
//!
//! This module implements MPLS attacks for sending packets with MPLS encapsulation.

use super::packet::MplsPacket;
use async_trait::async_trait;
use std::net::Ipv4Addr;
use std::sync::atomic::Ordering;
use std::time::Duration;
use tokio::time;
use yersinia_core::{Attack, AttackContext, AttackStats, Result};
use yersinia_packet::{EtherType, EthernetFrame, MacAddress};

/// Type of payload to encapsulate in MPLS
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MplsPayloadType {
    /// TCP payload
    Tcp,
    /// UDP payload
    Udp,
    /// ICMP payload
    Icmp,
}

/// MPLS Send Attack
///
/// Sends MPLS-encapsulated packets with different payload types.
/// Supports single label or label stacking (double header).
#[derive(Debug, Clone)]
pub struct MplsSendAttack {
    /// Payload type (TCP, UDP, or ICMP)
    pub payload_type: MplsPayloadType,
    /// Use double MPLS header (label stacking)
    pub use_double_header: bool,
    /// Primary MPLS label
    pub label1: u32,
    /// EXP bits for label1
    pub exp1: u8,
    /// TTL for label1
    pub ttl1: u8,
    /// Secondary MPLS label (used if use_double_header = true)
    pub label2: u32,
    /// EXP bits for label2
    pub exp2: u8,
    /// TTL for label2
    pub ttl2: u8,
    /// Source IP address for payload
    pub src_ip: Ipv4Addr,
    /// Destination IP address for payload
    pub dst_ip: Ipv4Addr,
    /// Source port (for TCP/UDP)
    pub src_port: u16,
    /// Destination port (for TCP/UDP)
    pub dst_port: u16,
    /// IP payload data
    pub ip_payload: Vec<u8>,
}

impl MplsSendAttack {
    /// Create a new MPLS send attack with single header
    pub fn new_single(payload_type: MplsPayloadType, label: u32, exp: u8, ttl: u8) -> Self {
        Self {
            payload_type,
            use_double_header: false,
            label1: label,
            exp1: exp,
            ttl1: ttl,
            label2: 0,
            exp2: 0,
            ttl2: 0,
            src_ip: Ipv4Addr::new(10, 0, 0, 1),
            dst_ip: Ipv4Addr::new(10, 0, 0, 2),
            src_port: 666,
            dst_port: 1998,
            ip_payload: b"YERSINIA".to_vec(),
        }
    }

    /// Create a new MPLS send attack with double header (label stacking)
    pub fn new_double(
        payload_type: MplsPayloadType,
        label1: u32,
        exp1: u8,
        ttl1: u8,
        label2: u32,
        exp2: u8,
        ttl2: u8,
    ) -> Self {
        Self {
            payload_type,
            use_double_header: true,
            label1,
            exp1,
            ttl1,
            label2,
            exp2,
            ttl2,
            src_ip: Ipv4Addr::new(10, 0, 0, 1),
            dst_ip: Ipv4Addr::new(10, 0, 0, 2),
            src_port: 666,
            dst_port: 1998,
            ip_payload: b"YERSINIA".to_vec(),
        }
    }

    /// Set source IP
    pub fn with_src_ip(mut self, ip: Ipv4Addr) -> Self {
        self.src_ip = ip;
        self
    }

    /// Set destination IP
    pub fn with_dst_ip(mut self, ip: Ipv4Addr) -> Self {
        self.dst_ip = ip;
        self
    }

    /// Set source port
    pub fn with_src_port(mut self, port: u16) -> Self {
        self.src_port = port;
        self
    }

    /// Set destination port
    pub fn with_dst_port(mut self, port: u16) -> Self {
        self.dst_port = port;
        self
    }

    /// Set IP payload
    pub fn with_payload(mut self, payload: Vec<u8>) -> Self {
        self.ip_payload = payload;
        self
    }

    /// Build the complete MPLS packet
    pub fn build_packet(&self) -> MplsPacket {
        // Build inner payload based on type
        let inner_payload = self.build_inner_payload();

        // Create MPLS packet
        if self.use_double_header {
            MplsPacket::new_double(
                self.label1,
                self.exp1,
                self.ttl1,
                self.label2,
                self.exp2,
                self.ttl2,
                inner_payload,
            )
        } else {
            MplsPacket::new_single(self.label1, self.exp1, self.ttl1, inner_payload)
        }
    }

    /// Build inner payload based on payload type
    fn build_inner_payload(&self) -> Vec<u8> {
        // For now, return a simple payload
        // In a full implementation, this would build proper TCP/UDP/ICMP packets
        match self.payload_type {
            MplsPayloadType::Tcp => {
                // Simplified TCP payload (normally would use yersinia-packet builder)
                let mut payload = Vec::new();
                payload.extend_from_slice(&self.src_ip.octets());
                payload.extend_from_slice(&self.dst_ip.octets());
                payload.extend_from_slice(&self.src_port.to_be_bytes());
                payload.extend_from_slice(&self.dst_port.to_be_bytes());
                payload.extend_from_slice(&self.ip_payload);
                payload
            }
            MplsPayloadType::Udp => {
                // Simplified UDP payload
                let mut payload = Vec::new();
                payload.extend_from_slice(&self.src_ip.octets());
                payload.extend_from_slice(&self.dst_ip.octets());
                payload.extend_from_slice(&self.src_port.to_be_bytes());
                payload.extend_from_slice(&self.dst_port.to_be_bytes());
                payload.extend_from_slice(&self.ip_payload);
                payload
            }
            MplsPayloadType::Icmp => {
                // Simplified ICMP payload
                let mut payload = Vec::new();
                payload.extend_from_slice(&self.src_ip.octets());
                payload.extend_from_slice(&self.dst_ip.octets());
                payload.extend_from_slice(&self.ip_payload);
                payload
            }
        }
    }

    /// Get attack name
    pub fn name(&self) -> &'static str {
        match (self.payload_type, self.use_double_header) {
            (MplsPayloadType::Tcp, false) => "Send TCP MPLS packet",
            (MplsPayloadType::Tcp, true) => "Send TCP MPLS with double header",
            (MplsPayloadType::Udp, false) => "Send UDP MPLS packet",
            (MplsPayloadType::Udp, true) => "Send UDP MPLS with double header",
            (MplsPayloadType::Icmp, false) => "Send ICMP MPLS packet",
            (MplsPayloadType::Icmp, true) => "Send ICMP MPLS with double header",
        }
    }
}

#[async_trait]
impl Attack for MplsSendAttack {
    async fn execute(&self, ctx: AttackContext) -> Result<()> {
        let interval = Duration::from_millis(100); // Send MPLS packets frequently

        while ctx.running.load(Ordering::Relaxed) {
            while ctx.paused.load(Ordering::Relaxed) && ctx.running.load(Ordering::Relaxed) {
                time::sleep(Duration::from_millis(100)).await;
            }

            if !ctx.running.load(Ordering::Relaxed) {
                break;
            }

            let mpls_packet = self.build_packet();
            let mpls_bytes = mpls_packet.serialize();

            // MPLS uses unicast - send to broadcast or specific destination
            let dst_mac = MacAddress([0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]);
            let src_mac = MacAddress(ctx.interface.mac_address.0);

            let frame = EthernetFrame::new(dst_mac, src_mac, EtherType::MPLS, mpls_bytes);
            let frame_bytes = frame.to_bytes();

            if let Err(e) = ctx.interface.send_raw(&frame_bytes) {
                ctx.stats.increment_errors();
                eprintln!("Error sending MPLS packet: {}", e);
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
        match (self.payload_type, self.use_double_header) {
            (MplsPayloadType::Tcp, false) => "Send TCP MPLS packet",
            (MplsPayloadType::Tcp, true) => "Send TCP MPLS with double header",
            (MplsPayloadType::Udp, false) => "Send UDP MPLS packet",
            (MplsPayloadType::Udp, true) => "Send UDP MPLS with double header",
            (MplsPayloadType::Icmp, false) => "Send ICMP MPLS packet",
            (MplsPayloadType::Icmp, true) => "Send ICMP MPLS with double header",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mpls_attack_single_tcp() {
        let attack = MplsSendAttack::new_single(MplsPayloadType::Tcp, 100, 3, 64);
        assert_eq!(attack.payload_type, MplsPayloadType::Tcp);
        assert!(!attack.use_double_header);
        assert_eq!(attack.label1, 100);
        assert_eq!(attack.exp1, 3);
        assert_eq!(attack.ttl1, 64);
    }

    #[test]
    fn test_mpls_attack_double_udp() {
        let attack = MplsSendAttack::new_double(MplsPayloadType::Udp, 100, 1, 64, 200, 2, 32);
        assert_eq!(attack.payload_type, MplsPayloadType::Udp);
        assert!(attack.use_double_header);
        assert_eq!(attack.label1, 100);
        assert_eq!(attack.label2, 200);
    }

    #[test]
    fn test_mpls_attack_builder_pattern() {
        let attack = MplsSendAttack::new_single(MplsPayloadType::Tcp, 100, 3, 64)
            .with_src_ip(Ipv4Addr::new(192, 168, 1, 1))
            .with_dst_ip(Ipv4Addr::new(192, 168, 1, 2))
            .with_src_port(1234)
            .with_dst_port(5678)
            .with_payload(b"TEST".to_vec());

        assert_eq!(attack.src_ip, Ipv4Addr::new(192, 168, 1, 1));
        assert_eq!(attack.dst_ip, Ipv4Addr::new(192, 168, 1, 2));
        assert_eq!(attack.src_port, 1234);
        assert_eq!(attack.dst_port, 5678);
        assert_eq!(attack.ip_payload, b"TEST");
    }

    #[test]
    fn test_mpls_attack_build_packet_single() {
        let attack = MplsSendAttack::new_single(MplsPayloadType::Tcp, 500, 4, 128);
        let packet = attack.build_packet();

        assert_eq!(packet.label1.label, 500);
        assert_eq!(packet.label1.exp, 4);
        assert_eq!(packet.label1.ttl, 128);
        assert!(packet.label1.bottom_of_stack);
        assert!(packet.label2.is_none());
    }

    #[test]
    fn test_mpls_attack_build_packet_double() {
        let attack = MplsSendAttack::new_double(MplsPayloadType::Icmp, 1000, 3, 255, 2000, 5, 200);
        let packet = attack.build_packet();

        assert_eq!(packet.label1.label, 1000);
        assert!(!packet.label1.bottom_of_stack);
        assert!(packet.label2.is_some());

        let label2 = packet.label2.unwrap();
        assert_eq!(label2.label, 2000);
        assert!(label2.bottom_of_stack);
    }

    #[test]
    fn test_mpls_attack_names() {
        let tcp_single = MplsSendAttack::new_single(MplsPayloadType::Tcp, 100, 0, 64);
        assert_eq!(tcp_single.name(), "Send TCP MPLS packet");

        let tcp_double = MplsSendAttack::new_double(MplsPayloadType::Tcp, 100, 0, 64, 200, 0, 32);
        assert_eq!(tcp_double.name(), "Send TCP MPLS with double header");

        let udp_single = MplsSendAttack::new_single(MplsPayloadType::Udp, 100, 0, 64);
        assert_eq!(udp_single.name(), "Send UDP MPLS packet");

        let icmp_double = MplsSendAttack::new_double(MplsPayloadType::Icmp, 100, 0, 64, 200, 0, 32);
        assert_eq!(icmp_double.name(), "Send ICMP MPLS with double header");
    }
}
