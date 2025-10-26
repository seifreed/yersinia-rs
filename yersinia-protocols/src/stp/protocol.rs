//! STP Protocol implementation

use async_trait::async_trait;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::SystemTime;
use yersinia_core::{
    attack::ParamDescriptor,
    protocol::{AttackParams, Protocol, ProtocolStats},
    Attack, AttackDescriptor, AttackHandle, AttackId, Error, Interface, Packet, Parameter,
    ParameterType, ProtocolId, Result,
};

use super::attack::*;
use super::packet::{BpduPacket, BridgeId};

/// Bridge information discovered from BPDUs
#[derive(Debug, Clone)]
pub struct BridgeInfo {
    /// Bridge ID
    _bridge_id: BridgeId,
    /// Root bridge ID (as claimed by this bridge)
    root_id: BridgeId,
    /// Path cost to root
    _path_cost: u32,
    /// Port ID where BPDU was received
    _port_id: u16,
    /// Last time we saw this bridge
    _last_seen: SystemTime,
    /// BPDU version (0=STP, 2=RSTP, 3=MSTP)
    _version: u8,
}

/// STP Protocol implementation
pub struct StpProtocol {
    /// Protocol statistics
    stats: Arc<Mutex<ProtocolStats>>,
    /// Discovered bridges (indexed by MAC address)
    discovered_bridges: Arc<Mutex<HashMap<[u8; 6], BridgeInfo>>>,
}

impl StpProtocol {
    /// Create a new STP protocol instance
    pub fn new() -> Self {
        Self {
            stats: Arc::new(Mutex::new(ProtocolStats::default())),
            discovered_bridges: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Get list of discovered bridges
    pub fn discovered_bridges(&self) -> Vec<BridgeInfo> {
        self.discovered_bridges
            .lock()
            .unwrap()
            .values()
            .cloned()
            .collect()
    }

    /// Get current root bridge (bridge with lowest ID)
    pub fn current_root(&self) -> Option<BridgeInfo> {
        let bridges = self.discovered_bridges.lock().unwrap();
        bridges
            .values()
            .min_by(|a, b| {
                let a_prio = a.root_id.priority;
                let b_prio = b.root_id.priority;
                a_prio
                    .cmp(&b_prio)
                    .then_with(|| a.root_id.mac.0.cmp(&b.root_id.mac.0))
            })
            .cloned()
    }
}

impl Default for StpProtocol {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Protocol for StpProtocol {
    fn name(&self) -> &'static str {
        "Spanning Tree Protocol"
    }

    fn shortname(&self) -> &'static str {
        "stp"
    }

    fn id(&self) -> ProtocolId {
        ProtocolId::STP
    }

    fn attacks(&self) -> &[AttackDescriptor] {
        static ATTACKS: std::sync::OnceLock<Vec<AttackDescriptor>> = std::sync::OnceLock::new();

        ATTACKS.get_or_init(|| {
            vec![
                AttackDescriptor {
                    id: AttackId(0),
                    name: "Send Config BPDU",
                    description: "Send a single Configuration BPDU with custom parameters",
                    parameters: vec![
                        ParamDescriptor::new("bridge_mac", ParameterType::MacAddr)
                            .with_description("Bridge MAC address")
                            .required(),
                        ParamDescriptor::new("priority", ParameterType::U32)
                            .with_description("Bridge priority (0-65535)")
                            .with_default("32768".to_string()),
                        ParamDescriptor::new("root", ParameterType::Bool)
                            .with_description("Claim to be root bridge")
                            .with_default("false".to_string()),
                    ],
                },
                AttackDescriptor {
                    id: AttackId(1),
                    name: "Send TCN BPDU",
                    description: "Send a single Topology Change Notification BPDU",
                    parameters: vec![ParamDescriptor::new("source_mac", ParameterType::MacAddr)
                        .with_description("Source MAC address")
                        .required()],
                },
                AttackDescriptor {
                    id: AttackId(2),
                    name: "DoS with Config BPDUs",
                    description: "Flood network with Config BPDUs causing constant reconvergence",
                    parameters: vec![
                        ParamDescriptor::new("rate_pps", ParameterType::U32)
                            .with_description("Packets per second")
                            .with_default("10".to_string()),
                        ParamDescriptor::new("randomize", ParameterType::Bool)
                            .with_description("Randomize bridge IDs")
                            .with_default("true".to_string()),
                    ],
                },
                AttackDescriptor {
                    id: AttackId(3),
                    name: "DoS with TCN BPDUs",
                    description: "Flood network with TCN BPDUs to flush MAC tables",
                    parameters: vec![ParamDescriptor::new("rate_pps", ParameterType::U32)
                        .with_description("Packets per second")
                        .with_default("10".to_string())],
                },
                AttackDescriptor {
                    id: AttackId(4),
                    name: "Claim Root Role",
                    description: "Continuously claim to be the root bridge (priority 0)",
                    parameters: vec![
                        ParamDescriptor::new("bridge_mac", ParameterType::MacAddr)
                            .with_description("Bridge MAC address")
                            .required(),
                        ParamDescriptor::new("hello_time", ParameterType::U32)
                            .with_description("Hello time in seconds")
                            .with_default("2".to_string()),
                        ParamDescriptor::new("version", ParameterType::String)
                            .with_description("STP version (stp/rstp/mstp)")
                            .with_default("stp".to_string()),
                    ],
                },
                AttackDescriptor {
                    id: AttackId(5),
                    name: "Claim Other Role",
                    description: "Claim to be a specific bridge (not root)",
                    parameters: vec![
                        ParamDescriptor::new("bridge_mac", ParameterType::MacAddr)
                            .with_description("Bridge MAC address to impersonate")
                            .required(),
                        ParamDescriptor::new("priority", ParameterType::U32)
                            .with_description("Bridge priority")
                            .with_default("32768".to_string()),
                        ParamDescriptor::new("root_mac", ParameterType::MacAddr)
                            .with_description("Root bridge MAC address")
                            .required(),
                        ParamDescriptor::new("root_priority", ParameterType::U32)
                            .with_description("Root bridge priority")
                            .with_default("32768".to_string()),
                    ],
                },
                AttackDescriptor {
                    id: AttackId(6),
                    name: "Root Role MITM",
                    description: "Claim root role with man-in-the-middle positioning",
                    parameters: vec![
                        ParamDescriptor::new("bridge_mac", ParameterType::MacAddr)
                            .with_description("Bridge MAC address")
                            .required(),
                        ParamDescriptor::new("interface1", ParameterType::String)
                            .with_description("First network interface")
                            .required(),
                        ParamDescriptor::new("interface2", ParameterType::String)
                            .with_description("Second network interface")
                            .required(),
                    ],
                },
                AttackDescriptor {
                    id: AttackId(7),
                    name: "TCN Flooding",
                    description:
                        "Flood network with Topology Change Notifications to flush MAC tables",
                    parameters: vec![
                        ParamDescriptor::new("bridge_mac", ParameterType::MacAddr)
                            .with_description("Source bridge MAC address")
                            .required(),
                        ParamDescriptor::new("rate", ParameterType::U32)
                            .with_description("Packets per second")
                            .with_default("100".to_string()),
                    ],
                },
                AttackDescriptor {
                    id: AttackId(8),
                    name: "BPDU Filter Bypass",
                    description: "Send BPDUs with characteristics to bypass BPDU filtering",
                    parameters: vec![ParamDescriptor::new("bridge_mac", ParameterType::MacAddr)
                        .with_description("Bridge MAC address")
                        .required()],
                },
                AttackDescriptor {
                    id: AttackId(9),
                    name: "Root Guard Bypass",
                    description: "Attempt to bypass Root Guard protection mechanisms",
                    parameters: vec![ParamDescriptor::new("bridge_mac", ParameterType::MacAddr)
                        .with_description("Bridge MAC address")
                        .required()],
                },
                AttackDescriptor {
                    id: AttackId(10),
                    name: "Loop Creation",
                    description: "Create bridging loops by sending conflicting BPDUs",
                    parameters: vec![ParamDescriptor::new("bridge_mac", ParameterType::MacAddr)
                        .with_description("Bridge MAC address")
                        .required()],
                },
            ]
        })
    }

    fn parameters(&self) -> Vec<Box<dyn Parameter>> {
        // STP doesn't have global parameters, only per-attack parameters
        vec![]
    }

    fn handle_packet(&mut self, packet: &Packet) -> Result<()> {
        // Update stats
        let mut stats = self.stats.lock().unwrap();
        stats.packets_received += 1;

        // Try to parse the BPDU
        // Note: In a real implementation, we would need to skip the Ethernet and LLC headers
        // For now, assume packet.data contains just the BPDU
        match BpduPacket::parse(&packet.data) {
            Ok(bpdu) => {
                match bpdu {
                    BpduPacket::Config(config) | BpduPacket::Rst(config) => {
                        // Extract bridge information
                        let bridge_info = BridgeInfo {
                            _bridge_id: config.bridge_id,
                            root_id: config.root_id,
                            _path_cost: config.root_path_cost,
                            _port_id: config.port_id,
                            _last_seen: SystemTime::now(),
                            _version: config.version,
                        };

                        // Store discovered bridge
                        let mut bridges = self.discovered_bridges.lock().unwrap();
                        bridges.insert(config.bridge_id.mac.0, bridge_info);

                        stats
                            .custom
                            .insert("bridges_discovered".to_string(), bridges.len() as u64);
                    }
                    BpduPacket::Tcn(_) => {
                        stats
                            .custom
                            .entry("tcn_received".to_string())
                            .and_modify(|c| *c += 1)
                            .or_insert(1);
                    }
                    BpduPacket::Mst(mst) => {
                        let bridge_info = BridgeInfo {
                            _bridge_id: mst.config.bridge_id,
                            root_id: mst.config.root_id,
                            _path_cost: mst.config.root_path_cost,
                            _port_id: mst.config.port_id,
                            _last_seen: SystemTime::now(),
                            _version: mst.config.version,
                        };

                        let mut bridges = self.discovered_bridges.lock().unwrap();
                        bridges.insert(mst.config.bridge_id.mac.0, bridge_info);
                    }
                }
            }
            Err(e) => {
                stats.packets_errors += 1;
                return Err(e);
            }
        }

        Ok(())
    }

    async fn launch_attack(
        &self,
        attack_id: AttackId,
        params: AttackParams,
        interface: &Interface,
    ) -> Result<AttackHandle> {
        use std::sync::atomic::AtomicBool;
        use std::sync::Arc;
        use std::time::SystemTime;
        use yersinia_core::AttackStatsCounters;

        let attack_name = match attack_id.0 {
            0 => "Send Config BPDU",
            1 => "Send TCN BPDU",
            2 => "DoS Config",
            3 => "DoS TCN",
            4 => "Claim Root",
            5 => "Claim Other",
            6 => "MITM",
            _ => {
                return Err(Error::NotImplemented(format!(
                    "STP attack ID {}",
                    attack_id.0
                )))
            }
        };

        // Create shared state for attack
        let running = Arc::new(AtomicBool::new(true));
        let paused = Arc::new(AtomicBool::new(false));
        let stats = Arc::new(AttackStatsCounters::default());

        let ctx = yersinia_core::AttackContext {
            interface: interface.clone(),
            running: running.clone(),
            paused: paused.clone(),
            stats: stats.clone(),
        };

        // Launch appropriate attack
        let task_handle = match attack_id.0 {
            0 => {
                let attack = StpSendConfAttack::new(params, interface)?;
                tokio::spawn(async move { attack.execute(ctx).await })
            }
            1 => {
                let attack = StpSendTcnAttack::new(params, interface)?;
                tokio::spawn(async move { attack.execute(ctx).await })
            }
            2 => {
                let attack = StpDosConfAttack::new(params, interface)?;
                tokio::spawn(async move { attack.execute(ctx).await })
            }
            3 => {
                let attack = StpDosTcnAttack::new(params, interface)?;
                tokio::spawn(async move { attack.execute(ctx).await })
            }
            4 => {
                let attack = StpClaimRootAttack::new(params, interface)?;
                tokio::spawn(async move { attack.execute(ctx).await })
            }
            5 => {
                let attack = StpClaimOtherAttack::new(params, interface)?;
                tokio::spawn(async move { attack.execute(ctx).await })
            }
            6 => {
                let attack = StpMitmAttack::new(params, interface)?;
                tokio::spawn(async move { attack.execute(ctx).await })
            }
            _ => unreachable!(),
        };

        Ok(AttackHandle {
            id: uuid::Uuid::now_v7(),
            protocol: "STP".to_string(),
            attack_name: attack_name.to_string(),
            running,
            paused,
            stats,
            started_at: SystemTime::now(),
            task_handle: Some(task_handle),
        })
    }

    fn stats(&self) -> ProtocolStats {
        self.stats.lock().unwrap().clone()
    }

    fn reset_stats(&mut self) {
        let mut stats = self.stats.lock().unwrap();
        *stats = ProtocolStats::default();

        let mut bridges = self.discovered_bridges.lock().unwrap();
        bridges.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_protocol_info() {
        let protocol = StpProtocol::new();
        assert_eq!(protocol.name(), "Spanning Tree Protocol");
        assert_eq!(protocol.shortname(), "stp");
        assert_eq!(protocol.id(), ProtocolId::STP);
    }

    #[test]
    fn test_attacks_available() {
        let protocol = StpProtocol::new();
        let attacks = protocol.attacks();
        assert_eq!(attacks.len(), 11, "Should have 11 STP attacks");

        // Verify attack names
        assert_eq!(attacks[0].name, "Send Config BPDU");
        assert_eq!(attacks[1].name, "Send TCN BPDU");
        assert_eq!(attacks[2].name, "DoS with Config BPDUs");
        assert_eq!(attacks[3].name, "DoS with TCN BPDUs");
        assert_eq!(attacks[4].name, "Claim Root Role");
        assert_eq!(attacks[5].name, "Claim Other Role");
        assert_eq!(attacks[6].name, "Root Role MITM");
    }

    #[test]
    fn test_stats() {
        let mut protocol = StpProtocol::new();
        let stats = protocol.stats();
        assert_eq!(stats.packets_received, 0);

        protocol.reset_stats();
        let stats = protocol.stats();
        assert_eq!(stats.packets_received, 0);
    }
}
