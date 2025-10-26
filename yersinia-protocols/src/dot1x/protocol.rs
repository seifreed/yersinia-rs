//! 802.1X Protocol Implementation
//!
//! Implements the Protocol trait for IEEE 802.1X (Port-based Network Access Control)
//! with full support for packet parsing, authentication tracking, statistics, and attacks.

use async_trait::async_trait;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::SystemTime;
use tokio::sync::RwLock;
use yersinia_core::{
    protocol::{AttackParams, Protocol, ProtocolStats},
    Attack, AttackDescriptor, AttackHandle, AttackId, Error, Interface, MacAddr, Packet, Parameter,
    ProtocolId, Result,
};

use super::attack::{
    Dot1xDosAttack, Dot1xEapDowngradeAttack, Dot1xEapTlsBypassAttack, Dot1xMabBypassAttack,
    Dot1xSpoofingAttack, Dot1xSupplicantImpersonationAttack, MacMode, TlsBypassMode,
};
use super::packet::{EapCode, EapPacket, EapolPacket, EapolType};

/// 802.1X Protocol Implementation
pub struct Dot1xProtocol {
    stats: Arc<RwLock<Dot1xStats>>,
    authenticated_clients: Arc<RwLock<HashMap<MacAddr, AuthInfo>>>,
}

/// Internal statistics for 802.1X protocol
#[derive(Debug, Clone, Default)]
struct Dot1xStats {
    /// Base protocol stats
    pub base: ProtocolStats,
    /// Number of EAPOL-Start packets seen
    pub eapol_start_seen: u64,
    /// Number of EAPOL-Logoff packets seen
    pub eapol_logoff_seen: u64,
    /// Number of EAP-Request packets seen
    pub eap_request_seen: u64,
    /// Number of EAP-Response packets seen
    pub eap_response_seen: u64,
    /// Number of EAP-Success packets seen
    pub eap_success_seen: u64,
    /// Number of EAP-Failure packets seen
    pub eap_failure_seen: u64,
    /// Number of EAP-Identity requests seen
    pub eap_identity_requests: u64,
    /// Number of EAP-Identity responses seen
    pub eap_identity_responses: u64,
}

/// Authentication state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthState {
    /// Initial state (no authentication)
    Initial,
    /// EAPOL-Start sent, waiting for authenticator
    Started,
    /// Identity requested by authenticator
    IdentityRequested,
    /// Identity provided by supplicant
    IdentityProvided,
    /// Authentication in progress
    Authenticating,
    /// Authentication succeeded
    Authenticated,
    /// Authentication failed
    Failed,
    /// Logged off
    LoggedOff,
}

/// Information about an authenticated client
#[derive(Debug, Clone)]
pub struct AuthInfo {
    /// MAC address of the client
    _mac: MacAddr,
    /// Identity (username)
    identity: String,
    /// Current authentication state
    state: AuthState,
    /// Last activity timestamp
    last_activity: SystemTime,
}

impl Dot1xProtocol {
    /// Create a new 802.1X protocol instance
    pub fn new() -> Self {
        Self {
            stats: Arc::new(RwLock::new(Dot1xStats::default())),
            authenticated_clients: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Get the number of tracked clients
    pub async fn client_count(&self) -> usize {
        self.authenticated_clients.read().await.len()
    }

    /// Get information about a specific client
    pub async fn get_client(&self, mac: &MacAddr) -> Option<AuthInfo> {
        self.authenticated_clients.read().await.get(mac).cloned()
    }

    /// Process EAPOL packet and extract authentication information
    fn process_eapol_packet(
        &self,
        eapol: &EapolPacket,
        src_mac: MacAddr,
        stats: &mut Dot1xStats,
        clients: &mut HashMap<MacAddr, AuthInfo>,
    ) {
        match eapol.packet_type {
            EapolType::Start => {
                stats.eapol_start_seen += 1;
                // Update or create client entry
                clients
                    .entry(src_mac)
                    .and_modify(|info| {
                        info.state = AuthState::Started;
                        info.last_activity = SystemTime::now();
                    })
                    .or_insert_with(|| AuthInfo {
                        _mac: src_mac,
                        identity: String::new(),
                        state: AuthState::Started,
                        last_activity: SystemTime::now(),
                    });
            }
            EapolType::Logoff => {
                stats.eapol_logoff_seen += 1;
                if let Some(info) = clients.get_mut(&src_mac) {
                    info.state = AuthState::LoggedOff;
                    info.last_activity = SystemTime::now();
                }
            }
            EapolType::EapPacket => {
                // Try to parse EAP packet
                if let Ok(eap) = eapol.parse_eap_body() {
                    self.process_eap_packet(&eap, src_mac, stats, clients);
                }
            }
            _ => {
                // Key, ASF Alert, etc.
            }
        }
    }

    /// Process EAP packet
    fn process_eap_packet(
        &self,
        eap: &EapPacket,
        src_mac: MacAddr,
        stats: &mut Dot1xStats,
        clients: &mut HashMap<MacAddr, AuthInfo>,
    ) {
        match eap.code {
            EapCode::Request => {
                stats.eap_request_seen += 1;
                if let Some(eap_type) = eap.eap_type {
                    if eap_type == super::packet::EapType::Identity {
                        stats.eap_identity_requests += 1;
                        // Authenticator requesting identity
                        if let Some(info) = clients.get_mut(&src_mac) {
                            info.state = AuthState::IdentityRequested;
                            info.last_activity = SystemTime::now();
                        }
                    }
                }
            }
            EapCode::Response => {
                stats.eap_response_seen += 1;
                if let Some(eap_type) = eap.eap_type {
                    if eap_type == super::packet::EapType::Identity {
                        stats.eap_identity_responses += 1;
                        // Extract identity from data
                        let identity = String::from_utf8_lossy(&eap.data).to_string();

                        clients
                            .entry(src_mac)
                            .and_modify(|info| {
                                info.identity = identity.clone();
                                info.state = AuthState::IdentityProvided;
                                info.last_activity = SystemTime::now();
                            })
                            .or_insert_with(|| AuthInfo {
                                _mac: src_mac,
                                identity,
                                state: AuthState::IdentityProvided,
                                last_activity: SystemTime::now(),
                            });
                    } else {
                        // Other EAP types indicate ongoing authentication
                        if let Some(info) = clients.get_mut(&src_mac) {
                            info.state = AuthState::Authenticating;
                            info.last_activity = SystemTime::now();
                        }
                    }
                }
            }
            EapCode::Success => {
                stats.eap_success_seen += 1;
                if let Some(info) = clients.get_mut(&src_mac) {
                    info.state = AuthState::Authenticated;
                    info.last_activity = SystemTime::now();
                }
            }
            EapCode::Failure => {
                stats.eap_failure_seen += 1;
                if let Some(info) = clients.get_mut(&src_mac) {
                    info.state = AuthState::Failed;
                    info.last_activity = SystemTime::now();
                }
            }
        }
    }
}

impl Default for Dot1xProtocol {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Protocol for Dot1xProtocol {
    fn name(&self) -> &'static str {
        "802.1X Port-based Network Access Control"
    }

    fn shortname(&self) -> &'static str {
        "dot1x"
    }

    fn id(&self) -> ProtocolId {
        ProtocolId::DOT1X
    }

    fn attacks(&self) -> &[AttackDescriptor] {
        static ATTACKS: [AttackDescriptor; 6] = [
            AttackDescriptor {
                id: AttackId(0),
                name: "802.1X EAPOL-Start DoS",
                description: "Flood authenticator with EAPOL-Start packets to exhaust resources",
                parameters: vec![],
            },
            AttackDescriptor {
                id: AttackId(1),
                name: "802.1X Identity Spoofing",
                description: "Spoof EAP-Response/Identity to test authentication bypass",
                parameters: vec![],
            },
            AttackDescriptor {
                id: AttackId(2),
                name: "802.1X MAB Bypass",
                description: "Bypass 802.1X by spoofing MAC addresses of authorized devices (MAC Authentication Bypass)",
                parameters: vec![],
            },
            AttackDescriptor {
                id: AttackId(3),
                name: "802.1X EAP Method Downgrade",
                description: "Force downgrade to weaker EAP methods like EAP-MD5 or EAP-GTC",
                parameters: vec![],
            },
            AttackDescriptor {
                id: AttackId(4),
                name: "802.1X Supplicant Impersonation",
                description: "Impersonate legitimate supplicant by cloning MAC address and credentials",
                parameters: vec![],
            },
            AttackDescriptor {
                id: AttackId(5),
                name: "802.1X EAP-TLS Bypass",
                description: "Attempt to bypass EAP-TLS certificate validation using malformed messages or weak certificates",
                parameters: vec![],
            },
        ];

        &ATTACKS
    }

    fn parameters(&self) -> Vec<Box<dyn Parameter>> {
        vec![]
    }

    fn handle_packet(&mut self, packet: &Packet) -> Result<()> {
        // Update basic stats
        let mut stats = self
            .stats
            .try_write()
            .map_err(|_| Error::protocol("Failed to acquire stats lock"))?;

        stats.base.packets_received += 1;
        stats.base.bytes_received += packet.data.len() as u64;

        // Parse Ethernet header to get source MAC
        if packet.data.len() < 14 {
            stats.base.packets_errors += 1;
            return Ok(());
        }

        let src_mac = MacAddr([
            packet.data[6],
            packet.data[7],
            packet.data[8],
            packet.data[9],
            packet.data[10],
            packet.data[11],
        ]);

        // Parse EAPOL packet (skip Ethernet header)
        if packet.data.len() > 14 {
            let eapol_data = &packet.data[14..];
            match EapolPacket::parse(eapol_data) {
                Ok(eapol_packet) => {
                    stats.base.packets_parsed += 1;

                    // Drop stats lock, acquire clients lock
                    drop(stats);

                    let mut clients = self
                        .authenticated_clients
                        .try_write()
                        .map_err(|_| Error::protocol("Failed to acquire clients lock"))?;

                    // Re-acquire stats lock
                    let mut stats = self
                        .stats
                        .try_write()
                        .map_err(|_| Error::protocol("Failed to acquire stats lock"))?;

                    // Process the packet
                    self.process_eapol_packet(&eapol_packet, src_mac, &mut stats, &mut clients);

                    // Update custom stats (extract values first to avoid borrow conflicts)
                    let eapol_start = stats.eapol_start_seen;
                    let eapol_logoff = stats.eapol_logoff_seen;
                    let eap_identity_resp = stats.eap_identity_responses;
                    let eap_success = stats.eap_success_seen;
                    let eap_failure = stats.eap_failure_seen;

                    stats
                        .base
                        .custom
                        .insert("clients_tracked".to_string(), clients.len() as u64);
                    stats
                        .base
                        .custom
                        .insert("eapol_start_seen".to_string(), eapol_start);
                    stats
                        .base
                        .custom
                        .insert("eapol_logoff_seen".to_string(), eapol_logoff);
                    stats
                        .base
                        .custom
                        .insert("eap_identity_responses".to_string(), eap_identity_resp);
                    stats
                        .base
                        .custom
                        .insert("eap_success_seen".to_string(), eap_success);
                    stats
                        .base
                        .custom
                        .insert("eap_failure_seen".to_string(), eap_failure);
                }
                Err(_) => {
                    stats.base.packets_errors += 1;
                }
            }
        } else {
            stats.base.packets_errors += 1;
        }

        Ok(())
    }

    async fn launch_attack(
        &self,
        attack_id: AttackId,
        params: AttackParams,
        interface: &Interface,
    ) -> Result<AttackHandle> {
        match attack_id.0 {
            // 802.1X EAPOL-Start DoS Attack
            0 => {
                // Parse rate_pps parameter
                let rate_pps = params.get_u32("rate_pps").unwrap_or(100);

                // Parse MAC mode parameter
                let mac_mode_str = params.get_string("mac_mode").unwrap_or("random");
                let mac_mode = match mac_mode_str.to_lowercase().as_str() {
                    "random" => MacMode::Random,
                    "pool" => {
                        let pool_size = params.get_u32("pool_size").unwrap_or(100) as usize;
                        MacMode::Pool(pool_size)
                    }
                    "list" => {
                        // Parse MAC address list from parameter
                        if let Some(mac_list_str) = params.get_string("mac_list") {
                            let macs: Vec<MacAddr> = mac_list_str
                                .split(',')
                                .filter_map(|s| s.trim().parse::<MacAddr>().ok())
                                .collect();
                            if macs.is_empty() {
                                MacMode::Random
                            } else {
                                MacMode::List(macs)
                            }
                        } else {
                            MacMode::Random
                        }
                    }
                    _ => MacMode::Random,
                };

                let attack = Dot1xDosAttack::new(rate_pps, mac_mode);

                // Create attack context
                let running = Arc::new(std::sync::atomic::AtomicBool::new(true));
                let paused = Arc::new(std::sync::atomic::AtomicBool::new(false));
                let stats = Arc::new(yersinia_core::AttackStatsCounters::default());

                let ctx = yersinia_core::AttackContext {
                    interface: interface.clone(),
                    running: running.clone(),
                    paused: paused.clone(),
                    stats: stats.clone(),
                };

                // Spawn attack task
                let task_handle = tokio::spawn(async move { attack.execute(ctx).await });

                Ok(AttackHandle {
                    id: uuid::Uuid::now_v7(),
                    protocol: "802.1X".to_string(),
                    attack_name: "EAPOL-Start DoS".to_string(),
                    running,
                    paused,
                    stats,
                    started_at: SystemTime::now(),
                    task_handle: Some(task_handle),
                })
            }

            // 802.1X Identity Spoofing Attack
            1 => {
                // Parse identity parameter
                let identity = params
                    .get_string("identity")
                    .unwrap_or("anonymous")
                    .to_string();

                // Parse source MAC
                let src_mac = if let Some(mac_str) = params.get_string("src_mac") {
                    mac_str.parse::<MacAddr>().map_err(|_| {
                        Error::invalid_parameter("src_mac", "Invalid source MAC address")
                    })?
                } else {
                    // Generate random MAC
                    let mut mac = [0u8; 6];
                    use rand::Rng;
                    let mut rng = rand::thread_rng();
                    rng.fill(&mut mac);
                    mac[0] &= 0xFE; // Ensure unicast
                    MacAddr(mac)
                };

                // Parse EAP identifier
                let eap_identifier = params.get_u32("eap_identifier").unwrap_or(0) as u8;

                // Parse continuous mode
                let continuous = params.get_bool("continuous").unwrap_or(false);
                let interval_ms = params.get_u32("interval_ms").unwrap_or(1000) as u64;

                let mut attack = Dot1xSpoofingAttack::new(identity, src_mac, eap_identifier);
                if continuous {
                    attack = attack.continuous(interval_ms);
                }

                // Create attack context
                let running = Arc::new(std::sync::atomic::AtomicBool::new(true));
                let paused = Arc::new(std::sync::atomic::AtomicBool::new(false));
                let stats = Arc::new(yersinia_core::AttackStatsCounters::default());

                let ctx = yersinia_core::AttackContext {
                    interface: interface.clone(),
                    running: running.clone(),
                    paused: paused.clone(),
                    stats: stats.clone(),
                };

                // Spawn attack task
                let task_handle = tokio::spawn(async move { attack.execute(ctx).await });

                Ok(AttackHandle {
                    id: uuid::Uuid::now_v7(),
                    protocol: "802.1X".to_string(),
                    attack_name: "Identity Spoofing".to_string(),
                    running,
                    paused,
                    stats,
                    started_at: SystemTime::now(),
                    task_handle: Some(task_handle),
                })
            }

            // 802.1X MAB Bypass Attack
            2 => {
                // Parse authorized MAC address
                let authorized_mac = if let Some(mac_str) = params.get_string("authorized_mac") {
                    mac_str.parse::<MacAddr>().map_err(|_| {
                        Error::invalid_parameter("authorized_mac", "Invalid MAC address")
                    })?
                } else {
                    return Err(Error::invalid_parameter(
                        "authorized_mac",
                        "Required parameter missing",
                    ));
                };

                let rate_pps = params.get_u32("rate_pps").unwrap_or(10);

                let attack = Dot1xMabBypassAttack::new(authorized_mac, rate_pps);

                let running = Arc::new(std::sync::atomic::AtomicBool::new(true));
                let paused = Arc::new(std::sync::atomic::AtomicBool::new(false));
                let stats = Arc::new(yersinia_core::AttackStatsCounters::default());

                let ctx = yersinia_core::AttackContext {
                    interface: interface.clone(),
                    running: running.clone(),
                    paused: paused.clone(),
                    stats: stats.clone(),
                };

                let task_handle = tokio::spawn(async move { attack.execute(ctx).await });

                Ok(AttackHandle {
                    id: uuid::Uuid::now_v7(),
                    protocol: "802.1X".to_string(),
                    attack_name: "MAB Bypass".to_string(),
                    running,
                    paused,
                    stats,
                    started_at: SystemTime::now(),
                    task_handle: Some(task_handle),
                })
            }

            // 802.1X EAP Downgrade Attack
            3 => {
                let src_mac = if let Some(mac_str) = params.get_string("src_mac") {
                    mac_str
                        .parse::<MacAddr>()
                        .map_err(|_| Error::invalid_parameter("src_mac", "Invalid MAC address"))?
                } else {
                    // Generate random MAC
                    let mut mac = [0u8; 6];
                    use rand::Rng;
                    let mut rng = rand::thread_rng();
                    rng.fill(&mut mac);
                    mac[0] &= 0xFE;
                    MacAddr(mac)
                };

                let identity = params.get_string("identity").unwrap_or("user").to_string();
                let target_method = params
                    .get_string("target_method")
                    .unwrap_or("MD5")
                    .to_string();

                let attack = Dot1xEapDowngradeAttack::new(src_mac, identity, target_method);

                let running = Arc::new(std::sync::atomic::AtomicBool::new(true));
                let paused = Arc::new(std::sync::atomic::AtomicBool::new(false));
                let stats = Arc::new(yersinia_core::AttackStatsCounters::default());

                let ctx = yersinia_core::AttackContext {
                    interface: interface.clone(),
                    running: running.clone(),
                    paused: paused.clone(),
                    stats: stats.clone(),
                };

                let task_handle = tokio::spawn(async move { attack.execute(ctx).await });

                Ok(AttackHandle {
                    id: uuid::Uuid::now_v7(),
                    protocol: "802.1X".to_string(),
                    attack_name: "EAP Downgrade".to_string(),
                    running,
                    paused,
                    stats,
                    started_at: SystemTime::now(),
                    task_handle: Some(task_handle),
                })
            }

            // 802.1X Supplicant Impersonation Attack
            4 => {
                let target_mac = if let Some(mac_str) = params.get_string("target_mac") {
                    mac_str.parse::<MacAddr>().map_err(|_| {
                        Error::invalid_parameter("target_mac", "Invalid MAC address")
                    })?
                } else {
                    return Err(Error::invalid_parameter(
                        "target_mac",
                        "Required parameter missing",
                    ));
                };

                let identity = params.get_string("identity").unwrap_or("").to_string();

                let attack = Dot1xSupplicantImpersonationAttack::new(target_mac, identity);

                let running = Arc::new(std::sync::atomic::AtomicBool::new(true));
                let paused = Arc::new(std::sync::atomic::AtomicBool::new(false));
                let stats = Arc::new(yersinia_core::AttackStatsCounters::default());

                let ctx = yersinia_core::AttackContext {
                    interface: interface.clone(),
                    running: running.clone(),
                    paused: paused.clone(),
                    stats: stats.clone(),
                };

                let task_handle = tokio::spawn(async move { attack.execute(ctx).await });

                Ok(AttackHandle {
                    id: uuid::Uuid::now_v7(),
                    protocol: "802.1X".to_string(),
                    attack_name: "Supplicant Impersonation".to_string(),
                    running,
                    paused,
                    stats,
                    started_at: SystemTime::now(),
                    task_handle: Some(task_handle),
                })
            }

            // 802.1X EAP-TLS Bypass Attack
            5 => {
                let src_mac = if let Some(mac_str) = params.get_string("src_mac") {
                    mac_str
                        .parse::<MacAddr>()
                        .map_err(|_| Error::invalid_parameter("src_mac", "Invalid MAC address"))?
                } else {
                    // Generate random MAC
                    let mut mac = [0u8; 6];
                    use rand::Rng;
                    let mut rng = rand::thread_rng();
                    rng.fill(&mut mac);
                    mac[0] &= 0xFE;
                    MacAddr(mac)
                };

                let identity = params.get_string("identity").unwrap_or("user").to_string();

                let bypass_mode = match params
                    .get_string("bypass_mode")
                    .unwrap_or("malformed")
                    .to_lowercase()
                    .as_str()
                {
                    "selfsigned" | "self_signed" => TlsBypassMode::SelfSigned,
                    "nullcipher" | "null_cipher" => TlsBypassMode::NullCipher,
                    "expired" => TlsBypassMode::ExpiredCert,
                    _ => TlsBypassMode::Malformed,
                };

                let attack = Dot1xEapTlsBypassAttack::new(src_mac, identity, bypass_mode);

                let running = Arc::new(std::sync::atomic::AtomicBool::new(true));
                let paused = Arc::new(std::sync::atomic::AtomicBool::new(false));
                let stats = Arc::new(yersinia_core::AttackStatsCounters::default());

                let ctx = yersinia_core::AttackContext {
                    interface: interface.clone(),
                    running: running.clone(),
                    paused: paused.clone(),
                    stats: stats.clone(),
                };

                let task_handle = tokio::spawn(async move { attack.execute(ctx).await });

                Ok(AttackHandle {
                    id: uuid::Uuid::now_v7(),
                    protocol: "802.1X".to_string(),
                    attack_name: "EAP-TLS Bypass".to_string(),
                    running,
                    paused,
                    stats,
                    started_at: SystemTime::now(),
                    task_handle: Some(task_handle),
                })
            }

            _ => Err(Error::InvalidAttackId(attack_id.0)),
        }
    }

    fn stats(&self) -> ProtocolStats {
        if let Ok(stats) = self.stats.try_read() {
            stats.base.clone()
        } else {
            ProtocolStats::default()
        }
    }

    fn reset_stats(&mut self) {
        if let Ok(mut stats) = self.stats.try_write() {
            *stats = Dot1xStats::default();
        }
        if let Ok(mut clients) = self.authenticated_clients.try_write() {
            clients.clear();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_protocol_metadata() {
        let dot1x = Dot1xProtocol::new();
        assert_eq!(dot1x.name(), "802.1X Port-based Network Access Control");
        assert_eq!(dot1x.shortname(), "dot1x");
        assert_eq!(dot1x.id(), ProtocolId::DOT1X);
    }

    #[test]
    fn test_protocol_attacks() {
        let dot1x = Dot1xProtocol::new();
        let attacks = dot1x.attacks();
        assert_eq!(attacks.len(), 6);
        assert_eq!(attacks[0].id.0, 0);
        assert_eq!(attacks[0].name, "802.1X EAPOL-Start DoS");
        assert_eq!(attacks[1].id.0, 1);
        assert_eq!(attacks[1].name, "802.1X Identity Spoofing");
    }

    #[test]
    fn test_stats_initialization() {
        let dot1x = Dot1xProtocol::new();
        let stats = dot1x.stats();
        assert_eq!(stats.packets_received, 0);
        assert_eq!(stats.packets_parsed, 0);
        assert_eq!(stats.packets_errors, 0);
    }

    #[tokio::test]
    async fn test_client_count_empty() {
        let dot1x = Dot1xProtocol::new();
        assert_eq!(dot1x.client_count().await, 0);
    }

    #[test]
    fn test_auth_state_values() {
        assert_eq!(AuthState::Initial, AuthState::Initial);
        assert_ne!(AuthState::Started, AuthState::Authenticated);
    }

    #[test]
    fn test_reset_stats() {
        let mut dot1x = Dot1xProtocol::new();
        {
            let mut stats = dot1x.stats.try_write().unwrap();
            stats.base.packets_received = 100;
            stats.eapol_start_seen = 50;
        }

        dot1x.reset_stats();

        let stats = dot1x.stats();
        assert_eq!(stats.packets_received, 0);
    }
}
