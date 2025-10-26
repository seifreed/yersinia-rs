//! Comprehensive tests for 802.1X protocol implementation

use super::constants::*;
use super::*;
use yersinia_core::{protocol::Protocol, MacAddr, ProtocolId};

// ===== Packet Tests =====

#[test]
fn test_eapol_start_build_parse() {
    let packet = EapolPacket::start();
    let bytes = packet.build();
    let parsed = EapolPacket::parse(&bytes).unwrap();

    assert_eq!(parsed.version, EAPOL_VERSION_1);
    assert_eq!(parsed.packet_type, EapolType::Start);
    assert_eq!(parsed.body.len(), 0);
}

#[test]
fn test_eapol_logoff_build_parse() {
    let packet = EapolPacket::logoff();
    let bytes = packet.build();
    let parsed = EapolPacket::parse(&bytes).unwrap();

    assert_eq!(parsed.packet_type, EapolType::Logoff);
    assert_eq!(parsed.body.len(), 0);
}

#[test]
fn test_eap_response_identity_build_parse() {
    let identity = "testuser@example.com";
    let packet = EapPacket::response_identity(42, identity);

    assert_eq!(packet.code, EapCode::Response);
    assert_eq!(packet.identifier, 42);
    assert_eq!(packet.eap_type, Some(EapType::Identity));
    assert_eq!(packet.data, identity.as_bytes());

    let bytes = packet.build();
    let parsed = EapPacket::parse(&bytes).unwrap();

    assert_eq!(parsed.code, packet.code);
    assert_eq!(parsed.identifier, packet.identifier);
    assert_eq!(parsed.eap_type, packet.eap_type);
    assert_eq!(parsed.data, packet.data);
}

#[test]
fn test_eap_request_identity_build_parse() {
    let packet = EapPacket::request_identity(5);

    assert_eq!(packet.code, EapCode::Request);
    assert_eq!(packet.identifier, 5);
    assert_eq!(packet.eap_type, Some(EapType::Identity));

    let bytes = packet.build();
    let parsed = EapPacket::parse(&bytes).unwrap();
    assert_eq!(parsed.code, packet.code);
}

#[test]
fn test_eap_success_build_parse() {
    let packet = EapPacket::success(10);

    assert_eq!(packet.code, EapCode::Success);
    assert_eq!(packet.identifier, 10);
    assert_eq!(packet.eap_type, None);

    let bytes = packet.build();
    assert_eq!(bytes.len(), 4); // Header only

    let parsed = EapPacket::parse(&bytes).unwrap();
    assert_eq!(parsed.code, EapCode::Success);
    assert_eq!(parsed.identifier, 10);
}

#[test]
fn test_eap_failure_build_parse() {
    let packet = EapPacket::failure(20);

    assert_eq!(packet.code, EapCode::Failure);
    assert_eq!(packet.identifier, 20);

    let bytes = packet.build();
    let parsed = EapPacket::parse(&bytes).unwrap();
    assert_eq!(parsed.code, EapCode::Failure);
}

#[test]
fn test_eapol_with_eap_packet() {
    let eap = EapPacket::response_identity(3, "admin");
    let eapol = EapolPacket::eap_packet(eap.clone());

    assert_eq!(eapol.packet_type, EapolType::EapPacket);
    assert_eq!(eapol.body, eap.build());

    // Parse back the EAP from EAPOL body
    let parsed_eap = eapol.parse_eap_body().unwrap();
    assert_eq!(parsed_eap.code, EapCode::Response);
    assert_eq!(parsed_eap.identifier, 3);
    assert_eq!(parsed_eap.data, b"admin");
}

#[test]
fn test_eapol_version_2() {
    let packet = EapolPacket::start().with_version(EAPOL_VERSION_2);
    assert_eq!(packet.version, EAPOL_VERSION_2);

    let bytes = packet.build();
    let parsed = EapolPacket::parse(&bytes).unwrap();
    assert_eq!(parsed.version, EAPOL_VERSION_2);
}

#[test]
fn test_eapol_version_3() {
    let packet = EapolPacket::start().with_version(EAPOL_VERSION_3);
    assert_eq!(packet.version, EAPOL_VERSION_3);

    let bytes = packet.build();
    assert_eq!(bytes[0], EAPOL_VERSION_3);
}

#[test]
fn test_eap_with_custom_data() {
    let custom_data = vec![0xAA, 0xBB, 0xCC, 0xDD];
    let packet = EapPacket::new(EapCode::Response, 7)
        .with_type(EapType::Md5Challenge)
        .with_data(custom_data.clone());

    assert_eq!(packet.data, custom_data);

    let bytes = packet.build();
    let parsed = EapPacket::parse(&bytes).unwrap();
    assert_eq!(parsed.data, custom_data);
}

// ===== Attack Tests =====

#[test]
fn test_dos_attack_random_macs() {
    let attack = Dot1xDosAttack::random_macs(200);
    assert_eq!(attack.rate_pps, 200);
    assert_eq!(attack.mac_mode, attack::MacMode::Random);
}

#[test]
fn test_dos_attack_with_pool() {
    let attack = Dot1xDosAttack::with_mac_pool(500, 100);
    assert_eq!(attack.rate_pps, 500);
    assert_eq!(attack.mac_pool.len(), 100);
}

#[test]
fn test_dos_attack_with_specific_macs() {
    let macs = vec![
        MacAddr([0x00, 0x01, 0x02, 0x03, 0x04, 0x05]),
        MacAddr([0x00, 0x01, 0x02, 0x03, 0x04, 0x06]),
        MacAddr([0x00, 0x01, 0x02, 0x03, 0x04, 0x07]),
    ];

    let attack = Dot1xDosAttack::with_mac_list(300, macs.clone());
    assert_eq!(attack.rate_pps, 300);
    assert_eq!(attack.mac_pool.len(), 3);
    assert_eq!(attack.mac_pool, macs);
}

#[test]
fn test_dos_attack_rate_limits() {
    // Test minimum rate
    let attack = Dot1xDosAttack::random_macs(0);
    assert_eq!(attack.rate_pps, 1);

    // Test maximum rate
    let attack = Dot1xDosAttack::random_macs(50000);
    assert_eq!(attack.rate_pps, MAX_DOS_RATE_PPS);

    // Test normal rate
    let attack = Dot1xDosAttack::random_macs(1000);
    assert_eq!(attack.rate_pps, 1000);
}

#[test]
fn test_spoofing_attack_creation() {
    let mac = MacAddr([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]);
    let attack = Dot1xSpoofingAttack::new("admin@corp.com".to_string(), mac, 15);

    assert_eq!(attack.identity, "admin@corp.com");
    assert_eq!(attack.src_mac, mac);
    assert_eq!(attack.eap_identifier, 15);
    assert!(!attack.continuous);
}

#[test]
fn test_spoofing_attack_one_shot() {
    let mac = MacAddr([0x11, 0x22, 0x33, 0x44, 0x55, 0x66]);
    let attack = Dot1xSpoofingAttack::one_shot("guest".to_string(), mac);

    assert_eq!(attack.identity, "guest");
    assert_eq!(attack.src_mac, mac);
    assert_eq!(attack.eap_identifier, DEFAULT_EAP_IDENTIFIER);
    assert!(!attack.continuous);
}

#[test]
fn test_spoofing_attack_continuous_mode() {
    let mac = MacAddr([0; 6]);
    let attack = Dot1xSpoofingAttack::new("test".to_string(), mac, 1).continuous(2000);

    assert!(attack.continuous);
    assert_eq!(attack.interval_ms, 2000);
}

// ===== Protocol Tests =====

#[test]
fn test_protocol_creation() {
    let protocol = Dot1xProtocol::new();
    assert_eq!(protocol.name(), "802.1X Port-based Network Access Control");
    assert_eq!(protocol.shortname(), "dot1x");
    assert_eq!(protocol.id(), ProtocolId::DOT1X);
}

#[test]
fn test_protocol_attacks_list() {
    let protocol = Dot1xProtocol::new();
    let attacks = protocol.attacks();

    assert_eq!(attacks.len(), 6);

    // DoS attack
    assert_eq!(attacks[0].id.0, 0);
    assert_eq!(attacks[0].name, "802.1X EAPOL-Start DoS");

    // Spoofing attack
    assert_eq!(attacks[1].id.0, 1);
    assert_eq!(attacks[1].name, "802.1X Identity Spoofing");
}

#[tokio::test]
async fn test_protocol_client_tracking() {
    let protocol = Dot1xProtocol::new();
    assert_eq!(protocol.client_count().await, 0);

    // Client count should start at 0
    let count = protocol.client_count().await;
    assert_eq!(count, 0);
}

#[test]
fn test_protocol_stats_initialization() {
    let protocol = Dot1xProtocol::new();
    let stats = protocol.stats();

    assert_eq!(stats.packets_received, 0);
    assert_eq!(stats.packets_parsed, 0);
    assert_eq!(stats.packets_errors, 0);
    assert_eq!(stats.bytes_received, 0);
}

#[test]
fn test_protocol_stats_reset() {
    let mut protocol = Dot1xProtocol::new();

    // Reset stats (this clears everything)
    protocol.reset_stats();

    let stats = protocol.stats();
    assert_eq!(stats.packets_received, 0);
    assert_eq!(stats.packets_parsed, 0);
}

// ===== Constants Tests =====

#[test]
fn test_eapol_constants() {
    assert_eq!(EAPOL_VERSION_1, 0x01);
    assert_eq!(EAPOL_VERSION_2, 0x02);
    assert_eq!(EAPOL_VERSION_3, 0x03);

    assert_eq!(EAPOL_TYPE_EAP_PACKET, 0x00);
    assert_eq!(EAPOL_TYPE_START, 0x01);
    assert_eq!(EAPOL_TYPE_LOGOFF, 0x02);
    assert_eq!(EAPOL_TYPE_KEY, 0x03);
}

#[test]
fn test_eap_constants() {
    assert_eq!(EAP_CODE_REQUEST, 0x01);
    assert_eq!(EAP_CODE_RESPONSE, 0x02);
    assert_eq!(EAP_CODE_SUCCESS, 0x03);
    assert_eq!(EAP_CODE_FAILURE, 0x04);

    assert_eq!(EAP_TYPE_IDENTITY, 0x01);
    assert_eq!(EAP_TYPE_NOTIFICATION, 0x02);
    assert_eq!(EAP_TYPE_MD5_CHALLENGE, 0x04);
    assert_eq!(EAP_TYPE_TLS, 0x0D);
}

#[test]
fn test_dot1x_multicast_mac() {
    assert_eq!(DOT1X_PAE_MULTICAST.0, [0x01, 0x80, 0xC2, 0x00, 0x00, 0x03]);
}

#[test]
fn test_ethertype() {
    assert_eq!(DOT1X_ETHERTYPE, 0x888E);
}

// ===== Edge Cases and Error Handling =====

#[test]
fn test_eapol_parse_too_short() {
    let data = vec![0x01, 0x00]; // Only 2 bytes, need at least 4
    assert!(EapolPacket::parse(&data).is_err());
}

#[test]
fn test_eap_parse_too_short() {
    let data = vec![0x01, 0x00, 0x00]; // Only 3 bytes, need at least 4
    assert!(EapPacket::parse(&data).is_err());
}

#[test]
fn test_eapol_invalid_type() {
    let data = vec![0x01, 0xFF, 0x00, 0x00]; // Invalid type 0xFF
    assert!(EapolPacket::parse(&data).is_err());
}

#[test]
fn test_eap_invalid_code() {
    let data = vec![0xFF, 0x00, 0x00, 0x04]; // Invalid code 0xFF
    assert!(EapPacket::parse(&data).is_err());
}

#[test]
fn test_eapol_parse_eap_body_wrong_type() {
    let eapol = EapolPacket::logoff();
    assert!(eapol.parse_eap_body().is_err());
}

#[test]
fn test_empty_identity() {
    let packet = EapPacket::response_identity(1, "");
    assert_eq!(packet.data.len(), 0);

    let bytes = packet.build();
    let parsed = EapPacket::parse(&bytes).unwrap();
    assert_eq!(parsed.data.len(), 0);
}

#[test]
fn test_long_identity() {
    let long_identity = "a".repeat(200);
    let packet = EapPacket::response_identity(1, &long_identity);
    assert_eq!(packet.data.len(), 200);

    let bytes = packet.build();
    let parsed = EapPacket::parse(&bytes).unwrap();
    assert_eq!(parsed.data.len(), 200);
    assert_eq!(String::from_utf8_lossy(&parsed.data), long_identity);
}

#[test]
fn test_eap_type_all_variants() {
    let types = vec![
        EapType::Identity,
        EapType::Notification,
        EapType::Nak,
        EapType::Md5Challenge,
        EapType::Otp,
        EapType::Gtc,
        EapType::Tls,
        EapType::Leap,
        EapType::Sim,
        EapType::Ttls,
        EapType::Aka,
        EapType::Peap,
        EapType::MsChapV2,
        EapType::Tlv,
        EapType::Fast,
    ];

    for eap_type in types {
        let byte = eap_type.to_byte();
        let parsed = EapType::from_byte(byte).unwrap();
        assert_eq!(parsed, eap_type);
    }
}

#[test]
fn test_auth_state_transitions() {
    use protocol::AuthState;

    assert_ne!(AuthState::Initial, AuthState::Started);
    assert_ne!(AuthState::Started, AuthState::Authenticated);
    assert_eq!(AuthState::Failed, AuthState::Failed);
}
