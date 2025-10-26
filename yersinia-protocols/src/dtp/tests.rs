//! Comprehensive tests for DTP implementation
//!
//! This test module provides 20+ tests covering all aspects of DTP:
//! - Packet parsing and building
//! - TLV encoding/decoding
//! - Status and Type byte handling
//! - Protocol implementation
//! - Attack functionality

#[cfg(test)]
mod packet_tests {
    use crate::dtp::packet::*;
    use bytes::{BufMut, BytesMut};
    use yersinia_core::MacAddr;

    #[test]
    fn test_constants() {
        assert_eq!(DTP_VERSION, 0x01);
        assert_eq!(DTP_SNAP_TYPE, 0x2004);
        assert_eq!(DTP_HELLO_INTERVAL, 30);
        assert_eq!(DTP_MULTICAST_MAC.0, [0x01, 0x00, 0x0C, 0xCC, 0xCC, 0xCC]);
    }

    #[test]
    fn test_status_all_combinations() {
        // Test all valid status combinations
        // Note: OFF (0x02) is a special case - neither fully access nor trunk active
        let statuses = vec![
            (DtpStatus::ACCESS_ON, false, true, false, false),
            (DtpStatus::ACCESS_OFF, false, true, false, false), // Still access mode, but disabled
            (DtpStatus::ACCESS_DESIRABLE, false, true, true, false),
            (DtpStatus::ACCESS_AUTO, false, true, false, true),
            (DtpStatus::TRUNK_ON, true, false, false, false),
            (DtpStatus::TRUNK_OFF, true, false, false, false), // Still trunk mode, but disabled
            (DtpStatus::TRUNK_DESIRABLE, true, false, true, false),
            (DtpStatus::TRUNK_AUTO, true, false, false, true),
        ];

        for (value, is_trunk, is_access, is_desirable, is_auto) in statuses {
            let status = DtpStatus::new(value);
            assert_eq!(status.is_trunk(), is_trunk, "Failed for 0x{:02X}", value);
            assert_eq!(status.is_access(), is_access, "Failed for 0x{:02X}", value);
            assert_eq!(
                status.is_desirable(),
                is_desirable,
                "Failed for 0x{:02X}",
                value
            );
            assert_eq!(status.is_auto(), is_auto, "Failed for 0x{:02X}", value);
        }
    }

    #[test]
    fn test_status_operating_admin_split() {
        let status = DtpStatus::new(0x83); // TRUNK_DESIRABLE
        assert_eq!(status.operating_status(), 0x80);
        assert_eq!(status.admin_status(), 0x03);

        let status = DtpStatus::new(0x04); // ACCESS_AUTO
        assert_eq!(status.operating_status(), 0x00);
        assert_eq!(status.admin_status(), 0x04);
    }

    #[test]
    fn test_type_all_combinations() {
        let types = vec![
            (DtpType::DOT1Q_DOT1Q, true, false),
            (DtpType::DOT1Q_ISL, true, false),
            (DtpType::DOT1Q_NATIVE, true, false),
            (DtpType::DOT1Q_NEGOTIATED, true, false),
            (DtpType::ISL_ISL, false, true),
            (DtpType::ISL_DOT1Q, false, true),
            (DtpType::ISL_NATIVE, false, true),
            (DtpType::ISL_NEGOTIATED, false, true),
        ];

        for (value, is_dot1q, is_isl) in types {
            let typ = DtpType::new(value);
            assert_eq!(typ.is_dot1q(), is_dot1q, "Failed for 0x{:02X}", value);
            assert_eq!(typ.is_isl(), is_isl, "Failed for 0x{:02X}", value);
        }
    }

    #[test]
    fn test_type_operating_admin_split() {
        let typ = DtpType::new(0xA5); // DOT1Q_DOT1Q
        assert_eq!(typ.operating_type(), 0xA0);
        assert_eq!(typ.admin_type(), 0x05);

        let typ = DtpType::new(0x42); // ISL_ISL
        assert_eq!(typ.operating_type(), 0x40);
        assert_eq!(typ.admin_type(), 0x02);
    }

    #[test]
    fn test_tlv_domain_encoding() {
        let domain = "testcorp";
        let tlv = DtpTlv::Domain(domain.to_string());

        let mut buf = BytesMut::new();
        tlv.write(&mut buf);

        // Verify encoding
        assert_eq!(buf[0..2], [0x00, 0x01]); // Type
        assert_eq!(buf[2..4], [0x00, 0x0C]); // Length (4 + 8)
        assert_eq!(&buf[4..12], domain.as_bytes());
    }

    #[test]
    fn test_tlv_domain_decoding() {
        let mut buf = BytesMut::new();
        buf.put_u16(tlv_types::DOMAIN);
        buf.put_u16(9); // 4 header + 5 data
        buf.put_slice(b"corp\x00"); // Domain with null terminator

        let mut data = buf.freeze();
        let tlv = DtpTlv::parse(&mut data).unwrap();

        match tlv {
            DtpTlv::Domain(d) => assert_eq!(d, "corp"), // Null should be stripped
            _ => panic!("Expected Domain TLV"),
        }
    }

    #[test]
    fn test_tlv_status_roundtrip() {
        for status_val in [0x03, 0x04, 0x83, 0x84, 0x01, 0x81] {
            let tlv = DtpTlv::Status(DtpStatus::new(status_val));
            let mut buf = BytesMut::new();
            tlv.write(&mut buf);

            let mut data = buf.freeze();
            let parsed = DtpTlv::parse(&mut data).unwrap();

            assert_eq!(tlv, parsed);
        }
    }

    #[test]
    fn test_tlv_type_roundtrip() {
        for type_val in [0xA5, 0x42, 0xA0, 0x21] {
            let tlv = DtpTlv::Type(DtpType::new(type_val));
            let mut buf = BytesMut::new();
            tlv.write(&mut buf);

            let mut data = buf.freeze();
            let parsed = DtpTlv::parse(&mut data).unwrap();

            assert_eq!(tlv, parsed);
        }
    }

    #[test]
    fn test_tlv_neighbor_roundtrip() {
        let mac = MacAddr([0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE]);
        let tlv = DtpTlv::Neighbor(mac);

        let mut buf = BytesMut::new();
        tlv.write(&mut buf);

        let mut data = buf.freeze();
        let parsed = DtpTlv::parse(&mut data).unwrap();

        assert_eq!(tlv, parsed);
    }

    #[test]
    fn test_packet_complete_roundtrip() {
        let mac = MacAddr([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
        let original = DtpPacket::new()
            .with_domain("engineering")
            .with_status(DtpStatus::trunk_desirable())
            .with_type(DtpType::dot1q())
            .with_neighbor(mac);

        let bytes = original.build();
        let parsed = DtpPacket::parse(&bytes).unwrap();

        assert_eq!(original.version, parsed.version);
        assert_eq!(original.domain(), parsed.domain());
        assert_eq!(original.status(), parsed.status());
        assert_eq!(original.trunk_type(), parsed.trunk_type());
        assert_eq!(original.neighbor(), parsed.neighbor());
    }

    #[test]
    fn test_packet_yersinia_default_format() {
        // Test packet with null domain like Yersinia default
        let mac = MacAddr([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]);
        let packet = DtpPacket::new()
            .with_domain("\x00\x00\x00\x00\x00\x00\x00\x00")
            .with_status(DtpStatus::access_desirable())
            .with_type(DtpType::dot1q())
            .with_neighbor(mac);

        let bytes = packet.build();
        let parsed = DtpPacket::parse(&bytes).unwrap();

        // Null domain should parse as empty
        assert_eq!(parsed.domain(), Some(""));
        assert_eq!(parsed.status(), Some(DtpStatus::access_desirable()));
        assert_eq!(parsed.trunk_type(), Some(DtpType::dot1q()));
    }

    #[test]
    fn test_packet_size_calculation() {
        let packet = DtpPacket::new()
            .with_domain("test")
            .with_status(DtpStatus::trunk_on())
            .with_type(DtpType::isl())
            .with_neighbor(MacAddr([0; 6]));

        // 1 (version) + 8 (domain TLV) + 5 (status TLV) + 5 (type TLV) + 10 (neighbor TLV)
        assert_eq!(packet.size(), 29);
    }

    #[test]
    fn test_packet_minimal() {
        // Packet with only version
        let packet = DtpPacket::new();
        assert_eq!(packet.size(), 1);
        assert_eq!(packet.domain(), None);
        assert_eq!(packet.status(), None);
    }

    #[test]
    fn test_packet_partial_tlvs() {
        // Packet with only some TLVs
        let packet = DtpPacket::new()
            .with_status(DtpStatus::trunk_desirable())
            .with_type(DtpType::dot1q());

        assert_eq!(packet.domain(), None);
        assert_eq!(packet.neighbor(), None);
        assert_eq!(packet.status(), Some(DtpStatus::trunk_desirable()));
        assert_eq!(packet.trunk_type(), Some(DtpType::dot1q()));
    }

    #[test]
    fn test_parse_unknown_tlv() {
        let mut buf = BytesMut::new();
        buf.put_u8(0x01); // Version
        buf.put_u16(0xFF99); // Unknown TLV type
        buf.put_u16(6); // Length
        buf.put_u16(0xDEAD); // Random data

        let result = DtpPacket::parse(&buf);
        // Should parse successfully but skip unknown TLV
        assert!(result.is_ok());
    }

    #[test]
    fn test_parse_truncated_tlv() {
        let mut buf = BytesMut::new();
        buf.put_u8(0x01); // Version
        buf.put_u16(tlv_types::DOMAIN); // Domain TLV
        buf.put_u16(100); // Length too long for actual data
        buf.put_slice(b"short");

        let result = DtpPacket::parse(&buf);
        // Should handle gracefully
        assert!(result.is_ok());
    }

    #[test]
    fn test_parse_empty() {
        let buf = Vec::new();
        let result = DtpPacket::parse(&buf);
        assert!(result.is_err());
    }

    #[test]
    fn test_display_formatting() {
        let packet = DtpPacket::new()
            .with_domain("corp")
            .with_status(DtpStatus::trunk_desirable())
            .with_type(DtpType::dot1q());

        let display = format!("{}", packet);
        assert!(display.contains("DTP Packet"));
        assert!(display.contains("Version: 0x01"));
        assert!(display.contains("Domain: \"corp\""));
        assert!(display.contains("TRUNK/DESIRABLE"));
        assert!(display.contains("802.1Q"));
    }

    #[test]
    fn test_long_domain_truncation() {
        // Test domain longer than max length
        let long_domain = "a".repeat(100);
        let packet = DtpPacket::new().with_domain(&long_domain);

        let bytes = packet.build();
        let parsed = DtpPacket::parse(&bytes).unwrap();

        // Domain should be preserved (we don't enforce max in builder)
        assert_eq!(parsed.domain().unwrap().len(), 100);
    }

    #[test]
    fn test_multiple_same_tlv_types() {
        // Build packet with TLVs in specific order
        let mut packet = DtpPacket::new();
        packet.tlvs.push(DtpTlv::Domain("first".to_string()));
        packet.tlvs.push(DtpTlv::Domain("second".to_string()));

        // Should use the first one found
        assert_eq!(packet.domain(), Some("first"));
    }
}

#[cfg(test)]
mod protocol_tests {
    use crate::dtp::protocol::DtpProtocol;
    use yersinia_core::protocol::Protocol;
    use yersinia_core::ProtocolId;

    #[test]
    fn test_protocol_info() {
        let proto = DtpProtocol::new();
        assert_eq!(proto.name(), "Dynamic Trunking Protocol");
        assert_eq!(proto.shortname(), "dtp");
        assert_eq!(proto.id(), ProtocolId::DTP);
    }

    #[test]
    fn test_protocol_attacks_count() {
        let proto = DtpProtocol::new();
        let attacks = proto.attacks();
        assert_eq!(attacks.len(), 1);
    }

    #[test]
    fn test_attack_descriptor() {
        let proto = DtpProtocol::new();
        let attacks = proto.attacks();
        assert_eq!(attacks[0].name, "DTP Trunk Negotiation");
        assert!(attacks[0].description.contains("trunk"));
    }

    #[tokio::test]
    async fn test_neighbor_tracking() {
        let proto = DtpProtocol::new();
        assert_eq!(proto.neighbor_count().await, 0);
    }
}

#[cfg(test)]
mod attack_tests {
    use crate::dtp::attack::DtpNegotiationAttack;
    use crate::dtp::packet::{DtpStatus, DtpType};
    use yersinia_core::{Attack, MacAddr};

    #[test]
    fn test_attack_basic_creation() {
        let mac = MacAddr([0x00, 0x01, 0x02, 0x03, 0x04, 0x05]);
        let attack = DtpNegotiationAttack::new(
            DtpStatus::trunk_desirable(),
            DtpType::dot1q(),
            "testdomain".to_string(),
            mac,
            15000,
        );

        assert_eq!(attack.name(), "DTP Trunk Negotiation");
    }

    #[test]
    fn test_attack_trunk_desirable_preset() {
        let mac = MacAddr([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]);
        let attack = DtpNegotiationAttack::trunk_desirable(mac);

        // Just verify it was created (internal fields are private)
        assert_eq!(attack.name(), "DTP Trunk Negotiation");
    }

    #[test]
    fn test_attack_access_desirable_preset() {
        let mac = MacAddr([0x11, 0x22, 0x33, 0x44, 0x55, 0x66]);
        let attack = DtpNegotiationAttack::access_desirable(mac);

        // Just verify it was created
        assert_eq!(attack.name(), "DTP Trunk Negotiation");
    }

    #[test]
    fn test_attack_control_flow() {
        let mac = MacAddr([0; 6]);
        let attack = DtpNegotiationAttack::trunk_desirable(mac);

        // Test pause/resume/stop using the Attack trait
        attack.pause();
        attack.resume();
        attack.stop();

        // Verify name is correct
        assert_eq!(attack.name(), "DTP Trunk Negotiation");
    }

    #[test]
    fn test_attack_with_isl() {
        let mac = MacAddr([0; 6]);
        let attack = DtpNegotiationAttack::new(
            DtpStatus::trunk_desirable(),
            DtpType::isl(),
            "".to_string(),
            mac,
            30000,
        );

        assert_eq!(attack.name(), "DTP Trunk Negotiation");
    }

    #[test]
    fn test_attack_with_negotiate() {
        let mac = MacAddr([0; 6]);
        let attack = DtpNegotiationAttack::new(
            DtpStatus::trunk_desirable(),
            DtpType::negotiate(),
            "".to_string(),
            mac,
            30000,
        );

        assert_eq!(attack.name(), "DTP Trunk Negotiation");
    }

    #[test]
    fn test_attack_interval_variations() {
        let mac = MacAddr([0; 6]);

        // Fast interval
        let _attack = DtpNegotiationAttack::new(
            DtpStatus::trunk_desirable(),
            DtpType::dot1q(),
            "".to_string(),
            mac,
            1000,
        );

        // Slow interval
        let _attack = DtpNegotiationAttack::new(
            DtpStatus::trunk_desirable(),
            DtpType::dot1q(),
            "".to_string(),
            mac,
            60000,
        );

        // Just verify they can be created with different intervals
    }
}
