//! Storm Generation Packet Structures

pub const BROADCAST_MAC: [u8; 6] = [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF];
pub const IPV4_MULTICAST_BASE: [u8; 6] = [0x01, 0x00, 0x5E, 0x00, 0x00, 0x00];
pub const IPV6_MULTICAST_BASE: [u8; 6] = [0x33, 0x33, 0x00, 0x00, 0x00, 0x00];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StormType {
    Broadcast,
    Multicast,
    UnknownUnicast,
}

#[derive(Debug, Clone)]
pub struct StormPacket {
    pub storm_type: StormType,
    pub destination_mac: [u8; 6],
    pub source_mac: [u8; 6],
    pub ethertype: u16,
    pub payload_size: usize,
    pub payload: Vec<u8>,
}

impl StormPacket {
    pub fn new(storm_type: StormType) -> Self {
        let destination_mac = match storm_type {
            StormType::Broadcast => BROADCAST_MAC,
            StormType::Multicast => IPV4_MULTICAST_BASE,
            StormType::UnknownUnicast => [0x00, 0x00, 0x00, 0x00, 0x00, 0x01],
        };

        Self {
            storm_type,
            destination_mac,
            source_mac: [0x00, 0x11, 0x22, 0x33, 0x44, 0x55],
            ethertype: 0x0800, // IPv4
            payload_size: 1500,
            payload: vec![0xAA; 1500],
        }
    }

    pub fn broadcast() -> Self {
        Self::new(StormType::Broadcast)
    }

    pub fn multicast() -> Self {
        Self::new(StormType::Multicast)
    }

    pub fn unknown_unicast() -> Self {
        Self::new(StormType::UnknownUnicast)
    }

    pub fn with_source(mut self, mac: [u8; 6]) -> Self {
        self.source_mac = mac;
        self
    }

    pub fn with_payload_size(mut self, size: usize) -> Self {
        self.payload_size = size;
        self.payload = vec![0xAA; size];
        self
    }

    pub fn with_ethertype(mut self, ethertype: u16) -> Self {
        self.ethertype = ethertype;
        self
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&self.destination_mac);
        bytes.extend_from_slice(&self.source_mac);
        bytes.extend_from_slice(&self.ethertype.to_be_bytes());
        bytes.extend_from_slice(&self.payload);
        bytes
    }
}

#[derive(Debug, Clone)]
pub struct StormConfig {
    pub packets_per_second: usize,
    pub duration_seconds: u64,
    pub packet_size: usize,
    pub randomize_source: bool,
}

impl Default for StormConfig {
    fn default() -> Self {
        Self::new()
    }
}

impl StormConfig {
    pub fn new() -> Self {
        Self {
            packets_per_second: 10000,
            duration_seconds: 60,
            packet_size: 1500,
            randomize_source: false,
        }
    }

    pub fn with_rate(mut self, pps: usize) -> Self {
        self.packets_per_second = pps;
        self
    }

    pub fn with_duration(mut self, seconds: u64) -> Self {
        self.duration_seconds = seconds;
        self
    }

    pub fn with_packet_size(mut self, size: usize) -> Self {
        self.packet_size = size;
        self
    }

    pub fn with_randomized_source(mut self) -> Self {
        self.randomize_source = true;
        self
    }

    pub fn total_packets(&self) -> usize {
        self.packets_per_second * self.duration_seconds as usize
    }

    pub fn total_bytes(&self) -> u64 {
        (self.total_packets() * self.packet_size) as u64
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_broadcast_packet() {
        let pkt = StormPacket::broadcast();
        assert_eq!(pkt.storm_type, StormType::Broadcast);
        assert_eq!(pkt.destination_mac, BROADCAST_MAC);
    }

    #[test]
    fn test_multicast_packet() {
        let pkt = StormPacket::multicast();
        assert_eq!(pkt.storm_type, StormType::Multicast);
        assert_eq!(&pkt.destination_mac[0..3], &IPV4_MULTICAST_BASE[0..3]);
    }

    #[test]
    fn test_unknown_unicast() {
        let pkt = StormPacket::unknown_unicast();
        assert_eq!(pkt.storm_type, StormType::UnknownUnicast);
    }

    #[test]
    fn test_packet_to_bytes() {
        let pkt = StormPacket::broadcast().with_payload_size(100);
        let bytes = pkt.to_bytes();
        assert_eq!(bytes.len(), 6 + 6 + 2 + 100); // dst + src + ethertype + payload
    }

    #[test]
    fn test_storm_config() {
        let config = StormConfig::new()
            .with_rate(1000)
            .with_duration(10)
            .with_packet_size(512);

        assert_eq!(config.packets_per_second, 1000);
        assert_eq!(config.duration_seconds, 10);
        assert_eq!(config.total_packets(), 10000);
    }

    #[test]
    fn test_total_bytes() {
        let config = StormConfig::new()
            .with_rate(1000)
            .with_duration(1)
            .with_packet_size(1500);

        assert_eq!(config.total_bytes(), 1500000);
    }
}
