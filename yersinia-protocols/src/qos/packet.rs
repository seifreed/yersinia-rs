//! QoS/CoS Packet Structures

// 802.1p Priority (CoS) values
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CosPriority {
    BestEffort = 0,      // Background
    Background = 1,      // Background
    ExcellentEffort = 2, // Spare
    CriticalApps = 3,    // Excellent effort
    Video = 4,           // Controlled load
    Voice = 5,           // Video
    InternetControl = 6, // Voice
    NetworkControl = 7,  // Network control
}

// DSCP (Differentiated Services Code Point) values
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DscpValue {
    Default = 0, // Best effort
    CS1 = 8,     // Class Selector 1
    CS2 = 16,    // Class Selector 2
    CS3 = 24,    // Class Selector 3
    CS4 = 32,    // Class Selector 4
    CS5 = 40,    // Class Selector 5
    CS6 = 48,    // Class Selector 6
    CS7 = 56,    // Class Selector 7
    AF11 = 10,   // Assured Forwarding 11
    AF12 = 12,   // Assured Forwarding 12
    AF13 = 14,   // Assured Forwarding 13
    AF21 = 18,   // Assured Forwarding 21
    AF22 = 20,   // Assured Forwarding 22
    AF23 = 22,   // Assured Forwarding 23
    AF31 = 26,   // Assured Forwarding 31
    AF32 = 28,   // Assured Forwarding 32
    AF33 = 30,   // Assured Forwarding 33
    AF41 = 34,   // Assured Forwarding 41
    AF42 = 36,   // Assured Forwarding 42
    AF43 = 38,   // Assured Forwarding 43
    EF = 46,     // Expedited Forwarding (Voice)
}

#[derive(Debug, Clone)]
pub struct QosPacket {
    pub cos_priority: u8,
    pub dscp_value: u8,
    pub payload_size: usize,
    pub payload: Vec<u8>,
}

impl Default for QosPacket {
    fn default() -> Self {
        Self::new()
    }
}

impl QosPacket {
    pub fn new() -> Self {
        Self {
            cos_priority: 0,
            dscp_value: 0,
            payload_size: 0,
            payload: Vec::new(),
        }
    }

    pub fn with_cos(mut self, priority: CosPriority) -> Self {
        self.cos_priority = priority as u8;
        self
    }

    pub fn with_dscp(mut self, dscp: DscpValue) -> Self {
        self.dscp_value = dscp as u8;
        self
    }

    pub fn with_payload(mut self, payload: Vec<u8>) -> Self {
        self.payload_size = payload.len();
        self.payload = payload;
        self
    }

    pub fn high_priority() -> Self {
        Self::new()
            .with_cos(CosPriority::NetworkControl)
            .with_dscp(DscpValue::EF)
    }

    pub fn voice_priority() -> Self {
        Self::new()
            .with_cos(CosPriority::Voice)
            .with_dscp(DscpValue::EF)
    }

    pub fn video_priority() -> Self {
        Self::new()
            .with_cos(CosPriority::Video)
            .with_dscp(DscpValue::AF41)
    }

    pub fn best_effort() -> Self {
        Self::new()
            .with_cos(CosPriority::BestEffort)
            .with_dscp(DscpValue::Default)
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();

        // Create a simple IP-like header with QoS markings
        // Version (4 bits) + IHL (4 bits) = 0x45 for IPv4 with 20 byte header
        bytes.push(0x45);

        // ToS byte: DSCP (6 bits) + ECN (2 bits)
        let tos = self.dscp_value << 2;
        bytes.push(tos);

        // Total length (2 bytes) - header + payload
        let total_len = 20 + self.payload.len();
        bytes.extend_from_slice(&(total_len as u16).to_be_bytes());

        // ID (2 bytes)
        bytes.extend_from_slice(&[0x00, 0x01]);

        // Flags + Fragment offset (2 bytes)
        bytes.extend_from_slice(&[0x40, 0x00]);

        // TTL (1 byte)
        bytes.push(64);

        // Protocol (1 byte) - UDP
        bytes.push(17);

        // Header checksum (2 bytes) - placeholder
        bytes.extend_from_slice(&[0x00, 0x00]);

        // Source IP (4 bytes)
        bytes.extend_from_slice(&[192, 168, 1, 100]);

        // Dest IP (4 bytes)
        bytes.extend_from_slice(&[192, 168, 1, 1]);

        // Add payload
        bytes.extend_from_slice(&self.payload);

        bytes
    }
}

#[derive(Debug, Clone)]
pub struct Dot1pHeader {
    pub priority: u8, // 3 bits (0-7)
    pub dei: bool,    // Drop Eligible Indicator
    pub vlan_id: u16, // 12 bits
}

impl Dot1pHeader {
    pub fn new(priority: u8, vlan_id: u16) -> Self {
        Self {
            priority: priority & 0x07,
            dei: false,
            vlan_id: vlan_id & 0x0FFF,
        }
    }

    pub fn with_dei(mut self) -> Self {
        self.dei = true;
        self
    }

    pub fn to_tci(&self) -> u16 {
        let priority_bits = (self.priority as u16) << 13;
        let dei_bit = if self.dei { 1u16 << 12 } else { 0 };
        priority_bits | dei_bit | self.vlan_id
    }

    pub fn to_bytes(&self) -> [u8; 2] {
        self.to_tci().to_be_bytes()
    }
}

#[derive(Debug, Clone)]
pub struct IpDscpHeader {
    pub version: u8,
    pub dscp: u8, // 6 bits
    pub ecn: u8,  // 2 bits (Explicit Congestion Notification)
    pub total_length: u16,
}

impl IpDscpHeader {
    pub fn new(dscp: u8) -> Self {
        Self {
            version: 4,
            dscp: dscp & 0x3F,
            ecn: 0,
            total_length: 20,
        }
    }

    pub fn with_ecn(mut self, ecn: u8) -> Self {
        self.ecn = ecn & 0x03;
        self
    }

    pub fn to_tos(&self) -> u8 {
        (self.dscp << 2) | self.ecn
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cos_priority() {
        let pkt = QosPacket::new().with_cos(CosPriority::Voice);
        assert_eq!(pkt.cos_priority, 5);
    }

    #[test]
    fn test_dscp_value() {
        let pkt = QosPacket::new().with_dscp(DscpValue::EF);
        assert_eq!(pkt.dscp_value, 46);
    }

    #[test]
    fn test_high_priority() {
        let pkt = QosPacket::high_priority();
        assert_eq!(pkt.cos_priority, CosPriority::NetworkControl as u8);
        assert_eq!(pkt.dscp_value, DscpValue::EF as u8);
    }

    #[test]
    fn test_dot1p_header() {
        let header = Dot1pHeader::new(5, 100);
        assert_eq!(header.priority, 5);
        assert_eq!(header.vlan_id, 100);
        let tci = header.to_tci();
        assert_eq!((tci >> 13) & 0x07, 5); // Priority bits
        assert_eq!(tci & 0x0FFF, 100); // VLAN ID
    }

    #[test]
    fn test_dscp_header() {
        let header = IpDscpHeader::new(46);
        assert_eq!(header.dscp, 46);
        assert_eq!(header.to_tos(), 46 << 2);
    }

    #[test]
    fn test_dscp_with_ecn() {
        let header = IpDscpHeader::new(46).with_ecn(3);
        assert_eq!(header.ecn, 3);
        assert_eq!(header.to_tos(), (46 << 2) | 3);
    }
}
