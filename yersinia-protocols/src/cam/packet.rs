//! CAM Table Exhaustion Packet Structures

#[derive(Debug, Clone)]
pub struct CamPacket {
    pub source_mac: [u8; 6],
    pub destination_mac: [u8; 6],
    pub vlan_id: Option<u16>,
    pub ethertype: u16,
    pub payload: Vec<u8>,
}

impl CamPacket {
    pub fn new(source_mac: [u8; 6]) -> Self {
        Self {
            source_mac,
            destination_mac: [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF],
            vlan_id: None,
            ethertype: 0x0800, // IPv4
            payload: vec![0; 64],
        }
    }

    pub fn with_destination(mut self, mac: [u8; 6]) -> Self {
        self.destination_mac = mac;
        self
    }

    pub fn with_vlan(mut self, vlan: u16) -> Self {
        self.vlan_id = Some(vlan);
        self
    }

    pub fn with_payload(mut self, payload: Vec<u8>) -> Self {
        self.payload = payload;
        self
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();

        bytes.extend_from_slice(&self.destination_mac);
        bytes.extend_from_slice(&self.source_mac);

        if let Some(vlan_id) = self.vlan_id {
            // 802.1Q VLAN tag
            bytes.extend_from_slice(&0x8100u16.to_be_bytes());
            bytes.extend_from_slice(&vlan_id.to_be_bytes());
        }

        bytes.extend_from_slice(&self.ethertype.to_be_bytes());
        bytes.extend_from_slice(&self.payload);

        bytes
    }
}

#[derive(Debug, Clone)]
pub struct MacAddressGenerator {
    counter: u64,
    vendor_prefix: [u8; 3],
    randomize: bool,
}

impl Default for MacAddressGenerator {
    fn default() -> Self {
        Self::new()
    }
}

impl Iterator for MacAddressGenerator {
    type Item = [u8; 6];

    fn next(&mut self) -> Option<Self::Item> {
        if self.randomize {
            use rand::Rng;
            let mut rng = rand::thread_rng();
            let mut mac: [u8; 6] = rng.gen();
            // Ensure it's unicast (clear LSB of first byte)
            mac[0] &= 0xFE;
            // Ensure it's locally administered (set second LSB)
            mac[0] |= 0x02;
            Some(mac)
        } else {
            self.counter += 1;
            let counter_bytes = self.counter.to_be_bytes();

            Some([
                self.vendor_prefix[0],
                self.vendor_prefix[1],
                self.vendor_prefix[2],
                counter_bytes[5],
                counter_bytes[6],
                counter_bytes[7],
            ])
        }
    }
}

impl MacAddressGenerator {
    pub fn new() -> Self {
        Self {
            counter: 0,
            vendor_prefix: [0x00, 0x11, 0x22],
            randomize: false,
        }
    }

    pub fn with_vendor_prefix(mut self, prefix: [u8; 3]) -> Self {
        self.vendor_prefix = prefix;
        self
    }

    pub fn with_randomization(mut self) -> Self {
        self.randomize = true;
        self
    }

    pub fn generate_batch(&mut self, count: usize) -> Vec<[u8; 6]> {
        self.take(count).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cam_packet() {
        let src = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];
        let pkt = CamPacket::new(src);
        assert_eq!(pkt.source_mac, src);
        assert_eq!(pkt.destination_mac, [0xFF; 6]);
    }

    #[test]
    fn test_cam_packet_with_vlan() {
        let src = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];
        let pkt = CamPacket::new(src).with_vlan(100);
        assert_eq!(pkt.vlan_id, Some(100));
    }

    #[test]
    fn test_cam_packet_to_bytes() {
        let src = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];
        let pkt = CamPacket::new(src);
        let bytes = pkt.to_bytes();
        assert!(bytes.len() >= 6 + 6 + 2); // dst + src + ethertype
    }

    #[test]
    fn test_mac_generator() {
        let mut gen = MacAddressGenerator::new();
        let mac1 = gen.next().unwrap();
        let mac2 = gen.next().unwrap();

        assert_ne!(mac1, mac2);
        assert_eq!(&mac1[0..3], &[0x00, 0x11, 0x22]);
    }

    #[test]
    fn test_mac_generator_custom_prefix() {
        let mut gen = MacAddressGenerator::new().with_vendor_prefix([0xAA, 0xBB, 0xCC]);
        let mac = gen.next().unwrap();
        assert_eq!(&mac[0..3], &[0xAA, 0xBB, 0xCC]);
    }

    #[test]
    fn test_mac_generator_batch() {
        let mut gen = MacAddressGenerator::new();
        let macs = gen.generate_batch(100);
        assert_eq!(macs.len(), 100);

        // Check uniqueness
        let unique_count = macs.iter().collect::<std::collections::HashSet<_>>().len();
        assert_eq!(unique_count, 100);
    }

    #[test]
    fn test_randomized_generator() {
        let mut gen = MacAddressGenerator::new().with_randomization();
        let mac1 = gen.next().unwrap();
        let mac2 = gen.next().unwrap();

        // Should be different (with very high probability)
        assert_ne!(mac1, mac2);

        // Should be unicast (LSB of first byte clear)
        assert_eq!(mac1[0] & 0x01, 0);
        assert_eq!(mac2[0] & 0x01, 0);

        // Should be locally administered (second LSB set)
        assert_eq!(mac1[0] & 0x02, 0x02);
        assert_eq!(mac2[0] & 0x02, 0x02);
    }
}
