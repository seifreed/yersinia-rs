//! VXLAN Packet Structures

use std::net::Ipv4Addr;

pub const VXLAN_UDP_PORT: u16 = 4789;
pub const VXLAN_FLAG_VNI_VALID: u8 = 0x08; // I flag (VNI valid)

/// VXLAN Header
#[derive(Debug, Clone)]
pub struct VxlanHeader {
    /// Flags (8 bits) - bit 3 = I flag (VNI valid)
    pub flags: u8,
    /// Reserved (24 bits)
    pub reserved1: [u8; 3],
    /// VNI - VXLAN Network Identifier (24 bits)
    pub vni: u32,
    /// Reserved (8 bits)
    pub reserved2: u8,
}

impl VxlanHeader {
    pub fn new(vni: u32) -> Self {
        Self {
            flags: VXLAN_FLAG_VNI_VALID,
            reserved1: [0, 0, 0],
            vni: vni & 0x00FFFFFF, // Only 24 bits
            reserved2: 0,
        }
    }

    /// Encode VXLAN header to bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();

        bytes.push(self.flags);
        bytes.extend_from_slice(&self.reserved1);

        // VNI (24 bits) + reserved (8 bits)
        let vni_bytes = self.vni.to_be_bytes();
        bytes.push(vni_bytes[1]); // Upper byte
        bytes.push(vni_bytes[2]); // Middle byte
        bytes.push(vni_bytes[3]); // Lower byte
        bytes.push(self.reserved2);

        bytes
    }

    /// Parse VXLAN header from bytes
    pub fn from_bytes(data: &[u8]) -> Option<Self> {
        if data.len() < 8 {
            return None;
        }

        let flags = data[0];
        let reserved1 = [data[1], data[2], data[3]];

        // VNI (24 bits)
        let vni = u32::from_be_bytes([0, data[4], data[5], data[6]]);
        let reserved2 = data[7];

        Some(Self {
            flags,
            reserved1,
            vni,
            reserved2,
        })
    }

    /// Check if VNI flag is set
    pub fn is_vni_valid(&self) -> bool {
        (self.flags & VXLAN_FLAG_VNI_VALID) != 0
    }
}

/// VXLAN Packet (VXLAN header + Ethernet frame)
#[derive(Debug, Clone)]
pub struct VxlanPacket {
    /// VXLAN header
    pub header: VxlanHeader,
    /// Inner Ethernet frame
    pub inner_ethernet: Vec<u8>,
}

impl VxlanPacket {
    pub fn new(vni: u32, inner_ethernet: Vec<u8>) -> Self {
        Self {
            header: VxlanHeader::new(vni),
            inner_ethernet,
        }
    }

    /// Create VXLAN packet with simple inner frame
    pub fn with_simple_frame(
        vni: u32,
        dst_mac: [u8; 6],
        src_mac: [u8; 6],
        ethertype: u16,
        payload: Vec<u8>,
    ) -> Self {
        let mut inner_frame = Vec::new();

        // Destination MAC
        inner_frame.extend_from_slice(&dst_mac);

        // Source MAC
        inner_frame.extend_from_slice(&src_mac);

        // EtherType
        inner_frame.extend_from_slice(&ethertype.to_be_bytes());

        // Payload
        inner_frame.extend_from_slice(&payload);

        Self::new(vni, inner_frame)
    }

    /// Encode complete VXLAN packet to bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = self.header.to_bytes();
        bytes.extend_from_slice(&self.inner_ethernet);
        bytes
    }

    /// Parse VXLAN packet from bytes
    pub fn from_bytes(data: &[u8]) -> Option<Self> {
        let header = VxlanHeader::from_bytes(data)?;

        if data.len() < 8 {
            return None;
        }

        let inner_ethernet = data[8..].to_vec();

        Some(Self {
            header,
            inner_ethernet,
        })
    }

    /// Get VNI
    pub fn vni(&self) -> u32 {
        self.header.vni
    }
}

/// VXLAN UDP Encapsulation (for complete packet construction)
#[derive(Debug, Clone)]
pub struct VxlanUdpPacket {
    /// Source IP (VTEP)
    pub src_ip: Ipv4Addr,
    /// Destination IP (VTEP or multicast)
    pub dst_ip: Ipv4Addr,
    /// Source port (ephemeral)
    pub src_port: u16,
    /// Destination port (4789)
    pub dst_port: u16,
    /// VXLAN packet
    pub vxlan: VxlanPacket,
}

impl VxlanUdpPacket {
    pub fn new(src_ip: Ipv4Addr, dst_ip: Ipv4Addr, src_port: u16, vxlan: VxlanPacket) -> Self {
        Self {
            src_ip,
            dst_ip,
            src_port,
            dst_port: VXLAN_UDP_PORT,
            vxlan,
        }
    }

    /// Use multicast destination for BUM traffic
    pub fn multicast(src_ip: Ipv4Addr, src_port: u16, vxlan: VxlanPacket) -> Self {
        // VXLAN multicast group (239.1.1.1 is common)
        let multicast_ip = Ipv4Addr::new(239, 1, 1, 1);
        Self::new(src_ip, multicast_ip, src_port, vxlan)
    }

    /// Unicast to specific VTEP
    pub fn unicast(
        src_ip: Ipv4Addr,
        dst_vtep: Ipv4Addr,
        src_port: u16,
        vxlan: VxlanPacket,
    ) -> Self {
        Self::new(src_ip, dst_vtep, src_port, vxlan)
    }

    /// Encode complete UDP/IP packet with VXLAN payload to bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        let vxlan_payload = self.vxlan.to_bytes();
        let udp_length = 8 + vxlan_payload.len() as u16;
        let total_length = 20 + udp_length;

        let mut packet = Vec::new();

        // IPv4 Header (20 bytes, no options)
        packet.push(0x45); // Version (4) + IHL (5)
        packet.push(0x00); // DSCP + ECN
        packet.extend_from_slice(&total_length.to_be_bytes()); // Total Length
        packet.extend_from_slice(&0u16.to_be_bytes()); // Identification
        packet.extend_from_slice(&0u16.to_be_bytes()); // Flags + Fragment Offset
        packet.push(64); // TTL
        packet.push(17); // Protocol (UDP)
        packet.extend_from_slice(&0u16.to_be_bytes()); // Checksum (will calculate)

        // Source IP
        packet.extend_from_slice(&self.src_ip.octets());
        // Destination IP
        packet.extend_from_slice(&self.dst_ip.octets());

        // Calculate IP header checksum
        let checksum = calculate_ipv4_checksum(&packet[0..20]);
        packet[10] = (checksum >> 8) as u8;
        packet[11] = (checksum & 0xFF) as u8;

        // UDP Header (8 bytes)
        packet.extend_from_slice(&self.src_port.to_be_bytes()); // Source Port
        packet.extend_from_slice(&self.dst_port.to_be_bytes()); // Destination Port
        packet.extend_from_slice(&udp_length.to_be_bytes()); // UDP Length
        packet.extend_from_slice(&0u16.to_be_bytes()); // UDP Checksum (optional, set to 0)

        // VXLAN Payload
        packet.extend_from_slice(&vxlan_payload);

        packet
    }
}

/// Calculate IPv4 header checksum
fn calculate_ipv4_checksum(header: &[u8]) -> u16 {
    let mut sum: u32 = 0;

    // Sum all 16-bit words
    for i in (0..header.len()).step_by(2) {
        if i + 1 < header.len() {
            let word = ((header[i] as u32) << 8) | (header[i + 1] as u32);
            sum += word;
        }
    }

    // Fold 32-bit sum to 16 bits
    while (sum >> 16) != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    // One's complement
    !sum as u16
}

/// VXLAN Multicast Group
pub const VXLAN_MULTICAST_BASE: [u8; 4] = [239, 1, 1, 0];

pub fn vni_to_multicast_group(vni: u32) -> Ipv4Addr {
    let group_offset = (vni & 0xFF) as u8;
    Ipv4Addr::new(239, 1, 1, group_offset)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vxlan_header() {
        let header = VxlanHeader::new(12345);
        let bytes = header.to_bytes();

        assert_eq!(bytes.len(), 8);
        assert_eq!(bytes[0], VXLAN_FLAG_VNI_VALID);

        let decoded = VxlanHeader::from_bytes(&bytes).unwrap();
        assert_eq!(decoded.vni, 12345);
        assert!(decoded.is_vni_valid());
    }

    #[test]
    fn test_vxlan_packet() {
        let inner_frame = vec![
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, // dst MAC
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, // src MAC
            0x08, 0x00, // IPv4 ethertype
                  // ... payload would go here
        ];

        let packet = VxlanPacket::new(100, inner_frame.clone());
        let bytes = packet.to_bytes();

        assert_eq!(bytes.len(), 8 + inner_frame.len());

        let decoded = VxlanPacket::from_bytes(&bytes).unwrap();
        assert_eq!(decoded.vni(), 100);
        assert_eq!(decoded.inner_ethernet, inner_frame);
    }

    #[test]
    fn test_vni_to_multicast() {
        let vni = 12345;
        let multicast = vni_to_multicast_group(vni);
        assert_eq!(multicast.octets()[0], 239);
        assert_eq!(multicast.octets()[1], 1);
        assert_eq!(multicast.octets()[2], 1);
    }
}
