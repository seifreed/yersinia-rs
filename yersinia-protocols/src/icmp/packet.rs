//! ICMP Packet Structures

use std::net::Ipv4Addr;

pub const ICMP_PROTOCOL: u8 = 1;

/// ICMP Message Types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum IcmpType {
    EchoReply = 0,
    DestinationUnreachable = 3,
    SourceQuench = 4,
    Redirect = 5,
    EchoRequest = 8,
    RouterAdvertisement = 9,
    RouterSolicitation = 10,
    TimeExceeded = 11,
    ParameterProblem = 12,
    Timestamp = 13,
    TimestampReply = 14,
    InformationRequest = 15,
    InformationReply = 16,
}

/// ICMP Redirect Codes
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum RedirectCode {
    Network = 0,
    Host = 1,
    TosNetwork = 2,
    TosHost = 3,
}

/// ICMP Packet
#[derive(Debug, Clone)]
pub struct IcmpPacket {
    pub icmp_type: IcmpType,
    pub code: u8,
    pub checksum: u16,
    pub data: Vec<u8>,
}

impl IcmpPacket {
    /// Create ICMP Echo Request (Ping)
    pub fn echo_request(id: u16, seq: u16, payload: Vec<u8>) -> Self {
        let mut data = Vec::with_capacity(4 + payload.len());
        data.extend_from_slice(&id.to_be_bytes());
        data.extend_from_slice(&seq.to_be_bytes());
        data.extend_from_slice(&payload);

        let mut packet = Self {
            icmp_type: IcmpType::EchoRequest,
            code: 0,
            checksum: 0,
            data,
        };
        packet.calculate_checksum();
        packet
    }

    /// Create ICMP Redirect packet
    pub fn redirect(code: RedirectCode, gateway: Ipv4Addr, original_ip_header: &[u8]) -> Self {
        let mut data = Vec::with_capacity(4 + original_ip_header.len());
        data.extend_from_slice(&gateway.octets());
        data.extend_from_slice(original_ip_header);

        let mut packet = Self {
            icmp_type: IcmpType::Redirect,
            code: code as u8,
            checksum: 0,
            data,
        };
        packet.calculate_checksum();
        packet
    }

    /// Create Router Advertisement packet
    pub fn router_advertisement(
        num_addrs: u8,
        addr_entry_size: u8,
        lifetime: u16,
        addresses: Vec<(Ipv4Addr, u32)>,
    ) -> Self {
        let mut data = Vec::new();
        data.push(num_addrs);
        data.push(addr_entry_size);
        data.extend_from_slice(&lifetime.to_be_bytes());

        for (addr, preference) in addresses {
            data.extend_from_slice(&addr.octets());
            data.extend_from_slice(&preference.to_be_bytes());
        }

        let mut packet = Self {
            icmp_type: IcmpType::RouterAdvertisement,
            code: 0,
            checksum: 0,
            data,
        };
        packet.calculate_checksum();
        packet
    }

    /// Create Destination Unreachable packet
    pub fn destination_unreachable(code: u8, original_ip_header: &[u8]) -> Self {
        let mut data = vec![0u8; 4]; // Unused field
        data.extend_from_slice(original_ip_header);

        let mut packet = Self {
            icmp_type: IcmpType::DestinationUnreachable,
            code,
            checksum: 0,
            data,
        };
        packet.calculate_checksum();
        packet
    }

    /// Encode packet to bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(8 + self.data.len());
        bytes.push(self.icmp_type as u8);
        bytes.push(self.code);
        bytes.extend_from_slice(&self.checksum.to_be_bytes());
        bytes.extend_from_slice(&self.data);
        bytes
    }

    /// Calculate and set checksum
    pub fn calculate_checksum(&mut self) {
        self.checksum = 0;
        let bytes = self.to_bytes();
        self.checksum = internet_checksum(&bytes);
    }

    /// Parse ICMP packet from bytes
    pub fn from_bytes(data: &[u8]) -> Option<Self> {
        if data.len() < 8 {
            return None;
        }

        let icmp_type = match data[0] {
            0 => IcmpType::EchoReply,
            3 => IcmpType::DestinationUnreachable,
            4 => IcmpType::SourceQuench,
            5 => IcmpType::Redirect,
            8 => IcmpType::EchoRequest,
            9 => IcmpType::RouterAdvertisement,
            10 => IcmpType::RouterSolicitation,
            11 => IcmpType::TimeExceeded,
            _ => return None,
        };

        Some(Self {
            icmp_type,
            code: data[1],
            checksum: u16::from_be_bytes([data[2], data[3]]),
            data: data[4..].to_vec(),
        })
    }
}

/// Calculate Internet checksum (RFC 1071)
fn internet_checksum(data: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut i = 0;

    while i < data.len() - 1 {
        sum += u16::from_be_bytes([data[i], data[i + 1]]) as u32;
        i += 2;
    }

    if i < data.len() {
        sum += (data[i] as u32) << 8;
    }

    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    !sum as u16
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_echo_request() {
        let packet = IcmpPacket::echo_request(1, 1, vec![0x42; 32]);
        let bytes = packet.to_bytes();

        assert_eq!(bytes[0], 8); // Echo Request
        assert!(packet.checksum != 0);

        let parsed = IcmpPacket::from_bytes(&bytes).unwrap();
        assert_eq!(parsed.icmp_type, IcmpType::EchoRequest);
    }

    #[test]
    fn test_redirect() {
        let gateway = Ipv4Addr::new(192, 168, 1, 1);
        let ip_header = vec![0x45, 0x00, 0x00, 0x1c];

        let packet = IcmpPacket::redirect(RedirectCode::Host, gateway, &ip_header);
        let bytes = packet.to_bytes();

        assert_eq!(bytes[0], 5); // Redirect
        assert_eq!(bytes[1], 1); // Host code
    }

    #[test]
    fn test_checksum() {
        let mut packet = IcmpPacket::echo_request(1, 1, vec![]);
        assert!(packet.checksum != 0);

        // Verify checksum is correct
        packet.checksum = 0;
        let expected = internet_checksum(&packet.to_bytes());
        packet.calculate_checksum();
        assert_eq!(packet.checksum, expected);
    }
}
