//! ARP Packet Structure and Parsing

use bytes::{BufMut, BytesMut};
use std::net::Ipv4Addr;
use yersinia_core::{Error, Result};

/// ARP EtherType
pub const ETHERTYPE_ARP: u16 = 0x0806;
pub const ETHERTYPE_RARP: u16 = 0x8035;

/// Hardware types
pub const HTYPE_ETHERNET: u16 = 1;

/// Protocol types
pub const PTYPE_IPV4: u16 = 0x0800;

/// ARP Operation Codes
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArpOpcode {
    /// ARP Request
    Request = 1,
    /// ARP Reply
    Reply = 2,
    /// RARP Request
    RarpRequest = 3,
    /// RARP Reply
    RarpReply = 4,
}

impl ArpOpcode {
    pub fn from_u16(val: u16) -> Option<Self> {
        match val {
            1 => Some(Self::Request),
            2 => Some(Self::Reply),
            3 => Some(Self::RarpRequest),
            4 => Some(Self::RarpReply),
            _ => None,
        }
    }
}

/// ARP Packet
#[derive(Debug, Clone)]
pub struct ArpPacket {
    /// Hardware type (typically 1 for Ethernet)
    pub htype: u16,
    /// Protocol type (typically 0x0800 for IPv4)
    pub ptype: u16,
    /// Hardware address length (6 for MAC)
    pub hlen: u8,
    /// Protocol address length (4 for IPv4)
    pub plen: u8,
    /// Operation
    pub operation: ArpOpcode,
    /// Sender hardware address (MAC)
    pub sender_hw_addr: [u8; 6],
    /// Sender protocol address (IP)
    pub sender_proto_addr: Ipv4Addr,
    /// Target hardware address (MAC)
    pub target_hw_addr: [u8; 6],
    /// Target protocol address (IP)
    pub target_proto_addr: Ipv4Addr,
}

impl ArpPacket {
    /// Create new ARP request
    pub fn new_request(sender_mac: [u8; 6], sender_ip: Ipv4Addr, target_ip: Ipv4Addr) -> Self {
        Self {
            htype: HTYPE_ETHERNET,
            ptype: PTYPE_IPV4,
            hlen: 6,
            plen: 4,
            operation: ArpOpcode::Request,
            sender_hw_addr: sender_mac,
            sender_proto_addr: sender_ip,
            target_hw_addr: [0; 6], // Unknown in request
            target_proto_addr: target_ip,
        }
    }

    /// Create new ARP reply
    pub fn new_reply(
        sender_mac: [u8; 6],
        sender_ip: Ipv4Addr,
        target_mac: [u8; 6],
        target_ip: Ipv4Addr,
    ) -> Self {
        Self {
            htype: HTYPE_ETHERNET,
            ptype: PTYPE_IPV4,
            hlen: 6,
            plen: 4,
            operation: ArpOpcode::Reply,
            sender_hw_addr: sender_mac,
            sender_proto_addr: sender_ip,
            target_hw_addr: target_mac,
            target_proto_addr: target_ip,
        }
    }

    /// Create gratuitous ARP (announcement)
    pub fn new_gratuitous(mac: [u8; 6], ip: Ipv4Addr) -> Self {
        Self {
            htype: HTYPE_ETHERNET,
            ptype: PTYPE_IPV4,
            hlen: 6,
            plen: 4,
            operation: ArpOpcode::Request, // or Reply
            sender_hw_addr: mac,
            sender_proto_addr: ip,
            target_hw_addr: [0; 6],
            target_proto_addr: ip, // Same as sender
        }
    }

    /// Parse ARP packet from bytes
    pub fn parse(data: &[u8]) -> Result<Self> {
        if data.len() < 28 {
            return Err(Error::protocol("ARP packet too short"));
        }

        let htype = u16::from_be_bytes([data[0], data[1]]);
        let ptype = u16::from_be_bytes([data[2], data[3]]);
        let hlen = data[4];
        let plen = data[5];
        let op_val = u16::from_be_bytes([data[6], data[7]]);

        let operation =
            ArpOpcode::from_u16(op_val).ok_or_else(|| Error::protocol("Invalid ARP opcode"))?;

        let mut sender_hw_addr = [0u8; 6];
        sender_hw_addr.copy_from_slice(&data[8..14]);

        let sender_proto_addr = Ipv4Addr::new(data[14], data[15], data[16], data[17]);

        let mut target_hw_addr = [0u8; 6];
        target_hw_addr.copy_from_slice(&data[18..24]);

        let target_proto_addr = Ipv4Addr::new(data[24], data[25], data[26], data[27]);

        Ok(Self {
            htype,
            ptype,
            hlen,
            plen,
            operation,
            sender_hw_addr,
            sender_proto_addr,
            target_hw_addr,
            target_proto_addr,
        })
    }

    /// Serialize ARP packet to bytes
    pub fn serialize(&self) -> Vec<u8> {
        let mut buf = BytesMut::with_capacity(28);

        buf.put_u16(self.htype);
        buf.put_u16(self.ptype);
        buf.put_u8(self.hlen);
        buf.put_u8(self.plen);
        buf.put_u16(self.operation as u16);
        buf.put_slice(&self.sender_hw_addr);
        buf.put_slice(&self.sender_proto_addr.octets());
        buf.put_slice(&self.target_hw_addr);
        buf.put_slice(&self.target_proto_addr.octets());

        buf.to_vec()
    }

    /// Check if this is a request
    pub fn is_request(&self) -> bool {
        self.operation == ArpOpcode::Request
    }

    /// Check if this is a reply
    pub fn is_reply(&self) -> bool {
        self.operation == ArpOpcode::Reply
    }

    /// Check if this is gratuitous ARP
    pub fn is_gratuitous(&self) -> bool {
        self.sender_proto_addr == self.target_proto_addr
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_arp_request_creation() {
        let sender_mac = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66];
        let sender_ip = Ipv4Addr::new(192, 168, 1, 1);
        let target_ip = Ipv4Addr::new(192, 168, 1, 2);

        let packet = ArpPacket::new_request(sender_mac, sender_ip, target_ip);

        assert_eq!(packet.operation, ArpOpcode::Request);
        assert_eq!(packet.sender_hw_addr, sender_mac);
        assert_eq!(packet.sender_proto_addr, sender_ip);
        assert_eq!(packet.target_proto_addr, target_ip);
        assert!(packet.is_request());
    }

    #[test]
    fn test_arp_reply_creation() {
        let sender_mac = [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF];
        let target_mac = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66];
        let sender_ip = Ipv4Addr::new(192, 168, 1, 1);
        let target_ip = Ipv4Addr::new(192, 168, 1, 2);

        let packet = ArpPacket::new_reply(sender_mac, sender_ip, target_mac, target_ip);

        assert_eq!(packet.operation, ArpOpcode::Reply);
        assert!(packet.is_reply());
    }

    #[test]
    fn test_arp_gratuitous() {
        let mac = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66];
        let ip = Ipv4Addr::new(192, 168, 1, 100);

        let packet = ArpPacket::new_gratuitous(mac, ip);

        assert!(packet.is_gratuitous());
        assert_eq!(packet.sender_proto_addr, packet.target_proto_addr);
    }

    #[test]
    fn test_arp_serialize_parse() {
        let sender_mac = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66];
        let sender_ip = Ipv4Addr::new(10, 0, 0, 1);
        let target_ip = Ipv4Addr::new(10, 0, 0, 2);

        let packet = ArpPacket::new_request(sender_mac, sender_ip, target_ip);
        let bytes = packet.serialize();

        assert_eq!(bytes.len(), 28);

        let parsed = ArpPacket::parse(&bytes).unwrap();

        assert_eq!(parsed.operation, packet.operation);
        assert_eq!(parsed.sender_hw_addr, packet.sender_hw_addr);
        assert_eq!(parsed.sender_proto_addr, packet.sender_proto_addr);
        assert_eq!(parsed.target_proto_addr, packet.target_proto_addr);
    }
}
