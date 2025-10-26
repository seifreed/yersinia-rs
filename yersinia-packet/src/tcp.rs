//! TCP segment construction and parsing
//!
//! This module provides functionality for building and parsing TCP segments,
//! including header construction, flags, and checksum calculation.

use crate::checksum::transport_checksum;
use bytes::{BufMut, BytesMut};
use std::net::Ipv4Addr;

/// Common TCP port numbers
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TcpPort(pub u16);

impl TcpPort {
    /// FTP Data (20)
    pub const FTP_DATA: TcpPort = TcpPort(20);

    /// FTP Control (21)
    pub const FTP_CONTROL: TcpPort = TcpPort(21);

    /// SSH (22)
    pub const SSH: TcpPort = TcpPort(22);

    /// Telnet (23)
    pub const TELNET: TcpPort = TcpPort(23);

    /// SMTP (25)
    pub const SMTP: TcpPort = TcpPort(25);

    /// HTTP (80)
    pub const HTTP: TcpPort = TcpPort(80);

    /// POP3 (110)
    pub const POP3: TcpPort = TcpPort(110);

    /// HTTPS (443)
    pub const HTTPS: TcpPort = TcpPort(443);

    pub fn new(port: u16) -> Self {
        TcpPort(port)
    }

    pub fn to_u16(self) -> u16 {
        self.0
    }
}

impl From<u16> for TcpPort {
    fn from(port: u16) -> Self {
        TcpPort(port)
    }
}

impl From<TcpPort> for u16 {
    fn from(port: TcpPort) -> Self {
        port.0
    }
}

/// TCP flags
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TcpFlags {
    /// FIN - No more data from sender
    pub fin: bool,
    /// SYN - Synchronize sequence numbers
    pub syn: bool,
    /// RST - Reset the connection
    pub rst: bool,
    /// PSH - Push function
    pub psh: bool,
    /// ACK - Acknowledgment field is significant
    pub ack: bool,
    /// URG - Urgent pointer field is significant
    pub urg: bool,
    /// ECE - ECN-Echo
    pub ece: bool,
    /// CWR - Congestion Window Reduced
    pub cwr: bool,
}

impl TcpFlags {
    /// No flags set
    pub const NONE: TcpFlags = TcpFlags {
        fin: false,
        syn: false,
        rst: false,
        psh: false,
        ack: false,
        urg: false,
        ece: false,
        cwr: false,
    };

    /// SYN flag (connection initiation)
    pub const SYN: TcpFlags = TcpFlags {
        fin: false,
        syn: true,
        rst: false,
        psh: false,
        ack: false,
        urg: false,
        ece: false,
        cwr: false,
    };

    /// SYN+ACK flags (connection acknowledgment)
    pub const SYN_ACK: TcpFlags = TcpFlags {
        fin: false,
        syn: true,
        rst: false,
        psh: false,
        ack: true,
        urg: false,
        ece: false,
        cwr: false,
    };

    /// ACK flag
    pub const ACK: TcpFlags = TcpFlags {
        fin: false,
        syn: false,
        rst: false,
        psh: false,
        ack: true,
        urg: false,
        ece: false,
        cwr: false,
    };

    /// FIN+ACK flags (connection termination)
    pub const FIN_ACK: TcpFlags = TcpFlags {
        fin: true,
        syn: false,
        rst: false,
        psh: false,
        ack: true,
        urg: false,
        ece: false,
        cwr: false,
    };

    /// RST flag (connection reset)
    pub const RST: TcpFlags = TcpFlags {
        fin: false,
        syn: false,
        rst: true,
        psh: false,
        ack: false,
        urg: false,
        ece: false,
        cwr: false,
    };

    /// PSH+ACK flags (push data)
    pub const PSH_ACK: TcpFlags = TcpFlags {
        fin: false,
        syn: false,
        rst: false,
        psh: true,
        ack: true,
        urg: false,
        ece: false,
        cwr: false,
    };

    pub fn new() -> Self {
        TcpFlags::NONE
    }

    /// Convert flags to u8 value
    pub fn to_u8(self) -> u8 {
        let mut flags = 0u8;
        if self.fin {
            flags |= 0b00000001;
        }
        if self.syn {
            flags |= 0b00000010;
        }
        if self.rst {
            flags |= 0b00000100;
        }
        if self.psh {
            flags |= 0b00001000;
        }
        if self.ack {
            flags |= 0b00010000;
        }
        if self.urg {
            flags |= 0b00100000;
        }
        if self.ece {
            flags |= 0b01000000;
        }
        if self.cwr {
            flags |= 0b10000000;
        }
        flags
    }

    /// Parse flags from u8 value
    pub fn from_u8(value: u8) -> Self {
        TcpFlags {
            fin: (value & 0b00000001) != 0,
            syn: (value & 0b00000010) != 0,
            rst: (value & 0b00000100) != 0,
            psh: (value & 0b00001000) != 0,
            ack: (value & 0b00010000) != 0,
            urg: (value & 0b00100000) != 0,
            ece: (value & 0b01000000) != 0,
            cwr: (value & 0b10000000) != 0,
        }
    }
}

impl Default for TcpFlags {
    fn default() -> Self {
        TcpFlags::NONE
    }
}

/// TCP segment
#[derive(Debug, Clone)]
pub struct TcpSegment {
    /// Source port
    pub source_port: TcpPort,
    /// Destination port
    pub destination_port: TcpPort,
    /// Sequence number
    pub sequence_number: u32,
    /// Acknowledgment number
    pub acknowledgment_number: u32,
    /// Data offset in 32-bit words (minimum 5)
    pub data_offset: u8,
    /// Reserved bits (should be 0)
    pub reserved: u8,
    /// TCP flags
    pub flags: TcpFlags,
    /// Window size
    pub window_size: u16,
    /// Checksum
    pub checksum: u16,
    /// Urgent pointer
    pub urgent_pointer: u16,
    /// Options (if data_offset > 5)
    pub options: Vec<u8>,
    /// Payload data
    pub payload: Vec<u8>,
}

impl TcpSegment {
    /// Minimum TCP header size (without options)
    pub const MIN_HEADER_SIZE: usize = 20;

    /// Maximum TCP header size (with maximum options)
    pub const MAX_HEADER_SIZE: usize = 60;

    /// Create a new TCP segment
    pub fn new(
        source_port: TcpPort,
        destination_port: TcpPort,
        sequence_number: u32,
        acknowledgment_number: u32,
        flags: TcpFlags,
        window_size: u16,
        payload: Vec<u8>,
    ) -> Self {
        TcpSegment {
            source_port,
            destination_port,
            sequence_number,
            acknowledgment_number,
            data_offset: 5, // 5 * 4 = 20 bytes (minimum header)
            reserved: 0,
            flags,
            window_size,
            checksum: 0, // Will be calculated
            urgent_pointer: 0,
            options: Vec::new(),
            payload,
        }
    }

    /// Set TCP options
    pub fn with_options(mut self, options: Vec<u8>) -> Self {
        // Options must be padded to 4-byte boundary
        let padded_len = (options.len() + 3) & !3;
        let mut padded_options = options;
        padded_options.resize(padded_len, 0);

        self.options = padded_options;
        self.data_offset = (Self::MIN_HEADER_SIZE + self.options.len()) as u8 / 4;
        self
    }

    /// Set the urgent pointer
    pub fn with_urgent_pointer(mut self, pointer: u16) -> Self {
        self.urgent_pointer = pointer;
        self
    }

    /// Calculate and set the TCP checksum
    ///
    /// The TCP checksum includes a pseudo-header containing the source and
    /// destination IP addresses.
    pub fn calculate_checksum(&mut self, src_ip: Ipv4Addr, dst_ip: Ipv4Addr) {
        // Set checksum to 0 before calculation
        self.checksum = 0;

        // Build TCP segment for checksum
        let data = self.build_for_checksum();

        // Calculate checksum with pseudo-header
        self.checksum = transport_checksum(
            &src_ip.octets(),
            &dst_ip.octets(),
            6, // TCP protocol number
            &data,
        );
    }

    /// Build TCP segment bytes for checksum calculation
    fn build_for_checksum(&self) -> Vec<u8> {
        let header_size = Self::MIN_HEADER_SIZE + self.options.len();
        let mut buffer = BytesMut::with_capacity(header_size + self.payload.len());

        // Source port
        buffer.put_u16(self.source_port.to_u16());

        // Destination port
        buffer.put_u16(self.destination_port.to_u16());

        // Sequence number
        buffer.put_u32(self.sequence_number);

        // Acknowledgment number
        buffer.put_u32(self.acknowledgment_number);

        // Data offset (4 bits) + Reserved (3 bits) + NS flag (1 bit)
        buffer.put_u8((self.data_offset << 4) | (self.reserved & 0x0F));

        // Flags
        buffer.put_u8(self.flags.to_u8());

        // Window size
        buffer.put_u16(self.window_size);

        // Checksum
        buffer.put_u16(self.checksum);

        // Urgent pointer
        buffer.put_u16(self.urgent_pointer);

        // Options
        buffer.put_slice(&self.options);

        // Payload
        buffer.put_slice(&self.payload);

        buffer.to_vec()
    }

    /// Convert the TCP segment to bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        self.build_for_checksum()
    }

    /// Convert the TCP segment to bytes with checksum calculation
    pub fn to_bytes_with_checksum(&self, src_ip: Ipv4Addr, dst_ip: Ipv4Addr) -> Vec<u8> {
        let mut segment = self.clone();
        segment.calculate_checksum(src_ip, dst_ip);
        segment.to_bytes()
    }

    /// Parse a TCP segment from bytes
    pub fn from_bytes(data: &[u8]) -> Option<Self> {
        if data.len() < Self::MIN_HEADER_SIZE {
            return None;
        }

        let source_port = TcpPort::new(u16::from_be_bytes([data[0], data[1]]));
        let destination_port = TcpPort::new(u16::from_be_bytes([data[2], data[3]]));
        let sequence_number = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
        let acknowledgment_number = u32::from_be_bytes([data[8], data[9], data[10], data[11]]);

        let data_offset_and_reserved = data[12];
        let data_offset = data_offset_and_reserved >> 4;
        let reserved = data_offset_and_reserved & 0x0F;

        let flags = TcpFlags::from_u8(data[13]);
        let window_size = u16::from_be_bytes([data[14], data[15]]);
        let checksum = u16::from_be_bytes([data[16], data[17]]);
        let urgent_pointer = u16::from_be_bytes([data[18], data[19]]);

        let header_len = (data_offset as usize) * 4;
        if data.len() < header_len {
            return None;
        }

        let options = if header_len > Self::MIN_HEADER_SIZE {
            data[Self::MIN_HEADER_SIZE..header_len].to_vec()
        } else {
            Vec::new()
        };

        let payload = if data.len() > header_len {
            data[header_len..].to_vec()
        } else {
            Vec::new()
        };

        Some(TcpSegment {
            source_port,
            destination_port,
            sequence_number,
            acknowledgment_number,
            data_offset,
            reserved,
            flags,
            window_size,
            checksum,
            urgent_pointer,
            options,
            payload,
        })
    }

    /// Get the header size in bytes
    pub fn header_len(&self) -> usize {
        (self.data_offset as usize) * 4
    }

    /// Get the total segment size in bytes
    pub fn len(&self) -> usize {
        self.header_len() + self.payload.len()
    }

    /// Check if empty
    pub fn is_empty(&self) -> bool {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tcp_port_constants() {
        assert_eq!(TcpPort::HTTP.0, 80);
        assert_eq!(TcpPort::HTTPS.0, 443);
        assert_eq!(TcpPort::SSH.0, 22);
    }

    #[test]
    fn test_tcp_flags() {
        let flags = TcpFlags::SYN;
        assert!(!flags.fin);
        assert!(flags.syn);
        assert!(!flags.ack);

        let flags_byte = flags.to_u8();
        assert_eq!(flags_byte, 0b00000010);

        let flags2 = TcpFlags::from_u8(flags_byte);
        assert_eq!(flags.syn, flags2.syn);
    }

    #[test]
    fn test_tcp_flags_syn_ack() {
        let flags = TcpFlags::SYN_ACK;
        assert!(flags.syn);
        assert!(flags.ack);

        let flags_byte = flags.to_u8();
        assert_eq!(flags_byte, 0b00010010);
    }

    #[test]
    fn test_tcp_segment_new() {
        let src_port = TcpPort::new(12345);
        let dst_port = TcpPort::HTTP;
        let payload = vec![0x01, 0x02, 0x03, 0x04];

        let segment = TcpSegment::new(
            src_port,
            dst_port,
            1000,
            2000,
            TcpFlags::SYN,
            65535,
            payload,
        );

        assert_eq!(segment.source_port, src_port);
        assert_eq!(segment.destination_port, dst_port);
        assert_eq!(segment.sequence_number, 1000);
        assert_eq!(segment.acknowledgment_number, 2000);
        assert_eq!(segment.flags, TcpFlags::SYN);
        assert_eq!(segment.window_size, 65535);
    }

    #[test]
    fn test_tcp_segment_to_bytes() {
        let src_port = TcpPort::new(12345);
        let dst_port = TcpPort::HTTP;
        let payload = vec![0x01, 0x02, 0x03, 0x04];

        let segment = TcpSegment::new(
            src_port,
            dst_port,
            1000,
            2000,
            TcpFlags::SYN,
            65535,
            payload,
        );
        let bytes = segment.to_bytes();

        // Check ports
        assert_eq!(u16::from_be_bytes([bytes[0], bytes[1]]), 12345);
        assert_eq!(u16::from_be_bytes([bytes[2], bytes[3]]), 80);

        // Check sequence number
        assert_eq!(
            u32::from_be_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]),
            1000
        );

        // Check acknowledgment number
        assert_eq!(
            u32::from_be_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]),
            2000
        );

        // Check data offset
        assert_eq!(bytes[12] >> 4, 5); // 5 * 4 = 20 bytes header

        // Check flags
        assert_eq!(bytes[13], TcpFlags::SYN.to_u8());

        // Check window size
        assert_eq!(u16::from_be_bytes([bytes[14], bytes[15]]), 65535);

        // Check payload
        assert_eq!(&bytes[20..24], &[0x01, 0x02, 0x03, 0x04]);
    }

    #[test]
    fn test_tcp_segment_checksum() {
        let src_ip = Ipv4Addr::new(192, 168, 1, 1);
        let dst_ip = Ipv4Addr::new(192, 168, 1, 2);
        let src_port = TcpPort::new(12345);
        let dst_port = TcpPort::HTTP;
        let payload = vec![0x01, 0x02, 0x03, 0x04];

        let mut segment = TcpSegment::new(
            src_port,
            dst_port,
            1000,
            2000,
            TcpFlags::SYN,
            65535,
            payload,
        );
        segment.calculate_checksum(src_ip, dst_ip);

        // Checksum should be non-zero
        assert_ne!(segment.checksum, 0);
    }

    #[test]
    fn test_tcp_segment_from_bytes() {
        let data = vec![
            0x30, 0x39, // Source port (12345)
            0x00, 0x50, // Dest port (80)
            0x00, 0x00, 0x03, 0xE8, // Sequence (1000)
            0x00, 0x00, 0x07, 0xD0, // Ack (2000)
            0x50, // Data offset (5) + reserved
            0x02, // Flags (SYN)
            0xFF, 0xFF, // Window (65535)
            0x00, 0x00, // Checksum
            0x00, 0x00, // Urgent pointer
            0x01, 0x02, 0x03, 0x04, // Payload
        ];

        let segment = TcpSegment::from_bytes(&data).unwrap();

        assert_eq!(segment.source_port.0, 12345);
        assert_eq!(segment.destination_port.0, 80);
        assert_eq!(segment.sequence_number, 1000);
        assert_eq!(segment.acknowledgment_number, 2000);
        assert_eq!(segment.data_offset, 5);
        assert!(segment.flags.syn);
        assert_eq!(segment.window_size, 65535);
        assert_eq!(segment.payload, vec![0x01, 0x02, 0x03, 0x04]);
    }

    #[test]
    fn test_tcp_segment_roundtrip() {
        let src_ip = Ipv4Addr::new(192, 168, 1, 1);
        let dst_ip = Ipv4Addr::new(192, 168, 1, 2);
        let src_port = TcpPort::new(12345);
        let dst_port = TcpPort::HTTP;
        let payload = vec![0x01, 0x02, 0x03, 0x04];

        let segment1 = TcpSegment::new(
            src_port,
            dst_port,
            1000,
            2000,
            TcpFlags::SYN,
            65535,
            payload,
        );
        let bytes = segment1.to_bytes_with_checksum(src_ip, dst_ip);
        let segment2 = TcpSegment::from_bytes(&bytes).unwrap();

        assert_eq!(segment1.source_port, segment2.source_port);
        assert_eq!(segment1.destination_port, segment2.destination_port);
        assert_eq!(segment1.sequence_number, segment2.sequence_number);
        assert_eq!(
            segment1.acknowledgment_number,
            segment2.acknowledgment_number
        );
        assert_eq!(segment1.flags.to_u8(), segment2.flags.to_u8());
        assert_eq!(segment1.window_size, segment2.window_size);
        assert_eq!(segment1.payload, segment2.payload);
    }

    #[test]
    fn test_tcp_segment_with_options() {
        let src_port = TcpPort::new(12345);
        let dst_port = TcpPort::HTTP;
        let options = vec![0x02, 0x04, 0x05, 0xB4]; // MSS option
        let payload = vec![];

        let segment = TcpSegment::new(
            src_port,
            dst_port,
            1000,
            2000,
            TcpFlags::SYN,
            65535,
            payload,
        )
        .with_options(options.clone());

        assert_eq!(segment.data_offset, 6); // 6 * 4 = 24 bytes header
        assert_eq!(segment.options.len(), 4); // Padded to 4 bytes
    }
}
