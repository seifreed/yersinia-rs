//! UDLD Packet Structures

pub const UDLD_MULTICAST: [u8; 6] = [0x01, 0x00, 0x0C, 0xCC, 0xCC, 0xCC];
pub const UDLD_SNAP_PID: [u8; 3] = [0x01, 0x11, 0x00]; // Cisco SNAP Protocol ID

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UdldOpcode {
    Reserved = 0x00,
    Probe = 0x01,
    Echo = 0x02,
    Flush = 0x03,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UdldTlvType {
    DeviceId = 0x0001,
    PortId = 0x0002,
    EchoInterval = 0x0003,
    DeviceName = 0x0004,
    SequenceNumber = 0x0005,
    MessageInterval = 0x0006,
    TimeoutInterval = 0x0007,
    Echo = 0x0008,
}

#[derive(Debug, Clone)]
pub struct UdldTlv {
    pub tlv_type: u16,
    pub length: u16,
    pub value: Vec<u8>,
}

impl UdldTlv {
    pub fn new(tlv_type: u16, value: Vec<u8>) -> Self {
        let length = value.len() as u16;
        Self {
            tlv_type,
            length,
            value,
        }
    }

    pub fn device_id(device_id: &str) -> Self {
        Self::new(UdldTlvType::DeviceId as u16, device_id.as_bytes().to_vec())
    }

    pub fn port_id(port_id: &str) -> Self {
        Self::new(UdldTlvType::PortId as u16, port_id.as_bytes().to_vec())
    }

    pub fn echo_interval(interval: u8) -> Self {
        Self::new(UdldTlvType::EchoInterval as u16, vec![interval])
    }

    pub fn message_interval(interval: u8) -> Self {
        Self::new(UdldTlvType::MessageInterval as u16, vec![interval])
    }

    pub fn timeout_interval(interval: u8) -> Self {
        Self::new(UdldTlvType::TimeoutInterval as u16, vec![interval])
    }

    pub fn sequence_number(seq: u32) -> Self {
        Self::new(
            UdldTlvType::SequenceNumber as u16,
            seq.to_be_bytes().to_vec(),
        )
    }

    pub fn echo(neighbor_device: &str, neighbor_port: &str) -> Self {
        let mut value = Vec::new();
        value.extend_from_slice(neighbor_device.as_bytes());
        value.push(0);
        value.extend_from_slice(neighbor_port.as_bytes());
        Self::new(UdldTlvType::Echo as u16, value)
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&self.tlv_type.to_be_bytes());
        bytes.extend_from_slice(&self.length.to_be_bytes());
        bytes.extend_from_slice(&self.value);
        bytes
    }
}

#[derive(Debug, Clone)]
pub struct UdldPacket {
    pub version: u8,
    pub opcode: u8,
    pub flags: u8,
    pub checksum: u16,
    pub tlvs: Vec<UdldTlv>,
}

impl UdldPacket {
    pub fn new(opcode: UdldOpcode) -> Self {
        Self {
            version: 0x01,
            opcode: opcode as u8,
            flags: 0x00,
            checksum: 0,
            tlvs: Vec::new(),
        }
    }

    pub fn probe(device_id: &str, port_id: &str) -> Self {
        let mut pkt = Self::new(UdldOpcode::Probe);
        pkt.tlvs.push(UdldTlv::device_id(device_id));
        pkt.tlvs.push(UdldTlv::port_id(port_id));
        pkt.tlvs.push(UdldTlv::echo_interval(15));
        pkt.tlvs.push(UdldTlv::message_interval(15));
        pkt.tlvs.push(UdldTlv::timeout_interval(5));
        pkt
    }

    pub fn echo(
        device_id: &str,
        port_id: &str,
        neighbor_device: &str,
        neighbor_port: &str,
    ) -> Self {
        let mut pkt = Self::new(UdldOpcode::Echo);
        pkt.tlvs.push(UdldTlv::device_id(device_id));
        pkt.tlvs.push(UdldTlv::port_id(port_id));
        pkt.tlvs.push(UdldTlv::echo(neighbor_device, neighbor_port));
        pkt
    }

    pub fn flush(device_id: &str, port_id: &str) -> Self {
        let mut pkt = Self::new(UdldOpcode::Flush);
        pkt.tlvs.push(UdldTlv::device_id(device_id));
        pkt.tlvs.push(UdldTlv::port_id(port_id));
        pkt
    }

    pub fn with_tlv(mut self, tlv: UdldTlv) -> Self {
        self.tlvs.push(tlv);
        self
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.push(self.version);
        bytes.push(self.opcode);
        bytes.push(self.flags);
        bytes.extend_from_slice(&self.checksum.to_be_bytes());

        for tlv in &self.tlvs {
            bytes.extend_from_slice(&tlv.to_bytes());
        }

        bytes
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_udld_probe() {
        let pkt = UdldPacket::probe("Switch01", "Gi0/1");
        assert_eq!(pkt.opcode, UdldOpcode::Probe as u8);
        assert!(pkt.tlvs.len() >= 2);
    }

    #[test]
    fn test_udld_echo() {
        let pkt = UdldPacket::echo("Switch01", "Gi0/1", "Switch02", "Gi0/2");
        assert_eq!(pkt.opcode, UdldOpcode::Echo as u8);
        assert!(pkt.tlvs.len() >= 3);
    }

    #[test]
    fn test_udld_flush() {
        let pkt = UdldPacket::flush("Switch01", "Gi0/1");
        assert_eq!(pkt.opcode, UdldOpcode::Flush as u8);
    }

    #[test]
    fn test_tlv_encoding() {
        let tlv = UdldTlv::device_id("TestDevice");
        let bytes = tlv.to_bytes();
        assert_eq!(bytes[0..2], [0x00, 0x01]); // Type
        assert!(!bytes.is_empty());
    }

    #[test]
    fn test_packet_encoding() {
        let pkt = UdldPacket::probe("Switch", "Port");
        let bytes = pkt.to_bytes();
        assert_eq!(bytes[0], 0x01); // Version
        assert_eq!(bytes[1], UdldOpcode::Probe as u8);
    }
}
