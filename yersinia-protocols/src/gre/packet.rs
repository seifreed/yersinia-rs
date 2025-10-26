//! GRE/Tunnel Packet Structures

pub const GRE_PROTOCOL: u8 = 47;

#[derive(Debug, Clone)]
pub struct GrePacket {
    pub flags: u16,
    pub protocol_type: u16,
    pub checksum: Option<u16>,
    pub key: Option<u32>,
    pub sequence: Option<u32>,
    pub payload: Vec<u8>,
}

impl GrePacket {
    pub fn new(protocol_type: u16) -> Self {
        Self {
            flags: 0,
            protocol_type,
            checksum: None,
            key: None,
            sequence: None,
            payload: vec![],
        }
    }

    pub fn with_key(mut self, key: u32) -> Self {
        self.key = Some(key);
        self.flags |= 0x2000;
        self
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&self.flags.to_be_bytes());
        bytes.extend_from_slice(&self.protocol_type.to_be_bytes());
        if let Some(cksum) = self.checksum {
            bytes.extend_from_slice(&cksum.to_be_bytes());
            bytes.extend_from_slice(&0u16.to_be_bytes()); // Reserved
        }
        if let Some(key) = self.key {
            bytes.extend_from_slice(&key.to_be_bytes());
        }
        if let Some(seq) = self.sequence {
            bytes.extend_from_slice(&seq.to_be_bytes());
        }
        bytes.extend_from_slice(&self.payload);
        bytes
    }
}

#[derive(Debug, Clone)]
pub struct IkePacket {
    pub initiator_spi: u64,
    pub responder_spi: u64,
    pub payload_type: u8,
    pub exchange_type: u8,
    pub flags: u8,
    pub message_id: u32,
    pub length: u32,
}

impl IkePacket {
    pub fn aggressive_mode() -> Self {
        Self {
            initiator_spi: rand::random(),
            responder_spi: 0,
            payload_type: 4,  // Key Exchange
            exchange_type: 4, // Aggressive Mode
            flags: 0,
            message_id: 0,
            length: 28,
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&self.initiator_spi.to_be_bytes());
        bytes.extend_from_slice(&self.responder_spi.to_be_bytes());
        bytes.push(self.payload_type);
        bytes.push(self.exchange_type);
        bytes.push(self.flags);
        bytes.push(0); // Reserved
        bytes.extend_from_slice(&self.message_id.to_be_bytes());
        bytes.extend_from_slice(&self.length.to_be_bytes());
        bytes
    }
}
