//! IS-IS Packet Structures

pub const ISIS_ALL_L1_IS: [u8; 6] = [0x01, 0x80, 0xC2, 0x00, 0x00, 0x14];
pub const ISIS_ALL_L2_IS: [u8; 6] = [0x01, 0x80, 0xC2, 0x00, 0x00, 0x15];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum IsisPduType {
    L1LanHello = 15,
    L2LanHello = 16,
    P2PHello = 17,
    L1Lsp = 18,
    L2Lsp = 20,
    L1Csnp = 24,
    L2Csnp = 25,
    L1Psnp = 26,
    L2Psnp = 27,
}

#[derive(Debug, Clone)]
pub struct IsisHeader {
    pub irpd: u8, // Intradomain Routing Protocol Discriminator
    pub length: u8,
    pub version: u8,
    pub id_length: u8,
    pub pdu_type: IsisPduType,
    pub version2: u8,
    pub reserved: u8,
    pub max_area_addresses: u8,
}

impl IsisHeader {
    pub fn new(pdu_type: IsisPduType) -> Self {
        Self {
            irpd: 0x83, // ISO 10589
            length: 27,
            version: 1,
            id_length: 0,
            pdu_type,
            version2: 1,
            reserved: 0,
            max_area_addresses: 0,
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        vec![
            self.irpd,
            self.length,
            self.version,
            self.id_length,
            self.pdu_type as u8,
            self.version2,
            self.reserved,
            self.max_area_addresses,
        ]
    }
}

#[derive(Debug, Clone)]
pub struct IsisLsp {
    pub header: IsisHeader,
    pub pdu_length: u16,
    pub remaining_lifetime: u16,
    pub lsp_id: [u8; 8],
    pub sequence_number: u32,
    pub checksum: u16,
    pub flags: u8,
    pub tlvs: Vec<u8>,
}

impl IsisLsp {
    pub fn new(level: u8, lsp_id: [u8; 8]) -> Self {
        let pdu_type = if level == 1 {
            IsisPduType::L1Lsp
        } else {
            IsisPduType::L2Lsp
        };

        Self {
            header: IsisHeader::new(pdu_type),
            pdu_length: 27,
            remaining_lifetime: 1200,
            lsp_id,
            sequence_number: 1,
            checksum: 0,
            flags: 0,
            tlvs: vec![],
        }
    }

    pub fn with_lifetime(mut self, lifetime: u16) -> Self {
        self.remaining_lifetime = lifetime;
        self
    }

    pub fn with_sequence(mut self, seq: u32) -> Self {
        self.sequence_number = seq;
        self
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = self.header.to_bytes();
        bytes.extend_from_slice(&self.pdu_length.to_be_bytes());
        bytes.extend_from_slice(&self.remaining_lifetime.to_be_bytes());
        bytes.extend_from_slice(&self.lsp_id);
        bytes.extend_from_slice(&self.sequence_number.to_be_bytes());
        bytes.extend_from_slice(&self.checksum.to_be_bytes());
        bytes.push(self.flags);
        bytes.extend_from_slice(&self.tlvs);
        bytes
    }
}

#[derive(Debug, Clone)]
pub struct IsisPacket {
    pub header: IsisHeader,
    pub payload: Vec<u8>,
}

impl IsisPacket {
    pub fn lsp(lsp: IsisLsp) -> Self {
        Self {
            header: lsp.header.clone(),
            payload: lsp.to_bytes()[8..].to_vec(),
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = self.header.to_bytes();
        bytes.extend_from_slice(&self.payload);
        bytes
    }
}
