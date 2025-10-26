//! ERSPAN Packet Structures

pub const ERSPAN_PROTOCOL: u8 = 47; // GRE
pub const ERSPAN_TYPE_II: u16 = 0x88BE;
pub const ERSPAN_TYPE_III: u16 = 0x22EB;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErspanVersion {
    TypeII = 1,
    TypeIII = 2,
}

#[derive(Debug, Clone)]
pub struct ErspanHeader {
    pub version: u8,
    pub vlan: u16,
    pub cos: u8,
    pub session_id: u16,
    pub timestamp: u32,
}

impl ErspanHeader {
    pub fn new(session_id: u16) -> Self {
        Self {
            version: 1, // Type II
            vlan: 0,
            cos: 0,
            session_id: session_id & 0x3FF, // 10 bits
            timestamp: 0,
        }
    }

    pub fn type_iii(session_id: u16) -> Self {
        Self {
            version: 2,
            vlan: 0,
            cos: 0,
            session_id,
            timestamp: 0,
        }
    }

    pub fn with_vlan(mut self, vlan: u16) -> Self {
        self.vlan = vlan & 0xFFF;
        self
    }

    pub fn with_cos(mut self, cos: u8) -> Self {
        self.cos = cos & 0x07;
        self
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();

        // Version and VLAN
        let ver_vlan = ((self.version as u16) << 12) | self.vlan;
        bytes.extend_from_slice(&ver_vlan.to_be_bytes());

        // COS, En, T, Session ID
        let cos_session = ((self.cos as u16) << 13) | self.session_id;
        bytes.extend_from_slice(&cos_session.to_be_bytes());

        // Reserved/Timestamp (Type II/III difference)
        bytes.extend_from_slice(&self.timestamp.to_be_bytes());

        bytes
    }
}

#[derive(Debug, Clone)]
pub struct ErspanPacket {
    pub gre_protocol: u16,
    pub gre_seq_num: u32,
    pub erspan_header: ErspanHeader,
    pub mirrored_frame: Vec<u8>,
}

impl ErspanPacket {
    pub fn new(session_id: u16, mirrored_frame: Vec<u8>) -> Self {
        Self {
            gre_protocol: ERSPAN_TYPE_II,
            gre_seq_num: 0,
            erspan_header: ErspanHeader::new(session_id),
            mirrored_frame,
        }
    }

    pub fn with_sequence(mut self, seq: u32) -> Self {
        self.gre_seq_num = seq;
        self
    }

    pub fn with_vlan(mut self, vlan: u16) -> Self {
        self.erspan_header = self.erspan_header.with_vlan(vlan);
        self
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();

        // GRE header with sequence number
        bytes.extend_from_slice(&0x1000u16.to_be_bytes()); // Flags (S bit set)
        bytes.extend_from_slice(&self.gre_protocol.to_be_bytes());
        bytes.extend_from_slice(&self.gre_seq_num.to_be_bytes());

        // ERSPAN header
        bytes.extend_from_slice(&self.erspan_header.to_bytes());

        // Mirrored frame
        bytes.extend_from_slice(&self.mirrored_frame);

        bytes
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_erspan_header() {
        let header = ErspanHeader::new(100);
        assert_eq!(header.version, 1);
        assert_eq!(header.session_id, 100);
    }

    #[test]
    fn test_erspan_header_with_vlan() {
        let header = ErspanHeader::new(100).with_vlan(200);
        assert_eq!(header.vlan, 200);
    }

    #[test]
    fn test_erspan_packet() {
        let frame = vec![0xAA; 100];
        let pkt = ErspanPacket::new(1, frame);
        assert_eq!(pkt.erspan_header.session_id, 1);
    }

    #[test]
    fn test_erspan_to_bytes() {
        let frame = vec![0xBB; 50];
        let pkt = ErspanPacket::new(5, frame).with_sequence(123);
        let bytes = pkt.to_bytes();
        assert!(!bytes.is_empty());
    }
}
