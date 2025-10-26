//! BFD Packet Structures

pub const BFD_CONTROL_PORT: u16 = 3784;
pub const BFD_ECHO_PORT: u16 = 3785;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum BfdState {
    AdminDown = 0,
    Down = 1,
    Init = 2,
    Up = 3,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum BfdDiagnostic {
    None = 0,
    ControlDetectionTimeExpired = 1,
    EchoFunctionFailed = 2,
    NeighborSignaledSessionDown = 3,
    ForwardingPlaneReset = 4,
    PathDown = 5,
    ConcatenatedPathDown = 6,
    AdministrativelyDown = 7,
    ReverseConcatenatedPathDown = 8,
}

#[derive(Debug, Clone)]
pub struct BfdPacket {
    pub version: u8,
    pub diagnostic: BfdDiagnostic,
    pub state: BfdState,
    pub poll: bool,
    pub final_bit: bool,
    pub control_plane_independent: bool,
    pub authentication_present: bool,
    pub demand_mode: bool,
    pub multipoint: bool,
    pub detect_mult: u8,
    pub length: u8,
    pub my_discriminator: u32,
    pub your_discriminator: u32,
    pub desired_min_tx_interval: u32,
    pub required_min_rx_interval: u32,
    pub required_min_echo_rx_interval: u32,
}

impl BfdPacket {
    pub fn new(my_disc: u32, your_disc: u32) -> Self {
        Self {
            version: 1,
            diagnostic: BfdDiagnostic::None,
            state: BfdState::Down,
            poll: false,
            final_bit: false,
            control_plane_independent: false,
            authentication_present: false,
            demand_mode: false,
            multipoint: false,
            detect_mult: 3,
            length: 24,
            my_discriminator: my_disc,
            your_discriminator: your_disc,
            desired_min_tx_interval: 1000000, // 1 second in microseconds
            required_min_rx_interval: 1000000,
            required_min_echo_rx_interval: 0,
        }
    }

    pub fn with_state(mut self, state: BfdState) -> Self {
        self.state = state;
        self
    }

    pub fn with_diagnostic(mut self, diag: BfdDiagnostic) -> Self {
        self.diagnostic = diag;
        self
    }

    pub fn with_intervals(mut self, tx: u32, rx: u32) -> Self {
        self.desired_min_tx_interval = tx;
        self.required_min_rx_interval = rx;
        self
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();

        // Byte 0: Version, Diagnostic
        bytes.push((self.version << 5) | (self.diagnostic as u8));

        // Byte 1: State and flags
        let mut flags = (self.state as u8) << 6;
        if self.poll {
            flags |= 0x20;
        }
        if self.final_bit {
            flags |= 0x10;
        }
        if self.control_plane_independent {
            flags |= 0x08;
        }
        if self.authentication_present {
            flags |= 0x04;
        }
        if self.demand_mode {
            flags |= 0x02;
        }
        if self.multipoint {
            flags |= 0x01;
        }
        bytes.push(flags);

        bytes.push(self.detect_mult);
        bytes.push(self.length);
        bytes.extend_from_slice(&self.my_discriminator.to_be_bytes());
        bytes.extend_from_slice(&self.your_discriminator.to_be_bytes());
        bytes.extend_from_slice(&self.desired_min_tx_interval.to_be_bytes());
        bytes.extend_from_slice(&self.required_min_rx_interval.to_be_bytes());
        bytes.extend_from_slice(&self.required_min_echo_rx_interval.to_be_bytes());

        bytes
    }
}
