//! BFD (Bidirectional Forwarding Detection) - RFC 5880
//! Ultra-fast failure detection for network paths

pub mod attack;
pub mod packet;
pub mod protocol;

pub use attack::{BfdFastFailureAttack, BfdKeepaliveManipulationAttack, BfdSessionHijackAttack};
pub use packet::{BfdDiagnostic, BfdPacket, BfdState, BFD_CONTROL_PORT, BFD_ECHO_PORT};
pub use protocol::BfdProtocol;
