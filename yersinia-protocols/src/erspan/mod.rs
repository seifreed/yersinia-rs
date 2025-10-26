//! ERSPAN/RSPAN Remote SPAN Protocol
pub mod attack;
pub mod packet;
pub mod protocol;

pub use attack::{
    ErspanSessionHijackingAttack, RspanVlanHoppingAttack, SpanTrafficManipulationAttack,
};
pub use packet::{ErspanHeader, ErspanPacket, ErspanVersion, ERSPAN_PROTOCOL};
pub use protocol::ErspanProtocol;
