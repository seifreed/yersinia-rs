//! EIGRP (Enhanced Interior Gateway Routing Protocol) - Cisco Proprietary
//!
//! EIGRP is a Cisco advanced distance-vector routing protocol using
//! DUAL algorithm for loop-free routing decisions.

pub mod attack;
pub mod packet;
pub mod protocol;

pub use attack::{
    EigrpMetricManipulationAttack, EigrpNeighborHijackAttack, EigrpRouteInjectionAttack,
};
pub use packet::{
    EigrpOpcode, EigrpPacket, EigrpTlv, EigrpTlvType, EIGRP_MULTICAST, EIGRP_PROTOCOL,
};
pub use protocol::EigrpProtocol;
