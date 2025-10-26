//! Q-in-Q / 802.1ad Provider Bridging Protocol
pub mod attack;
pub mod packet;
pub mod protocol;

pub use attack::{
    ProviderBridgeBypassAttack, QinQVlanHoppingAttack, ServiceVlanManipulationAttack,
};
pub use packet::{QinQPacket, QinQTag, DOT1Q_ETHERTYPE, QINQ_ETHERTYPE};
pub use protocol::QinQProtocol;
