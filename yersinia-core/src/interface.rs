//! Network interface types

use crate::{Error, MacAddr};
use pnet_datalink::{self, Channel, DataLinkSender};
use std::fmt;
use std::sync::{Arc, Mutex};

/// Network interface
#[derive(Debug, Clone)]
pub struct Interface {
    /// Interface name (e.g., "eth0", "en0")
    pub name: String,
    /// Interface index
    pub index: u32,
    /// MAC address
    pub mac_address: MacAddr,
    /// MTU (Maximum Transmission Unit)
    pub mtu: u32,
    /// Is interface up?
    pub is_up: bool,
    /// Is interface in promiscuous mode?
    pub is_promisc: bool,
}

impl Interface {
    /// Create a new interface
    pub fn new(name: String, index: u32, mac_address: MacAddr) -> Self {
        Self {
            name,
            index,
            mac_address,
            mtu: 1500, // Default Ethernet MTU
            is_up: true,
            is_promisc: false,
        }
    }

    /// Get interface by name
    pub fn by_name(name: &str) -> Result<Self, Error> {
        let interfaces = pnet_datalink::interfaces();
        let iface = interfaces
            .into_iter()
            .find(|i| i.name == name)
            .ok_or_else(|| Error::InterfaceNotFound(name.to_string()))?;

        // Extract MAC address
        let mac_bytes = if let Some(mac) = iface.mac {
            [mac.0, mac.1, mac.2, mac.3, mac.4, mac.5]
        } else {
            [0, 0, 0, 0, 0, 0] // Default if no MAC
        };

        Ok(Self {
            name: iface.name.clone(),
            index: iface.index,
            mac_address: MacAddr(mac_bytes),
            mtu: 1500, // Default, pnet doesn't expose MTU directly
            is_up: iface.is_up(),
            is_promisc: false, // pnet doesn't expose promisc mode
        })
    }

    /// List all available interfaces
    pub fn list_all() -> Result<Vec<Self>, Error> {
        let interfaces = pnet_datalink::interfaces();

        let result: Vec<Self> = interfaces
            .into_iter()
            .map(|iface| {
                let mac_bytes = if let Some(mac) = iface.mac {
                    [mac.0, mac.1, mac.2, mac.3, mac.4, mac.5]
                } else {
                    [0, 0, 0, 0, 0, 0]
                };

                Self {
                    name: iface.name.clone(),
                    index: iface.index,
                    mac_address: MacAddr(mac_bytes),
                    mtu: 1500,
                    is_up: iface.is_up(),
                    is_promisc: false,
                }
            })
            .collect();

        Ok(result)
    }

    /// Get the first IPv4 address of this interface
    ///
    /// # Returns
    /// The first IPv4 address found on the interface, or None if no IPv4 is assigned
    pub fn get_ipv4(&self) -> Option<std::net::Ipv4Addr> {
        let interfaces = pnet_datalink::interfaces();
        let interface = interfaces
            .into_iter()
            .find(|iface| iface.name == self.name)?;

        // Find first IPv4 address
        for ip_network in interface.ips {
            if let ipnetwork::IpNetwork::V4(ipv4_net) = ip_network {
                return Some(ipv4_net.ip());
            }
        }

        None
    }

    /// Send a raw packet on this interface
    ///
    /// # Arguments
    /// * `packet` - Raw packet bytes including Ethernet header
    ///
    /// # Returns
    /// Ok(()) on success, Error on failure
    pub fn send_raw(&self, packet: &[u8]) -> Result<(), Error> {
        // Find the network interface by name
        let interfaces = pnet_datalink::interfaces();
        let interface = interfaces
            .into_iter()
            .find(|iface| iface.name == self.name)
            .ok_or_else(|| Error::Interface(format!("Interface {} not found", self.name)))?;

        // Create a channel to send on
        let (mut tx, _) = match pnet_datalink::channel(&interface, Default::default()) {
            Ok(Channel::Ethernet(tx, rx)) => (tx, rx),
            Ok(_) => return Err(Error::Interface("Unsupported channel type".to_string())),
            Err(e) => return Err(Error::Interface(format!("Failed to create channel: {}", e))),
        };

        // Send the packet
        tx.send_to(packet, None)
            .ok_or_else(|| Error::Interface("Failed to send packet".to_string()))?
            .map_err(|e| Error::Interface(format!("Send error: {}", e)))?;

        Ok(())
    }

    /// Create a persistent sender for this interface (more efficient for multiple packets)
    ///
    /// Returns an Arc<Mutex<DataLinkSender>> that can be cloned and used across threads
    pub fn create_sender(&self) -> Result<Arc<Mutex<Box<dyn DataLinkSender>>>, Error> {
        let interfaces = pnet_datalink::interfaces();
        let interface = interfaces
            .into_iter()
            .find(|iface| iface.name == self.name)
            .ok_or_else(|| Error::Interface(format!("Interface {} not found", self.name)))?;

        let (tx, _) = match pnet_datalink::channel(&interface, Default::default()) {
            Ok(Channel::Ethernet(tx, rx)) => (tx, rx),
            Ok(_) => return Err(Error::Interface("Unsupported channel type".to_string())),
            Err(e) => return Err(Error::Interface(format!("Failed to create channel: {}", e))),
        };

        Ok(Arc::new(Mutex::new(tx)))
    }
}

impl fmt::Display for Interface {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} ({}), MTU: {}", self.name, self.mac_address, self.mtu)
    }
}
