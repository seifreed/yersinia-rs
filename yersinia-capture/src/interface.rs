//! Network interface enumeration and information

use pnet_datalink::{self, NetworkInterface};
use std::net::IpAddr;
use yersinia_core::{Error, Result};

/// Information about a network interface
#[derive(Debug, Clone)]
pub struct InterfaceInfo {
    /// Interface name (e.g., "eth0", "wlan0")
    pub name: String,
    /// Human-readable description
    pub description: String,
    /// MAC address if available
    pub mac: Option<String>,
    /// List of IP addresses assigned to this interface
    pub ips: Vec<IpAddr>,
    /// Whether the interface is up
    pub is_up: bool,
    /// Whether the interface is a loopback
    pub is_loopback: bool,
    /// Whether the interface supports multicast
    pub is_multicast: bool,
    /// MTU (Maximum Transmission Unit)
    pub mtu: Option<u32>,
}

impl From<&NetworkInterface> for InterfaceInfo {
    fn from(iface: &NetworkInterface) -> Self {
        let mac = iface.mac.map(|mac| {
            format!(
                "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                mac.0, mac.1, mac.2, mac.3, mac.4, mac.5
            )
        });

        let ips: Vec<IpAddr> = iface.ips.iter().map(|network| network.ip()).collect();

        InterfaceInfo {
            name: iface.name.clone(),
            description: iface.description.clone(),
            mac,
            ips,
            is_up: iface.is_up(),
            is_loopback: iface.is_loopback(),
            is_multicast: iface.is_multicast(),
            mtu: Some(iface.index),
        }
    }
}

impl InterfaceInfo {
    /// Check if the interface is suitable for packet capture
    pub fn is_capture_capable(&self) -> bool {
        self.is_up && !self.is_loopback
    }

    /// Get the primary IPv4 address if available
    pub fn primary_ipv4(&self) -> Option<IpAddr> {
        self.ips
            .iter()
            .find(|ip| matches!(ip, IpAddr::V4(_)))
            .copied()
    }

    /// Get the primary IPv6 address if available
    pub fn primary_ipv6(&self) -> Option<IpAddr> {
        self.ips
            .iter()
            .find(|ip| matches!(ip, IpAddr::V6(_)))
            .copied()
    }
}

/// List all available network interfaces
pub fn list_interfaces() -> Result<Vec<InterfaceInfo>> {
    let interfaces = pnet_datalink::interfaces();

    if interfaces.is_empty() {
        return Err(Error::Capture(
            "No network interfaces found. Are you running with sufficient privileges?".to_string(),
        ));
    }

    Ok(interfaces.iter().map(InterfaceInfo::from).collect())
}

/// Get information about a specific interface by name
pub fn get_interface(name: &str) -> Result<InterfaceInfo> {
    let interfaces = pnet_datalink::interfaces();

    interfaces
        .iter()
        .find(|iface| iface.name == name)
        .map(InterfaceInfo::from)
        .ok_or_else(|| Error::InterfaceNotFound(name.to_string()))
}

/// Find the default interface (first non-loopback, up interface)
pub fn default_interface() -> Result<InterfaceInfo> {
    let interfaces = list_interfaces()?;

    interfaces
        .into_iter()
        .find(|iface| iface.is_capture_capable())
        .ok_or_else(|| Error::Capture("No suitable default interface found".to_string()))
}

/// List all interfaces suitable for packet capture
pub fn list_capture_interfaces() -> Result<Vec<InterfaceInfo>> {
    let interfaces = list_interfaces()?;
    Ok(interfaces
        .into_iter()
        .filter(|iface| iface.is_capture_capable())
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_list_interfaces() {
        let result = list_interfaces();
        // Should at least have loopback
        assert!(result.is_ok());
        let interfaces = result.unwrap();
        assert!(!interfaces.is_empty());
    }

    #[test]
    fn test_loopback_interface() {
        let result = list_interfaces();
        assert!(result.is_ok());
        let interfaces = result.unwrap();

        // Should have at least one loopback interface
        let loopback = interfaces.iter().find(|iface| iface.is_loopback);
        assert!(loopback.is_some());
    }

    #[test]
    fn test_get_nonexistent_interface() {
        let result = get_interface("nonexistent_interface_xyz");
        assert!(result.is_err());
        match result {
            Err(Error::InterfaceNotFound(_)) => {}
            _ => panic!("Expected InterfaceNotFound error"),
        }
    }

    #[test]
    fn test_interface_info_properties() {
        let result = list_interfaces();
        assert!(result.is_ok());
        let interfaces = result.unwrap();

        for iface in interfaces {
            // Name should not be empty
            assert!(!iface.name.is_empty());

            // Loopback should not be capture capable
            if iface.is_loopback {
                assert!(!iface.is_capture_capable());
            }

            // Up + non-loopback = capture capable
            if iface.is_up && !iface.is_loopback {
                assert!(iface.is_capture_capable());
            }
        }
    }
}
