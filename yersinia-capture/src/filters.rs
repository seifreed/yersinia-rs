//! BPF (Berkeley Packet Filter) filter builders for various protocols

/// CDP (Cisco Discovery Protocol) filter
/// Captures packets on multicast address 01:00:0c:cc:cc:cc with ethertype 0x2000
pub fn cdp_filter() -> String {
    "ether dst 01:00:0c:cc:cc:cc and ether[20:2] == 0x2000".to_string()
}

/// STP (Spanning Tree Protocol) filter
/// Captures 802.1D STP BPDUs
pub fn stp_filter() -> String {
    "ether dst 01:80:c2:00:00:00 and ether[14:2] == 0x0000".to_string()
}

/// DHCP filter (both client and server)
/// Captures DHCP traffic on ports 67 and 68
pub fn dhcp_filter() -> String {
    "(udp port 67 or udp port 68)".to_string()
}

/// DHCPv6 filter
/// Captures DHCPv6 traffic on ports 546 and 547
pub fn dhcpv6_filter() -> String {
    "(udp port 546 or udp port 547)".to_string()
}

/// DTP (Dynamic Trunking Protocol) filter
/// Captures DTP packets
pub fn dtp_filter() -> String {
    "ether dst 01:00:0c:cc:cc:cc and ether[20:2] == 0x2004".to_string()
}

/// VTP (VLAN Trunking Protocol) filter
/// Captures VTP advertisements
pub fn vtp_filter() -> String {
    "ether dst 01:00:0c:cc:cc:cc and ether[20:2] == 0x2003".to_string()
}

/// HSRP (Hot Standby Router Protocol) filter
/// Captures HSRP hello packets
pub fn hsrp_filter() -> String {
    "udp dst port 1985".to_string()
}

/// ARP filter
/// Captures all ARP packets
pub fn arp_filter() -> String {
    "arp".to_string()
}

/// 802.1Q VLAN tagged packets filter
pub fn vlan_filter() -> String {
    "vlan".to_string()
}

/// Specific VLAN ID filter
pub fn vlan_id_filter(vlan_id: u16) -> String {
    format!("vlan {}", vlan_id)
}

/// MPLS filter
pub fn mpls_filter() -> String {
    "mpls".to_string()
}

/// ISL (Inter-Switch Link) filter
pub fn isl_filter() -> String {
    "ether[0:4] == 0x01000c00".to_string()
}

/// 802.1X (Port-based Network Access Control) filter
pub fn dot1x_filter() -> String {
    "ether proto 0x888e".to_string()
}

/// LLDP (Link Layer Discovery Protocol) filter
pub fn lldp_filter() -> String {
    "ether proto 0x88cc".to_string()
}

/// IPv4 filter
pub fn ipv4_filter() -> String {
    "ip".to_string()
}

/// IPv6 filter
pub fn ipv6_filter() -> String {
    "ip6".to_string()
}

/// TCP filter
pub fn tcp_filter() -> String {
    "tcp".to_string()
}

/// UDP filter
pub fn udp_filter() -> String {
    "udp".to_string()
}

/// ICMP filter
pub fn icmp_filter() -> String {
    "icmp".to_string()
}

/// ICMPv6 filter
pub fn icmpv6_filter() -> String {
    "icmp6".to_string()
}

/// Filter for specific source IP
pub fn src_ip_filter(ip: &str) -> String {
    format!("src host {}", ip)
}

/// Filter for specific destination IP
pub fn dst_ip_filter(ip: &str) -> String {
    format!("dst host {}", ip)
}

/// Filter for specific source or destination IP
pub fn host_filter(ip: &str) -> String {
    format!("host {}", ip)
}

/// Filter for specific network
pub fn net_filter(network: &str, netmask: &str) -> String {
    format!("net {} mask {}", network, netmask)
}

/// Filter for specific source MAC address
pub fn src_mac_filter(mac: &str) -> String {
    format!("ether src {}", mac)
}

/// Filter for specific destination MAC address
pub fn dst_mac_filter(mac: &str) -> String {
    format!("ether dst {}", mac)
}

/// Filter for broadcast packets
pub fn broadcast_filter() -> String {
    "ether broadcast".to_string()
}

/// Filter for multicast packets
pub fn multicast_filter() -> String {
    "ether multicast".to_string()
}

/// Filter for specific TCP port (source or destination)
pub fn tcp_port_filter(port: u16) -> String {
    format!("tcp port {}", port)
}

/// Filter for specific UDP port (source or destination)
pub fn udp_port_filter(port: u16) -> String {
    format!("udp port {}", port)
}

/// Filter for port range
pub fn port_range_filter(start: u16, end: u16) -> String {
    format!("portrange {}-{}", start, end)
}

/// Combine multiple filters with AND logic
pub fn combine_filters(filters: &[&str]) -> String {
    if filters.is_empty() {
        return String::new();
    }

    filters
        .iter()
        .map(|f| format!("({})", f))
        .collect::<Vec<_>>()
        .join(" and ")
}

/// Combine multiple filters with OR logic
pub fn combine_filters_or(filters: &[&str]) -> String {
    if filters.is_empty() {
        return String::new();
    }

    filters
        .iter()
        .map(|f| format!("({})", f))
        .collect::<Vec<_>>()
        .join(" or ")
}

/// Negate a filter
pub fn not_filter(filter: &str) -> String {
    format!("not ({})", filter)
}

/// Filter for all Layer 2 discovery protocols (CDP, LLDP, etc.)
pub fn layer2_discovery_filter() -> String {
    combine_filters_or(&[&cdp_filter(), &lldp_filter(), &dot1x_filter()])
}

/// Filter for all Cisco proprietary protocols
pub fn cisco_protocols_filter() -> String {
    combine_filters_or(&[&cdp_filter(), &vtp_filter(), &dtp_filter(), &hsrp_filter()])
}

/// Filter for all spanning tree variants
pub fn all_stp_filter() -> String {
    // Captures regular STP, RSTP, MSTP
    "ether dst 01:80:c2:00:00:00".to_string()
}

/// Filter for IPv6 neighbor discovery
pub fn ipv6_nd_filter() -> String {
    "icmp6 and (ip6[40] == 133 or ip6[40] == 134 or ip6[40] == 135 or ip6[40] == 136)".to_string()
}

/// Filter for IPv6 router advertisements
pub fn ipv6_ra_filter() -> String {
    "icmp6 and ip6[40] == 134".to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_basic_filters() {
        assert_eq!(arp_filter(), "arp");
        assert_eq!(ipv4_filter(), "ip");
        assert_eq!(ipv6_filter(), "ip6");
        assert_eq!(tcp_filter(), "tcp");
        assert_eq!(udp_filter(), "udp");
    }

    #[test]
    fn test_protocol_filters() {
        // CDP filter should contain multicast MAC
        assert!(cdp_filter().contains("01:00:0c:cc:cc:cc"));

        // STP filter should contain bridge multicast MAC
        assert!(stp_filter().contains("01:80:c2:00:00:00"));

        // DHCP should use correct ports
        let dhcp = dhcp_filter();
        assert!(dhcp.contains("67"));
        assert!(dhcp.contains("68"));
    }

    #[test]
    fn test_vlan_filters() {
        assert_eq!(vlan_filter(), "vlan");
        assert_eq!(vlan_id_filter(100), "vlan 100");
        assert_eq!(vlan_id_filter(4094), "vlan 4094");
    }

    #[test]
    fn test_host_filters() {
        assert_eq!(src_ip_filter("192.168.1.1"), "src host 192.168.1.1");
        assert_eq!(dst_ip_filter("10.0.0.1"), "dst host 10.0.0.1");
        assert_eq!(host_filter("172.16.0.1"), "host 172.16.0.1");
    }

    #[test]
    fn test_mac_filters() {
        let mac = "aa:bb:cc:dd:ee:ff";
        assert_eq!(src_mac_filter(mac), format!("ether src {}", mac));
        assert_eq!(dst_mac_filter(mac), format!("ether dst {}", mac));
    }

    #[test]
    fn test_port_filters() {
        assert_eq!(tcp_port_filter(80), "tcp port 80");
        assert_eq!(udp_port_filter(53), "udp port 53");
        assert_eq!(port_range_filter(8000, 8999), "portrange 8000-8999");
    }

    #[test]
    fn test_combine_filters() {
        let filters = vec!["tcp", "port 80"];
        let combined = combine_filters(&filters);
        assert_eq!(combined, "(tcp) and (port 80)");

        let empty: Vec<&str> = vec![];
        assert_eq!(combine_filters(&empty), "");
    }

    #[test]
    fn test_combine_filters_or() {
        let filters = vec!["tcp port 80", "tcp port 443"];
        let combined = combine_filters_or(&filters);
        assert_eq!(combined, "(tcp port 80) or (tcp port 443)");
    }

    #[test]
    fn test_not_filter() {
        assert_eq!(not_filter("tcp"), "not (tcp)");
        assert_eq!(not_filter("port 22"), "not (port 22)");
    }

    #[test]
    fn test_layer2_discovery() {
        let filter = layer2_discovery_filter();
        assert!(filter.contains("01:00:0c:cc:cc:cc")); // CDP
        assert!(filter.contains("0x88cc")); // LLDP
        assert!(filter.contains("or"));
    }

    #[test]
    fn test_cisco_protocols() {
        let filter = cisco_protocols_filter();
        assert!(filter.contains("01:00:0c:cc:cc:cc"));
        assert!(filter.contains("or"));
    }

    #[test]
    fn test_broadcast_multicast() {
        assert_eq!(broadcast_filter(), "ether broadcast");
        assert_eq!(multicast_filter(), "ether multicast");
    }

    #[test]
    fn test_complex_filter_combination() {
        // Test combining multiple filter types
        let tcp_http = tcp_port_filter(80);
        let tcp_https = tcp_port_filter(443);
        let web_traffic = combine_filters_or(&[&tcp_http, &tcp_https]);

        let specific_host = host_filter("192.168.1.1");
        let final_filter = combine_filters(&[&web_traffic, &specific_host]);

        assert!(final_filter.contains("80"));
        assert!(final_filter.contains("443"));
        assert!(final_filter.contains("192.168.1.1"));
        assert!(final_filter.contains("and"));
        assert!(final_filter.contains("or"));
    }
}
