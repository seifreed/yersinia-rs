//! Common types used throughout Yersinia-RS

use std::fmt;
use std::str::FromStr;

/// MAC Address (6 bytes)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct MacAddr(pub [u8; 6]);

impl MacAddr {
    /// Create a new MAC address
    pub const fn new(bytes: [u8; 6]) -> Self {
        Self(bytes)
    }

    /// Broadcast MAC address (ff:ff:ff:ff:ff:ff)
    pub const fn broadcast() -> Self {
        Self([0xff, 0xff, 0xff, 0xff, 0xff, 0xff])
    }

    /// Zero MAC address (00:00:00:00:00:00)
    pub const fn zero() -> Self {
        Self([0x00, 0x00, 0x00, 0x00, 0x00, 0x00])
    }

    /// Get bytes as slice
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Convert to array
    pub fn octets(&self) -> [u8; 6] {
        self.0
    }
}

impl fmt::Display for MacAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            self.0[0], self.0[1], self.0[2], self.0[3], self.0[4], self.0[5]
        )
    }
}

impl FromStr for MacAddr {
    type Err = crate::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let parts: Vec<&str> = s.split(':').collect();
        if parts.len() != 6 {
            return Err(crate::Error::protocol("Invalid MAC address format"));
        }

        let mut bytes = [0u8; 6];
        for (i, part) in parts.iter().enumerate() {
            bytes[i] = u8::from_str_radix(part, 16)
                .map_err(|_| crate::Error::protocol("Invalid MAC address hex"))?;
        }

        Ok(MacAddr(bytes))
    }
}

/// Protocol identifier
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ProtocolId(pub u8);

impl ProtocolId {
    // Original protocols (0-10)
    pub const CDP: Self = Self(0);
    pub const STP: Self = Self(1);
    pub const DHCP: Self = Self(2);
    pub const VTP: Self = Self(3);
    pub const DTP: Self = Self(4);
    pub const DOT1Q: Self = Self(5);
    pub const DOT1X: Self = Self(6);
    pub const HSRP: Self = Self(7);
    pub const ISL: Self = Self(8);
    pub const MPLS: Self = Self(9);
    pub const ARP: Self = Self(10);

    // New protocols Phase 1 (11-23)
    pub const LLDP: Self = Self(11);
    pub const VRRP: Self = Self(12);
    pub const IPV6_ND: Self = Self(13);
    pub const DHCPV6: Self = Self(14);
    pub const ICMP: Self = Self(15);
    pub const OSPF: Self = Self(16);
    pub const EIGRP: Self = Self(17);
    pub const RIPV2: Self = Self(18);
    pub const LACP: Self = Self(19);
    pub const PAGP: Self = Self(20);
    pub const PPPOE: Self = Self(21);
    pub const GLBP: Self = Self(22);
    pub const VXLAN: Self = Self(23);

    // New protocols Phase 2 (24-37) - Advanced L2/L3 auditing
    pub const BGP: Self = Self(24);
    pub const IGMP: Self = Self(25);
    pub const BFD: Self = Self(26);
    pub const ISIS: Self = Self(27);
    pub const PIM: Self = Self(28);
    pub const GRE: Self = Self(29);
    pub const GVRP: Self = Self(30);
    pub const UDLD: Self = Self(31);
    pub const QOS: Self = Self(32);
    pub const STORM: Self = Self(33);
    pub const CAM: Self = Self(34);
    pub const ERSPAN: Self = Self(35);
    pub const LLDPMED: Self = Self(36);
    pub const QINQ: Self = Self(37);
}

/// Ethertype constants
pub mod ethertypes {
    pub const IPV4: u16 = 0x0800;
    pub const ARP: u16 = 0x0806;
    pub const DOT1Q: u16 = 0x8100;
    pub const IPV6: u16 = 0x86DD;
    pub const MPLS_UNICAST: u16 = 0x8847;
    pub const MPLS_MULTICAST: u16 = 0x8848;
}

/// Protocol-specific constants
pub mod protocol_constants {
    /// CDP uses LLC/SNAP with OUI 00-00-0C and type 0x2000
    pub const CDP_LLC_DSAP: u8 = 0xAA;
    pub const CDP_LLC_SSAP: u8 = 0xAA;
    pub const CDP_LLC_CONTROL: u8 = 0x03;
    pub const CDP_SNAP_OUI: [u8; 3] = [0x00, 0x00, 0x0C];
    pub const CDP_SNAP_TYPE: u16 = 0x2000;

    /// STP multicast address
    pub const STP_MULTICAST: [u8; 6] = [0x01, 0x80, 0xC2, 0x00, 0x00, 0x00];

    /// DHCP ports
    pub const DHCP_SERVER_PORT: u16 = 67;
    pub const DHCP_CLIENT_PORT: u16 = 68;

    /// HSRP multicast addresses
    pub const HSRP_V1_MULTICAST: [u8; 4] = [224, 0, 0, 2];
    pub const HSRP_V2_MULTICAST: [u8; 4] = [224, 0, 0, 102];
}
