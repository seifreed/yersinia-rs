//! Packet builder for constructing network packets with a fluent API
//!
//! This module provides a high-level builder interface for constructing
//! complete network packets from layer 2 (Ethernet) to layer 4 (TCP/UDP).

use crate::ethernet::{EtherType, EthernetFrame, MacAddress};
use crate::ip::{IpProtocol, Ipv4Packet};
use crate::llc::{LlcSnapFrame, Oui, SnapProtocolId};
use crate::tcp::{TcpFlags, TcpPort, TcpSegment};
use crate::udp::{UdpDatagram, UdpPort};
use std::net::Ipv4Addr;
use yersinia_core::{Error, Result};

/// Layer 2 frame type
#[derive(Debug, Clone)]
enum Layer2 {
    Ethernet {
        src: MacAddress,
        dst: MacAddress,
        ethertype: EtherType,
    },
}

/// Layer 2.5 frame type (LLC/SNAP)
#[derive(Debug, Clone)]
enum Layer2_5 {
    LlcSnap {
        oui: Oui,
        protocol_id: SnapProtocolId,
    },
}

/// Layer 3 packet type
#[derive(Debug, Clone)]
enum Layer3 {
    Ipv4 {
        src: Ipv4Addr,
        dst: Ipv4Addr,
        ttl: u8,
        identification: u16,
    },
}

/// Layer 4 segment/datagram type
#[derive(Debug, Clone, Copy)]
enum Layer4 {
    Udp {
        src_port: u16,
        dst_port: u16,
    },
    Tcp {
        src_port: u16,
        dst_port: u16,
        seq: u32,
        ack: u32,
        flags: TcpFlags,
        window: u16,
    },
}

/// Packet builder with fluent API for constructing network packets
///
/// # Examples
///
/// ```
/// use yersinia_packet::PacketBuilder;
/// use yersinia_packet::ethernet::{MacAddress, EtherType};
/// use yersinia_packet::llc::{Oui, SnapProtocolId};
///
/// // Build a CDP packet
/// let packet = PacketBuilder::new()
///     .ethernet(
///         MacAddress([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]),
///         MacAddress::CDP_MULTICAST,
///         EtherType::LLC,
///     )
///     .llc_snap(Oui::CISCO, SnapProtocolId::CDP)
///     .payload(vec![0x02, 0x00, 0x00, 0x01]) // CDP data
///     .build()
///     .unwrap();
/// ```
pub struct PacketBuilder {
    layer2: Option<Layer2>,
    layer2_5: Option<Layer2_5>,
    layer3: Option<Layer3>,
    layer4: Option<Layer4>,
    payload: Vec<u8>,
}

impl PacketBuilder {
    /// Create a new packet builder
    pub fn new() -> Self {
        PacketBuilder {
            layer2: None,
            layer2_5: None,
            layer3: None,
            layer4: None,
            payload: Vec::new(),
        }
    }

    /// Add an Ethernet layer
    ///
    /// # Arguments
    ///
    /// * `src` - Source MAC address
    /// * `dst` - Destination MAC address
    /// * `ethertype` - EtherType (or use EtherType::LLC for LLC/SNAP frames)
    pub fn ethernet(mut self, src: MacAddress, dst: MacAddress, ethertype: EtherType) -> Self {
        self.layer2 = Some(Layer2::Ethernet {
            src,
            dst,
            ethertype,
        });
        self
    }

    /// Add an LLC/SNAP layer
    ///
    /// This is typically used for CDP, VTP, DTP, and other Cisco protocols.
    /// When using LLC/SNAP, the Ethernet layer should use EtherType::LLC.
    ///
    /// # Arguments
    ///
    /// * `oui` - Organizationally Unique Identifier
    /// * `protocol_id` - SNAP protocol ID
    pub fn llc_snap(mut self, oui: Oui, protocol_id: SnapProtocolId) -> Self {
        self.layer2_5 = Some(Layer2_5::LlcSnap { oui, protocol_id });
        self
    }

    /// Add an IPv4 layer
    ///
    /// # Arguments
    ///
    /// * `src` - Source IP address
    /// * `dst` - Destination IP address
    pub fn ipv4(mut self, src: Ipv4Addr, dst: Ipv4Addr) -> Self {
        self.layer3 = Some(Layer3::Ipv4 {
            src,
            dst,
            ttl: 64,
            identification: 0,
        });
        self
    }

    /// Set the TTL for the IPv4 layer
    ///
    /// Must be called after `ipv4()`.
    pub fn ttl(mut self, new_ttl: u8) -> Self {
        if let Some(Layer3::Ipv4 { ref mut ttl, .. }) = self.layer3 {
            *ttl = new_ttl;
        }
        self
    }

    /// Set the identification for the IPv4 layer
    ///
    /// Must be called after `ipv4()`.
    pub fn identification(mut self, id: u16) -> Self {
        if let Some(Layer3::Ipv4 {
            ref mut identification,
            ..
        }) = self.layer3
        {
            *identification = id;
        }
        self
    }

    /// Add a UDP layer
    ///
    /// # Arguments
    ///
    /// * `src_port` - Source port
    /// * `dst_port` - Destination port
    pub fn udp(mut self, src_port: u16, dst_port: u16) -> Self {
        self.layer4 = Some(Layer4::Udp { src_port, dst_port });
        self
    }

    /// Add a TCP layer
    ///
    /// # Arguments
    ///
    /// * `src_port` - Source port
    /// * `dst_port` - Destination port
    /// * `seq` - Sequence number
    /// * `ack` - Acknowledgment number
    /// * `flags` - TCP flags
    pub fn tcp(
        mut self,
        src_port: u16,
        dst_port: u16,
        seq: u32,
        ack: u32,
        flags: TcpFlags,
    ) -> Self {
        self.layer4 = Some(Layer4::Tcp {
            src_port,
            dst_port,
            seq,
            ack,
            flags,
            window: 65535,
        });
        self
    }

    /// Set the TCP window size
    ///
    /// Must be called after `tcp()`.
    pub fn window(mut self, new_window: u16) -> Self {
        if let Some(Layer4::Tcp { ref mut window, .. }) = self.layer4 {
            *window = new_window;
        }
        self
    }

    /// Set the payload data
    pub fn payload(mut self, data: Vec<u8>) -> Self {
        self.payload = data;
        self
    }

    /// Build the complete packet
    ///
    /// This constructs the packet from all configured layers and returns
    /// the final byte representation.
    ///
    /// # Errors
    ///
    /// Returns an error if the layer configuration is invalid (e.g., Layer 4
    /// without Layer 3, Layer 3 without Layer 2).
    pub fn build(self) -> Result<Vec<u8>> {
        // Start with the payload
        let mut packet_data = self.payload.clone();

        // Build Layer 4 (TCP/UDP)
        if let Some(layer4) = self.layer4 {
            let layer3 = self
                .layer3
                .as_ref()
                .ok_or_else(|| Error::PacketConstruction("Layer 4 requires Layer 3".into()))?;

            match (layer3, layer4) {
                (&Layer3::Ipv4 { src, dst, .. }, Layer4::Udp { src_port, dst_port }) => {
                    let mut udp = UdpDatagram::new(
                        UdpPort::new(src_port),
                        UdpPort::new(dst_port),
                        packet_data,
                    );
                    udp.calculate_checksum(src, dst);
                    packet_data = udp.to_bytes();
                }
                (
                    &Layer3::Ipv4 { src, dst, .. },
                    Layer4::Tcp {
                        src_port,
                        dst_port,
                        seq,
                        ack,
                        flags,
                        window,
                    },
                ) => {
                    let mut tcp = TcpSegment::new(
                        TcpPort::new(src_port),
                        TcpPort::new(dst_port),
                        seq,
                        ack,
                        flags,
                        window,
                        packet_data,
                    );
                    tcp.calculate_checksum(src, dst);
                    packet_data = tcp.to_bytes();
                }
            }
        }

        // Build Layer 3 (IP)
        if let Some(layer3) = self.layer3 {
            match layer3 {
                Layer3::Ipv4 {
                    src,
                    dst,
                    ttl,
                    identification,
                } => {
                    let protocol = match self.layer4 {
                        Some(Layer4::Udp { .. }) => IpProtocol::UDP,
                        Some(Layer4::Tcp { .. }) => IpProtocol::TCP,
                        None => IpProtocol::Custom(0), // Raw IP
                    };

                    let ip = Ipv4Packet::new(src, dst, protocol, packet_data)
                        .with_ttl(ttl)
                        .with_identification(identification);

                    packet_data = ip.to_bytes();
                }
            }
        }

        // Build Layer 2.5 (LLC/SNAP)
        if let Some(layer2_5) = self.layer2_5 {
            match layer2_5 {
                Layer2_5::LlcSnap { oui, protocol_id } => {
                    let llc_snap = LlcSnapFrame::custom(oui, protocol_id, packet_data);
                    packet_data = llc_snap.to_bytes();
                }
            }
        }

        // Build Layer 2 (Ethernet)
        let layer2 = self
            .layer2
            .ok_or_else(|| Error::PacketConstruction("Layer 2 is required".into()))?;

        match layer2 {
            Layer2::Ethernet {
                src,
                dst,
                ethertype,
            } => {
                let frame = EthernetFrame::new(dst, src, ethertype, packet_data);
                packet_data = frame.to_bytes();
            }
        }

        Ok(packet_data)
    }

    /// Build and send the packet on the specified interface
    ///
    /// This is a convenience method that builds the packet and sends it
    /// using the provided transmit function.
    ///
    /// # Arguments
    ///
    /// * `tx` - Transmit function that takes packet bytes
    ///
    /// # Errors
    ///
    /// Returns an error if packet building fails or transmission fails.
    pub fn send<F>(self, mut tx: F) -> Result<()>
    where
        F: FnMut(&[u8]) -> Result<()>,
    {
        let packet = self.build()?;
        tx(&packet)
    }
}

impl Default for PacketBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_builder_ethernet_only() {
        let src = MacAddress([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
        let dst = MacAddress([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]);
        let payload = vec![0x01, 0x02, 0x03, 0x04];

        let packet = PacketBuilder::new()
            .ethernet(src, dst, EtherType::IPv4)
            .payload(payload.clone())
            .build()
            .unwrap();

        // Parse back
        let frame = EthernetFrame::from_bytes(&packet).unwrap();
        assert_eq!(frame.source, src);
        assert_eq!(frame.destination, dst);
        assert_eq!(frame.ethertype, EtherType::IPv4);
    }

    #[test]
    fn test_builder_llc_snap() {
        let src = MacAddress([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
        let dst = MacAddress::CDP_MULTICAST;
        let payload = vec![0x02, 0x00, 0x00, 0x01];

        let packet = PacketBuilder::new()
            .ethernet(src, dst, EtherType::LLC)
            .llc_snap(Oui::CISCO, SnapProtocolId::CDP)
            .payload(payload.clone())
            .build()
            .unwrap();

        // Parse Ethernet
        let frame = EthernetFrame::from_bytes(&packet).unwrap();
        assert_eq!(frame.ethertype, EtherType::LLC);

        // Parse LLC/SNAP
        let llc_snap = LlcSnapFrame::from_bytes(&frame.payload).unwrap();
        assert_eq!(llc_snap.snap.oui, Oui::CISCO);
        assert_eq!(llc_snap.snap.protocol_id, SnapProtocolId::CDP);
    }

    #[test]
    fn test_builder_ethernet_ip_udp() {
        let src_mac = MacAddress([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
        let dst_mac = MacAddress([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]);
        let src_ip = Ipv4Addr::new(192, 168, 1, 1);
        let dst_ip = Ipv4Addr::new(192, 168, 1, 2);
        let payload = vec![0x01, 0x02, 0x03, 0x04];

        let packet = PacketBuilder::new()
            .ethernet(src_mac, dst_mac, EtherType::IPv4)
            .ipv4(src_ip, dst_ip)
            .udp(12345, 53)
            .payload(payload.clone())
            .build()
            .unwrap();

        // Parse Ethernet
        let frame = EthernetFrame::from_bytes(&packet).unwrap();
        assert_eq!(frame.ethertype, EtherType::IPv4);

        // Parse IP
        let ip = Ipv4Packet::from_bytes(&frame.payload).unwrap();
        assert_eq!(ip.source, src_ip);
        assert_eq!(ip.destination, dst_ip);
        assert_eq!(ip.protocol, IpProtocol::UDP);

        // Parse UDP
        let udp = UdpDatagram::from_bytes(&ip.payload).unwrap();
        assert_eq!(udp.source_port.0, 12345);
        assert_eq!(udp.destination_port.0, 53);
    }

    #[test]
    fn test_builder_ethernet_ip_tcp() {
        let src_mac = MacAddress([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
        let dst_mac = MacAddress([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]);
        let src_ip = Ipv4Addr::new(192, 168, 1, 1);
        let dst_ip = Ipv4Addr::new(192, 168, 1, 2);
        let payload = vec![0x01, 0x02, 0x03, 0x04];

        let packet = PacketBuilder::new()
            .ethernet(src_mac, dst_mac, EtherType::IPv4)
            .ipv4(src_ip, dst_ip)
            .tcp(12345, 80, 1000, 2000, TcpFlags::SYN)
            .payload(payload.clone())
            .build()
            .unwrap();

        // Parse Ethernet
        let frame = EthernetFrame::from_bytes(&packet).unwrap();
        assert_eq!(frame.ethertype, EtherType::IPv4);

        // Parse IP
        let ip = Ipv4Packet::from_bytes(&frame.payload).unwrap();
        assert_eq!(ip.source, src_ip);
        assert_eq!(ip.destination, dst_ip);
        assert_eq!(ip.protocol, IpProtocol::TCP);

        // Parse TCP
        let tcp = TcpSegment::from_bytes(&ip.payload).unwrap();
        assert_eq!(tcp.source_port.0, 12345);
        assert_eq!(tcp.destination_port.0, 80);
        assert_eq!(tcp.sequence_number, 1000);
        assert_eq!(tcp.acknowledgment_number, 2000);
        assert!(tcp.flags.syn);
    }

    #[test]
    fn test_builder_ttl_and_identification() {
        let src_mac = MacAddress([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
        let dst_mac = MacAddress([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]);
        let src_ip = Ipv4Addr::new(192, 168, 1, 1);
        let dst_ip = Ipv4Addr::new(192, 168, 1, 2);

        let packet = PacketBuilder::new()
            .ethernet(src_mac, dst_mac, EtherType::IPv4)
            .ipv4(src_ip, dst_ip)
            .ttl(128)
            .identification(0x1234)
            .payload(vec![])
            .build()
            .unwrap();

        let frame = EthernetFrame::from_bytes(&packet).unwrap();
        let ip = Ipv4Packet::from_bytes(&frame.payload).unwrap();

        assert_eq!(ip.ttl, 128);
        assert_eq!(ip.identification, 0x1234);
    }

    #[test]
    fn test_builder_missing_layer2() {
        let result = PacketBuilder::new().payload(vec![0x01, 0x02]).build();

        assert!(result.is_err());
    }

    #[test]
    fn test_builder_layer4_without_layer3() {
        let src_mac = MacAddress([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
        let dst_mac = MacAddress([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]);

        let result = PacketBuilder::new()
            .ethernet(src_mac, dst_mac, EtherType::IPv4)
            .udp(12345, 53)
            .payload(vec![])
            .build();

        assert!(result.is_err());
    }

    #[test]
    fn test_builder_send() {
        let src_mac = MacAddress([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
        let dst_mac = MacAddress([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]);
        let payload = vec![0x01, 0x02, 0x03, 0x04];

        let mut sent_packet = Vec::new();

        let result = PacketBuilder::new()
            .ethernet(src_mac, dst_mac, EtherType::IPv4)
            .payload(payload.clone())
            .send(|packet| {
                sent_packet = packet.to_vec();
                Ok(())
            });

        assert!(result.is_ok());
        assert!(!sent_packet.is_empty());
    }
}
