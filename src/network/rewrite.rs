use crate::network::cap::PacketCapture;
use crate::network::error::{NetworkError, NetworkErrorKind};
use crate::network::interface::{get_network_channel, NetworkConfig};
use crate::network::packet::{DataLinkPacket, IpPacket, NetworkPacket};
use pcap::{Activated, State};
use pnet::datalink::MacAddr;
use pnet::packet::dns::MutableDnsPacket;
use pnet::packet::ethernet::{EtherTypes, EthernetPacket, MutableEthernetPacket};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::{checksum, MutableIpv4Packet};
use pnet::packet::ipv6::MutableIpv6Packet;
use pnet::packet::tcp::MutableTcpPacket;
use pnet::packet::udp::MutableUdpPacket;
use pnet::packet::vlan::MutableVlanPacket;
use pnet::packet::{MutablePacket, Packet};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::thread::sleep;

pub trait Rewritable {}

#[derive(Default)]
pub struct Rewrite {
    pub datalink_rewrite: Option<DataLinkRewrite>,
    pub ip_rewrite: Option<IpRewrite>,
    pub transport_rewrite: Option<PortRewrite>,
}

pub struct IpRewrite {
    pub ipv4_rewrite: Option<Ipv4Rewrite>,
    pub ipv6_rewrite: Option<Ipv6Rewrite>,
}

pub struct DataLinkRewrite {
    pub mac_rewrite: Option<MacRewrite>,
    pub vlan_rewrite: Option<VlanRewrite>,
}
#[derive(Default)]
pub struct PortRewrite {
    pub src_port: Option<u16>,
    pub dst_port: Option<u16>,
}

#[derive(Default)]
pub struct Ipv4Rewrite {
    pub src_ip: Option<Ipv4Addr>,
    pub dst_ip: Option<Ipv4Addr>,
}

#[derive(Default)]
pub struct Ipv6Rewrite {
    pub src_ip: Option<Ipv6Addr>,
    pub dst_ip: Option<Ipv6Addr>,
}

#[derive(Default)]
pub struct MacRewrite {
    pub src_mac: Option<MacAddr>,
    pub dst_mac: Option<MacAddr>,
}

#[derive(Default)]
pub struct VlanRewrite {
    pub vlan_id: u16,
}

pub fn cap_rewrite<T>(
    mut capture: impl PacketCapture<T>,
    net_config: NetworkConfig,
    rewrite: Rewrite,
) -> Result<(), NetworkError>
where
    T: State + Activated,
{
    capture.apply_filter()?;
    let mut channel = get_network_channel(&net_config)?;
    let mut cap = capture.get_capture();
    while let Ok(cap_packet) = cap.next_packet() {
        let packet = EthernetPacket::new(cap_packet.data).ok_or(NetworkError::new(
            NetworkErrorKind::PacketConstructionError,
            "Invalid EthernetPacket",
        ))?;

        let mut buffer = vec![0; packet.packet().len()];
        
        let mut datalink_packet = DataLinkPacket::from_buffer(&mut buffer, &packet)?;
        let ip_packet = datalink_packet
            .rewrite(&rewrite.datalink_rewrite)
            .get_next_layer();
        if let Some(mut packet) = ip_packet {
            packet.rewrite(&rewrite.ip_rewrite);
        }

        let new_packet = MutableEthernetPacket::new(&mut buffer[..]).ok_or(NetworkError::new(
            NetworkErrorKind::PacketConstructionError,
            "Could not construct an EthernetPacket",
        ))?;

        let eth_packet = new_packet.to_immutable();

        if net_config.straight || packet != eth_packet {
            channel.tx.send_to(eth_packet.packet(), None);
            println!("Packet sent")
        }
        if let Some(delay) = net_config.interval {
            sleep(delay);
        }
    }
    Ok(())
}

pub fn rewrite_mac(packet: &mut MutableEthernetPacket, rewrite: &DataLinkRewrite) {
    let Some(rewrite) = &rewrite.mac_rewrite else {
        return;
    };
    if let Some(src_mac) = rewrite.src_mac {
        println!(
            "src_mac: {}, dst_mac: {}, changing src to: {}",
            packet.get_source(),
            packet.get_destination(),
            src_mac
        );
        packet.set_source(src_mac);
    }

    if let Some(dst_mac) = rewrite.dst_mac {
        println!(
            "src_mac: {}, dst_mac: {}, changing dst to: {}",
            packet.get_source(),
            packet.get_destination(),
            dst_mac
        );
        packet.set_destination(dst_mac);
    }
}

pub fn rewrite_vlan(vlan_packet: &mut MutableVlanPacket, rewrite: &DataLinkRewrite) {
    let Some(rewrite) = &rewrite.vlan_rewrite else {
        return;
    };
    println!(
        "vlan_id: {}, changing to: {}",
        vlan_packet.get_vlan_identifier(),
        rewrite.vlan_id
    );
    vlan_packet.set_vlan_identifier(rewrite.vlan_id);
}

pub fn rewrite_ipv4(ipv4_packet: &mut MutableIpv4Packet, rewrite: &IpRewrite) {
    let Some(rewrite) = &rewrite.ipv4_rewrite else {
        return;
    };

    if let Some(src_ip) = rewrite.src_ip {
        println!(
            "src_ip: {}, dst_ip: {}, changing src to: {}",
            ipv4_packet.get_source(),
            ipv4_packet.get_destination(),
            src_ip
        );
        ipv4_packet.set_source(src_ip)
    }
    if let Some(dst_ip) = rewrite.dst_ip {
        println!(
            "src_ip: {}, dst_ip: {}, changing dst to: {}",
            ipv4_packet.get_source(),
            ipv4_packet.get_destination(),
            dst_ip
        );
        ipv4_packet.set_destination(dst_ip);
        ipv4_packet.set_checksum(checksum(&ipv4_packet.to_immutable()));
    };
}

pub fn rewrite_ipv6(ipv6_packet: &mut MutableIpv6Packet, rewrite: &IpRewrite) {
    let Some(rewrite) = &rewrite.ipv6_rewrite else {
        return;
    };

    if let Some(src_ip) = rewrite.src_ip {
        println!(
            "src_ip: {}, dst_ip: {}, changing src to: {}",
            ipv6_packet.get_source(),
            ipv6_packet.get_destination(),
            src_ip
        );
        ipv6_packet.set_source(src_ip)
    }
    if let Some(dst_ip) = rewrite.dst_ip {
        println!(
            "src_ip: {}, dst_ip: {}, changing dst to: {}",
            ipv6_packet.get_source(),
            ipv6_packet.get_destination(),
            dst_ip
        );
        ipv6_packet.set_destination(dst_ip);
    };
}

// pub fn rewrite_port(
//     packet: &mut MutableEthernetPacket,
//     rewrites: &Rewrite,
// ) -> Result<(), NetworkError> {
//     let Some(rewrite) = &rewrites.transport_rewrite else {
//         return Ok(());
//     };
//
//     let Some(mut ip_packet) = get_ip_packet(packet)? else {
//         return Ok(());
//     };
//
//     match ip_packet.get_next_header_protocol() {
//         IpNextHeaderProtocols::Tcp => {
//             let mut tcp_packet =
//                 MutableTcpPacket::new(ip_packet.get_mut_payload()).ok_or(NetworkError::new(
//                     NetworkErrorKind::PacketConstructionError,
//                     "TCP Packet is empty",
//                 ))?;
//             if let Some(src) = rewrite.src_port {
//                 tcp_packet.set_source(src);
//             }
//             if let Some(dst) = rewrite.dst_port {
//                 tcp_packet.set_destination(dst);
//             };
//             Ok(())
//         }
//         IpNextHeaderProtocols::Udp => {
//             let mut udp_packet =
//                 MutableUdpPacket::new(ip_packet.get_mut_payload()).ok_or(NetworkError::new(
//                     NetworkErrorKind::PacketConstructionError,
//                     "UDP Packet is empty",
//                 ))?;
//             if let Some(src) = rewrite.src_port {
//                 udp_packet.set_source(src);
//             }
//             if let Some(dst) = rewrite.dst_port {
//                 udp_packet.set_destination(dst);
//             };
//
//             let dns = MutableDnsPacket::new(udp_packet.payload_mut()).unwrap();
//             for q in dns.get_queries_iter() {
//                 println!("query: {:?}", String::from_utf8(q.get_qname()));
//             }
//             Ok(())
//         }
//         _ => Ok(()),
//     }
// }

pub fn get_ip_packet<'a>(
    packet: &'a mut MutableEthernetPacket,
) -> Result<Option<IpPacket<'a>>, NetworkError> {
    match packet.get_ethertype() {
        EtherTypes::Ipv4 => {
            let ipv4_packet =
                MutableIpv4Packet::new(packet.payload_mut()).ok_or(NetworkError::new(
                    NetworkErrorKind::PacketConstructionError,
                    "IPv4 packet is empty",
                ))?;
            Ok(Some(IpPacket::Ipv4Packet(ipv4_packet)))
        }
        EtherTypes::Ipv6 => {
            let ipv6_packet =
                MutableIpv6Packet::new(packet.payload_mut()).ok_or(NetworkError::new(
                    NetworkErrorKind::PacketConstructionError,
                    "IPv4 packet is empty",
                ))?;
            Ok(Some(IpPacket::Ipv6Packet(ipv6_packet)))
        }
        _ => Ok(None),
    }
}
