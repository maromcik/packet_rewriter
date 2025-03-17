use crate::network::cap::PacketCapture;
use crate::network::error::NetworkError;
use crate::network::interface::{get_network_channel, NetworkConfig};
use pcap::{Activated, State};
use pnet::datalink::MacAddr;
use pnet::packet::ethernet::{EtherTypes, EthernetPacket, MutableEthernetPacket};
use pnet::packet::ip::{IpNextHeaderProtocol, IpNextHeaderProtocols};
use pnet::packet::ipv4::{checksum, MutableIpv4Packet};
use pnet::packet::ipv6::MutableIpv6Packet;
use pnet::packet::tcp::MutableTcpPacket;
use pnet::packet::vlan::MutableVlanPacket;
use pnet::packet::{MutablePacket, Packet};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::thread::sleep;
use pnet::packet::udp::MutableUdpPacket;

#[derive(Default)]
pub struct Rewrite {
    pub mac_rewrite: Option<MacRewrite>,
    pub ipv4_rewrite: Option<Ipv4Rewrite>,
    pub ipv6_rewrite: Option<Ipv6Rewrite>,
    pub port_rewrite: Option<PortRewrite>,
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
        let Some(packet) = EthernetPacket::new(cap_packet.data) else {
            println!("Invalid packet type");
            continue;
        };

        let mut buffer = vec![0; packet.packet().len()];
        let Some(mut eth_packet) = MutableEthernetPacket::new(&mut buffer[..]) else {
            println!("Could not build the new packet");
            continue;
        };

        eth_packet.clone_from(&packet);
        
        rewrite_mac(&mut eth_packet, &rewrite);
        
        let eth_packet = eth_packet.to_immutable();

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

pub fn rewrite_mac(packet: &mut MutableEthernetPacket, rewrites: &Rewrite) {
    let Some(rewrite) = &rewrites.mac_rewrite else { 
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
    rewrite_vlan(packet, rewrites);
    rewrite_ipv4(packet, rewrites);
    rewrite_ipv6(packet, rewrites);
}

pub fn rewrite_vlan(packet: &mut MutableEthernetPacket, rewrite: &Rewrite) {
    let Some(rewrite) = &rewrite.vlan_rewrite else {
        return;
    };
    if packet.get_ethertype() == EtherTypes::Vlan {
        let Some(mut vlan_packet) = MutableVlanPacket::new(packet.payload_mut()) else {
            eprintln!("Could not build the IPv4 packet");
            return;
        };
        println!(
            "vlan_id: {}, changing to: {}",
            vlan_packet.get_vlan_identifier(),
            rewrite.vlan_id
        );
        vlan_packet.set_vlan_identifier(rewrite.vlan_id);
    }
}

pub fn rewrite_ipv4(packet: &mut MutableEthernetPacket, rewrites: &Rewrite) {
    let Some(rewrite) = &rewrites.ipv4_rewrite else {
        return;
    };
    if packet.get_ethertype() == EtherTypes::Ipv4 {
        let Some(mut ipv4_packet) = MutableIpv4Packet::new(packet.payload_mut()) else {
            eprintln!("Could not build the IPv4 packet");
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
        }
        let protocol = ipv4_packet.get_next_level_protocol();
        rewrite_port(ipv4_packet.payload_mut(), protocol, rewrites);
    }
}

pub fn rewrite_ipv6(packet: &mut MutableEthernetPacket, rewrites: &Rewrite) {
    let Some(rewrite) = &rewrites.ipv6_rewrite else {
        return;
    };
    if packet.get_ethertype() == EtherTypes::Ipv6 {
        let Some(mut ipv6_packet) = MutableIpv6Packet::new(packet.payload_mut()) else {
            eprintln!("Could not build the IPv6 packet");
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
        let protocol = ipv6_packet.get_next_header();
        rewrite_port(ipv6_packet.payload_mut(), protocol, rewrites);
    }
}

pub fn rewrite_port(packet: &mut [u8], protocol: IpNextHeaderProtocol ,rewrites: &Rewrite) {
    let Some(rewrite) = &rewrites.port_rewrite else {
        return;
    };
    match protocol {
        IpNextHeaderProtocols::Tcp => {
            let Some(mut tcp_packet) = MutableTcpPacket::new(packet) else {
                eprintln!("Could not build the TCP packet");
                return;
            };
            if let Some(src) = rewrite.src_port {
                tcp_packet.set_source(src);
            }
            if let Some(dst) = rewrite.dst_port {
                tcp_packet.set_destination(dst);
            }
        }
        IpNextHeaderProtocols::Udp => {
            let Some(mut udp_packet) = MutableUdpPacket::new(packet) else {
                eprintln!("Could not build the UDP packet");
                return;
            };
            if let Some(src) = rewrite.src_port {
                udp_packet.set_source(src);
            }
            if let Some(dst) = rewrite.dst_port {
                udp_packet.set_destination(dst);
            } 
        }
        _ => {}
    }
}
