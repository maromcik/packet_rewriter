use pnet::datalink::MacAddr;
use std::net::{Ipv4Addr, Ipv6Addr};

use crate::network::error::{NetworkError, NetworkErrorKind};
use crate::network::CaptureConfig;
use pcap::{Capture, Device};
use pnet::datalink;
use pnet::datalink::Channel::Ethernet;
use pnet::packet::ethernet::{EtherTypes, EthernetPacket, MutableEthernetPacket};
use pnet::packet::ipv4::MutableIpv4Packet;
use pnet::packet::{MutablePacket, Packet};
use pnet::packet::ipv6::MutableIpv6Packet;
use pnet::packet::vlan::MutableVlanPacket;

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

pub fn cap_rewrite(capture: CaptureConfig, rewrite: Rewrite) -> Result<(), NetworkError> {
    let devices = Device::list()?;
    let target = devices
        .into_iter()
        .find(|d| d.name == capture.capture_device)
        .ok_or(NetworkError::new(
            NetworkErrorKind::CaptureError,
            &format!("Capture device {} not found", capture.capture_device),
        ))?;

    println!("Listening on: {:?}", target.name);

    let mut cap = Capture::from_device(target)?
        .promisc(true)
        .immediate_mode(true)
        .open()?;

    if let Some(filter) = &capture.filter {
        println!("Filter applied: {}", filter);
        cap.filter(&filter, true)?;
    }

    let interfaces = datalink::interfaces();
    let interface = interfaces
        .iter()
        .find(|i| i.name == capture.output_device)
        .ok_or(NetworkError::new(
            NetworkErrorKind::NetworkInterfaceError,
            &format!("Output device {} not found", capture.output_device),
        ))?;
    println!("Sending to: {:?}", interface.name);
    let (mut tx, mut rx) = match datalink::channel(interface, Default::default()) {
        Ok(Ethernet(tx, rx)) => Ok((tx, rx)),
        Ok(_) => Err(NetworkError::new(
            NetworkErrorKind::NetworkChannelError,
            "Unknown channel type",
        )),
        Err(e) => Err(NetworkError::new(
            NetworkErrorKind::NetworkChannelError,
            &e.to_string(),
        )),
    }?;

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

        if let Some(mac_rewrite) = &rewrite.mac_rewrite {
            rewrite_mac(&mut eth_packet, &mac_rewrite)
        };
        if let Some(vlan_rewrite) = &rewrite.vlan_rewrite {
            rewrite_vlan(&mut eth_packet, &vlan_rewrite);
        }
        if let Some(ip_rewrite) = &rewrite.ipv4_rewrite {
            rewrite_ipv4(&mut eth_packet, &ip_rewrite);
        }
        if let Some(ip_rewrite) = &rewrite.ipv6_rewrite {
            rewrite_ipv6(&mut eth_packet, &ip_rewrite);
        }
        let eth_packet = eth_packet.consume_to_immutable();
        if packet != eth_packet {
            tx.send_to(eth_packet.packet(), None);
            println!("Packet sent")
        }
    }
    Ok(())
}


pub fn rewrite_mac(mut packet: &mut MutableEthernetPacket, rewrite: &MacRewrite) {
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

pub fn rewrite_vlan(mut packet: &mut MutableEthernetPacket, rewrite: &VlanRewrite) {
    match packet.get_ethertype() {
        EtherTypes::Vlan => {
            let Some(mut vlan_packet) = MutableVlanPacket::new(packet.payload_mut()) else {
                eprintln!("Could not build the IPv4 packet");
                return;
            };
            println!("vlan_id: {}, changing to: {}", vlan_packet.get_vlan_identifier(), rewrite.vlan_id);
            vlan_packet.set_vlan_identifier(rewrite.vlan_id);
        },
        _ => {}
    }
}

pub fn rewrite_ipv4(mut packet: &mut MutableEthernetPacket, rewrite: &Ipv4Rewrite) {
    match packet.get_ethertype() {
        EtherTypes::Ipv4 => {
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
                ipv4_packet.set_destination(dst_ip)
            }
        },
        _ => {}
    }
}

pub fn rewrite_ipv6(mut packet: &mut MutableEthernetPacket, rewrite: &Ipv6Rewrite) {
    match packet.get_ethertype() {
        EtherTypes::Ipv6 => {
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
                ipv6_packet.set_destination(dst_ip)
            }
        },
        _ => {}
    }
}