use pnet::datalink::MacAddr;
use std::net::Ipv4Addr;

use crate::network::error::{NetworkError, NetworkErrorKind};
use crate::network::CaptureConfig;
use pcap::{Capture, Device};
use pnet::datalink;
use pnet::datalink::Channel::Ethernet;
use pnet::packet::ethernet::{EtherType, EtherTypes, EthernetPacket, MutableEthernetPacket};
use pnet::packet::ipv4::{Ipv4Packet, MutableIpv4Packet};
use pnet::packet::ipv6::MutableIpv6Packet;
use pnet::packet::{MutablePacket, Packet};

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
    let interface = interfaces.iter().find(|i| i.name == capture.output_device).ok_or(NetworkError::new(
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
            continue;
        };

        tx.build_and_send(1, packet.packet().len(), &mut |new_packet| {
            if let Some(mut eth_packet) = MutableEthernetPacket::new(new_packet) {
                eth_packet.clone_from(&packet);

                if let Some(mac_rewrite) = &rewrite.mac_rewrite {
                    rewrite_mac(&mut eth_packet, &mac_rewrite)
                };
                if let Some(ip_rewrite) = &rewrite.ipv4_rewrite {
                    rewrite_ip(&mut eth_packet, &ip_rewrite);
                }
            }
            else {
                eprintln!("Could not build the Ethernet packet")
            }
        });

        // let mut new_packet = vec![0u8; packet.packet().len()];
        // let Some(mut eth_packet) =
        //     MutableEthernetPacket::new(&mut new_packet)
        // else {
        //     eprintln!("Could not build the Ethernet packet");
        //     continue;
        // };
        //
        // eth_packet.clone_from(&packet);
        //
        // if let Some(mac_rewrite) = &rewrite.mac_rewrite {
        //     rewrite_mac(&mut eth_packet, &mac_rewrite)
        // };
        // if let Some(ip_rewrite) = &rewrite.ipv4_rewrite {
        //     rewrite_ip(&mut eth_packet, &ip_rewrite);
        // }
        // match tx.send_to(eth_packet.packet(), None) {
        //     Some(Ok(_)) => println!("Packet sent successfully!"),
        //     Some(Err(e)) => eprintln!("Failed to send packet: {}", e),
        //     None => eprintln!("send_to() returned None"),
        // }
    }
    Ok(())
}

pub struct Rewrite {
    pub mac_rewrite: Option<MacRewrite>,
    pub ipv4_rewrite: Option<Ipv4Rewrite>,
    pub port_rewrite: Option<PortRewrite>,
}

pub struct PortRewrite {
    pub src_port: Option<u16>,
    pub dst_port: Option<u16>,
}

pub struct Ipv4Rewrite {
    pub src_ip: Option<Ipv4Addr>,
    pub dst_ip: Option<Ipv4Addr>,
}

pub struct MacRewrite {
    pub src_mac: Option<MacAddr>,
    pub dst_mac: Option<MacAddr>,
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

pub fn rewrite_ip(mut packet: &mut MutableEthernetPacket, rewrite: &Ipv4Rewrite) {
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
        }
        // EtherTypes::Ipv6 => {
        //     let Some(mut ipv4_packet) = MutableIpv6Packet::new(packet.packet_mut()) else
        //     {
        //         eprintln!("Could not build the IPv6 packet");
        //         return;
        //     };
        //     if let Some(src_ip) = rewrite.src_ip {
        //         ipv4_packet.set_source(src_ip)
        //     }
        //     if let Some(dst_ip) = rewrite.dst_ip {
        //         ipv4_packet.set_destination(dst_ip)
        //     }
        // },
        _ => {}
    }
}
