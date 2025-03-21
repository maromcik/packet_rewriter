use crate::network::packet::{DataLinkPacket, NetworkPacket};
use pnet::datalink::MacAddr;
use pnet::packet::ethernet::MutableEthernetPacket;
use pnet::packet::ipv4::{checksum, MutableIpv4Packet};
use pnet::packet::ipv6::MutableIpv6Packet;
use pnet::packet::tcp::MutableTcpPacket;
use pnet::packet::udp::MutableUdpPacket;
use pnet::packet::vlan::MutableVlanPacket;
use std::net::{Ipv4Addr, Ipv6Addr};


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

pub fn rewrite_packet(mut packet: DataLinkPacket, rewrite: &Rewrite) -> Option<()> {
    packet
        .rewrite(&rewrite.datalink_rewrite)
        .unpack_vlan()
        .rewrite(&rewrite.datalink_rewrite)
        .get_next_layer()?
        .rewrite(&rewrite.ip_rewrite)
        .get_next_layer()?
        .rewrite(&rewrite.transport_rewrite)
        .get_next_layer()?
        .print_payload();
    Some(())
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

pub fn rewrite_udp(packet: &mut MutableUdpPacket, rewrite: &Option<PortRewrite>) {
    let Some(rewrite) = rewrite else {
        return;
    };

    if let Some(src) = rewrite.src_port {
        println!(
            "src_port: {}, dst_port: {}, changing src to: {}",
            packet.get_source(),
            packet.get_destination(),
            src
        );
        packet.set_source(src);
    }
    if let Some(dst) = rewrite.dst_port {
        println!(
            "src_port: {}, dst_port: {}, changing src to: {}",
            packet.get_source(),
            packet.get_destination(),
            dst
        );
        packet.set_destination(dst);
    }
}

pub fn rewrite_tcp(packet: &mut MutableTcpPacket, rewrite: &Option<PortRewrite>) {
    let Some(rewrite) = rewrite else {
        return;
    };

    if let Some(src) = rewrite.src_port {
        println!(
            "src_port: {}, dst_port: {}, changing src to: {}",
            packet.get_source(),
            packet.get_destination(),
            src
        );
        packet.set_source(src);
    }
    if let Some(dst) = rewrite.dst_port {
        println!(
            "src_port: {}, dst_port: {}, changing src to: {}",
            packet.get_source(),
            packet.get_destination(),
            dst
        );
        packet.set_destination(dst);
    }
}
