use crate::network::packet::{DataLinkPacket, NetworkPacket};
use hickory_proto::op::Message;
use hickory_proto::rr::{RData, Record};
use log::debug;
use pnet::datalink::MacAddr;
use pnet::packet::ethernet::MutableEthernetPacket;
use pnet::packet::ipv4::MutableIpv4Packet;
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
    pub dns_rewrite: Option<DnsRewrite>,
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

#[derive(Default)]
pub struct DnsRewrite {
    pub a: Option<Ipv4Addr>,
    pub aaaa: Option<Ipv6Addr>,
}

pub fn rewrite_packet<'a>(packet: DataLinkPacket<'a>, rewrite: &'a Rewrite) -> Option<()> {
    let mut data_link_packet = packet.rewrite(&rewrite.datalink_rewrite);
    let mut vlan_packet = data_link_packet
        .unpack_vlan()?
        .rewrite(&rewrite.datalink_rewrite);
    let mut ip_packet = vlan_packet.get_next_layer()?.rewrite(&rewrite.ip_rewrite);
    let mut transport_packet = ip_packet
        .get_next_layer()?
        .rewrite(&rewrite.transport_rewrite);
    let _application_packet = transport_packet.get_next_layer();

    Some(())
}

pub fn rewrite_mac(packet: &mut MutableEthernetPacket, rewrite: &DataLinkRewrite) {
    let Some(rewrite) = &rewrite.mac_rewrite else {
        return;
    };
    if let Some(src_mac) = rewrite.src_mac {
        debug!(
            "src_mac: {}, dst_mac: {}, changing src to: {}",
            packet.get_source(),
            packet.get_destination(),
            src_mac
        );
        packet.set_source(src_mac);
    }

    if let Some(dst_mac) = rewrite.dst_mac {
        debug!(
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
    debug!(
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
        debug!(
            "src_ip: {}, dst_ip: {}, changing src to: {}",
            ipv4_packet.get_source(),
            ipv4_packet.get_destination(),
            src_ip
        );
        ipv4_packet.set_source(src_ip)
    }
    if let Some(dst_ip) = rewrite.dst_ip {
        debug!(
            "src_ip: {}, dst_ip: {}, changing dst to: {}",
            ipv4_packet.get_source(),
            ipv4_packet.get_destination(),
            dst_ip
        );
        ipv4_packet.set_destination(dst_ip);
    };
}

pub fn rewrite_ipv6(ipv6_packet: &mut MutableIpv6Packet, rewrite: &IpRewrite) {
    let Some(rewrite) = &rewrite.ipv6_rewrite else {
        return;
    };

    if let Some(src_ip) = rewrite.src_ip {
        debug!(
            "src_ip: {}, dst_ip: {}, changing src to: {}",
            ipv6_packet.get_source(),
            ipv6_packet.get_destination(),
            src_ip
        );
        ipv6_packet.set_source(src_ip)
    }
    if let Some(dst_ip) = rewrite.dst_ip {
        debug!(
            "src_ip: {}, dst_ip: {}, changing dst to: {}",
            ipv6_packet.get_source(),
            ipv6_packet.get_destination(),
            dst_ip
        );
        ipv6_packet.set_destination(dst_ip);
    };
}

pub fn rewrite_udp(packet: &mut MutableUdpPacket, rewrite: &Option<PortRewrite>) {
    if let Some(rewrite) = rewrite {
        if let Some(src) = rewrite.src_port {
            debug!(
                "src_port: {}, dst_port: {}, changing src to: {}",
                packet.get_source(),
                packet.get_destination(),
                src
            );
            packet.set_source(src);
        }
        if let Some(dst) = rewrite.dst_port {
            debug!(
                "src_port: {}, dst_port: {}, changing dst to: {}",
                packet.get_source(),
                packet.get_destination(),
                dst
            );
            packet.set_destination(dst);
        }
    }
}

pub fn rewrite_tcp(packet: &mut MutableTcpPacket, rewrite: &Option<PortRewrite>) {
    if let Some(rewrite) = rewrite {
        if let Some(src) = rewrite.src_port {
            debug!(
                "src_port: {}, dst_port: {}, changing src to: {}",
                packet.get_source(),
                packet.get_destination(),
                src
            );
            packet.set_source(src);
        }
        if let Some(dst) = rewrite.dst_port {
            debug!(
                "src_port: {}, dst_port: {}, changing src to: {}",
                packet.get_source(),
                packet.get_destination(),
                dst
            );
            packet.set_destination(dst);
        }
    };
}

pub fn rewrite_dns(message: &mut Message, rewrite: &Option<DnsRewrite>) {
    if let Some(rewrite) = rewrite {
        for ans in message.answers_mut().iter_mut() {
            if let Some(ipv4) = rewrite.a {
                rewrite_a_record(ans, ipv4);
            }
            if let Some(ipv6) = rewrite.aaaa {
                rewrite_aaaa_record(ans, ipv6);
            }
        }

        for add in message.additionals_mut() {
            if let Some(ipv4) = rewrite.a {
                rewrite_a_record(add, ipv4);
            }
            if let Some(ipv6) = rewrite.aaaa {
                rewrite_aaaa_record(add, ipv6);
            }
        }
    }

    pub fn rewrite_a_record(record: &mut Record, ipv4: Ipv4Addr) {
        if record.data().is_a() {
            record.set_data(RData::A(hickory_proto::rr::rdata::a::A::from(ipv4)));
        }
    }

    pub fn rewrite_aaaa_record(record: &mut Record, ipv6: Ipv6Addr) {
        if record.data().is_aaaa() {
            record.set_data(RData::AAAA(hickory_proto::rr::rdata::aaaa::AAAA::from(
                ipv6,
            )));
        }
    }
}
