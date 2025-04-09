use crate::network::error::{NetworkError, NetworkErrorKind};
use crate::network::rewrite::{
    rewrite_ipv4, rewrite_ipv6, rewrite_mac, rewrite_tcp, rewrite_udp, rewrite_vlan,
    DataLinkRewrite, IpRewrite, PortRewrite,
};
use pnet::packet::dns::{
    DnsQueryPacket, DnsResponsePacket, MutableDnsPacket, MutableDnsResponsePacket,
};
use pnet::packet::ethernet::{EtherType, EtherTypes, EthernetPacket, MutableEthernetPacket};
use pnet::packet::icmp::MutableIcmpPacket;
use pnet::packet::ip::{IpNextHeaderProtocol, IpNextHeaderProtocols};
use pnet::packet::ipv4::{Ipv4Packet, MutableIpv4Packet};
use pnet::packet::ipv6::{Ipv6Packet, MutableIpv6Packet};
use pnet::packet::tcp::MutableTcpPacket;
use pnet::packet::udp::MutableUdpPacket;
use pnet::packet::vlan::MutableVlanPacket;
use pnet::packet::{MutablePacket, Packet};
use std::net::{Ipv4Addr, Ipv6Addr};
use clap::builder;
use dns_parser::RData;

pub trait NetworkPacket {
    type ThisLayer<'a>;
    type NextLayer<'a>;
    fn get_next_layer(&mut self) -> Option<impl NetworkPacket>;
    fn get_mut_payload(&mut self) -> &mut [u8];
    fn get_payload(&self) -> &[u8];
}

pub enum DataLinkPacket<'a> {
    EthPacket(MutableEthernetPacket<'a>),
    VlanPacket(MutableVlanPacket<'a>),
}

pub enum IpPacket<'a> {
    Ipv4Packet(MutableIpv4Packet<'a>),
    Ipv6Packet(MutableIpv6Packet<'a>),
}

pub enum TransportPacket<'a> {
    Udp(MutableUdpPacket<'a>, TransportPacketIpAddress),
    Tcp(MutableTcpPacket<'a>, TransportPacketIpAddress),
    Icmp(MutableIcmpPacket<'a>),
}

pub enum TransportPacketIpAddress {
    Ipv4(TransportPacketIpv4Addresses),
    Ipv6(TransportPacketIpv6Addresses),
}

pub struct TransportPacketIpv4Addresses {
    pub src: Ipv4Addr,
    pub dst: Ipv4Addr,
}

impl TransportPacketIpv4Addresses {
    pub fn new(src: Ipv4Addr, dst: Ipv4Addr) -> TransportPacketIpv4Addresses {
        Self { src, dst }
    }
}
pub struct TransportPacketIpv6Addresses {
    pub src: Ipv6Addr,
    pub dst: Ipv6Addr,
}

impl TransportPacketIpv6Addresses {
    pub fn new(src: Ipv6Addr, dst: Ipv6Addr) -> TransportPacketIpv6Addresses {
        Self { src, dst }
    }
}

pub enum ApplicationPacket<'a> {
    DnsPacket(MutableDnsPacket<'a>),
}

impl<'a> From<MutableEthernetPacket<'a>> for DataLinkPacket<'a> {
    fn from(value: MutableEthernetPacket<'a>) -> Self {
        Self::EthPacket(value)
    }
}

impl<'a> From<MutableVlanPacket<'a>> for DataLinkPacket<'a> {
    fn from(value: MutableVlanPacket<'a>) -> Self {
        Self::VlanPacket(value)
    }
}

impl NetworkPacket for DataLinkPacket<'_> {
    type ThisLayer<'a> = DataLinkPacket<'a>;
    type NextLayer<'a> = IpPacket<'a>;

    fn get_next_layer(&mut self) -> Option<Self::NextLayer<'_>> {
        match self {
            DataLinkPacket::EthPacket(packet) => {
                get_ip_packet(packet.get_ethertype(), packet.payload_mut())
            }
            DataLinkPacket::VlanPacket(packet) => {
                get_ip_packet(packet.get_ethertype(), packet.payload_mut())
            }
        }
    }

    fn get_mut_payload(&mut self) -> &mut [u8] {
        match self {
            DataLinkPacket::EthPacket(packet) => packet.payload_mut(),
            DataLinkPacket::VlanPacket(packet) => packet.payload_mut(),
        }
    }

    fn get_payload(&self) -> &[u8] {
        match self {
            DataLinkPacket::EthPacket(packet) => packet.payload(),
            DataLinkPacket::VlanPacket(packet) => packet.payload(),
        }
    }
}

fn get_ip_packet(ether_type: EtherType, payload: &mut [u8]) -> Option<IpPacket> {
    match ether_type {
        EtherTypes::Ipv4 => {
            let ipv4_packet = MutableIpv4Packet::new(payload)?;
            Some(IpPacket::Ipv4Packet(ipv4_packet))
        }
        EtherTypes::Ipv6 => {
            let ipv6_packet = MutableIpv6Packet::new(payload)?;
            Some(IpPacket::Ipv6Packet(ipv6_packet))
        }
        _ => None,
    }
}

impl<'a> DataLinkPacket<'a> {
    pub fn from_buffer(
        value: &'a mut [u8],
        packet: &EthernetPacket,
    ) -> Result<DataLinkPacket<'a>, NetworkError> {
        let mut new_packet =
            MutableEthernetPacket::new(&mut value[..]).ok_or(NetworkError::new(
                NetworkErrorKind::PacketConstructionError,
                "Could not construct an EthernetPacket",
            ))?;
        new_packet.clone_from(packet);
        Ok(DataLinkPacket::EthPacket(new_packet))
    }
    pub fn new_eth(packet: MutableEthernetPacket<'a>) -> Self {
        DataLinkPacket::EthPacket(packet)
    }

    pub fn new_vlan(packet: MutableVlanPacket<'a>) -> Self {
        DataLinkPacket::VlanPacket(packet)
    }

    pub fn get_ether_type(&'a self) -> EtherType {
        match self {
            DataLinkPacket::EthPacket(p) => p.get_ethertype(),
            DataLinkPacket::VlanPacket(p) => p.get_ethertype(),
        }
    }

    pub fn rewrite(mut self, rewrite: &Option<DataLinkRewrite>) -> DataLinkPacket<'a> {
        let Some(rewrite) = &rewrite else { return self };
        match self {
            DataLinkPacket::EthPacket(ref mut packet) => rewrite_mac(packet, rewrite),
            DataLinkPacket::VlanPacket(ref mut packet) => rewrite_vlan(packet, rewrite),
        }
        self
    }

    pub fn unpack_vlan(&'a mut self) -> Option<DataLinkPacket<'a>> {
        match self {
            DataLinkPacket::EthPacket(ref mut packet) => {
                if packet.get_ethertype() == EtherTypes::Vlan {
                    return Some(DataLinkPacket::VlanPacket(MutableVlanPacket::new(
                        packet.payload_mut(),
                    )?));
                }
                Some(DataLinkPacket::EthPacket(MutableEthernetPacket::new(
                    packet.packet_mut(),
                )?))
            }
            DataLinkPacket::VlanPacket(packet) => Some(DataLinkPacket::VlanPacket(
                MutableVlanPacket::new(packet.packet_mut())?,
            )),
        }
    }
}

impl NetworkPacket for IpPacket<'_> {
    type ThisLayer<'a> = IpPacket<'a>;
    type NextLayer<'a> = TransportPacket<'a>;

    fn get_next_layer(&mut self) -> Option<Self::NextLayer<'_>> {
        match self {
            IpPacket::Ipv4Packet(packet) => match packet.get_next_level_protocol() {
                IpNextHeaderProtocols::Icmp => {
                    let icmp_packet =
                        Self::NextLayer::Icmp(MutableIcmpPacket::new(self.get_mut_payload())?);
                    Some(icmp_packet)
                }
                IpNextHeaderProtocols::Tcp => {
                    let ip_addr_info = IpPacket::get_transport_packet_ipv4_addr(packet);
                    let tcp_packet = Self::NextLayer::Tcp(
                        MutableTcpPacket::new(self.get_mut_payload())?,
                        ip_addr_info,
                    );
                    Some(tcp_packet)
                }
                IpNextHeaderProtocols::Udp => {
                    let ip_addr_info = IpPacket::get_transport_packet_ipv4_addr(packet);
                    let udp_packet = Self::NextLayer::Udp(
                        MutableUdpPacket::new(self.get_mut_payload())?,
                        ip_addr_info,
                    );
                    Some(udp_packet)
                }
                _ => None,
            },
            IpPacket::Ipv6Packet(packet) => match packet.get_next_header() {
                IpNextHeaderProtocols::Icmp => {
                    let icmp_packet =
                        Self::NextLayer::Icmp(MutableIcmpPacket::new(self.get_mut_payload())?);
                    Some(icmp_packet)
                }
                IpNextHeaderProtocols::Tcp => {
                    let ip_addr_info = IpPacket::get_transport_packet_ipv6_addr(packet);
                    let tcp_packet = Self::NextLayer::Tcp(
                        MutableTcpPacket::new(self.get_mut_payload())?,
                        ip_addr_info,
                    );
                    Some(tcp_packet)
                }
                IpNextHeaderProtocols::Udp => {
                    let ip_addr_info = IpPacket::get_transport_packet_ipv6_addr(packet);
                    let udp_packet = Self::NextLayer::Udp(
                        MutableUdpPacket::new(self.get_mut_payload())?,
                        ip_addr_info,
                    );
                    Some(udp_packet)
                }
                _ => None,
            },
        }
    }

    fn get_mut_payload(&mut self) -> &mut [u8] {
        match self {
            IpPacket::Ipv4Packet(packet) => packet.payload_mut(),
            IpPacket::Ipv6Packet(packet) => packet.payload_mut(),
        }
    }

    fn get_payload(&self) -> &[u8] {
        match self {
            IpPacket::Ipv4Packet(packet) => packet.payload(),
            IpPacket::Ipv6Packet(packet) => packet.payload(),
        }
    }
}

impl<'a> IpPacket<'a> {
    pub fn get_next_header_protocol(&self) -> IpNextHeaderProtocol {
        match self {
            IpPacket::Ipv4Packet(packet) => packet.get_next_level_protocol(),
            IpPacket::Ipv6Packet(packet) => packet.get_next_header(),
        }
    }

    pub fn rewrite(mut self, rewrite: &Option<IpRewrite>) -> IpPacket<'a> {
        let Some(rewrite) = &rewrite else { return self };
        match self {
            IpPacket::Ipv4Packet(ref mut packet) => rewrite_ipv4(packet, rewrite),
            IpPacket::Ipv6Packet(ref mut packet) => rewrite_ipv6(packet, rewrite),
        }
        self
    }
    pub fn get_transport_packet_ipv4_addr(
        packet: &mut MutableIpv4Packet,
    ) -> TransportPacketIpAddress {
        TransportPacketIpAddress::Ipv4(TransportPacketIpv4Addresses::new(
            packet.get_source(),
            packet.get_destination(),
        ))
    }

    pub fn get_transport_packet_ipv6_addr(packet: &MutableIpv6Packet) -> TransportPacketIpAddress {
        TransportPacketIpAddress::Ipv6(TransportPacketIpv6Addresses::new(
            packet.get_source(),
            packet.get_destination(),
        ))
    }
}

impl NetworkPacket for TransportPacket<'_> {
    type ThisLayer<'a> = TransportPacket<'a>;
    type NextLayer<'a> = ApplicationPacket<'a>;

    fn get_next_layer(&mut self) -> Option<Self::NextLayer<'_>> {
        match self {
            TransportPacket::Udp(packet, _) => {
                Some(ApplicationPacket::DnsPacket(
                    MutableDnsPacket::new(packet.payload_mut())?
                ))
            },
            TransportPacket::Tcp(packet, _) => None,
            TransportPacket::Icmp(packet) => None,
        }
    }

    fn get_mut_payload(&mut self) -> &mut [u8] {
        match self {
            TransportPacket::Udp(packet, _) => packet.payload_mut(),
            TransportPacket::Tcp(packet, _) => packet.payload_mut(),
            TransportPacket::Icmp(packet) => packet.payload_mut(),
        }
    }

    fn get_payload(&self) -> &[u8] {
        match self {
            TransportPacket::Udp(packet, _) => packet.payload(),
            TransportPacket::Tcp(packet, _) => packet.payload(),
            TransportPacket::Icmp(packet) => packet.payload(),
        }
    }
}

impl<'a> TransportPacket<'a> {
    pub fn rewrite(mut self, rewrite: &Option<PortRewrite>) -> TransportPacket<'a> {
        match self {
            TransportPacket::Udp(ref mut packet, ref ip_addr_info) => {
                rewrite_udp(packet, rewrite, ip_addr_info)
            }
            TransportPacket::Tcp(ref mut packet, ref ip_addr_info) => {
                rewrite_tcp(packet, rewrite, ip_addr_info)
            }
            TransportPacket::Icmp(_) => {}
        }
        self
    }
}

impl NetworkPacket for ApplicationPacket<'_> {
    type ThisLayer<'a> = ApplicationPacket<'a>;
    type NextLayer<'a> = Option<()>;

    fn get_next_layer(&mut self) -> Option<Self::ThisLayer<'_>> {
        None
    }

    fn get_mut_payload(&mut self) -> &mut [u8] {
        match self {
            ApplicationPacket::DnsPacket(packet) => packet.payload_mut(),
        }
    }

    fn get_payload(&self) -> &[u8] {
        match self {
            ApplicationPacket::DnsPacket(packet) => packet.payload(),
        }
    }
}

impl ApplicationPacket<'_> {
    pub fn print_payload(&mut self) -> Option<()> {
        match self {
            ApplicationPacket::DnsPacket(packet) => {
                
                let mut dns_packet = dns_parser::Packet::parse(packet.packet()).unwrap();
                
                for q in &dns_packet.questions {
                    println!("Q: {}", q.qname);
                }
                
                for r in &mut dns_packet.answers {
                    println!("R: {}", r.name);
                    match &mut r.data {
                        RData::A(a) => {
                            println!("BEFORE: {}", a.0);
                            
                            a.0 = Ipv4Addr::from([192, 168, 1, 1]);
                            println!("AFTER: {}", a.0)
                            }
                        RData::AAAA(aaaa) => {println!("AAAA: {}", aaaa.0)}
                        RData::CNAME(cname) => {println!("CNAME: {}", cname.0)}
                        RData::MX(_) => {}
                        RData::NS(_) => {}
                        RData::PTR(ptr) => {println!("PTR: {}", ptr.0)}
                        RData::SOA(_) => {}
                        RData::SRV(_) => {}
                        RData::TXT(txt) => {
                                for record in txt.iter() {
                                    println!("TXT: {:?}", String::from_utf8(Vec::from(record)).unwrap());
                                }   
                            }
                        RData::Unknown(_, _) => {}
                    }
                }
                let mut new_dns = dns_parser::Builder::new_query(1, false);
                new_dns.add_question(
                    "pes.sk", false, dns_parser::QueryType::A, dns_parser::QueryClass::IN
                );
                
                packet.set_payload(&new_dns.build().unwrap());

                Some(())
            }
        }
    }
}
