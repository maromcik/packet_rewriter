use crate::network::error::{NetworkError, NetworkErrorKind};
use crate::network::rewrite::{rewrite_dns, rewrite_ipv4, rewrite_ipv6, rewrite_mac, rewrite_tcp, rewrite_udp, rewrite_vlan, DataLinkRewrite, DnsRewrite, IpRewrite, PortRewrite};
use hickory_proto::op::Message;
use hickory_proto::serialize::binary::{BinDecodable, BinEncodable};
use pnet::packet::ethernet::{EtherType, EtherTypes, EthernetPacket, MutableEthernetPacket};
use pnet::packet::icmp::MutableIcmpPacket;
use pnet::packet::ip::{IpNextHeaderProtocol, IpNextHeaderProtocols};
use pnet::packet::ipv4::{checksum, MutableIpv4Packet};
use pnet::packet::ipv6::MutableIpv6Packet;
use pnet::packet::tcp::MutableTcpPacket;
use pnet::packet::tcp::{ipv4_checksum as ipv4_checksum_tcp, ipv6_checksum as ipv6_checksum_tcp};
use pnet::packet::udp::MutableUdpPacket;
use pnet::packet::udp::{ipv4_checksum as ipv4_checksum_udp, ipv6_checksum as ipv6_checksum_udp};
use pnet::packet::vlan::MutableVlanPacket;
use pnet::packet::{MutablePacket, Packet};
use std::net::{Ipv4Addr, Ipv6Addr};

pub trait FixablePacket {
    fn fix(&mut self, payload_len: Option<usize>);
    fn fix_payload_length(&mut self, payload_len: usize);
    fn fix_checksum(&mut self);
}

pub trait NetworkPacket {
    type ThisLayer<'a>;
    type NextLayer<'a>
    where
        Self: 'a;
    fn get_next_layer<'a>(&'a mut self) -> Self::NextLayer<'a>;
    fn get_mut_payload(&mut self) -> &mut [u8];
    fn get_payload(&self) -> &[u8];
    fn get_mut_packet(&mut self) -> &mut [u8];
    fn get_packet(&self) -> &[u8];
    fn set_payload(&mut self, payload: &[u8]);
}

pub trait NetworkApplicationPacket {
    type TransportLayer<'a>;
    type Type<'a>;
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

pub enum ApplicationPacketType<'a> {
    DnsPacket(Message),
    Other(&'a [u8]),}

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
    type NextLayer<'a>
        = Option<IpPacket<'a>>
    where
        Self: 'a;
    fn get_next_layer(&mut self) -> Self::NextLayer<'_> {
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

    fn get_mut_packet(&mut self) -> &mut [u8] {
        match self {
            DataLinkPacket::EthPacket(packet) => packet.packet_mut(),
            DataLinkPacket::VlanPacket(packet) => packet.packet_mut(),
        }
    }

    fn get_packet(&self) -> &[u8] {
        match self {
            DataLinkPacket::EthPacket(packet) => packet.packet(),
            DataLinkPacket::VlanPacket(packet) => packet.packet(),
        }
    }

    fn set_payload(&mut self, payload: &[u8]) {
        match self {
            DataLinkPacket::EthPacket(packet) => packet.set_payload(payload),
            DataLinkPacket::VlanPacket(packet) => packet.set_payload(payload),
        }
    }
}

fn get_ip_packet(ether_type: EtherType, payload: &'_ mut [u8]) -> Option<IpPacket<'_>> {
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

    pub fn unpack_vlan(&mut self) -> Option<DataLinkPacket> {
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

    pub fn get_length(&self) -> usize {
        match self {
            DataLinkPacket::EthPacket(packet) => packet.packet().len(),
            DataLinkPacket::VlanPacket(packet) => packet.packet().len(),
        }
    }
}

impl NetworkPacket for IpPacket<'_> {
    type ThisLayer<'a> = IpPacket<'a>;
    type NextLayer<'a>
        = Option<TransportPacket<'a>>
    where
        Self: 'a;
    fn get_next_layer(&mut self) -> Self::NextLayer<'_> {
        match self {
            IpPacket::Ipv4Packet(packet) => match packet.get_next_level_protocol() {
                IpNextHeaderProtocols::Icmp => {
                    let icmp_packet =
                        TransportPacket::Icmp(MutableIcmpPacket::new(self.get_mut_payload())?);
                    Some(icmp_packet)
                }
                IpNextHeaderProtocols::Tcp => {
                    let ip_addr_info = IpPacket::get_transport_packet_ipv4_addr(packet);
                    let tcp_packet = TransportPacket::Tcp(
                        MutableTcpPacket::new(self.get_mut_payload())?,
                        ip_addr_info,
                    );
                    Some(tcp_packet)
                }
                IpNextHeaderProtocols::Udp => {
                    let ip_addr_info = IpPacket::get_transport_packet_ipv4_addr(packet);
                    let udp_packet = TransportPacket::Udp(
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
                        TransportPacket::Icmp(MutableIcmpPacket::new(self.get_mut_payload())?);
                    Some(icmp_packet)
                }
                IpNextHeaderProtocols::Tcp => {
                    let ip_addr_info = IpPacket::get_transport_packet_ipv6_addr(packet);
                    let tcp_packet = TransportPacket::Tcp(
                        MutableTcpPacket::new(self.get_mut_payload())?,
                        ip_addr_info,
                    );
                    Some(tcp_packet)
                }
                IpNextHeaderProtocols::Udp => {
                    let ip_addr_info = IpPacket::get_transport_packet_ipv6_addr(packet);
                    let udp_packet = TransportPacket::Udp(
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

    fn get_mut_packet(&mut self) -> &mut [u8] {
        match self {
            IpPacket::Ipv4Packet(packet) => packet.packet_mut(),
            IpPacket::Ipv6Packet(packet) => packet.packet_mut(),
        }
    }

    fn get_packet(&self) -> &[u8] {
        match self {
            IpPacket::Ipv4Packet(packet) => packet.packet(),
            IpPacket::Ipv6Packet(packet) => packet.packet(),
        }
    }

    fn set_payload(&mut self, payload: &[u8]) {
        match self {
            IpPacket::Ipv4Packet(packet) => {
                packet.set_payload(payload);
            }
            IpPacket::Ipv6Packet(packet) => packet.set_payload(payload),
        }
        self.fix(Some(payload.len()));
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
            IpPacket::Ipv4Packet(ref mut packet) => {
                rewrite_ipv4(packet, rewrite);
            }
            IpPacket::Ipv6Packet(ref mut packet) => rewrite_ipv6(packet, rewrite),
        }
        self.fix(None);
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

impl FixablePacket for IpPacket<'_> {
    fn fix(&mut self, payload_len: Option<usize>) {
        if let Some(payload_len) = payload_len {
            self.fix_payload_length(payload_len);
        }
        self.fix_checksum();
    }
    fn fix_payload_length(&mut self, payload_len: usize) {
        match self {
            IpPacket::Ipv4Packet(packet) => {
                let total_len = (packet.get_header_length() as usize + payload_len) as u16;
                packet.set_total_length(total_len);
            }
            IpPacket::Ipv6Packet(packet) => {
                let payload_len = payload_len as u16;
                packet.set_payload_length(payload_len);
            }
        }
    }

    fn fix_checksum(&mut self) {
        if let IpPacket::Ipv4Packet(packet) = self {
            packet.set_checksum(checksum(&packet.to_immutable()))
        }
    }
}

impl NetworkPacket for TransportPacket<'_> {
    type ThisLayer<'a> = TransportPacket<'a>;
    type NextLayer<'a> = Option<ApplicationPacket<'a>>
    where
        Self: 'a;

    fn get_next_layer(&mut self) -> Self::NextLayer<'_> {
            ApplicationPacket::new(self)
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

    fn get_mut_packet(&mut self) -> &mut [u8] {
        match self {
            TransportPacket::Udp(packet, _) => packet.packet_mut(),
            TransportPacket::Tcp(packet, _) => packet.packet_mut(),
            TransportPacket::Icmp(packet) => packet.packet_mut(),
        }
    }

    fn get_packet(&self) -> &[u8] {
        match self {
            TransportPacket::Udp(packet, _) => packet.packet(),
            TransportPacket::Tcp(packet, _) => packet.packet(),
            TransportPacket::Icmp(packet) => packet.packet(),
        }
    }

    fn set_payload(&mut self, payload: &[u8]) {
        match self {
            TransportPacket::Udp(packet, _) => {
                packet.set_payload(payload);
            }
            TransportPacket::Tcp(packet, _) => {
                packet.set_payload(payload);
            }
            TransportPacket::Icmp(packet) => packet.set_payload(payload),
        }
        self.fix(Some(payload.len()))
    }
}

impl<'a> TransportPacket<'a> {
    pub fn rewrite(mut self, rewrite: &Option<PortRewrite>) -> TransportPacket<'a> {
        match self {
            TransportPacket::Udp(ref mut packet, _) => {
                rewrite_udp(packet, rewrite);
            }
            TransportPacket::Tcp(ref mut packet, _) => {
                rewrite_tcp(packet, rewrite);
            }
            TransportPacket::Icmp(_) => {}
        }
        self.fix(None);
        self
    }
}

impl FixablePacket for TransportPacket<'_> {
    fn fix(&mut self, payload_len: Option<usize>) {
        if let Some(payload_len) = payload_len {
            self.fix_payload_length(payload_len);
        }
        self.fix_checksum();
    }

    fn fix_payload_length(&mut self, payload_len: usize) {
        if let TransportPacket::Udp(packet, _) = self {
            let udp_len = (8 + payload_len) as u16;
            packet.set_length(udp_len);
        }
    }

    fn fix_checksum(&mut self) {
        match self {
            TransportPacket::Udp(packet, addr_info) => {
                let checksum = match addr_info {
                    TransportPacketIpAddress::Ipv4(ip_addr) => {
                        ipv4_checksum_udp(&packet.to_immutable(), &ip_addr.src, &ip_addr.dst)
                    }
                    TransportPacketIpAddress::Ipv6(ip_addr) => {
                        ipv6_checksum_udp(&packet.to_immutable(), &ip_addr.src, &ip_addr.dst)
                    }
                };
                packet.set_checksum(checksum);
            }
            TransportPacket::Tcp(packet, addr_info) => {
                let checksum = match addr_info {
                    TransportPacketIpAddress::Ipv4(ip_addr) => {
                        ipv4_checksum_tcp(&packet.to_immutable(), &ip_addr.src, &ip_addr.dst)
                    }
                    TransportPacketIpAddress::Ipv6(ip_addr) => {
                        ipv6_checksum_tcp(&packet.to_immutable(), &ip_addr.src, &ip_addr.dst)
                    }
                };
                packet.set_checksum(checksum);
            }
            TransportPacket::Icmp(_) => {}
        }
    }
}

pub struct ApplicationPacket<'a> {
    pub application_packet_type: ApplicationPacketType<'a>,
}

impl<'a> ApplicationPacket<'a> {
    pub fn new(transport: &'a TransportPacket<'a>) -> Option<ApplicationPacket<'a>> {
        match transport {
            TransportPacket::Udp(packet, _) => {
                let msg = Message::from_bytes(packet.payload()).ok()?;
                Some(ApplicationPacket {
                    application_packet_type: ApplicationPacketType::DnsPacket(msg),
                })
            }
            _ => None,
        }
    }
    pub fn from_bytes(port: i32, bytes: &'_ [u8]) -> Result<ApplicationPacket<'_>, NetworkError> {
        match port {
            53 | 5353 => Ok(ApplicationPacket {
                application_packet_type: ApplicationPacketType::DnsPacket(Message::from_bytes(
                    bytes,
                )?),
            }),
            _ => Ok(ApplicationPacket {
                application_packet_type: ApplicationPacketType::Other(bytes),
            }),
        }
    }

    pub fn get_owned_payload(&self) -> Result<Vec<u8>, NetworkError> {
        match self.application_packet_type {
            ApplicationPacketType::DnsPacket(ref packet) => Ok(packet.to_bytes()?),
            ApplicationPacketType::Other(packet) => Ok(packet.to_owned()),
        }
    }

    pub fn read_content(&mut self) -> String {
        match self.application_packet_type {
            ApplicationPacketType::DnsPacket(ref mut packet) => {
                packet.to_string()
            }
            ApplicationPacketType::Other(packet) => String::from_utf8_lossy(packet).to_string(),
        }
    }

    pub fn rewrite(mut self, rewrite: &Option<DnsRewrite>) -> ApplicationPacket<'a> {
        match self.application_packet_type {
            ApplicationPacketType::DnsPacket(ref mut packet) => rewrite_dns(packet, rewrite),
            ApplicationPacketType::Other(_) => {}
        }
        self
    }
}