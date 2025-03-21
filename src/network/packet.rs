use crate::network::error::{NetworkError, NetworkErrorKind};
use crate::network::rewrite::{
    rewrite_ipv4, rewrite_ipv6, rewrite_mac, rewrite_tcp, rewrite_udp, rewrite_vlan,
    DataLinkRewrite, IpRewrite, PortRewrite,
};
use pnet::packet::dns::MutableDnsPacket;
use pnet::packet::ethernet::{EtherType, EtherTypes, EthernetPacket, MutableEthernetPacket};
use pnet::packet::ip::{IpNextHeaderProtocol, IpNextHeaderProtocols};
use pnet::packet::ipv4::MutableIpv4Packet;
use pnet::packet::ipv6::MutableIpv6Packet;
use pnet::packet::tcp::MutableTcpPacket;
use pnet::packet::udp::MutableUdpPacket;
use pnet::packet::vlan::MutableVlanPacket;
use pnet::packet::{MutablePacket, Packet};

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
    Udp(MutableUdpPacket<'a>),
    Tcp(MutableTcpPacket<'a>),
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

    pub fn unpack_vlan(self) -> DataLinkPacket<'a> {
        match self {
            DataLinkPacket::EthPacket(_) => self,
            DataLinkPacket::VlanPacket(packet) => DataLinkPacket::VlanPacket(packet),
        }
    }
}

impl NetworkPacket for IpPacket<'_> {
    type ThisLayer<'a> = IpPacket<'a>;
    type NextLayer<'a> = TransportPacket<'a>;

    fn get_next_layer(&mut self) -> Option<Self::NextLayer<'_>> {
        match self {
            IpPacket::Ipv4Packet(_) | IpPacket::Ipv6Packet(_) => {
                match self.get_next_header_protocol() {
                    IpNextHeaderProtocols::Tcp => {
                        let tcp_packet =
                            Self::NextLayer::Tcp(MutableTcpPacket::new(self.get_mut_payload())?);
                        Some(tcp_packet)
                    }
                    IpNextHeaderProtocols::Udp => {
                        let udp_packet =
                            Self::NextLayer::Udp(MutableUdpPacket::new(self.get_mut_payload())?);
                        Some(udp_packet)
                    }
                    _ => None,
                }
            }
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
}

impl NetworkPacket for TransportPacket<'_> {
    type ThisLayer<'a> = TransportPacket<'a>;
    type NextLayer<'a> = ApplicationPacket<'a>;

    fn get_next_layer(&mut self) -> Option<Self::NextLayer<'_>> {
        match self {
            TransportPacket::Udp(packet) => Some(ApplicationPacket::DnsPacket(
                MutableDnsPacket::new(packet.payload_mut())?,
            )),
            TransportPacket::Tcp(packet) => None,
        }
    }

    fn get_mut_payload(&mut self) -> &mut [u8] {
        match self {
            TransportPacket::Udp(packet) => packet.payload_mut(),
            TransportPacket::Tcp(packet) => packet.payload_mut(),
        }
    }

    fn get_payload(&self) -> &[u8] {
        match self {
            TransportPacket::Udp(packet) => packet.payload(),
            TransportPacket::Tcp(packet) => packet.payload(),
        }
    }
}

impl<'a> TransportPacket<'a> {
    pub fn rewrite(mut self, rewrite: &Option<PortRewrite>) -> TransportPacket<'a> {
        match self {
            TransportPacket::Udp(ref mut packet) => rewrite_udp(packet, rewrite),
            TransportPacket::Tcp(ref mut packet) => rewrite_tcp(packet, rewrite),
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
    pub fn print_payload(&self) {
        match self {
            ApplicationPacket::DnsPacket(packet) => {
                // for q in packet.get_queries() {
                //     if let Ok(data) = String::from_utf8(q.qname) {
                //         println!("QUERY: {}", data);
                //     } else {
                //         println!("Error in reading mDNS query")
                //     }
                }
                // for r in packet.get_responses() {
                //     if let Ok(data) = String::from_utf8(r.payload) {
                //         println!("RESPONSE: {}", data)
                //     } else {
                //         println!("Error in reading mDNS response")
                //     }
                // }
            }
    }
}
