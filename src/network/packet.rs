use crate::network::error::{NetworkError, NetworkErrorKind};
use crate::network::rewrite::{
    rewrite_ipv4, rewrite_ipv6, rewrite_mac, rewrite_vlan, DataLinkRewrite, IpRewrite, MacRewrite,
    Rewrite, VlanRewrite,
};
use pnet::packet::ethernet::{EtherType, EtherTypes, MutableEthernetPacket};
use pnet::packet::ip::{IpNextHeaderProtocol, IpNextHeaderProtocols};
use pnet::packet::ipv4::MutableIpv4Packet;
use pnet::packet::ipv6::MutableIpv6Packet;
use pnet::packet::tcp::MutableTcpPacket;
use pnet::packet::udp::MutableUdpPacket;
use pnet::packet::vlan::{MutableVlanPacket, VlanPacket};
use pnet::packet::{MutablePacket, Packet};

pub trait NetworkPacket {
    type ThisLayer<'a>;
    type NextLayer<'a>;
    fn get_next_layer<'a>(&'a mut self) -> Option<impl NetworkPacket>;
    fn get_mut_payload<'a>(&'a mut self) -> &'a mut [u8];
    fn get_payload<'a>(&'a self) -> &'a [u8];
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

impl<'a> From<MutableEthernetPacket<'a>> for DataLinkPacket<'a> {
    fn from(value: MutableEthernetPacket<'a>) -> Self {
        // if let EtherTypes::Vlan = value.get_ethertype() {
        //     let vlan_packet = MutableVlanPacket::new(value).ok_or(
        //         NetworkError::new(NetworkErrorKind::PacketConstructionError, "Invalid VLAN packet")
        //     ).unwrap();
        //     return DataLinkPacket::VlanPacket(vlan_packet)
        // }
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

    fn get_next_layer<'a>(&'a mut self) -> Option<Self::NextLayer<'a>> {
        match self {
            DataLinkPacket::EthPacket(packet) => match packet.get_ethertype() {
                EtherTypes::Ipv4 => {
                    let ipv4_packet =
                        MutableIpv4Packet::new(packet.payload_mut())?;
                    Some(IpPacket::Ipv4Packet(ipv4_packet))
                }
                EtherTypes::Ipv6 => {
                    let ipv6_packet =
                        MutableIpv6Packet::new(packet.payload_mut())?;
                    Some(IpPacket::Ipv6Packet(ipv6_packet))
                }
                _ => None,
            },
            DataLinkPacket::VlanPacket(packet) => match packet.get_ethertype() {
                EtherTypes::Ipv4 => {
                    let ipv4_packet =
                        MutableIpv4Packet::new(packet.payload_mut())?;
                    Some(IpPacket::Ipv4Packet(ipv4_packet))
                }
                EtherTypes::Ipv6 => {
                    let ipv6_packet =
                        MutableIpv6Packet::new(packet.payload_mut())?;
                    Some(IpPacket::Ipv6Packet(ipv6_packet))
                }
                _ => None,
            },
        }
    }

    fn get_mut_payload<'a>(&'a mut self) -> &'a mut [u8] {
        match self {
            DataLinkPacket::EthPacket(packet) => packet.payload_mut(),
            DataLinkPacket::VlanPacket(packet) => packet.payload_mut(),
        }
    }

    fn get_payload<'a>(&'a self) -> &'a [u8] {
        match self {
            DataLinkPacket::EthPacket(packet) => packet.payload(),
            DataLinkPacket::VlanPacket(packet) => packet.payload(),
        }
    }
}

impl<'a> DataLinkPacket<'a> {
    pub fn from_buffer(value: &'a mut Vec<u8>) -> Result<DataLinkPacket<'a>, NetworkError> {
        Ok(DataLinkPacket::EthPacket(MutableEthernetPacket::new(&mut value[..]).ok_or(NetworkError::new(
            NetworkErrorKind::PacketConstructionError,
            "Could not construct a EthernetPacket",
        ))?))
    }
    pub fn new_eth(packet: MutableEthernetPacket<'a>) -> Self {
        DataLinkPacket::EthPacket(packet)
    }

    pub fn new_vlan(packet: MutableVlanPacket<'a>) -> Self {
        DataLinkPacket::VlanPacket(packet)
    }
    pub fn get_ether_type(&'a mut self) -> EtherType {
        match self {
            DataLinkPacket::EthPacket(p) => p.get_ethertype(),
            DataLinkPacket::VlanPacket(p) => p.get_ethertype(),
        }
    }

    pub fn rewrite(&'a mut self, rewrite: &Option<DataLinkRewrite>) -> &mut DataLinkPacket<'a> {
        let Some(rewrite) = &rewrite else {
            return self
        };
        match self {
            DataLinkPacket::EthPacket(packet) => rewrite_mac(packet, rewrite),
            DataLinkPacket::VlanPacket(packet) => rewrite_vlan(packet, rewrite),
        }
        self
    }

    pub fn unpack_vlan(self) -> DataLinkPacket<'a> {
        match self {
            DataLinkPacket::EthPacket(packet) => DataLinkPacket::new_eth(packet),
            DataLinkPacket::VlanPacket(packet) => DataLinkPacket::VlanPacket(packet),
        }
    }
}

impl NetworkPacket for IpPacket<'_> {
    type ThisLayer<'a> = IpPacket<'a>;
    type NextLayer<'a> = TransportPacket<'a>;

    fn get_next_layer<'a>(&'a mut self) -> Option<Self::NextLayer<'a>> {
        match self {
            IpPacket::Ipv4Packet(_) | IpPacket::Ipv6Packet(_) => match self
                .get_next_header_protocol()
            {
                IpNextHeaderProtocols::Tcp => {
                    let tcp_packet = TransportPacket::Tcp(
                        MutableTcpPacket::new(self.get_mut_payload())?,
                    );
                    Some(tcp_packet)
                }
                IpNextHeaderProtocols::Udp => {
                    let udp_packet = TransportPacket::Udp(
                        MutableUdpPacket::new(self.get_mut_payload())?,
                    );
                    Some(udp_packet)
                }
                _ => None,
            },
        }
    }

    fn get_mut_payload<'a>(&'a mut self) -> &'a mut [u8] {
        match self {
            IpPacket::Ipv4Packet(packet) => packet.payload_mut(),
            IpPacket::Ipv6Packet(packet) => packet.payload_mut(),
        }
    }

    fn get_payload<'a>(&'a self) -> &'a [u8] {
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

    pub fn rewrite(&'a mut self, rewrite: &Option<IpRewrite>) -> &'a mut IpPacket<'a> {
        let Some(rewrite) = &rewrite else {
            return self
        };
        match self {
            IpPacket::Ipv4Packet(packet) => rewrite_ipv4(packet, rewrite),
            IpPacket::Ipv6Packet(packet) => rewrite_ipv6(packet, rewrite),
        }
        self
    }
}

impl NetworkPacket for TransportPacket<'_> {
    type ThisLayer<'a> = TransportPacket<'a>;
    type NextLayer<'a> = ();

    fn get_next_layer<'a>(&'a mut self) -> Option<Self::ThisLayer<'a>> {
        todo!()
    }

    fn get_mut_payload<'a>(&'a mut self) -> &'a mut [u8] {
        todo!()
    }

    fn get_payload<'a>(&'a self) -> &'a [u8] {
        todo!()
    }
}
