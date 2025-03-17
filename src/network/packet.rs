use pnet::packet::ip::IpNextHeaderProtocol;
use pnet::packet::ipv4::MutableIpv4Packet;
use pnet::packet::ipv6::MutableIpv6Packet;
use pnet::packet::MutablePacket;

pub enum IpPacket<'a> {
    Ipv4Packet(MutableIpv4Packet<'a>),
    Ipv6Packet(MutableIpv6Packet<'a>),
}

impl<'a> IpPacket<'a> {
    pub fn get_mut_payload(&'a mut self) -> &'a mut [u8] {
        match self {
            IpPacket::Ipv4Packet(packet) => packet.payload_mut(),
            IpPacket::Ipv6Packet(packet) => packet.payload_mut(),
        }
    }
    
    pub fn get_next_header_protocol(&self) -> IpNextHeaderProtocol {
        match self {
            IpPacket::Ipv4Packet(packet) => packet.get_next_level_protocol(),
            IpPacket::Ipv6Packet(packet) => packet.get_next_header()
        }
    }
}