use crate::network::error::{NetworkError, NetworkErrorKind};
use crate::network::interface::{get_ipv4_channel, get_ipv6_channel, NetworkConfig};
use crate::network::packet::IpPacket;
use crate::network::rewrite::{rewrite_ip_packet, Rewrite};
use log::{debug, info, trace};
use nfq::Queue;
use pnet::packet::ipv4::{Ipv4Packet, MutableIpv4Packet};
use pnet::packet::ipv6::{Ipv6Packet, MutableIpv6Packet};
use pnet::packet::Packet;
use std::net::IpAddr;

pub fn nf_rewrite(
    _net_config: NetworkConfig,
    rewrite: Rewrite,
    nf_queue: u16,
) -> Result<(), NetworkError> {
    let mut channel4 = get_ipv4_channel()?;
    let mut channel6 = get_ipv6_channel()?;

    let mut queue = Queue::open()?;
    queue.bind(nf_queue)?;
    queue.set_recv_conntrack(nf_queue, true)?;
    queue.set_recv_security_context(nf_queue, true)?;
    queue.set_recv_uid_gid(nf_queue, true)?;

    info!("nfqueue initialized");

    loop {
        let mut msg = queue.recv()?;
        match msg.get_hw_protocol() {
            2048 => {
                let packet = Ipv4Packet::new(msg.get_payload_mut()).ok_or(NetworkError::new(
                    NetworkErrorKind::PacketConstructionError,
                    "Invalid IPv4 Packet",
                ))?;

                let mut buffer = vec![0; packet.packet().len()];
                let ip_packet = IpPacket::from_buffer_ipv4(&mut buffer, &packet)?;
                rewrite_ip_packet(ip_packet, &rewrite);
                let new_packet =
                    MutableIpv4Packet::new(&mut buffer[..]).ok_or(NetworkError::new(
                        NetworkErrorKind::PacketConstructionError,
                        "Could not construct an IPv4",
                    ))?;
                let dst = new_packet.get_destination();
                channel4.0.send_to(new_packet, IpAddr::V4(dst))?;
            }
            34525 => {
                let packet = Ipv6Packet::new(msg.get_payload_mut()).ok_or(NetworkError::new(
                    NetworkErrorKind::PacketConstructionError,
                    "Invalid IPv6 Packet",
                ))?;

                let mut buffer = vec![0; packet.packet().len()];
                let ip_packet = IpPacket::from_buffer_ipv6(&mut buffer, &packet)?;
                rewrite_ip_packet(ip_packet, &rewrite);
                let new_packet =
                    MutableIpv6Packet::new(&mut buffer[..]).ok_or(NetworkError::new(
                        NetworkErrorKind::PacketConstructionError,
                        "Could not construct an IPv6",
                    ))?;
                let dst = new_packet.get_destination();
                channel6.0.send_to(new_packet, IpAddr::V6(dst))?;
            }
            _ => {
                debug!("Not an IPv4 or IPv6 packet, skipping");
            }
        };
        trace!("Packet sent");
        queue.verdict(msg)?;
    }
}
