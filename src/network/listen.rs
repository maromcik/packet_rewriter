use std::thread::sleep;
use pcap::{Activated, State};
use pnet::packet::ethernet::{EthernetPacket, MutableEthernetPacket};
use pnet::packet::Packet;
use crate::network::capture::PacketCapture;
use crate::network::error::{NetworkError, NetworkErrorKind};
use crate::network::interface::{get_network_channel, NetworkConfig};
use crate::network::packet::DataLinkPacket;
use crate::network::rewrite::{rewrite_packet, Rewrite};

pub fn cap_rewrite<T>(
    mut capture: impl PacketCapture<T>,
    net_config: NetworkConfig,
    rewrite: Rewrite,
) -> Result<(), NetworkError>
where
    T: State + Activated,
{
    capture.apply_filter()?;
    let mut channel = get_network_channel(&net_config)?;
    let mut cap = capture.get_capture();
    while let Ok(cap_packet) = cap.next_packet() {
        let packet = EthernetPacket::new(cap_packet.data).ok_or(NetworkError::new(
            NetworkErrorKind::PacketConstructionError,
            "Invalid EthernetPacket",
        ))?;

        let mut buffer = vec![0; packet.packet().len()];
        let datalink_packet = DataLinkPacket::from_buffer(&mut buffer, &packet)?;
        rewrite_packet(datalink_packet, &rewrite);


        let new_packet = MutableEthernetPacket::new(&mut buffer[..]).ok_or(NetworkError::new(
            NetworkErrorKind::PacketConstructionError,
            "Could not construct an EthernetPacket",
        ))?;

        let eth_packet = new_packet.to_immutable();

        if net_config.straight || packet != eth_packet {
            channel.tx.send_to(eth_packet.packet(), None);
            println!("Packet sent")
        }
        if let Some(delay) = net_config.interval {
            sleep(delay);
        }
    }
    Ok(())
}