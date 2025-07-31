use log::{debug, info};
use nfq::{Message, Queue, Verdict};
use pnet::datalink::DataLinkSender;
use pnet::packet::ethernet::{EthernetPacket, MutableEthernetPacket};
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::Packet;
use crate::network::capture::PacketCapture;
use crate::network::error::{NetworkError, NetworkErrorKind};
use crate::network::interface::{get_network_channel, NetworkConfig};
use crate::network::packet::{DataLinkPacket, IpPacket};
use crate::network::rewrite::{rewrite_packet, Rewrite};

pub struct State {
    tx: Box<dyn DataLinkSender>,
    rewrite: Rewrite,
}

impl State {
    pub fn new(tx: Box<dyn DataLinkSender>, rewrite: Rewrite) -> Self {
        Self {
            tx,
            rewrite
        }
    }
}

pub fn nf_rewrite(net_config: NetworkConfig, rewrite: Rewrite, nf_queue: u16) -> Result<(), NetworkError> {
    let mut channel = get_network_channel(&net_config)?;


    let mut queue = Queue::open().unwrap();
    queue.bind(nf_queue).unwrap();
    queue.set_recv_conntrack(nf_queue, true).unwrap();
    queue.set_recv_security_context(nf_queue, true).unwrap();
    queue.set_recv_uid_gid(nf_queue, true).unwrap();


    info!("nfqueue initialized");

    loop {
        let mut msg = queue.recv().unwrap();

        let packet = Ipv4Packet::new(msg.get_payload()).ok_or(NetworkError::new(
            NetworkErrorKind::PacketConstructionError,
            "Invalid EthernetPacket",
        ))?;
        println!("KOKOT {:?}", msg.get_payload().len());

        let mut buffer = vec![0; packet.packet().len()];
        let datalink_packet = IpPacket::from_buffer(&mut buffer, &packet)?;
        rewrite_packet(datalink_packet, &rewrite);

        let new_packet = MutableEthernetPacket::new(&mut buffer[..]).ok_or(NetworkError::new(
            NetworkErrorKind::PacketConstructionError,
            "Could not construct an EthernetPacket",
        ))?;

        let eth_packet = new_packet.to_immutable();
        // channel.tx.send_to(eth_packet.packet(), None);

        msg.set_payload(eth_packet.packet());
        msg.set_verdict(Verdict::Accept);
        queue.verdict(msg).unwrap();
        debug!("Packet sent")

    }



}
