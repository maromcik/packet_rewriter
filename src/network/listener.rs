use crate::network::error::{NetworkError, NetworkErrorKind};
use pcap::{Capture, Device};
use pnet::datalink;
use pnet::datalink::Channel::Ethernet;
use pnet::packet::ethernet::{EthernetPacket, MutableEthernetPacket};
use pnet::packet::{MutablePacket, Packet};
use crate::network::rewrite::{rewrite_mac, Rewrite};

pub struct CaptureConfig {
    pub capture_device: String,
    pub filter: String,
    pub output_device: String,
}


pub fn cap_rewrite(capture: CaptureConfig, rewrite: Rewrite) -> Result<(), NetworkError> {
    let devices = Device::list()?;
    let target = devices
        .into_iter()
        .find(|d| d.name == capture.capture_device)
        .expect(&format!("No {} device found", capture.capture_device));

    println!("Listening on: {:?}", target.name);

    let mut cap = Capture::from_device(target)?
        .promisc(true)
        .immediate_mode(true)
        .open()?;

    cap.filter(&capture.filter, true)?;

    let interfaces = datalink::interfaces();
    let interface = interfaces.first().unwrap();

    let (mut tx, mut rx) = match datalink::channel(interface, Default::default()) {
        Ok(Ethernet(tx, rx)) => Ok((tx, rx)),
        Ok(_) => Err(NetworkError::new(NetworkErrorKind::NetworkChannelError, "Unknown channel type")),
        Err(e) => Err(NetworkError::new(NetworkErrorKind::NetworkChannelError, &e.to_string()))
    }?;

    while let Ok(cap_packet) = cap.next_packet() {
        let Some(packet) = EthernetPacket::new(cap_packet.data) else { continue };
        
        
        tx.build_and_send(1, packet.packet().len(),
                          &mut |mut new_packet| {
                              let mut new_packet = MutableEthernetPacket::new(new_packet).unwrap();

                              new_packet.clone_from(&packet);
                              
                              rewrite_mac(new_packet, &rewrite);
                              
                          });
    }
    Ok(())
}

