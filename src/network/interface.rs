use crate::network::error::{NetworkError, NetworkErrorKind};
use pnet::datalink;
use pnet::datalink::Channel::Ethernet;
use pnet::datalink::{DataLinkReceiver, DataLinkSender};
use pnet::packet::ip::{IpNextHeaderProtocol, IpNextHeaderProtocols};
use pnet::transport::{TransportChannelType, TransportReceiver, TransportSender};
use std::time::Duration;

pub struct NetworkConfig {
    pub output_device: String,
    pub interval: Option<Duration>,
    pub straight: bool,
}

#[allow(dead_code)]
pub struct NetworkChannel {
    pub rx: Box<dyn DataLinkReceiver>,
    pub tx: Box<dyn DataLinkSender>,
}

pub fn get_network_channel(capture: &NetworkConfig) -> Result<NetworkChannel, NetworkError> {
    let interfaces = datalink::interfaces();
    let interface = interfaces
        .iter()
        .find(|i| i.name == capture.output_device)
        .ok_or(NetworkError::new(
            NetworkErrorKind::NetworkInterfaceError,
            &format!("Output device {} not found", capture.output_device),
        ))?;
    let (tx, rx) = match datalink::channel(interface, Default::default()) {
        Ok(Ethernet(tx, rx)) => Ok((tx, rx)),
        Ok(_) => Err(NetworkError::new(
            NetworkErrorKind::NetworkChannelError,
            "Unknown channel type",
        )),
        Err(e) => Err(NetworkError::new(
            NetworkErrorKind::NetworkChannelError,
            &e.to_string(),
        )),
    }?;

    Ok(NetworkChannel { rx, tx })
}

pub fn get_ipv4_channel() -> Result<(TransportSender, TransportReceiver), NetworkError> {
    let t = TransportChannelType::Layer3(IpNextHeaderProtocol(IpNextHeaderProtocols::Ipv4.0));
    let channel = pnet::transport::transport_channel(1000, t)?;
    Ok(channel)
}

pub fn get_ipv6_channel() -> Result<(TransportSender, TransportReceiver), NetworkError> {
    let t = TransportChannelType::Layer3(IpNextHeaderProtocol(IpNextHeaderProtocols::Ipv6.0));
    let channel = pnet::transport::transport_channel(1000, t)?;
    Ok(channel)
}
