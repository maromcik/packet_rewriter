use std::time::Duration;
use crate::network::error::{NetworkError, NetworkErrorKind};
use pnet::datalink;
use pnet::datalink::Channel::Ethernet;
use pnet::datalink::{DataLinkReceiver, DataLinkSender};


pub struct NetworkConfig {
    pub output_device: String,
    pub interval: Option<Duration>,
    pub straight: bool,
}

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
