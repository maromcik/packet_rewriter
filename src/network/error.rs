use pnet::datalink::ParseMacAddrErr;
use std::error::Error;
use std::fmt::{Display, Formatter};
use std::net::AddrParseError;
use std::num::ParseIntError;
use std::sync::mpsc;

#[derive(Debug, Clone)]
pub enum NetworkErrorKind {
    CaptureError,
    NetworkInterfaceError,
    NetworkChannelError,
    RustChannelError,
    ParseAddrError,
    PacketConstructionError,
    DnsError,
}

impl Display for NetworkErrorKind {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            NetworkErrorKind::CaptureError => f.write_str("Capture error"),
            NetworkErrorKind::NetworkInterfaceError => f.write_str("Network interface error"),
            NetworkErrorKind::NetworkChannelError => f.write_str("Network channel error"),
            NetworkErrorKind::RustChannelError => f.write_str("Rust channel error"),
            NetworkErrorKind::ParseAddrError => f.write_str("Address parse error"),
            NetworkErrorKind::PacketConstructionError => {
                f.write_str("Packet could not be constructed")
            }
            NetworkErrorKind::DnsError => f.write_str("Dns packet could not be parsed"),
        }
    }
}

#[derive(Debug, Clone)]
pub struct NetworkError {
    pub error_kind: NetworkErrorKind,
    pub message: String,
}

impl Display for NetworkError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "Network Error: {}: {}", self.error_kind, self.message)
    }
}

impl Error for NetworkError {}

impl NetworkError {
    pub fn new(error_kind: NetworkErrorKind, message: &str) -> Self {
        Self {
            error_kind,
            message: message.to_owned(),
        }
    }
}

impl From<pcap::Error> for NetworkError {
    fn from(value: pcap::Error) -> Self {
        NetworkError::new(NetworkErrorKind::CaptureError, &value.to_string())
    }
}

impl<T> From<mpsc::SendError<T>> for NetworkError {
    fn from(value: mpsc::SendError<T>) -> Self {
        NetworkError::new(NetworkErrorKind::RustChannelError, &value.to_string())
    }
}

impl From<mpsc::RecvError> for NetworkError {
    fn from(value: mpsc::RecvError) -> Self {
        NetworkError::new(NetworkErrorKind::RustChannelError, &value.to_string())
    }
}

impl From<ParseMacAddrErr> for NetworkError {
    fn from(value: ParseMacAddrErr) -> Self {
        NetworkError::new(NetworkErrorKind::ParseAddrError, &value.to_string())
    }
}

impl From<AddrParseError> for NetworkError {
    fn from(value: AddrParseError) -> Self {
        NetworkError::new(NetworkErrorKind::ParseAddrError, &value.to_string())
    }
}

impl From<ParseIntError> for NetworkError {
    fn from(value: ParseIntError) -> Self {
        NetworkError::new(NetworkErrorKind::ParseAddrError, &value.to_string())
    }
}

impl From<hickory_proto::ProtoError> for NetworkError {
    fn from(value: hickory_proto::ProtoError) -> Self {
        Self::new(NetworkErrorKind::DnsError, value.to_string().as_str())
    }
}
