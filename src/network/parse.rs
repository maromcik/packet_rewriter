use crate::network::error::NetworkError;
use pnet::datalink::MacAddr;
use std::str::FromStr;

pub fn parse_mac(mac: Option<String>) -> Result<Option<MacAddr>, NetworkError> {
    // Ok(mac.map(|m| MacAddr::from_str(&m)?))
    match mac {
        None => Ok(None),
        Some(m) => Ok(Some(MacAddr::from_str(&m)?)),
    }
}

