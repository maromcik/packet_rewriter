use crate::error::AppError;
use crate::network::error::NetworkError;
use crate::network::rewrite::{Ipv4Rewrite, MacRewrite, PortRewrite, Rewrite, VlanRewrite};
use crate::Cli;
use pnet::datalink::{MacAddr, ParseMacAddrErr};
use std::net::{AddrParseError, Ipv4Addr, Ipv6Addr};
use std::num::ParseIntError;
use std::str::FromStr;

pub fn parse_mac(mac: Option<&String>) -> Result<Option<MacAddr>, ParseMacAddrErr> {
    mac.map(|m| MacAddr::from_str(&m)).transpose()
}

pub fn parse_ipv4(ip: Option<&String>) -> Result<Option<Ipv4Addr>, AddrParseError> {
    ip.map(|m| Ipv4Addr::from_str(&m)).transpose()
}

pub fn parse_ipv6(ip: Option<&String>) -> Result<Option<Ipv6Addr>, AddrParseError> {
    ip.map(|m| Ipv6Addr::from_str(&m)).transpose()
}

pub fn parse_port(port: Option<&String>) -> Result<Option<u16>, ParseIntError> {
    port.map(|p| p.parse::<u16>()).transpose()
}

pub fn parse_rewrites(cli: Cli) -> Result<Rewrite, NetworkError> {
    let mac_rewrite = match (cli.src_mac, cli.dst_mac) {
        (src_mac, Some(dst_mac)) => Some(MacRewrite {
            src_mac,
            dst_mac: Some(dst_mac),
        }),
        (Some(src_mac), dst_mac) => Some(MacRewrite {
            src_mac: Some(src_mac),
            dst_mac,
        }),
        (None, None) => None,
    };

    let ipv4_rewrite = match (cli.src_ipv4, cli.dst_ipv4) {
        (src_ip, Some(dst_ip)) => Some(Ipv4Rewrite {
            src_ip,
            dst_ip: Some(dst_ip)
        }),
        (Some(src_ip), dst_ip) => Some(Ipv4Rewrite {
            src_ip: Some(src_ip),
            dst_ip,
        }),
        (None, None) => None,
    };
    let port_rewrite = match (cli.src_port, cli.dst_port) {
        (src_port, Some(dst_port)) => Some(PortRewrite {
            src_port,
            dst_port: Some(dst_port),
        }),
        (Some(src_port), dst_port) => Some(PortRewrite {
            src_port: Some(src_port),
            dst_port,
        }),
        (None, None) => None,
    };

    let vlan_rewrite = cli.vlan_id.map(|id| VlanRewrite { vlan_id: id });

    Ok(Rewrite {
        mac_rewrite,
        ipv4_rewrite,
        port_rewrite,
        vlan_rewrite,
    })
}