use crate::network::error::NetworkError;
use crate::network::rewrite::{
    Ipv4Rewrite, Ipv6Rewrite, MacRewrite, PortRewrite, Rewrite, VlanRewrite,
};
use crate::Cli;

pub fn parse_rewrites(cli: &Cli) -> Result<Rewrite, NetworkError> {
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
            dst_ip: Some(dst_ip),
        }),
        (Some(src_ip), dst_ip) => Some(Ipv4Rewrite {
            src_ip: Some(src_ip),
            dst_ip,
        }),
        (None, None) => None,
    };

    let ipv6_rewrite = match (cli.src_ipv6, cli.dst_ipv6) {
        (src_ip, Some(dst_ip)) => Some(Ipv6Rewrite {
            src_ip,
            dst_ip: Some(dst_ip),
        }),
        (Some(src_ip), dst_ip) => Some(Ipv6Rewrite {
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
        ipv6_rewrite,
        port_rewrite,
        vlan_rewrite,
    })
}
