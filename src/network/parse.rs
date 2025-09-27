use crate::network::error::NetworkError;
use crate::network::rewrite::{DataLinkRewrite, DnsRewrite, IpRewrite, Ipv4Rewrite, Ipv6Rewrite, MacRewrite, PortRewrite, Rewrite, VlanRewrite};
use crate::Cli;

pub fn parse_rewrites(cli: &Cli) -> Result<Rewrite, NetworkError> {
    let vlan_rewrite = cli.vlan_id.map(|id| VlanRewrite { vlan_id: id });
    let mac_rewrite = match (cli.src_mac, cli.dst_mac) {
        (None, None) => None,
        (_, _) => Some(MacRewrite {
            src_mac: cli.src_mac,
            dst_mac: cli.dst_mac,
        }),
    };

    let datalink_rewrite = Some(DataLinkRewrite {
        mac_rewrite,
        vlan_rewrite,
    });

    let ipv4_rewrite = match (cli.src_ipv4, cli.dst_ipv4) {
        (None, None) => None,
        (_, _) => Some(Ipv4Rewrite {
            src_ip: cli.src_ipv4,
            dst_ip: cli.dst_ipv4,
        }),
    };

    let ipv6_rewrite = match (cli.src_ipv6, cli.dst_ipv6) {
        (None, None) => None,
        (_, _) => Some(Ipv6Rewrite {
            src_ip: cli.src_ipv6,
            dst_ip: cli.dst_ipv6,
        }),
    };

    let transport_rewrite = match (cli.src_port, cli.dst_port) {
        (None, None) => None,
        (_, _) => Some(PortRewrite {
            src_port: cli.src_port,
            dst_port: cli.dst_port,
        }),
    };

    let ip_rewrite = match (&ipv4_rewrite, &ipv6_rewrite) {
        (None, None) => None,
        (_, _) => Some(IpRewrite {
            ipv4_rewrite,
            ipv6_rewrite,
        }),
    };
    
    let dns_rewrite = match (&cli.a, &cli.aaaa) {
        (None, None) => None,
        (_, _) => Some(DnsRewrite {
            a: cli.a,
            aaaa: cli.aaaa
        })
    };

    Ok(Rewrite {
        datalink_rewrite,
        ip_rewrite,
        transport_rewrite,
        dns_rewrite,
    })
}
