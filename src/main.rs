extern crate core;

use crate::network::parse::{parse_mac, parse_rewrites};
use crate::network::rewrite::{cap_rewrite, Ipv4Rewrite, MacRewrite, PortRewrite, Rewrite};
use crate::network::CaptureConfig;
use clap::Parser;
use std::error::Error;
use std::net::{Ipv4Addr, Ipv6Addr};
use pnet::datalink::MacAddr;

mod error;
mod network;

#[derive(Parser)]
#[clap(author, version, about, long_about = None)]
struct Cli {
    /// Device to run packet capture on
    #[clap(short = 'c', long = "cap-dev", value_name = "CAPTURE_DEVICE")]
    capture_device: String,

    /// BPF Filter for packets
    #[clap(short, long, value_name = "BPF_FILTER")]
    filter: Option<String>,

    /// Output device to send modified packets out
    #[clap(short = 'o', long = "out-dev", value_name = "OUTPUT_DEVICE")]
    output_device: String,

    /// New source MAC
    #[clap(long = "src-mac", value_name = "SRC_MAC")]
    src_mac: Option<MacAddr>,

    /// New destination MAC
    #[clap(long = "dst-mac", value_name = "DST_MAC")]
    dst_mac: Option<MacAddr>,

    /// New source IPv4
    #[clap(short = 's', long = "src-ipv4", value_name = "SRC_IPv4")]
    src_ipv4: Option<Ipv4Addr>,

    /// New destination IPv4
    #[clap(short = 'd', long = "dst-ipv4", value_name = "DST_IPv4")]
    dst_ipv4: Option<Ipv4Addr>,

    /// New source IPv6
    #[clap(long = "src-ip6", value_name = "SRC_IPv6")]
    src_ipv6: Option<Ipv6Addr>,

    /// New destination IPv6
    #[clap(long = "dst-ipv6", value_name = "DST_IPv6")]
    dst_ipv6: Option<Ipv6Addr>,

    /// New source Port
    #[clap(long = "src-port", value_name = "SRC_PORT")]
    src_port: Option<u16>,

    /// New destination Port
    #[clap(long = "dst-port", value_name = "DST_PORT")]
    dst_port: Option<u16>,

    /// New VLAN identifier
    #[clap(short = 'v', long = "vlan", value_name = "VLAN IDENTIFIER")]
    vlan_id: Option<u16>,

}

fn main() -> Result<(), Box<dyn Error>> {
    let cli = Cli::parse();

    let cap = CaptureConfig {
        capture_device: cli.capture_device.clone(),
        filter: cli.filter.clone(),
        output_device: cli.output_device.clone(),
    };

    let rewrite = parse_rewrites(cli)?;

    cap_rewrite(cap, rewrite)?;

    Ok(())
}
