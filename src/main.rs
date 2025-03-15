extern crate core;

use crate::network::listener::{cap_rewrite, CaptureConfig};
use crate::network::parse::parse_mac;
use crate::network::rewrite::{IpRewrite, MacRewrite, PortRewrite, Rewrite};
use clap::Parser;
use std::error::Error;

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
    filter: String,

    /// Output device to send modified packets out
    #[clap(short = 'o', long = "out-dev", value_name = "OUTPUT_DEVICE")]
    output_device: String,

    /// New source MAC
    #[clap(long = "src-mac", value_name = "SRC_MAC")]
    src_mac: Option<String>,

    /// New destination MAC
    #[clap(long = "dst-mac", value_name = "DST_MAC")]
    dst_mac: Option<String>,

    /// New source IP
    #[clap(short = 's', long = "src-ip", value_name = "SRC_IP")]
    src_ip: Option<String>,

    /// New destination IP
    #[clap(short = 'd', long = "dst-ip", value_name = "DST_IP")]
    dst_ip: Option<String>,

    /// New source Port
    #[clap(long = "src-port", value_name = "SRC_PORT")]
    src_port: Option<String>,

    /// New destination Port
    #[clap(long = "dst-port", value_name = "DST_PORT")]
    dst_port: Option<String>,
    // /// Print occurrence count instead of the regular output
    // #[arg(short = 'c', long, action = clap::ArgAction::SetTrue)]
    // count: bool,
}

fn main() -> Result<(), Box<dyn Error>> {
    let cli = Cli::parse();

    let cap = CaptureConfig {
        capture_device: cli.capture_device,
        filter: cli.filter,
        output_device: cli.output_device,
    };

    let rewrite = Rewrite {
        mac_rewrite: MacRewrite {
            src_mac: parse_mac(cli.src_mac)?,
            dst_mac: parse_mac(cli.dst_mac)?,
        },

        ip_rewrite: IpRewrite {
            src_ip: cli.src_ip,
            dst_ip: cli.dst_ip,
        },
        port_rewrite: PortRewrite {
            src_port: cli.src_port,
            dst_port: cli.dst_port,
        },
    };

    cap_rewrite(cap, rewrite)?;
    
    Ok(())
}
