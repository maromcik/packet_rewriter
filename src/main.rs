extern crate core;

use crate::error::{AppError, AppErrorKind};
use crate::network::capture::PacketCaptureGeneric;
use crate::network::interface::NetworkConfig;
use crate::network::listen::cap_rewrite;
use crate::network::parse::parse_rewrites;
use clap::Parser;
use env_logger::Env;
use pcap::{Active, Offline};
use pnet::datalink::MacAddr;
use std::error::Error;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::time::Duration;

mod error;
mod network;

#[derive(Parser)]
#[clap(author, version, about, long_about = None, group(
        clap::ArgGroup::new("capture")
            .required(true)
            .args(&["capture_device", "capture_file"])
    ))]
struct Cli {
    /// Device to run packet capture on
    #[clap(
        short = 'd',
        long = "cap-dev",
        value_name = "CAPTURE_DEVICE",
        group = "capture"
    )]
    capture_device: Option<String>,

    /// File with pcap data
    #[clap(
        short = 'p',
        long = "cap-file",
        value_name = "CAPTURE_FILE",
        group = "capture"
    )]
    capture_file: Option<String>,

    /// BPF Filter for packets
    #[clap(short = 'f', long, value_name = "BPF_FILTER")]
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
    #[clap(long = "src-ipv4", value_name = "SRC_IPv4")]
    src_ipv4: Option<Ipv4Addr>,

    /// New destination IPv4
    #[clap(long = "dst-ipv4", value_name = "DST_IPv4")]
    dst_ipv4: Option<Ipv4Addr>,

    /// New source IPv6
    #[clap(long = "src-ipv6", value_name = "SRC_IPv6")]
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

    /// Interval between packets in milliseconds
    #[clap(short = 'i', long = "interval", value_name = "INTERVAL")]
    interval: Option<u64>,

    /// If true, packets that are same after rewrite are not sent
    #[arg(short = 's', long = "straight", action = clap::ArgAction::SetTrue)]
    straight: bool,
}

fn main() -> Result<(), Box<dyn Error>> {
    let cli = Cli::parse();
    dotenvy::dotenv().ok();
    env_logger::init_from_env(Env::default().default_filter_or("info"));
    let net_config = NetworkConfig {
        output_device: cli.output_device.clone(),
        interval: cli.interval.map(Duration::from_millis),
        straight: cli.straight,
    };

    let rewrite = parse_rewrites(&cli)?;

    match (&cli.capture_device, &cli.capture_file) {
        (Some(device), _) => {
            let capture = PacketCaptureGeneric::<Active>::open_device_capture(device, cli.filter)?;
            cap_rewrite(capture, net_config, rewrite)?;
        }
        (_, Some(file)) => {
            let capture = PacketCaptureGeneric::<Offline>::open_file_capture(file, cli.filter)?;
            cap_rewrite(capture, net_config, rewrite)?;
        }
        _ => {
            return Err(AppError::new(
                AppErrorKind::ArgumentError,
                "Exactly one from: CAPTURE_DEVICE or CAPTURE_FILE must be provided",
            )
            .into())
        }
    };

    Ok(())
}
