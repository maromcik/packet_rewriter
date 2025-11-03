extern crate core;

use crate::error::{AppError, AppErrorKind};
use crate::network::capture::PacketCaptureGeneric;
use crate::network::interface::NetworkConfig;
use crate::network::listen::cap_rewrite;
use crate::network::nfqueue::nf_rewrite;
use crate::network::parse::parse_rewrites;
use clap::Parser;
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

    #[clap(
        short = 'n',
        long = "nf-queue",
        value_name = "NETFILTER_QUEUE",
        group = "capture"
    )]
    nf_queue: Option<u16>,
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

    /// New A value in all records
    #[clap(long = "dns-a", value_name = "A_RECORD")]
    a: Option<Ipv4Addr>,

    /// new AAAA value in all records
    #[clap(long = "dns-aaaa", value_name = "AAAA_RECORD")]
    aaaa: Option<Ipv6Addr>,
    /// Interval between packets in milliseconds
    #[clap(short = 'i', long = "interval", value_name = "INTERVAL")]
    interval: Option<u64>,

    /// If true, packets that are same after rewrite are sent as well
    #[arg(short = 's', long = "straight", action = clap::ArgAction::SetTrue)]
    straight: bool,

    /// Optional log level.
    #[clap(
        short = 'l',
        long,
        value_name = "LOG_LEVEL",
        env = "RUST_LOG",
        default_value = "info"
    )]
    log_level: log::LevelFilter,
}

fn main() -> Result<(), Box<dyn Error>> {
    let cli = Cli::parse();
    dotenvy::dotenv().ok();

    env_logger::Builder::new()
        .filter(None, cli.log_level)
        .init();

    let net_config = NetworkConfig {
        output_device: cli.output_device.clone(),
        interval: cli.interval.map(Duration::from_millis),
        straight: cli.straight,
    };

    let rewrite = parse_rewrites(&cli)?;

    match (&cli.capture_device, &cli.capture_file, &cli.nf_queue) {
        (Some(device), _, _) => {
            let capture = PacketCaptureGeneric::<Active>::open_device_capture(device, cli.filter)?;
            cap_rewrite(capture, net_config, rewrite)?;
        }
        (_, Some(file), _) => {
            let capture = PacketCaptureGeneric::<Offline>::open_file_capture(file, cli.filter)?;
            cap_rewrite(capture, net_config, rewrite)?;
        }
        (_, _, Some(nf_queue)) => nf_rewrite(net_config, rewrite, *nf_queue)?,
        _ => return Err(AppError::new(
            AppErrorKind::ArgumentError,
            "Exactly one from: CAPTURE_DEVICE or CAPTURE_FILE or NETFILTER_QUEUE must be provided",
        )
        .into()),
    };

    Ok(())
}
