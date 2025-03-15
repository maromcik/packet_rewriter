use pnet::datalink::MacAddr;
use pnet::packet::ethernet::MutableEthernetPacket;

pub struct Rewrite {
    pub mac_rewrite: MacRewrite,
    pub ip_rewrite: IpRewrite,
    pub port_rewrite: PortRewrite
}

pub struct PortRewrite {
    pub src_port: Option<String>,
    pub dst_port: Option<String>,
}

pub struct IpRewrite {
    pub src_ip: Option<String>,
    pub dst_ip: Option<String>,
}

pub struct MacRewrite {
    pub src_mac: Option<MacAddr>,
    pub dst_mac: Option<MacAddr>,
}

pub fn rewrite_mac(mut packet: MutableEthernetPacket, rewrite: &Rewrite) {
    if let Some(src_mac) = rewrite.mac_rewrite.src_mac {
        packet.set_source(src_mac.clone());
    }

    if let Some(src_mac) = rewrite.mac_rewrite.src_mac {
        packet.set_source(src_mac.clone());
    }

}