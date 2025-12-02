# packet_rewriter 📦

A Rust-based tool for capturing, rewriting, and retransmitting network packets — useful for testing, prototyping, and debugging network behaviour.

---

## 🚀 What is packet_rewriter?

`packet_rewriter` allows you to:

- Capture live network traffic or load packets from a `.pcap` file
- Rewrite packet headers at OSI layers 2, 3, or 4 (e.g. MAC addresses, IPs, ports)
- For DNS/mDNS traffic: optionally modify application-layer records (A / AAAA)
- Transmit the modified packets back onto the network

This makes it a powerful companion when testing scenarios like mDNS bridging, device masquerading, or subnet traversal — especially in environments where network configuration prevents native multicast discovery.

---

## 🧰 How it works

1. **Capture or import packets** … either from a network interface or from an existing pcap file.
2. **Apply transformations** … using filters and rewrite rules, you can adjust Ethernet, IP, TCP/UDP headers — or even modify DNS records within packets.
3. **Replay / retransmit** … send the altered packets back out onto the network, optionally adjusting timing or intervals.

Use cases include: protocol testing, traffic replay, simulating remote devices, or debugging tricky multicast/unicast interactions.

---

## 🛠️ Usage

```bash
# Build the tool (requires Rust & Cargo)
git clone https://github.com/maromcik/packet_rewriter.git
cd packet_rewriter
cargo build --release

# Example: capture live traffic on interface eth0 and apply a rewrite rule
sudo ./target/release/packet_rewriter \
  --interface eth0 \
  --rewrite "ip src=192.168.0.2 dst=192.168.0.50" \
  --output-interface eth0

# Example: load packets from a pcap file, change DNS A records, then replay
sudo ./target/release/packet_rewriter \
  --pcap captured.pcap \
  --dns-rewrite "rewrite A 192.168.1.100" \
  --output-interface eth0
