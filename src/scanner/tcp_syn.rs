use anyhow::Result;
use pnet_datalink::{channel, Channel, Config, MacAddr};
use pnet_packet::ethernet::{EtherTypes, MutableEthernetPacket, EthernetPacket};
use pnet_packet::ip::IpNextHeaderProtocols;
use pnet_packet::ipv4::{Ipv4Flags, MutableIpv4Packet, Ipv4Packet};
use pnet_packet::tcp::{MutableTcpPacket, TcpFlags, TcpPacket};
use pnet_packet::Packet;
use std::net::{IpAddr, Ipv4Addr};
use std::time::Duration;
use tokio::time::timeout;

pub async fn scan_tcp_syn(
    target: &str,
    ports: Vec<u16>,
    timeout_ms: u64,
    _max_concurrent: usize,
) -> Result<Vec<u16>> {
    let target_ip: Ipv4Addr = target.parse()?;
    let interfaces = pnet_datalink::interfaces();
    let interface = interfaces
        .into_iter()
        .find(|i| !i.is_loopback() && i.ips.iter().any(|ip| ip.is_ipv4()))
        .ok_or_else(|| anyhow::anyhow!("No suitable network interface found"))?;

    let source_ip = interface.ips.iter()
        .find_map(|ip| match ip.ip() {
            IpAddr::V4(v4) => Some(v4),
            _ => None,
        })
        .ok_or_else(|| anyhow::anyhow!("No IPv4 address found on interface"))?;

    let source_mac = interface.mac.ok_or_else(|| anyhow::anyhow!("No MAC address found"))?;
    
    let mut config = Config::default();
    config.read_timeout = Some(Duration::from_millis(timeout_ms));
    config.write_buffer_size = 65536;
    config.read_buffer_size = 65536;

    let (mut tx, mut rx) = match channel(&interface, config) {
        Ok(Channel::Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => return Err(anyhow::anyhow!("Unhandled channel type")),
        Err(e) => return Err(anyhow::anyhow!("Unable to create datalink channel: {}", e)),
    };

    let mut open_ports = Vec::new();
    let broadcast_mac: MacAddr = [0xff, 0xff, 0xff, 0xff, 0xff, 0xff].into();

    for port in ports {
        let mut eth_buf = [0u8; 14 + 20 + 20];
        let mut eth_packet = MutableEthernetPacket::new(&mut eth_buf).unwrap();
        eth_packet.set_destination(broadcast_mac);
        eth_packet.set_source(source_mac);
        eth_packet.set_ethertype(EtherTypes::Ipv4);

        let mut tcp_buf = [0u8; 20];
        let mut tcp_packet = MutableTcpPacket::new(&mut tcp_buf).unwrap();
        tcp_packet.set_source(45678);
        tcp_packet.set_destination(port);
        tcp_packet.set_sequence(1000);
        tcp_packet.set_flags(TcpFlags::SYN);
        tcp_packet.set_window(1024);
        tcp_packet.set_checksum(pnet_packet::tcp::ipv4_checksum(&tcp_packet.to_immutable(), &source_ip, &target_ip));

        let mut ip_buf = [0u8; 20];
        let mut ip_packet = MutableIpv4Packet::new(&mut ip_buf).unwrap();
        ip_packet.set_version(4);
        ip_packet.set_header_length(5);
        ip_packet.set_total_length(40);
        ip_packet.set_ttl(64);
        ip_packet.set_next_level_protocol(IpNextHeaderProtocols::Tcp);
        ip_packet.set_source(source_ip);
        ip_packet.set_destination(target_ip);
        ip_packet.set_flags(Ipv4Flags::DontFragment);
        ip_packet.set_payload(&tcp_buf);
        ip_packet.set_checksum(pnet_packet::ipv4::checksum(&ip_packet.to_immutable()));

        eth_packet.set_payload(&ip_buf);

        let _ = tx.send_to(eth_packet.packet(), None);

        let result = timeout(Duration::from_millis(timeout_ms), async {
            loop {
                match rx.next() {
                    Ok(packet) => {
                        if let Some(eth) = EthernetPacket::new(packet) {
                            if eth.get_ethertype() == EtherTypes::Ipv4 {
                                if let Some(ipv4) = Ipv4Packet::new(eth.payload()) {
                                    if ipv4.get_source() == target_ip && ipv4.get_next_level_protocol() == IpNextHeaderProtocols::Tcp {
                                        let payload = ipv4.payload();
                                        if let Some(tcp) = TcpPacket::new(payload) {
                                            if tcp.get_destination() == 45678 && (tcp.get_flags() & TcpFlags::SYN) != 0 && (tcp.get_flags() & TcpFlags::ACK) != 0 {
                                                return true;
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                    Err(_) => return false,
                }
            }
        }).await;

        if let Ok(true) = result {
            open_ports.push(port);
        }
    }

    open_ports.sort();
    Ok(open_ports)
}