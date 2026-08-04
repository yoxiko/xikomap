use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::tcp::{ipv4_checksum, MutableTcpPacket, TcpFlags, TcpPacket};
use pnet::transport::{tcp_packet_iter, transport_channel, TransportChannelType, TransportProtocol};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tracing::{debug, info};

pub struct SynScanner {
    wait_secs: u64,
}

impl Default for SynScanner {
    fn default() -> Self {
        Self::new()
    }
}

impl SynScanner {
    pub fn new() -> Self {
        Self { wait_secs: 4 }
    }

    pub async fn run(&self, target: &str, ports: Vec<u16>) -> Result<Vec<u16>, String> {
        let start = Instant::now();

        let target_ip = resolve_target(target).await?;
        let source_ip = local_source_ip(target_ip)
            .ok_or_else(|| "No suitable IPv4 interface found".to_string())?;

        let (mut tx, mut rx) = transport_channel(
            65536,
            TransportChannelType::Layer4(TransportProtocol::Ipv4(IpNextHeaderProtocols::Tcp)),
        )
        .map_err(|e| {
            format!(
                "Raw socket unavailable (run as administrator / install Npcap): {}",
                e
            )
        })?;

        let open_ports: Arc<Mutex<Vec<u16>>> = Arc::new(Mutex::new(Vec::new()));
        let listener_ports = ports.clone();
        let listener_open = Arc::clone(&open_ports);
        let wait = self.wait_secs;

        let listener = std::thread::spawn(move || {
            let mut iter = tcp_packet_iter(&mut rx);
            let deadline = Instant::now() + Duration::from_secs(wait);
            loop {
                if Instant::now() >= deadline {
                    break;
                }
                match iter.next_with_timeout(Duration::from_millis(250)) {
                    Ok(Some((tcp, addr))) => {
                        if addr != IpAddr::V4(target_ip) {
                            continue;
                        }
                        let flags = tcp.get_flags();
                        if flags & TcpFlags::SYN != 0 && flags & TcpFlags::ACK != 0 {
                            let sport = tcp.get_source();
                            if listener_ports.contains(&sport) {
                                let mut open = listener_open.lock().unwrap();
                                if !open.contains(&sport) {
                                    open.push(sport);
                                }
                            }
                        }
                    }
                    Ok(None) => {}
                    Err(e) => {
                        debug!("Receiver error: {}", e);
                        break;
                    }
                }
            }
        });

        let source_port = 40000 + (rand::random::<u16>() % 20000);

        for (i, port) in ports.iter().enumerate() {
            let mut buf = vec![0u8; 20];
            {
                let mut tcp = MutableTcpPacket::new(&mut buf).unwrap();
                tcp.set_source(source_port);
                tcp.set_destination(*port);
                tcp.set_sequence(rand::random::<u32>());
                tcp.set_data_offset(5);
                tcp.set_flags(TcpFlags::SYN);
                tcp.set_window(64240);
                tcp.set_urgent_ptr(0);
            }
            let checksum = ipv4_checksum(&TcpPacket::new(&buf).unwrap(), &source_ip, &target_ip);
            {
                let mut tcp = MutableTcpPacket::new(&mut buf).unwrap();
                tcp.set_checksum(checksum);
            }
            let packet = TcpPacket::new(&buf).unwrap();
            if let Err(e) = tx.send_to(&packet, IpAddr::V4(target_ip)) {
                debug!("Send error on port {}: {}", port, e);
            }
            if i % 50 == 49 {
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
        }

        let _ = listener.join();

        let mut result = open_ports.lock().unwrap().clone();
        result.sort_unstable();

        info!(
            "TCP scan completed in {:.2} seconds.",
            start.elapsed().as_secs_f64()
        );

        Ok(result)
    }
}

async fn resolve_target(target: &str) -> Result<Ipv4Addr, String> {
    if let Ok(ip) = target.parse::<Ipv4Addr>() {
        return Ok(ip);
    }
    let addrs = tokio::net::lookup_host(format!("{}:80", target))
        .await
        .map_err(|e| format!("DNS resolution failed: {}", e))?;
    for addr in addrs {
        if let IpAddr::V4(v4) = addr.ip() {
            return Ok(v4);
        }
    }
    Err("No IPv4 address resolved for target".to_string())
}

fn local_source_ip(target: Ipv4Addr) -> Option<Ipv4Addr> {
    let socket = std::net::UdpSocket::bind("0.0.0.0:0").ok()?;
    socket
        .connect(SocketAddr::new(IpAddr::V4(target), 1))
        .ok()?;
    match socket.local_addr().ok()? {
        SocketAddr::V4(v4) => Some(*v4.ip()),
        _ => None,
    }
}