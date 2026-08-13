use std::net::IpAddr;
use std::time::Duration;

#[cfg(not(target_os = "windows"))]
use std::sync::atomic::{AtomicBool, Ordering};
#[cfg(not(target_os = "windows"))]
use std::sync::Arc;
#[cfg(not(target_os = "windows"))]
use std::time::Instant;
#[cfg(not(target_os = "windows"))]
use tokio::time::sleep;
#[cfg(not(target_os = "windows"))]
use tracing::{debug, warn};

#[cfg(not(target_os = "windows"))]
use pnet::{
    datalink,
    packet::{
        tcp::{ipv4_checksum, MutableTcpPacket, TcpFlags, TcpPacket},
        Packet,
    },
    transport::{transport_channel, Layer4Channel, Layer4Protocol, TransportChannelType},
};

pub struct SynScanner {
    timeout: Duration,
    rate_limit: u32,
}

impl SynScanner {
    pub fn new(timeout_ms: u64, rate_limit: u32) -> Self {
        Self {
            timeout: Duration::from_millis(timeout_ms),
            rate_limit,
        }
    }

    pub async fn run(
        &self,
        target: IpAddr,
        ports: &[u16],
    ) -> Result<Vec<u16>, ScannerError> {
        #[cfg(target_os = "windows")]
        {
            let _ = target;
            let _ = ports;
            return Err(ScannerError::UnsupportedPlatform(
                "SYN scan is not supported on Windows. Use connect scan.".into(),
            ));
        }

        #[cfg(not(target_os = "windows"))]
        {
            let source_port = rand::random::<u16>() | 1024;
            self.run_raw_sockets(target, ports, source_port).await
        }
    }

    #[cfg(not(target_os = "windows"))]
    async fn run_raw_sockets(
        &self,
        target: IpAddr,
        ports: &[u16],
        source_port: u16,
    ) -> Result<Vec<u16>, ScannerError> {
        use std::collections::HashSet;
        use std::sync::Mutex;

        let interface = datalink::interfaces()
            .into_iter()
            .find(|iface| {
                !iface.ips.is_empty()
                    && iface.ips.iter().any(|ip| ip.ip().is_ipv4())
                    && !iface.is_loopback()
            })
            .ok_or(ScannerError::NoInterface)?;

        let channel_type = TransportChannelType::Layer4(Layer4Channel {
            protocol: Layer4Protocol::Tcp,
        });

        let (mut tx, mut rx) = transport_channel(65536, channel_type)
            .map_err(|e| ScannerError::ChannelCreation(e.to_string()))?;

        let source_ip = interface
            .ips
            .iter()
            .find(|ip| ip.ip().is_ipv4())
            .map(|ip| ip.ip())
            .ok_or(ScannerError::NoSourceIp)?;

        let open_ports = Arc::new(Mutex::new(HashSet::new()));
        let open_ports_clone = Arc::clone(&open_ports);
        let target_for_listener = target;
        let expected_source_port = source_port;
        let stop_signal = Arc::new(AtomicBool::new(false));
        let stop_signal_clone = Arc::clone(&stop_signal);

        let listener = tokio::task::spawn_blocking(move || {
            use pnet::transport::tcp_packet_iter;

            let mut iter = tcp_packet_iter(&mut rx);

            loop {
                if stop_signal_clone.load(Ordering::Relaxed) {
                    break;
                }

                match iter.next() {
                    Ok((packet, addr)) => {
                        if addr.ip() == target_for_listener
                            && packet.get_source() == expected_source_port
                        {
                            let flags = packet.get_flags();
                            let port = packet.get_destination();

                            if (flags & TcpFlags::SYN != 0) && (flags & TcpFlags::ACK != 0) {
                                if let Ok(mut ports) = open_ports_clone.lock() {
                                    ports.insert(port);
                                }
                                debug!("SYN-ACK from port {}", port);
                            } else if flags & TcpFlags::RST != 0 {
                                debug!("RST from port {} (closed)", port);
                            }
                        }
                    }
                    Err(e) => {
                        warn!("Listener error: {}", e);
                        break;
                    }
                }
            }
        });

        let interval = if self.rate_limit > 0 {
            Duration::from_micros(1_000_000 / self.rate_limit as u64)
        } else {
            Duration::from_micros(100)
        };

        let start_time = Instant::now();
        for &port in ports {
            let mut buffer = [0u8; 20];
            let mut tcp_packet = MutableTcpPacket::new(&mut buffer)
                .ok_or(ScannerError::PacketCreation)?;

            tcp_packet.set_source(source_port);
            tcp_packet.set_destination(port);
            tcp_packet.set_sequence(rand::random());
            tcp_packet.set_acknowledgement(0);
            tcp_packet.set_data_offset(5);
            tcp_packet.set_flags(TcpFlags::SYN);
            tcp_packet.set_window(1024);
            tcp_packet.set_urgent_pointer(0);

            let checksum = ipv4_checksum(&tcp_packet.to_immutable(), &source_ip, &target);
            tcp_packet.set_checksum(checksum);

            if let Err(e) = tx.send_to(&tcp_packet.to_immutable(), target) {
                debug!("Failed to send SYN to port {}: {}", port, e);
            }

            sleep(interval).await;
        }

        let elapsed = start_time.elapsed();
        if elapsed < self.timeout {
            sleep(self.timeout - elapsed).await;
        }

        stop_signal.store(true, Ordering::Relaxed);

        let _ = tokio::time::timeout(Duration::from_millis(100), listener).await;

        let mut result: Vec<u16> = open_ports.lock().unwrap().iter().copied().collect();
        result.sort_unstable();
        Ok(result)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ScannerError {
    #[error("SYN scan is not supported on this platform: {0}")]
    UnsupportedPlatform(String),
    #[error("No suitable network interface found")]
    NoInterface,
    #[error("No IPv4 address available for source")]
    NoSourceIp,
    #[error("Failed to create channel: {0}")]
    ChannelCreation(String),
    #[error("Failed to create packet")]
    PacketCreation,
}