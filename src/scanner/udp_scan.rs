use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::time::timeout;

pub enum UdpScanState {
    Open,
    Closed,
    OpenOrFiltered,
}

pub struct UdpScanResult {
    pub ip: String,
    pub port: u16,
    pub state: UdpScanState,
    pub response: Vec<u8>,
}

pub async fn scan_udp_port(ip: &str, port: u16, timeout_ms: u64) -> UdpScanResult {
    let addr = format!("{}:{}", ip, port);
    let socket = match UdpSocket::bind("0.0.0.0:0").await {
        Ok(s) => s,
        Err(_) => {
            return UdpScanResult {
                ip: ip.to_string(),
                port,
                state: UdpScanState::OpenOrFiltered,
                response: Vec::new(),
            }
        }
    };

    let _ = socket.connect(&addr).await;
    let payload = b"\x00";

    match timeout(Duration::from_millis(timeout_ms), socket.send(payload)).await {
        Ok(Ok(_)) => {}
        _ => {
            return UdpScanResult {
                ip: ip.to_string(),
                port,
                state: UdpScanState::OpenOrFiltered,
                response: Vec::new(),
            }
        }
    }

    let mut buf = vec![0u8; 1024];
    match timeout(Duration::from_millis(timeout_ms), socket.recv(&mut buf)).await {
        Ok(Ok(size)) => {
            buf.truncate(size);
            UdpScanResult {
                ip: ip.to_string(),
                port,
                state: UdpScanState::Open,
                response: buf,
            }
        }
        _ => UdpScanResult {
            ip: ip.to_string(),
            port,
            state: UdpScanState::OpenOrFiltered,
            response: Vec::new(),
        },
    }
}