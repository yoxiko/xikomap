use std::time::Duration;
use tokio::net::TcpStream;
use tokio::time::timeout;

pub struct ScanResult {
    pub ip: String,
    pub port: u16,
    pub is_open: bool,
}

pub async fn scan_port(ip: &str, port: u16, timeout_ms: u64) -> ScanResult {
    let addr = format!("{}:{}", ip, port);
    let is_open = match timeout(Duration::from_millis(timeout_ms), TcpStream::connect(&addr)).await {
        Ok(Ok(_)) => true,
        _ => false,
    };

    ScanResult {
        ip: ip.to_string(),
        port,
        is_open,
    }
}