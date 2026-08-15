use futures::stream::{self, StreamExt};
use std::net::SocketAddr;
use std::time::Duration;
use tokio::net::TcpStream;
use tokio::time::timeout;

#[derive(Debug, thiserror::Error)]
pub enum ScanError {
    #[error("Resolution failed: {0}")]
    Resolution(String),
    #[error("Scan failed: {0}")]
    Scan(String),
}

pub struct ScannerEngine {
    concurrency: usize,
    timeout_ms: u64,
}

impl ScannerEngine {
    pub fn new(concurrency: usize) -> Self {
        ScannerEngine {
            concurrency,
            timeout_ms: 2000,
        }
    }

    pub async fn run(&self, target: &str, ports: Vec<u16>) -> Result<Vec<u16>, ScanError> {
        // FIX 1: Async DNS resolution instead of blocking to_socket_addrs
        let addrs: Vec<SocketAddr> = tokio::net::lookup_host(format!("{}:0", target))
            .await
            .map_err(|e| ScanError::Resolution(e.to_string()))?
            .map(|mut a| {
                a.set_port(0);
                a
            })
            .collect();

        if addrs.is_empty() {
            return Err(ScanError::Resolution(
                "Could not resolve target".to_string(),
            ));
        }

        let ip = addrs[0].ip();
        let timeout_ms = self.timeout_ms;

        let open_ports: Vec<u16> = stream::iter(ports)
            .map(|port| async move {
                let addr = SocketAddr::new(ip, port);
                match timeout(Duration::from_millis(timeout_ms), TcpStream::connect(addr)).await {
                    Ok(Ok(_)) => Some(port),
                    _ => None,
                }
            })
            .buffer_unordered(self.concurrency)
            .filter_map(|x| async move { x })
            .collect()
            .await;

        let mut open_ports = open_ports;
        open_ports.sort();
        Ok(open_ports)
    }
}