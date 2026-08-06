use std::net::{SocketAddr, ToSocketAddrs};
use std::time::Duration;
use tokio::net::TcpStream;
use tokio::time::timeout;

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

    pub async fn run(&self, target: &str, ports: Vec<u16>) -> Result<Vec<u16>, String> {
        let addrs: Vec<SocketAddr> = format!("{}:0", target)
            .to_socket_addrs()
            .map_err(|e| e.to_string())?
            .map(|mut a| {
                a.set_port(0);
                a
            })
            .collect();

        if addrs.is_empty() {
            return Err("Could not resolve target".to_string());
        }

        let ip = addrs[0].ip();
        let mut open_ports = Vec::new();
        let mut tasks = Vec::new();

        for chunk in ports.chunks(self.concurrency) {
            for &port in chunk {
                let addr = SocketAddr::new(ip, port);
                let t = self.timeout_ms;
                tasks.push(tokio::spawn(async move {
                    match timeout(Duration::from_millis(t), TcpStream::connect(addr)).await {
                        Ok(Ok(_)) => Some(port),
                        _ => None,
                    }
                }));
            }

            for handle in tasks.drain(..) {
                if let Ok(Some(port)) = handle.await {
                    open_ports.push(port);
                }
            }
        }

        open_ports.sort();
        Ok(open_ports)
    }
}