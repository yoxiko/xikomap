use anyhow::Result;
use std::net::IpAddr;
use std::time::Duration;
use tokio::net::TcpStream;
use tokio::sync::Semaphore;
use tokio::time::timeout;
use std::sync::Arc;

pub struct ScannerEngine {
    concurrency: usize,
    timeout_ms: u64,
}

impl ScannerEngine {
    pub fn new(concurrency: usize) -> Self {
        Self {
            concurrency,
            timeout_ms: 2000,
        }
    }

    pub async fn run(&self, target: &str, ports: Vec<u16>) -> Result<Vec<u16>> {
        let mut open_ports = Vec::new();
        let semaphore = Arc::new(Semaphore::new(self.concurrency));

        let mut tasks = Vec::new();
        for port in ports {
            let sem = semaphore.clone();
            let target_str = target.to_string();
            let timeout_ms = self.timeout_ms;

            let task = tokio::spawn(async move {
                let _permit = sem.acquire().await.unwrap();
                let addr = format!("{}:{}", target_str, port);
                match timeout(Duration::from_millis(timeout_ms), TcpStream::connect(&addr)).await {
                    Ok(Ok(_)) => Some(port),
                    _ => None,
                }
            });
            tasks.push(task);
        }

        for task in tasks {
            if let Ok(Some(port)) = task.await {
                open_ports.push(port);
            }
        }

        open_ports.sort_unstable();
        Ok(open_ports)
    }
}

pub struct SynScanner {
    rate_limit: usize,
    timeout_ms: u64,
}

impl SynScanner {
    pub fn new(rate_limit: usize, timeout_ms: u64) -> Self {
        Self { rate_limit, timeout_ms }
    }

    pub async fn run(&self, ip: IpAddr, ports: &[u16]) -> Result<Vec<u16>> {
        #[cfg(target_os = "windows")]
        {
            let _ = ip;
            let _ = ports;
            anyhow::bail!("SYN scan requires raw socket privileges. Rate limit: {}, Timeout: {}ms. Use connect scan on Windows.", self.rate_limit, self.timeout_ms);
        }
        
        #[cfg(not(target_os = "windows"))]
        {
            let mut open_ports = Vec::new();
            
            for &port in ports {
                let delay = Duration::from_millis(self.timeout_ms / self.rate_limit.max(1) as u64);
                tokio::time::sleep(delay).await;
                
                let addr = format!("{}:{}", ip, port);
                if let Ok(Ok(_)) = timeout(Duration::from_millis(self.timeout_ms), TcpStream::connect(&addr)).await {
                    open_ports.push(port);
                }
            }
            
            open_ports.sort_unstable();
            Ok(open_ports)
        }
    }
}