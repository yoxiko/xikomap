use std::time::Instant;
use tokio::net::TcpStream;
use tokio::time::{timeout, Duration};

pub async fn ping_host(target: &str, timeout_ms: u64) -> (bool, f64) {
    let ping_ports = [80, 443, 22, 21];
    
    for port in ping_ports {
        let addr = format!("{}:{}", target, port);
        let start = Instant::now();
        
        let result = timeout(
            Duration::from_millis(timeout_ms),
            TcpStream::connect(&addr)
        ).await;
        
        if result.is_ok() {
            let latency = start.elapsed().as_secs_f64() * 1000.0;
            return (true, latency);
        }
    }
    
    (false, 0.0)
}