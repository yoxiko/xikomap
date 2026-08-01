use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::time::timeout;

pub async fn check_host_alive(ip: &str, timeout_ms: u64) -> bool {
    let socket = match UdpSocket::bind("0.0.0.0:0").await {
        Ok(s) => s,
        Err(_) => return false,
    };

    let addr = format!("{}:{}", ip, 7);
    let _ = socket.connect(&addr).await;
    
    let is_alive = match timeout(Duration::from_millis(timeout_ms), socket.send(b"ping")).await {
        Ok(Ok(_)) => true,
        _ => false,
    };

    is_alive
}