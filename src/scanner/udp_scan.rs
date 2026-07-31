use anyhow::Result;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::time::timeout;
use crate::core::results::PortState;
use crate::scanner::ScanResult;

pub async fn scan_udp(
    target: &str,
    ports: Vec<u16>,
    timeout_ms: u64,
    max_concurrent: usize,
) -> Result<Vec<ScanResult>> {
    let mut tasks = Vec::new();
    let semaphore = Arc::new(tokio::sync::Semaphore::new(max_concurrent));
    let socket = Arc::new(UdpSocket::bind("0.0.0.0:0").await?);

    for port in ports {
        let target_owned = target.to_string();
        let sem_clone = Arc::clone(&semaphore);
        let socket_clone = Arc::clone(&socket);
        
        let task = tokio::spawn(async move {
            let _permit = sem_clone.acquire().await.unwrap();
            let addr = format!("{}:{}", target_owned, port);
            
            let _ = socket_clone.send_to(b"\x00", &addr).await;
            
            let mut buf = [0u8; 1024];
            let result = timeout(
                Duration::from_millis(timeout_ms),
                socket_clone.recv_from(&mut buf)
            ).await;

            let state = if result.is_ok() {
                PortState::Open
            } else {
                PortState::Filtered
            };

            ScanResult { port, state }
        });
        
        tasks.push(task);
    }

    let mut results = Vec::new();
    for task in tasks {
        if let Ok(res) = task.await {
            results.push(res);
        }
    }

    results.sort_by_key(|r| r.port);
    Ok(results)
}