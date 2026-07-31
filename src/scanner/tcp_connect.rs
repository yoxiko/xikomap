use anyhow::Result;
use std::io::ErrorKind;
use std::time::Duration;
use tokio::net::TcpStream;
use tokio::time::timeout;
use crate::core::results::PortState;
use crate::scanner::ScanResult;

pub async fn scan_tcp_connect(
    target: &str,
    ports: Vec<u16>,
    timeout_ms: u64,
    max_concurrent: usize,
) -> Result<Vec<ScanResult>> {
    let mut tasks = Vec::new();
    let semaphore = std::sync::Arc::new(tokio::sync::Semaphore::new(max_concurrent));

    for port in ports {
        let target_owned = target.to_string();
        let sem_clone = semaphore.clone();
        
        let task = tokio::spawn(async move {
            let _permit = sem_clone.acquire().await.unwrap();
            let addr = format!("{}:{}", target_owned, port);
            
            let result = timeout(
                Duration::from_millis(timeout_ms),
                TcpStream::connect(&addr)
            ).await;

            let state = match result {
                Ok(Ok(_)) => PortState::Open,
                Ok(Err(e)) if e.kind() == ErrorKind::ConnectionRefused => PortState::Closed,
                _ => PortState::Filtered,
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