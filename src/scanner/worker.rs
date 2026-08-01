use crate::detectors::http_probe::probe_http;
use serde::{Deserialize, Serialize};
use std::time::Duration;
use tokio::net::TcpStream;
use tokio::time::timeout;

#[derive(Serialize, Deserialize, Debug)]
pub struct ScanResult {
    pub ip: String,
    pub port: u16,
    pub protocol: String,
    pub banner: String,
    pub http_body: String,
    pub http_headers: String,
}

pub async fn scan_single_port(ip: String, port: u16, timeout_ms: u64) -> Option<ScanResult> {
    let addr = format!("{}:{}", ip, port);
    let connect_result = timeout(
        Duration::from_millis(timeout_ms),
        TcpStream::connect(&addr),
    ).await;

    if let Ok(Ok(_stream)) = connect_result {
        let mut banner = "Open".to_string();
        let mut http_body = String::new();
        let mut http_headers = String::new();

        if port == 80 || port == 443 || port == 8080 || port == 8443 {
            if let Some(probe) = probe_http(&ip, port).await {
                http_body = probe.body_snippet;
                http_headers = probe.headers;
                banner = format!("HTTP {}", probe.status_code);
            }
        }

        return Some(ScanResult {
            ip,
            port,
            protocol: "tcp".to_string(),
            banner,
            http_body,
            http_headers,
        });
    }
    None
}