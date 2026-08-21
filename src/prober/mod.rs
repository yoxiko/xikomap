pub mod cors;
pub mod dns_enumerator;
pub mod favicon;
pub mod grpc;
pub mod http2_fingerprint;
pub mod jarm;
pub mod quic;
pub mod rdns;
pub mod screenshot;
pub mod security_headers;
pub mod ssh_fingerprint;
pub mod tls_fingerprint;
pub mod websocket;

use crate::core::findings::{Finding, PortReport};
use reqwest::Client;
use std::time::Duration;

pub async fn probe_port(target: String, port: u16, _is_full_scan: bool, client: Client) -> PortReport {
    let mut findings = Vec::new();
    
    let scheme = if [443, 8443].contains(&port) { "https" } else { "http" };
    let url = format!("{}://{}:{}", scheme, target, port);

    match client.get(&url).timeout(Duration::from_secs(5)).send().await {
        Ok(resp) => {
            findings.push(Finding::Service {
                name: "HTTP".to_string(),
                detail: format!("Status {}", resp.status()),
            });
            
            if let Some(server) = resp.headers().get("server") {
                if let Ok(val) = server.to_str() {
                    findings.push(Finding::Technology {
                        name: "Server".to_string(),
                        version: val.to_string(),
                    });
                }
            }
        }
        Err(_) => {
            findings.push(Finding::Service {
                name: "Unknown".to_string(),
                detail: "Port open but no HTTP response".to_string(),
            });
        }
    }

    if port == 22 {
        findings.push(Finding::Service {
            name: "SSH".to_string(),
            detail: "Detected".to_string(),
        });
    }

    PortReport { port, findings }
}

pub fn format_url(target: &str, port: u16, scheme: &str) -> String {
    format!("{}://{}:{}", scheme, target, port)
}