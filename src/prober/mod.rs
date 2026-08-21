pub mod dns_enumerator;
pub mod rdns;
pub mod screenshot;

pub use crate::prober::rdns::PtrRecord;
pub use crate::prober::screenshot::ScreenshotResult;

#[derive(Debug, Clone)]
pub struct SshFingerprint {
    pub banner: String,
    pub software: String,
    pub version: String,
}

#[derive(Debug, Clone)]
pub struct JarmResult {
    pub hash: String,
}

#[derive(Debug, Clone)]
pub struct SecurityHeadersResult {
    pub url: String,
    pub grade: String,
    pub total_score: u32,
    pub max_total_score: u32,
}

#[derive(Debug, Clone)]
pub struct FaviconResult {
    pub hash: String,
    pub technology: Option<String>,
}

#[derive(Debug, Clone)]
pub struct CorsResult {
    pub url: String,
    pub severity: String,
    pub issues: Vec<String>,
}

use crate::core::findings::{Finding, PortReport};
use reqwest::Client;
use std::time::Duration;

pub async fn probe_port(target: String, port: u16, _is_full_scan: bool, client: Client) -> PortReport {
    let mut findings = Vec::new();
    let scheme = if [443, 8443, 9443].contains(&port) { "https" } else { "http" };
    let url = format!("{}://{}:{}", scheme, target, port);

    match client.get(&url).timeout(Duration::from_secs(5)).send().await {
        Ok(resp) => {
            let status = resp.status();
            let headers = resp.headers();
            
            findings.push(Finding::Service {
                name: "HTTP".to_string(),
                detail: format!("Status {}", status),
            });

            if let Some(server) = headers.get("server") {
                if let Ok(val) = server.to_str() {
                    let server_lower = val.to_lowercase();
                    findings.push(Finding::Technology {
                        name: "Server".to_string(),
                        version: val.to_string(),
                    });
                    
                    if server_lower.contains("vercel") {
                        findings.push(Finding::Technology {
                            name: "Platform".to_string(),
                            version: "Vercel".to_string(),
                        });
                    } else if server_lower.contains("cloudflare") {
                        findings.push(Finding::Technology {
                            name: "Platform".to_string(),
                            version: "Cloudflare".to_string(),
                        });
                    } else if server_lower.contains("nginx") {
                        findings.push(Finding::Technology {
                            name: "WebServer".to_string(),
                            version: "Nginx".to_string(),
                        });
                    } else if server_lower.contains("golang") || server_lower.contains("go-http") {
                        findings.push(Finding::Technology {
                            name: "WebServer".to_string(),
                            version: "Golang".to_string(),
                        });
                    }
                }
            }

            if let Some(location) = headers.get("location") {
                if let Ok(val) = location.to_str() {
                    findings.push(Finding::Service {
                        name: "HTTP-Redirect".to_string(),
                        detail: val.to_string(),
                    });
                }
            }

            if let Ok(text) = resp.text().await {
                if let Some(title) = extract_title(&text) {
                    findings.push(Finding::Service {
                        name: "HTTP-Title".to_string(),
                        detail: title,
                    });
                }
            }
        }
        Err(_) => {
            match port {
                22 => findings.push(Finding::Service { name: "SSH".to_string(), detail: "Detected".to_string() }),
                21 => findings.push(Finding::Service { name: "FTP".to_string(), detail: "Detected".to_string() }),
                25 => findings.push(Finding::Service { name: "SMTP".to_string(), detail: "Detected".to_string() }),
                53 => findings.push(Finding::Service { name: "DNS".to_string(), detail: "Detected".to_string() }),
                3306 => findings.push(Finding::Service { name: "MySQL".to_string(), detail: "Detected".to_string() }),
                5432 => findings.push(Finding::Service { name: "PostgreSQL".to_string(), detail: "Detected".to_string() }),
                6379 => findings.push(Finding::Service { name: "Redis".to_string(), detail: "Detected".to_string() }),
                _ => findings.push(Finding::Service { name: "Unknown".to_string(), detail: "Port open but HTTP failed".to_string() }),
            }
        }
    }

    PortReport { port, findings }
}

fn extract_title(html: &str) -> Option<String> {
    let start = html.find("<title>")?;
    let end = html.find("</title>")?;
    if start < end {
        Some(html[start + 7..end].trim().to_string())
    } else {
        None
    }
}

pub fn format_url(target: &str, port: u16, scheme: &str) -> String {
    format!("{}://{}:{}", scheme, target, port)
}