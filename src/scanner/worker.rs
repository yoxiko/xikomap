use crate::prober::tcp::probe_port;
use serde::{Deserialize, Serialize};
use tracing::debug;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ScanResult {
    pub ip: String,
    pub port: u16,
    pub protocol: String,
    pub banner: String,
    pub http_body: String,
    pub http_headers: String,
    pub retries: u8,
}

pub async fn scan_port_with_retry(
    ip: String,
    port: u16,
    timeout_ms: u64,
    max_retries: u8,
) -> Option<ScanResult> {
    let mut last_error: Option<String> = None;

    for attempt in 0..=max_retries {
        if attempt > 0 {
            debug!("Retrying {}:{} (attempt {}/{})", ip, port, attempt + 1, max_retries + 1);
        }

        match probe_port(&ip, port, timeout_ms).await {
            Ok(probe_result) if probe_result.is_open => {
                return Some(ScanResult {
                    ip,
                    port,
                    protocol: probe_result.protocol_guess,
                    banner: probe_result.banner,
                    http_body: String::new(),
                    http_headers: String::new(),
                    retries: attempt,
                });
            }
            Ok(_) => {
                return None;
            }
            Err(e) => {
                last_error = Some(e.to_string());
                continue;
            }
        }
    }

    debug!("Port {}:{} failed after {} retries: {:?}", ip, port, max_retries, last_error);
    None
}