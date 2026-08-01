use crate::prober::http::probe_http;
use crate::prober::protocol::{get_probe_payload, guess_protocol};
use std::io;
use std::time::Duration;
use thiserror::Error;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

#[derive(Error, Debug)]
pub enum ProbeError {
    #[error("Connection timeout")]
    Timeout,
    #[error("Connection refused")]
    ConnectionRefused,
    #[error("IO error: {0}")]
    Io(#[from] io::Error),
}

pub struct ProbeResult {
    pub is_open: bool,
    pub protocol_guess: String,
    pub banner: String,
}

pub async fn probe_port(ip: &str, port: u16, timeout_ms: u64) -> Result<ProbeResult, ProbeError> {
    let addr = format!("{}:{}", ip, port);

    let mut stream = match timeout(Duration::from_millis(timeout_ms), TcpStream::connect(&addr)).await {
        Ok(Ok(s)) => s,
        Ok(Err(e)) => {
            if e.kind() == io::ErrorKind::ConnectionRefused {
                return Err(ProbeError::ConnectionRefused);
            }
            return Err(ProbeError::Io(e));
        }
        Err(_) => return Err(ProbeError::Timeout),
    };

    let mut buf = vec![0u8; 4096];

    let probe_payload = get_probe_payload(port);

    if !probe_payload.is_empty() {
        let _ = stream.writable().await;
        let _ = stream.write_all(&probe_payload).await;
    }

    let banner;
    let protocol_guess;

    match timeout(Duration::from_millis(timeout_ms), stream.read(&mut buf)).await {
        Ok(Ok(n)) if n > 0 => {
            let raw_banner = String::from_utf8_lossy(&buf[..n]).to_string();
            banner = raw_banner.replace(['\r', '\n'], " ").trim().to_string();
            protocol_guess = guess_protocol(port, &banner);
        }
        _ => {
            if port == 80 || port == 443 || port == 8080 || port == 8443 {
                if let Some(http_result) = probe_http(ip, port, timeout_ms).await {
                    banner = format!("HTTP/1.1 {}", http_result.status_code);
                    protocol_guess = "http".to_string();
                } else {
                    banner = "open (no banner)".to_string();
                    protocol_guess = "http".to_string();
                }
            } else {
                banner = "open (stealth)".to_string();
                protocol_guess = "tcp".to_string();
            }
        }
    }

    Ok(ProbeResult {
        is_open: true,
        protocol_guess,
        banner,
    })
}