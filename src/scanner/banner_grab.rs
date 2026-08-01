use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

pub struct BannerResult {
    pub ip: String,
    pub port: u16,
    pub banner: String,
}

pub async fn grab_banner(ip: &str, port: u16, timeout_ms: u64) -> Option<BannerResult> {
    let addr = format!("{}:{}", ip, port);
    let mut stream = match timeout(Duration::from_millis(timeout_ms), TcpStream::connect(&addr)).await {
        Ok(Ok(s)) => s,
        _ => return None,
    };

    let mut buf = vec![0u8; 2048];
    let mut total_read = 0;

    let read_future = async {
        loop {
            match stream.read(&mut buf[total_read..]).await {
                Ok(0) => break,
                Ok(n) => {
                    total_read += n;
                    if total_read >= buf.len() {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
    };

    let _ = timeout(Duration::from_millis(timeout_ms), read_future).await;

    if total_read == 0 {
        let probe_payload = match port {
            80 | 8080 | 8000 | 8443 => b"GET / HTTP/1.0\r\nHost: localhost\r\n\r\n".to_vec(),
            21 => b"FEAT\r\n".to_vec(),
            25 | 587 => b"EHLO localhost\r\n".to_vec(),
            22 => b"SSH-2.0-OpenSSH_8.0\r\n".to_vec(),
            _ => Vec::new(),
        };

        if !probe_payload.is_empty() {
            let _ = stream.write_all(&probe_payload).await;
            let _ = timeout(Duration::from_millis(timeout_ms), stream.read(&mut buf)).await;
            total_read = buf.iter().position(|&x| x == 0).unwrap_or(buf.len());
        }
    }

    if total_read > 0 {
        let banner = String::from_utf8_lossy(&buf[..total_read]).to_string();
        Some(BannerResult {
            ip: ip.to_string(),
            port,
            banner,
        })
    } else {
        None
    }
}