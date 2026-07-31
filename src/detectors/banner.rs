use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

pub async fn grab_banner(target: &str, port: u16, timeout_ms: u64) -> Option<String> {
    let addr = format!("{}:{}", target, port);
    
    let connect_result = timeout(
        Duration::from_millis(timeout_ms),
        TcpStream::connect(&addr)
    ).await;

    let mut stream = match connect_result {
        Ok(Ok(s)) => s,
        _ => return None,
    };

    if port == 80 || port == 8080 || port == 443 {
        let request = format!("GET / HTTP/1.0\r\nHost: {}\r\n\r\n", target);
        let _ = stream.write_all(request.as_bytes()).await;
    }

    let mut buffer = vec![0u8; 1024];
    
    let read_result = timeout(
        Duration::from_millis(timeout_ms),
        stream.read(&mut buffer)
    ).await;

    match read_result {
        Ok(Ok(n)) if n > 0 => {
            let banner_str = String::from_utf8_lossy(&buffer[..n]).to_string();
            Some(banner_str.trim().to_string())
        }
        _ => None,
    }
}