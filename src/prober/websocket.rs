use futures::{SinkExt, StreamExt};
use std::time::Duration;
use tokio::time::timeout;
use tracing::debug;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct WsResult {
    pub scheme: String,
    pub path: String,
}

const PATHS: [&str; 4] = ["/", "/ws", "/socket", "/websocket"];

pub async fn probe_websocket(host: &str, port: u16) -> Option<WsResult> {
    let host_part = if host.contains(':') && !host.contains('[') {
        format!("[{}]", host)
    } else {
        host.to_string()
    };

    let schemes = if port == 443 || port == 8443 || port == 8883 {
        ["wss", "ws"]
    } else {
        ["ws", "wss"]
    };

    for scheme in schemes {
        for path in PATHS {
            let url = format!("{}://{}:{}{}", scheme, host_part, port, path);
            match timeout(Duration::from_secs(4), handshake(&url)).await {
                Ok(true) => {
                    return Some(WsResult {
                        scheme: scheme.to_string(),
                        path: path.to_string(),
                    });
                }
                Ok(false) => debug!("WebSocket handshake rejected: {}", url),
                Err(_) => debug!("WebSocket probe timeout: {}", url),
            }
        }
    }

    None
}

async fn handshake(url: &str) -> bool {
    let (mut ws, response) = match tokio_tungstenite::connect_async(url).await {
        Ok(pair) => pair,
        Err(e) => {
            debug!("WebSocket connect error on {}: {}", url, e);
            return false;
        }
    };

    if response.status().as_u16() != 101 {
        let _ = ws.close(None).await;
        return false;
    }

    let _ = timeout(Duration::from_millis(300), async {
        while let Some(msg) = ws.next().await {
            if msg.is_err() {
                break;
            }
        }
    })
    .await;

    let _ = ws.close(None).await;
    true
}