use serde::{Deserialize, Serialize};
use tokio_tungstenite::connect_async;
use tokio_tungstenite::tungstenite::http::Request;

#[derive(Debug, Serialize, Deserialize)]
pub struct WebSocketInfo {
    pub scheme: String,
    pub path: String,
    pub server_header: Option<String>,
}

pub async fn probe_websocket(host: &str, port: u16) -> Option<WebSocketInfo> {
    let schemes = if port == 80 || port == 8080 || port == 3000 {
        vec!["ws"]
    } else {
        vec!["wss"]
    };

    let paths = vec!["/", "/ws", "/socket", "/socket.io", "/graphql", "/api/ws"];

    for scheme in &schemes {
        for path in &paths {
            let url = format!("{}://{}:{}{}", scheme, host, port, path);
            let request = match Request::builder()
                .uri(&url)
                .header("Host", host)
                .header("Connection", "Upgrade")
                .header("Upgrade", "websocket")
                .header("Sec-WebSocket-Version", "13")
                .header("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==")
                .body(())
            {
                Ok(r) => r,
                Err(_) => continue,
            };

            match tokio::time::timeout(std::time::Duration::from_secs(3), connect_async(request))
                .await
            {
                Ok(Ok((_, response))) => {
                    let server_header = response
                        .headers()
                        .get("server")
                        .and_then(|v| v.to_str().ok())
                        .map(|s| s.to_string());
                    return Some(WebSocketInfo {
                        scheme: scheme.to_string(),
                        path: path.to_string(),
                        server_header,
                    });
                }
                _ => continue,
            }
        }
    }

    None
}