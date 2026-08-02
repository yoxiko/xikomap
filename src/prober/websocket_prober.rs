use std::time::Duration;
use tokio_tungstenite::connect_async;
use tokio_tungstenite::tungstenite::http::Request;

const WS_PATHS: [&str; 5] = [
    "/",
    "/ws",
    "/websocket",
    "/socket.io/?EIO=4&transport=websocket",
    "/api/ws",
];

pub struct WebSocketProbeResult {
    pub path: String,
    pub scheme: String,
    pub server_header: Option<String>,
}

pub async fn probe_websocket(host: &str, port: u16) -> Option<WebSocketProbeResult> {
    let scheme = if port == 443 || port == 8443 || port == 8443 {
        "wss"
    } else {
        "ws"
    };

    for path in &WS_PATHS {
        let url = format!("{}://{}:{}{}", scheme, host, port, path);

        let request = match Request::builder()
            .uri(&url)
            .header("User-Agent", "XikomapScanner/1.0")
            .header("Origin", format!("http://{}", host))
            .body(())
        {
            Ok(r) => r,
            Err(_) => continue,
        };

        let connect_future = connect_async(request);

        match tokio::time::timeout(Duration::from_secs(3), connect_future).await {
            Ok(Ok((ws_stream, response))) => {
                let server_header = response
                    .headers()
                    .get("server")
                    .and_then(|v| v.to_str().ok())
                    .map(|s| s.to_string());

                drop(ws_stream);

                return Some(WebSocketProbeResult {
                    path: path.to_string(),
                    scheme: scheme.to_string(),
                    server_header,
                });
            }
            _ => continue,
        }
    }

    None
}