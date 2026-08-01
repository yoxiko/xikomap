use reqwest::Client;
use std::time::Duration;

pub struct HttpProbeResult {
    pub status_code: u16,
    pub headers: String,
    pub body_snippet: String,
}

pub async fn probe_http(ip: &str, port: u16) -> Option<HttpProbeResult> {
    let client = Client::builder()
        .timeout(Duration::from_secs(3))
        .build()
        .ok()?;

    let scheme = if port == 443 || port == 8443 { "https" } else { "http" };
    let url = format!("{}://{}:{}", scheme, ip, port);
    
    if let Ok(response) = client.get(&url).send().await {
        let status = response.status().as_u16();
        let headers = response.headers()
            .iter()
            .map(|(k, v)| format!("{}: {}", k, v.to_str().unwrap_or("")))
            .collect::<Vec<_>>()
            .join("\n");
        
        let body = response.text().await.unwrap_or_default();
        let body_snippet = body.chars().take(1000).collect();

        return Some(HttpProbeResult {
            status_code: status,
            headers,
            body_snippet,
        });
    }
    None
}