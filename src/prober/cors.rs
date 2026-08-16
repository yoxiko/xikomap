use std::time::Duration;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct CorsResult {
    pub url: String,
    pub issues: Vec<String>,
    pub severity: String,
}

pub struct CorsScanner {
    client: reqwest::Client,
}

impl CorsScanner {
    pub fn new(client: reqwest::Client) -> Self {
        Self { client }
    }

    pub async fn analyze(&self, url: &str) -> Option<CorsResult> {
        let mut issues = Vec::new();

        if let Some(resp) = self.request_with_origin(url, "https://evil.com").await {
            let acao = header(&resp, "access-control-allow-origin");
            let acac = header(&resp, "access-control-allow-credentials") == Some("true".to_string());

            match acao.as_deref() {
                Some("https://evil.com") if acac => issues.push(
                    "Arbitrary origin reflected with Allow-Credentials (critical)".to_string(),
                ),
                Some("https://evil.com") => {
                    issues.push("Arbitrary origin reflected (medium)".to_string())
                }
                Some("*") if acac => issues.push(
                    "Wildcard origin combined with Allow-Credentials (high)".to_string(),
                ),
                Some("*") => issues.push("Wildcard Access-Control-Allow-Origin (low)".to_string()),
                _ => {}
            }
        }

        if let Some(resp) = self.request_with_origin(url, "null").await {
            let acao = header(&resp, "access-control-allow-origin");
            let acac = header(&resp, "access-control-allow-credentials") == Some("true".to_string());

            if acao.as_deref() == Some("null") {
                if acac {
                    issues.push("null origin allowed with Allow-Credentials (high)".to_string());
                } else {
                    issues.push("null origin allowed (medium)".to_string());
                }
            }
        }

        if issues.is_empty() {
            return None;
        }

        let severity = if issues.iter().any(|i| i.contains("critical")) {
            "critical".to_string()
        } else if issues.iter().any(|i| i.contains("high")) {
            "high".to_string()
        } else if issues.iter().any(|i| i.contains("medium")) {
            "medium".to_string()
        } else {
            "low".to_string()
        };

        Some(CorsResult {
            url: url.to_string(),
            issues,
            severity,
        })
    }

    async fn request_with_origin(&self, url: &str, origin: &str) -> Option<reqwest::Response> {
        tokio::time::timeout(
            Duration::from_secs(5),
            self.client.get(url).header("Origin", origin).send(),
        )
        .await
        .ok()?
        .ok()
    }
}

fn header(resp: &reqwest::Response, name: &str) -> Option<String> {
    resp.headers()
        .get(name)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string())
}