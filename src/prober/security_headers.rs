#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct HeaderCheck {
    pub name: String,
    pub present: bool,
    pub value: String,
    pub score: u32,
    pub max_score: u32,
    pub recommendation: String,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SecurityHeadersResult {
    pub url: String,
    pub grade: String,
    pub total_score: u32,
    pub max_total_score: u32,
    pub checks: Vec<HeaderCheck>,
    pub missing_critical: Vec<String>,
}

pub struct SecurityHeadersAnalyzer {
    client: reqwest::Client,
}

impl SecurityHeadersAnalyzer {
    pub fn new(client: reqwest::Client) -> Self {
        Self { client }
    }

    pub async fn analyze(&self, url: &str) -> Option<SecurityHeadersResult> {
        let response = match self.client.get(url).send().await {
            Ok(r) => r,
            Err(_) => return None,
        };

        let headers = response.headers();
        let mut checks = Vec::new();
        let mut total_score: u32 = 0;
        let mut max_total_score: u32 = 0;
        let mut missing_critical = Vec::new();

        let header_defs: Vec<(&str, u32, &str, bool)> = vec![
            (
                "strict-transport-security",
                15,
                "Set Strict-Transport-Security with max-age=31536000; includeSubDomains; preload",
                true,
            ),
            (
                "content-security-policy",
                25,
                "Set Content-Security-Policy to prevent XSS and injection attacks",
                true,
            ),
            (
                "x-frame-options",
                10,
                "Set X-Frame-Options to DENY or SAMEORIGIN to prevent clickjacking",
                false,
            ),
            (
                "x-content-type-options",
                10,
                "Set X-Content-Type-Options to nosniff",
                false,
            ),
            (
                "referrer-policy",
                10,
                "Set Referrer-Policy to strict-origin-when-cross-origin or no-referrer",
                false,
            ),
            (
                "permissions-policy",
                10,
                "Set Permissions-Policy to restrict browser features",
                false,
            ),
            (
                "x-xss-protection",
                5,
                "Set X-XSS-Protection to 1; mode=block (legacy, prefer CSP)",
                false,
            ),
            (
                "cross-origin-opener-policy",
                5,
                "Set Cross-Origin-Opener-Policy to same-origin",
                false,
            ),
            (
                "cross-origin-resource-policy",
                5,
                "Set Cross-Origin-Resource-Policy to same-origin",
                false,
            ),
            (
                "cross-origin-embedder-policy",
                5,
                "Set Cross-Origin-Embedder-Policy to require-corp",
                false,
            ),
        ];

        for (header_name, max_score, recommendation, critical) in header_defs {
            let value = headers
                .get(header_name)
                .and_then(|v| v.to_str().ok())
                .unwrap_or("");

            let present = !value.is_empty();
            let score = if present { max_score } else { 0 };

            if !present && critical {
                missing_critical.push(header_name.to_string());
            }

            total_score += score;
            max_total_score += max_score;

            checks.push(HeaderCheck {
                name: header_name.to_string(),
                present,
                value: value.to_string(),
                score,
                max_score,
                recommendation: if present { String::new() } else { recommendation.to_string() },
            });
        }

        if headers.get("server").is_some() {
            total_score = total_score.saturating_sub(5);
            checks.push(HeaderCheck {
                name: "server".to_string(),
                present: true,
                value: headers.get("server").and_then(|v| v.to_str().ok()).unwrap_or("").to_string(),
                score: 0,
                max_score: 5,
                recommendation: "Remove Server header to avoid information disclosure".to_string(),
            });
            max_total_score += 5;
        }

        if headers.get("x-powered-by").is_some() {
            total_score = total_score.saturating_sub(5);
            checks.push(HeaderCheck {
                name: "x-powered-by".to_string(),
                present: true,
                value: headers.get("x-powered-by").and_then(|v| v.to_str().ok()).unwrap_or("").to_string(),
                score: 0,
                max_score: 5,
                recommendation: "Remove X-Powered-By header to avoid information disclosure".to_string(),
            });
            max_total_score += 5;
        }

        let percentage = if max_total_score > 0 {
            (total_score as f64 / max_total_score as f64) * 100.0
        } else {
            0.0
        };

        let grade = match percentage as u32 {
            90..=100 => "A+".to_string(),
            80..=89 => "A".to_string(),
            70..=79 => "B".to_string(),
            60..=69 => "C".to_string(),
            50..=59 => "D".to_string(),
            30..=49 => "E".to_string(),
            _ => "F".to_string(),
        };

        Some(SecurityHeadersResult {
            url: url.to_string(),
            grade,
            total_score,
            max_total_score,
            checks,
            missing_critical,
        })
    }
}