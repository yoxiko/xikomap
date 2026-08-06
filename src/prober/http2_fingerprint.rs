use reqwest::Client;
use std::collections::HashMap;
use std::time::Duration;

pub struct HTTP2Fingerprint {
    pub alpn: Vec<String>,
    pub settings: HashMap<String, String>,
    pub priority_frames: bool,
    pub window_update: Option<u32>,
    pub header_compression: Option<String>,
}

impl HTTP2Fingerprint {
    pub async fn analyze(host: &str, port: u16) -> Result<Self, Box<dyn std::error::Error>> {
        let mut fp = HTTP2Fingerprint {
            alpn: Vec::new(),
            settings: HashMap::new(),
            priority_frames: false,
            window_update: None,
            header_compression: None,
        };

        let client = Client::builder()
            .http2_prior_knowledge()
            .danger_accept_invalid_certs(true)
            .timeout(Duration::from_secs(5))
            .build()?;

        let url = format!("https://{}:{}", host, port);

        match client.get(&url).send().await {
            Ok(response) => {
                let headers = response.headers();

                if response.version() == reqwest::Version::HTTP_2 {
                    fp.alpn.push("h2".to_string());
                }

                if let Some(server) = headers.get("server") {
                    if let Ok(s) = server.to_str() {
                        fp.settings.insert("server".to_string(), s.to_string());
                    }
                }

                if let Some(alt_svc) = headers.get("alt-svc") {
                    if let Ok(s) = alt_svc.to_str() {
                        fp.settings.insert("alt_svc".to_string(), s.to_string());
                    }
                }

                for (key, value) in headers.iter() {
                    let key_lower = key.as_str().to_lowercase();
                    if key_lower.contains("x-http2") || key_lower.contains("http2") {
                        if let Ok(v) = value.to_str() {
                            fp.settings.insert(key.to_string(), v.to_string());
                        }
                    }
                }
            }
            Err(e) => {
                fp.settings.insert("error".to_string(), e.to_string());
            }
        }

        Ok(fp)
    }

    pub fn to_fingerprint_string(&self) -> String {
        let mut parts = Vec::new();

        parts.push(format!("alpn:{}", self.alpn.join(",")));
        parts.push(format!("settings:{}", self.settings.len()));
        parts.push(format!("priority:{}", self.priority_frames));

        parts.join("|")
    }
}