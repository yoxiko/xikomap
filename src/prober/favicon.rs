use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use md5::{Digest, Md5};
use std::time::Duration;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct FaviconResult {
    pub port: u16,
    pub url: String,
    pub hash: String,
    pub technology: Option<String>,
}

const KNOWN_HASHES: [(i32, &str); 6] = [
    (116323821, "WordPress"),
    (-115216596, "Joomla"),
    (-1571283328, "Drupal"),
    (-1138591607, "Cloudflare"),
    (-1163926846, "Apache Tomcat"),
    (-1414493421, "Microsoft IIS"),
];

pub struct FaviconProber;

impl FaviconProber {
    pub async fn probe(
        client: &reqwest::Client,
        target: &str,
        port: u16,
        scheme: &str,
    ) -> Option<FaviconResult> {
        let host_part = if target.contains(':') && !target.contains('[') {
            format!("[{}]", target)
        } else {
            target.to_string()
        };

        let url = format!("{}://{}:{}/favicon.ico", scheme, host_part, port);

        let resp = tokio::time::timeout(Duration::from_secs(5), client.get(&url).send())
            .await
            .ok()?
            .ok()?;

        if !resp.status().is_success() {
            return None;
        }

        let bytes = resp.bytes().await.ok()?;
        if bytes.is_empty() {
            return None;
        }

        let b64 = STANDARD.encode(&bytes);
        
        let mut hasher = Md5::new();
        hasher.update(b64.as_bytes());
        let result = hasher.finalize();
        let hash = i32::from_be_bytes([result[0], result[1], result[2], result[3]]);

        let technology = KNOWN_HASHES
            .iter()
            .find(|(h, _)| *h == hash)
            .map(|(_, t)| t.to_string());

        Some(FaviconResult {
            port,
            url,
            hash: hash.to_string(),
            technology,
        })
    }
}