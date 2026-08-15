use std::net::IpAddr;
use std::str::FromStr;
use std::time::Duration;
use tokio::time::timeout;
use trust_dns_resolver::config::{ResolverConfig, ResolverOpts};
use trust_dns_resolver::TokioAsyncResolver;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PtrRecord {
    pub ip: String,
    pub hostname: String,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct RdnsResult {
    pub records: Vec<PtrRecord>,
}

pub struct RdnsProber {
    resolver: TokioAsyncResolver,
}

impl RdnsProber {
    pub fn new() -> Option<Self> {
        let resolver = TokioAsyncResolver::tokio(
            ResolverConfig::default(),
            ResolverOpts::default(),
        );
        Some(Self { resolver })
    }

    pub async fn lookup(&self, ip: &str) -> Option<PtrRecord> {
        let parsed = IpAddr::from_str(ip).ok()?;

        let result = timeout(
            Duration::from_secs(5),
            self.resolver.reverse_lookup(parsed),
        )
        .await;

        match result {
            Ok(Ok(response)) => {
                let hostname = response
                    .iter()
                    .next()
                    .map(|name| name.to_string().trim_end_matches('.').to_string())
                    .unwrap_or_default();

                if hostname.is_empty() {
                    return None;
                }

                Some(PtrRecord {
                    ip: ip.to_string(),
                    hostname,
                })
            }
            _ => None,
        }
    }

    pub async fn lookup_multiple(&self, ips: &[String]) -> RdnsResult {
        let mut records = Vec::new();

        for ip in ips {
            if let Some(ptr) = self.lookup(ip).await {
                records.push(ptr);
            }
        }

        RdnsResult { records }
    }
}