use trust_dns_resolver::config::{ResolverConfig, ResolverOpts};
use trust_dns_resolver::TokioAsyncResolver;

pub struct PtrRecord {
    pub ip: String,
    pub hostname: String,
}

pub struct RdnsResult {
    pub records: Vec<PtrRecord>,
}

pub struct RdnsProber {
    resolver: TokioAsyncResolver,
}

impl RdnsProber {
    pub fn new() -> Option<Self> {
        Some(Self {
            resolver: TokioAsyncResolver::tokio(
                ResolverConfig::default(),
                ResolverOpts::default(),
            ),
        })
    }

    pub async fn lookup(&self, ip: &str) -> Option<PtrRecord> {
        if let Ok(ip_addr) = ip.parse() {
            if let Ok(lookup) = self.resolver.reverse_lookup(ip_addr).await {
                if let Some(name) = lookup.iter().next() {
                    return Some(PtrRecord {
                        ip: ip.to_string(),
                        hostname: name.to_string(),
                    });
                }
            }
        }
        None
    }

    pub async fn lookup_multiple(&self, ips: &[String]) -> RdnsResult {
        let mut records = Vec::new();
        for ip in ips {
            if let Some(record) = self.lookup(ip).await {
                records.push(record);
            }
        }
        RdnsResult { records }
    }
}