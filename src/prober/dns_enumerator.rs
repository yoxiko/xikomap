use std::collections::HashSet;
use trust_dns_resolver::config::{ResolverConfig, ResolverOpts};
use trust_dns_resolver::TokioAsyncResolver;

pub struct DnsEnumerator {
    resolver: TokioAsyncResolver,
}

impl DnsEnumerator {
    pub fn new() -> Result<Self, Box<dyn std::error::Error>> {
        let resolver = TokioAsyncResolver::tokio(ResolverConfig::default(), ResolverOpts::default());

        Ok(DnsEnumerator { resolver })
    }

    pub async fn enumerate_subdomains(&self, domain: &str) -> Vec<String> {
        let mut subdomains = HashSet::new();

        let common_prefixes = vec![
            "www", "mail", "ftp", "api", "dev", "staging", "prod", "admin", "test", "vpn", "ssh",
            "web", "app", "portal", "blog", "shop", "store", "docs", "cdn", "static", "beta",
            "demo", "login", "auth", "sso", "oauth",
        ];

        for prefix in common_prefixes {
            let subdomain = format!("{}.{}", prefix, domain);
            if self.check_domain(&subdomain).await {
                subdomains.insert(subdomain);
            }
        }

        subdomains.into_iter().collect()
    }

    async fn check_domain(&self, domain: &str) -> bool {
        self.resolver.lookup_ip(domain).await.is_ok()
    }

    pub async fn get_txt_records(&self, domain: &str) -> Vec<String> {
        let mut records = Vec::new();

        if let Ok(txt_response) = self.resolver.txt_lookup(domain).await {
            for txt in txt_response.iter() {
                if let Ok(data) = String::from_utf8(txt.txt_data().concat().to_vec()) {
                    records.push(data);
                }
            }
        }

        records
    }

    pub async fn get_mx_records(&self, domain: &str) -> Vec<String> {
        let mut records = Vec::new();

        if let Ok(mx_response) = self.resolver.mx_lookup(domain).await {
            for mx in mx_response.iter() {
                records.push(format!("{} (priority: {})", mx.exchange(), mx.preference()));
            }
        }

        records
    }
}