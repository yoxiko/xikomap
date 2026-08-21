use trust_dns_resolver::config::{ResolverConfig, ResolverOpts};
use trust_dns_resolver::TokioAsyncResolver;
use std::collections::HashSet;

pub struct DnsEnumerator {
    resolver: TokioAsyncResolver,
}

impl DnsEnumerator {
    pub fn new() -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let resolver = TokioAsyncResolver::tokio(
            ResolverConfig::default(),
            ResolverOpts::default(),
        );
        Ok(Self { resolver })
    }

    pub async fn enumerate_subdomains(&self, domain: &str) -> Vec<String> {
        let common_subdomains = vec![
            "www", "mail", "ftp", "api", "dev", "staging", "test", "admin",
            "blog", "shop", "app", "cdn", "static", "assets", "support",
        ];
        
        let mut results = HashSet::new();
        
        for sub in common_subdomains {
            let candidate = format!("{}.{}", sub, domain);
            if let Ok(_) = self.resolver.lookup_ip(&candidate).await {
                results.insert(candidate);
            }
        }
        
        results.into_iter().collect()
    }

    pub async fn get_txt_records(&self, domain: &str) -> Vec<String> {
        if let Ok(lookup) = self.resolver.txt_lookup(domain).await {
            lookup.iter().map(|r| r.to_string()).collect()
        } else {
            Vec::new()
        }
    }

    pub async fn get_mx_records(&self, domain: &str) -> Vec<String> {
        if let Ok(lookup) = self.resolver.mx_lookup(domain).await {
            lookup.iter().map(|r| r.exchange().to_string()).collect()
        } else {
            Vec::new()
        }
    }
}