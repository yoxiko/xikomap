use crate::core::config::ScanConfig;
use crate::core::target::TargetResolver;
use crate::scanner::worker::{scan_single_port, ScanResult};
use std::sync::Arc;
use tokio::sync::Semaphore;
use tokio::task::JoinSet;

pub struct ScanEngine {
    config: ScanConfig,
}

impl ScanEngine {
    pub fn new(config: ScanConfig) -> Self {
        Self { config }
    }

    pub async fn run(&self) -> Result<Vec<ScanResult>, String> {
        let resolver = TargetResolver::new(&self.config.targets, &self.config.exclude)?;
        let targets = resolver.resolve(self.config.randomize);
        
        if targets.is_empty() {
            return Err("No valid targets found".to_string());
        }

        let ports = self.config.port_strategy.get_ports();
        let semaphore = Arc::new(Semaphore::new(self.config.concurrency));
        let mut set = JoinSet::new();
        let timeout_ms = self.config.timeout_ms;

        for target in targets {
            let ip_str = target.to_string();
            for port in &ports {
                let ip_clone = ip_str.clone();
                let port_clone = *port;
                let sem_clone = Arc::clone(&semaphore);

                set.spawn(async move {
                    let _permit = sem_clone.acquire().await.unwrap();
                    scan_single_port(ip_clone, port_clone, timeout_ms).await
                });
            }
        }

        let mut results = Vec::new();
        while let Some(res) = set.join_next().await {
            if let Ok(Some(scan_res)) = res {
                results.push(scan_res);
            }
        }

        results.sort_by(|a, b| {
            a.ip.cmp(&b.ip).then_with(|| a.port.cmp(&b.port))
        });

        Ok(results)
    }
}