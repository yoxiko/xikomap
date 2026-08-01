use crate::core::config::ScanConfig;
use crate::core::target::TargetResolver;
use crate::scanner::worker::{scan_port_with_retry, ScanResult};
use crate::utils::signals::ShutdownHandler;
use futures::stream::{self, StreamExt};
use std::sync::Arc;
use thiserror::Error;
use tracing::{info, warn};

#[derive(Error, Debug)]
pub enum ScanError {
    #[error("Target resolution failed: {0}")]
    TargetError(#[from] crate::core::target::TargetError),
    #[error("Scan was interrupted")]
    Interrupted,
}

pub struct ScanEngine {
    config: ScanConfig,
    shutdown_handler: Arc<ShutdownHandler>,
}

impl ScanEngine {
    pub fn new(config: ScanConfig, shutdown_handler: Arc<ShutdownHandler>) -> Self {
        Self {
            config,
            shutdown_handler,
        }
    }

    pub async fn run(&self) -> Result<Vec<ScanResult>, ScanError> {
        let resolver = TargetResolver::new(&self.config.targets, &self.config.exclude)?;
        let targets = resolver.resolve(self.config.randomize);

        if targets.is_empty() {
            return Err(ScanError::TargetError(
                crate::core::target::TargetError::ResolutionFailed("No valid targets".to_string())
            ));
        }

        info!("Starting scan of {} targets", targets.len());

        let ports = self.config.port_strategy.get_ports();
        let total_scans = targets.len() * ports.len();
        info!("Will perform {} port scans", total_scans);

        let mut results = Vec::new();
        let concurrency = self.config.concurrency;
        let timeout_ms = self.config.timeout_ms;
        let retries = self.config.retries;

        let tasks: Vec<_> = targets
            .iter()
            .flat_map(|target| {
                let ip_str = target.to_string();
                ports.iter().map(move |&port| (ip_str.clone(), port))
            })
            .collect();

        let mut stream = stream::iter(tasks)
            .map(|(ip, port)| {
                let shutdown = Arc::clone(&self.shutdown_handler);
                async move {
                    if shutdown.is_shutdown_requested() {
                        return None;
                    }
                    scan_port_with_retry(ip, port, timeout_ms, retries).await
                }
            })
            .buffer_unordered(concurrency);

        while let Some(result) = stream.next().await {
            if let Some(scan_result) = result {
                results.push(scan_result);
            }
            
            if self.shutdown_handler.is_shutdown_requested() {
                warn!("Scan interrupted by user");
                break;
            }
        }

        results.sort_by(|a, b| {
            a.ip.cmp(&b.ip).then_with(|| a.port.cmp(&b.port))
        });

        info!("Scan completed. Found {} open ports", results.len());
        Ok(results)
    }
}