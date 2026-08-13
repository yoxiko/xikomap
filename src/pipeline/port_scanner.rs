use crate::scanner::{ScannerEngine, SynScanner};
use crate::utils::cli::Cli;
use std::net::IpAddr;
use tracing::{info, warn};

pub struct PortScanner {
    stealth: bool,
    concurrency: usize,
    timeout_ms: u64,
}

impl PortScanner {
    pub fn new(cli: &Cli) -> Self {
        Self {
            stealth: cli.stealth,
            concurrency: if cli.all { 2000 } else { 500 },
            timeout_ms: 1000,
        }
    }

    pub async fn scan(
        &self,
        target: &str,
        ports: Vec<u16>,
    ) -> Result<(Vec<u16>, IpAddr), String> {
        let target_ip = ScannerEngine::resolve_target(target)
            .await
            .map_err(|e| e.to_string())?;

        let open_ports = if self.stealth {
            info!("Attempting SYN stealth scan...");
            let syn = SynScanner::new(self.timeout_ms, 1000);
            match syn.run(target_ip, &ports, 54321).await {
                Ok(p) if !p.is_empty() => p,
                _ => {
                    warn!("SYN scan failed or unavailable. Falling back to connect scan.");
                    self.connect_scan(target, ports).await?
                }
            }
        } else {
            self.connect_scan(target, ports).await?
        };

        Ok((open_ports, target_ip))
    }

    async fn connect_scan(&self, target: &str, ports: Vec<u16>) -> Result<Vec<u16>, String> {
        let engine = ScannerEngine::new(self.concurrency, self.timeout_ms);
        engine.run(target, ports).await.map_err(|e| e.to_string())
    }
}