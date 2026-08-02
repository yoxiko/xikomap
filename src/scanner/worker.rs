use crate::prober::tcp::{probe_tcp, ProbeError};
use tracing::debug;

pub struct ScanResult {
    pub host: String,
    pub port: u16,
    pub is_open: bool,
}

pub struct Worker {
    id: usize,
}

impl Worker {
    pub fn new(id: usize) -> Self {
        Self { id }
    }

    pub async fn process_task(&self, host: &str, port: u16) -> Result<ScanResult, ProbeError> {
        debug!("Worker {} probing {}:{}", self.id, host, port);
        let is_open = probe_tcp(host, port).await?;
        Ok(ScanResult {
            host: host.to_string(),
            port,
            is_open,
        })
    }
}