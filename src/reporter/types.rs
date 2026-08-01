use crate::scanner::worker::ScanResult;
use chrono::{DateTime, Local};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanReport {
    pub target: String,
    pub timestamp: DateTime<Local>,
    pub total_ports_scanned: usize,
    pub open_ports: usize,
    pub scan_duration_secs: f64,
    pub results: Vec<ScanResult>,
    pub metadata: ReportMetadata,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReportMetadata {
    pub version: String,
    pub scanner: String,
    pub concurrency: usize,
    pub timeout_ms: u64,
    pub retries: u8,
}

impl ScanReport {
    pub fn new(
        target: String,
        results: Vec<ScanResult>,
        total_ports: usize,
        duration: f64,
        concurrency: usize,
        timeout_ms: u64,
        retries: u8,
    ) -> Self {
        Self {
            target,
            timestamp: Local::now(),
            total_ports_scanned: total_ports,
            open_ports: results.len(),
            scan_duration_secs: duration,
            results,
            metadata: ReportMetadata {
                version: env!("CARGO_PKG_VERSION").to_string(),
                scanner: "xikomap".to_string(),
                concurrency,
                timeout_ms,
                retries,
            },
        }
    }
}