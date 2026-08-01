use crate::reporter::types::ScanReport;
use serde_json;
use std::fs::File;
use std::io::Write;
use std::path::Path;
use thiserror::Error;
use tracing::info;

#[derive(Error, Debug)]
pub enum JsonReportError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("JSON serialization error: {0}")]
    Json(#[from] serde_json::Error),
}

pub struct JsonReporter;

impl JsonReporter {
    pub fn generate(report: &ScanReport, output_path: &Path) -> Result<(), JsonReportError> {
        let mut file = File::create(output_path)?;
        serde_json::to_writer_pretty(&mut file, report)?;
        info!("JSON report saved to: {}", output_path.display());
        Ok(())
    }

    pub fn generate_to_string(report: &ScanReport) -> Result<String, JsonReportError> {
        let json = serde_json::to_string_pretty(report)?;
        Ok(json)
    }
}