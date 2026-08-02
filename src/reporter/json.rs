use crate::reporter::types::ScanReport;
use serde_json;
use std::fs::File;
use std::io::Write;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum JsonReportError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
}

pub struct JsonReporter;

impl JsonReporter {
    pub fn write(report: &ScanReport, output_path: &str) -> Result<(), JsonReportError> {
        let json_data = serde_json::to_string_pretty(report)?;
        let mut file = File::create(output_path)?;
        file.write_all(json_data.as_bytes())?;
        Ok(())
    }
}