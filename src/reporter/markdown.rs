use crate::reporter::types::ScanReport;
use std::fs::File;
use std::io::Write;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum MarkdownReportError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
}

pub struct MarkdownReporter;

impl MarkdownReporter {
    pub fn write(report: &ScanReport, output_path: &str) -> Result<(), MarkdownReportError> {
        let mut file = File::create(output_path)?;
        
        writeln!(file, "# Xikomap Scan Report")?;
        writeln!(file, "**Target:** {}", report.metadata.target)?;
        writeln!(file, "**Duration:** {:.2} seconds", report.metadata.duration_seconds)?;
        writeln!(file, "\n## Open Ports")?;
        
        for port in &report.open_ports {
            writeln!(file, "- {}", port)?;
        }
        
        writeln!(file, "\n## Detected Technologies")?;
        for tech in &report.technologies {
            writeln!(file, "- {}", tech)?;
        }
        
        writeln!(file, "\n## Graph Data")?;
        writeln!(file, "```json")?;
        writeln!(file, "{}", report.graph_data)?;
        writeln!(file, "```")?;
        
        Ok(())
    }
}