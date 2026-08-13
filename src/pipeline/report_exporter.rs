use crate::core::graph::ReconGraph;
use crate::reporter::{graphml_reporter, json_reporter, pdf_reporter};
use crate::utils::cli::Cli;
use tracing::{error, info};

pub struct ReportExporter {
    export_json: bool,
    export_pdf: bool,
}

impl ReportExporter {
    pub fn new(cli: &Cli) -> Self {
        Self {
            export_json: cli.export_json,
            export_pdf: cli.export_pdf,
        }
    }

    pub async fn export(&self, graph: &ReconGraph, target: &str) -> Result<(), String> {
        let safe_target_name = target.replace(['.', ':', '/'], "_");

        if self.export_json {
            let json_output = format!("{}_graph.json", safe_target_name);
            match json_reporter::export(graph, &json_output) {
                Ok(_) => info!("JSON saved to: {}", json_output),
                Err(e) => error!("Failed to write JSON: {}", e),
            }

            let graphml_output = format!("{}_graph.graphml", safe_target_name);
            match graphml_reporter::export(graph, &graphml_output) {
                Ok(_) => info!("GraphML saved to: {}", graphml_output),
                Err(e) => error!("Failed to write GraphML: {}", e),
            }
        }

        if self.export_pdf {
            let pdf_output = format!("{}_report.pdf", safe_target_name);
            match pdf_reporter::PdfReporter::generate(graph, target, &pdf_output) {
                Ok(_) => info!("PDF report saved to: {}", pdf_output),
                Err(e) => error!("Failed to generate PDF: {}", e),
            }
        }

        Ok(())
    }
}