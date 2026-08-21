use crate::core::graph::ReconGraph;
use crate::detectors::api::ApiResult;
use crate::detectors::cloud::CloudResult;
use crate::prober::{CorsResult, FaviconResult, JarmResult, PtrRecord, ScreenshotResult, SecurityHeadersResult, SshFingerprint};
use crate::utils::log_collector::LogEntry;
use anyhow::Result;
use chrono::{DateTime, Utc};
use printpdf::*;
use std::fs::File;
use std::io::BufWriter;

pub struct PdfReporter;

impl PdfReporter {
    #[allow(clippy::too_many_arguments)]
    pub fn generate(
        _graph: &ReconGraph,
        target: &str,
        output_path: &str,
        scan_type: &str,
        open_ports: &[u16],
        total_ports: usize,
        _concurrency: usize,
        technologies: &[(String, String)],
        api_results: &ApiResult,
        cloud_results: &CloudResult,
        _ssh_results: &[SshFingerprint],
        _jarm_results: &[JarmResult],
        _security_results: &[SecurityHeadersResult],
        _ptr_results: &[PtrRecord],
        _favicon_results: &[FaviconResult],
        cors_results: &[CorsResult],
        screenshot_results: &[ScreenshotResult],
        start_time: DateTime<Utc>,
        end_time: DateTime<Utc>,
        _logs: &[LogEntry],
    ) -> Result<()> {
        let (mut doc, page1, layer1) = PdfDocument::new(
            format!("Xikomap Report: {}", target),
            Mm(210.0),
            Mm(297.0),
            "Layer 1",
        );

        let font = doc.add_builtin_font(BuiltinFont::Helvetica).unwrap();
        let font_bold = doc.add_builtin_font(BuiltinFont::HelveticaBold).unwrap();

        let mut y_pos = 270.0;
        let margin = 15.0;

        let mut add_text = |text: &str, x: f32, y: f32, size: f32, is_bold: bool| {
            let f = if is_bold { font_bold.clone() } else { font.clone() };
            let page_ref = doc.get_page(page1);
            let layer_ref = page_ref.get_layer(layer1);
            layer_ref.use_text(text, size, Mm(x), Mm(y), &f);
        };

        add_text(&format!("Xikomap Reconnaissance Report"), margin, y_pos, 24.0, true);
        y_pos -= 12.0;
        add_text(&format!("Target: {}", target), margin, y_pos, 14.0, false);
        y_pos -= 8.0;
        add_text(
            &format!("Scan Type: {} | Ports Scanned: {} | Open: {}", scan_type, total_ports, open_ports.len()),
            margin,
            y_pos,
            10.0,
            false,
        );
        y_pos -= 6.0;
        add_text(
            &format!(
                "Duration: {} - {}",
                start_time.format("%Y-%m-%d %H:%M:%S"),
                end_time.format("%Y-%m-%d %H:%M:%S")
            ),
            margin,
            y_pos,
            10.0,
            false,
        );
        y_pos -= 15.0;

        add_text("Open Ports", margin, y_pos, 16.0, true);
        y_pos -= 8.0;
        let ports_str: Vec<String> = open_ports.iter().map(|p| p.to_string()).collect();
        add_text(&ports_str.join(", "), margin + 5.0, y_pos, 10.0, false);
        y_pos -= 15.0;

        if !technologies.is_empty() {
            add_text("Technologies Detected", margin, y_pos, 16.0, true);
            y_pos -= 8.0;
            for (name, version) in technologies {
                add_text(&format!("- {} ({})", name, version), margin + 5.0, y_pos, 10.0, false);
                y_pos -= 6.0;
            }
            y_pos -= 10.0;
        }

        if !cloud_results.services.is_empty() {
            add_text("Cloud Services", margin, y_pos, 16.0, true);
            y_pos -= 8.0;
            for service in &cloud_results.services {
                add_text(&format!("- {}", service), margin + 5.0, y_pos, 10.0, false);
                y_pos -= 6.0;
            }
            y_pos -= 10.0;
        }

        if !cors_results.is_empty() {
            add_text("Security Findings (CORS)", margin, y_pos, 16.0, true);
            y_pos -= 8.0;
            for cors in cors_results {
                add_text(
                    &format!("- [{}] {}", cors.severity, cors.url),
                    margin + 5.0,
                    y_pos,
                    10.0,
                    false,
                );
                y_pos -= 6.0;
            }
            y_pos -= 10.0;
        }

        if !screenshot_results.is_empty() {
            add_text("Screenshots / Fallbacks", margin, y_pos, 16.0, true);
            y_pos -= 8.0;
            for ss in screenshot_results {
                add_text(
                    &format!("- {} (Title: {})", ss.url, ss.title),
                    margin + 5.0,
                    y_pos,
                    10.0,
                    false,
                );
                y_pos -= 6.0;
            }
            y_pos -= 10.0;
        }

        if api_results.openapi.is_some() || api_results.graphql.is_some() {
            add_text("API Endpoints", margin, y_pos, 16.0, true);
            y_pos -= 8.0;
            if let Some(openapi) = &api_results.openapi {
                add_text(
                    &format!("- OpenAPI: {} ({})", openapi.title, openapi.version),
                    margin + 5.0,
                    y_pos,
                    10.0,
                    false,
                );
                y_pos -= 6.0;
            }
            if let Some(graphql) = &api_results.graphql {
                add_text(&format!("- GraphQL: {}", graphql.url), margin + 5.0, y_pos, 10.0, false);
                y_pos -= 6.0;
            }
        }

        let file = File::create(output_path)?;
        doc.save(&mut BufWriter::new(file))?;

        Ok(())
    }
}