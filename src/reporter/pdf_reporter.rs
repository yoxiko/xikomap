use crate::core::graph::ReconGraph;
use crate::detectors::api::ApiResult;
use crate::detectors::cloud::CloudResult;
use crate::prober::jarm::JarmResult;
use crate::prober::rdns::PtrRecord;
use crate::prober::screenshot::ScreenshotResult;
use crate::prober::security_headers::SecurityHeadersResult;
use crate::prober::ssh_fingerprint::SshFingerprint;
use printpdf::*;
use std::fs::File;
use std::io::BufWriter;

pub struct PdfReporter;

impl PdfReporter {
    #[allow(unused_mut, unused_assignments)]
    pub fn generate(
        graph: &ReconGraph,
        target: &str,
        output_path: &str,
        scan_type: &str,
        open_ports: &[u16],
        technologies: &[(String, String)],
        api_results: &ApiResult,
        cloud_results: &CloudResult,
        ssh_results: &[SshFingerprint],
        jarm_results: &[JarmResult],
        security_results: &[SecurityHeadersResult],
        ptr_results: &[PtrRecord],
        screenshot_results: &[ScreenshotResult],
    ) -> Result<(), Box<dyn std::error::Error>> {
        let (mut doc, mut current_page, mut current_layer_idx) =
            PdfDocument::new("Xikomap Report", Mm(210.0), Mm(297.0), "Layer 1");
        let mut current_layer = doc.get_page(current_page).get_layer(current_layer_idx);
        let font = doc.add_builtin_font(BuiltinFont::Helvetica)?;
        let font_bold = doc.add_builtin_font(BuiltinFont::HelveticaBold)?;

        let mut y = 280.0;
        let margin = 20.0;
        let page_width = 190.0;

        macro_rules! check_page {
            ($needed_height:expr) => {
                if y < $needed_height {
                    let (new_page, new_layer) = doc.add_page(Mm(210.0), Mm(297.0), "Layer 1");
                    current_page = new_page;
                    current_layer_idx = new_layer;
                    current_layer = doc.get_page(current_page).get_layer(current_layer_idx);
                    y = 280.0;
                }
            };
        }

        macro_rules! section_title {
            ($title:expr) => {
                check_page!(40.0);
                current_layer.use_text($title, 16.0, Mm(margin), Mm(y), &font_bold);
                y -= 8.0;
            };
        }

        macro_rules! text_line {
            ($text:expr, $size:expr) => {
                check_page!(20.0);
                current_layer.use_text($text, $size, Mm(margin), Mm(y), &font);
                y -= 6.0;
            };
        }

        macro_rules! bold_text_line {
            ($text:expr, $size:expr) => {
                check_page!(20.0);
                current_layer.use_text($text, $size, Mm(margin), Mm(y), &font_bold);
                y -= 6.0;
            };
        }

        current_layer.use_text(
            "Xikomap Reconnaissance Report",
            24.0,
            Mm(margin),
            Mm(y),
            &font_bold,
        );
        y -= 10.0;
        text_line!(&format!("Target: {}", target), 12.0);
        text_line!(
            &format!("Date: {}", chrono::Utc::now().format("%Y-%m-%d %H:%M:%S")),
            12.0
        );
        text_line!(&format!("Scan Type: {}", scan_type), 12.0);
        y -= 5.0;

        current_layer.add_line(Line {
            points: vec![
                (Point::new(Mm(margin), Mm(y)), false),
                (Point::new(Mm(page_width), Mm(y)), false),
            ],
            is_closed: false,
        });
        current_layer.set_outline_color(Color::Rgb(Rgb::new(0.0, 0.0, 0.0, None)));
        current_layer.set_outline_thickness(0.5);
        y -= 15.0;

        section_title!("Executive Summary");
        text_line!(&format!("Total Open Ports: {}", open_ports.len()), 11.0);
        text_line!(&format!("Technologies Detected: {}", technologies.len()), 11.0);
        text_line!(
            &format!("SSH Services: {}", ssh_results.len()),
            11.0
        );
        text_line!(
            &format!("JARM Fingerprints: {}", jarm_results.len()),
            11.0
        );
        text_line!(
            &format!("Security Audits: {}", security_results.len()),
            11.0
        );
        text_line!(
            &format!("PTR Records: {}", ptr_results.len()),
            11.0
        );
        text_line!(
            &format!("Screenshots Captured: {}", screenshot_results.len()),
            11.0
        );
        text_line!(
            &format!("Graph Nodes: {}, Edges: {}", graph.node_count(), graph.edge_count()),
            11.0
        );
        y -= 10.0;

        section_title!("Open Ports");
        let ports_str = open_ports
            .iter()
            .map(|p| p.to_string())
            .collect::<Vec<String>>()
            .join(", ");
        text_line!(&ports_str, 11.0);
        y -= 10.0;

        if !ptr_results.is_empty() {
            section_title!("Reverse DNS (PTR)");
            for ptr in ptr_results {
                text_line!(&format!("{} -> {}", ptr.ip, ptr.hostname), 11.0);
            }
            y -= 10.0;
        }

        if !ssh_results.is_empty() {
            section_title!("SSH Fingerprinting");
            for ssh in ssh_results {
                bold_text_line!(
                    &format!("Port {} - {} {}", ssh.port, ssh.software, ssh.version),
                    11.0
                );
                text_line!(&format!("  Banner: {}", ssh.banner), 10.0);
                text_line!(&format!("  Protocol: SSH-{}", ssh.protocol_version), 10.0);
                if !ssh.kex_algorithms.is_empty() {
                    let kex_str = ssh.kex_algorithms.join(", ");
                    let truncated = if kex_str.len() > 80 {
                        format!("{}...", &kex_str[..80])
                    } else {
                        kex_str
                    };
                    text_line!(&format!("  KEX: {}", truncated), 9.0);
                }
                if !ssh.encryption_ciphers.is_empty() {
                    let enc_str = ssh.encryption_ciphers.join(", ");
                    let truncated = if enc_str.len() > 80 {
                        format!("{}...", &enc_str[..80])
                    } else {
                        enc_str
                    };
                    text_line!(&format!("  Ciphers: {}", truncated), 9.0);
                }
                y -= 4.0;
            }
            y -= 10.0;
        }

        if !jarm_results.is_empty() {
            section_title!("JARM Fingerprints");
            for jarm in jarm_results {
                text_line!(&format!("Port {}: {}", jarm.port, jarm.hash), 10.0);
            }
            y -= 10.0;
        }

        if !security_results.is_empty() {
            section_title!("Security Headers Analysis");
            for sec in security_results {
                bold_text_line!(
                    &format!(
                        "{} - Grade: {} ({}/{})",
                        sec.url, sec.grade, sec.total_score, sec.max_total_score
                    ),
                    11.0
                );

                if !sec.missing_critical.is_empty() {
                    text_line!(
                        &format!("  Missing critical: {}", sec.missing_critical.join(", ")),
                        10.0
                    );
                }

                for check in &sec.checks {
                    if !check.present && !check.recommendation.is_empty() {
                        check_page!(20.0);
                        text_line!(
                            &format!("  [MISSING] {}: {}", check.name, check.recommendation),
                            9.0
                        );
                    }
                }
                y -= 4.0;
            }
            y -= 10.0;
        }

        if !technologies.is_empty() {
            section_title!("Technologies & Fingerprinting");
            for (tech, version) in technologies {
                text_line!(&format!("- {} ({})", tech, version), 11.0);
            }
            y -= 10.0;
        }

        if !api_results.endpoints.is_empty()
            || api_results.openapi.is_some()
            || api_results.graphql.is_some()
        {
            section_title!("API Discovery");

            if let Some(openapi) = &api_results.openapi {
                text_line!(
                    &format!("OpenAPI: {} (v{})", openapi.title, openapi.version),
                    11.0
                );
            }

            if let Some(graphql) = &api_results.graphql {
                text_line!(&format!("GraphQL Endpoint: {}", graphql.url), 11.0);
            }

            for endpoint in api_results.endpoints.iter().take(100) {
                text_line!(&format!("  {}", endpoint), 10.0);
            }
            y -= 10.0;
        }

        if !cloud_results.services.is_empty() {
            section_title!("Cloud Infrastructure");
            for service in &cloud_results.services {
                text_line!(&format!("- {}", service), 11.0);
            }
            if let Some(ip) = &cloud_results.ip {
                text_line!(&format!("Resolved IP: {}", ip), 11.0);
            }
            y -= 10.0;
        }

        if !screenshot_results.is_empty() {
            section_title!("Screenshots");
            for ss in screenshot_results {
                text_line!(&format!("URL: {}", ss.url), 10.0);
                text_line!(&format!("Title: {}", ss.title), 10.0);
                text_line!(&format!("File: {}", ss.file_path), 10.0);
                if let Some(status) = ss.status_code {
                    text_line!(&format!("Status: {}", status), 10.0);
                }
                y -= 4.0;
            }
            y -= 10.0;
        }

        let file = File::create(output_path)?;
        let mut writer = BufWriter::new(file);
        doc.save(&mut writer)?;

        Ok(())
    }
}