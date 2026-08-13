use crate::core::graph::ReconGraph;
use crate::detectors::api::ApiResult;
use crate::detectors::cloud::CloudResult;
use printpdf::*;
use std::fs::File;
use std::io::BufWriter;

pub struct PdfReporter;

impl PdfReporter {
    pub fn generate(
        graph: &ReconGraph,
        target: &str,
        output_path: &str,
        scan_type: &str,
        open_ports: &[u16],
        technologies: &[(String, String)],
        api_results: &ApiResult,
        cloud_results: &CloudResult,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let (doc, page1, layer1) =
            PdfDocument::new("Xikomap Report", Mm(210.0), Mm(297.0), "Layer 1");
        let current_layer = doc.get_page(page1).get_layer(layer1);
        let font = doc.add_builtin_font(BuiltinFont::Helvetica)?;
        let font_bold = doc.add_builtin_font(BuiltinFont::HelveticaBold)?;

        let mut y = 280.0;
        let margin = 20.0;
        let page_width = 190.0;

        current_layer.use_text(
            "Xikomap Reconnaissance Report",
            24.0,
            Mm(margin),
            Mm(y),
            &font_bold,
        );
        y -= 10.0;
        current_layer.use_text(&format!("Target: {}", target), 12.0, Mm(margin), Mm(y), &font);
        y -= 6.0;
        current_layer.use_text(
            &format!(
                "Date: {}",
                chrono::Utc::now().format("%Y-%m-%d %H:%M:%S")
            ),
            12.0,
            Mm(margin),
            Mm(y),
            &font,
        );
        y -= 6.0;
        current_layer.use_text(&format!("Scan Type: {}", scan_type), 12.0, Mm(margin), Mm(y), &font);
        y -= 15.0;

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

        current_layer.use_text("Executive Summary", 16.0, Mm(margin), Mm(y), &font_bold);
        y -= 8.0;
        current_layer.use_text(
            &format!("Total Open Ports: {}", open_ports.len()),
            11.0,
            Mm(margin),
            Mm(y),
            &font,
        );
        y -= 6.0;
        current_layer.use_text(
            &format!("Technologies Detected: {}", technologies.len()),
            11.0,
            Mm(margin),
            Mm(y),
            &font,
        );
        y -= 6.0;
        current_layer.use_text(
            &format!("Graph Nodes: {}, Edges: {}", graph.node_count(), graph.edge_count()),
            11.0,
            Mm(margin),
            Mm(y),
            &font,
        );
        y -= 15.0;

        current_layer.use_text("Open Ports", 16.0, Mm(margin), Mm(y), &font_bold);
        y -= 8.0;
        let ports_str = open_ports
            .iter()
            .map(|p| p.to_string())
            .collect::<Vec<String>>()
            .join(", ");
        current_layer.use_text(&ports_str, 11.0, Mm(margin), Mm(y), &font);
        y -= 15.0;

        if !technologies.is_empty() {
            current_layer.use_text("Technologies & Fingerprinting", 16.0, Mm(margin), Mm(y), &font_bold);
            y -= 8.0;
            for (tech, version) in technologies {
                if y < 20.0 {
                    break;
                }
                current_layer.use_text(
                    &format!("- {} ({})", tech, version),
                    11.0,
                    Mm(margin),
                    Mm(y),
                    &font,
                );
                y -= 6.0;
            }
            y -= 10.0;
        }

        if !api_results.endpoints.is_empty()
            || api_results.openapi.is_some()
            || api_results.graphql.is_some()
        {
            current_layer.use_text("API Discovery", 16.0, Mm(margin), Mm(y), &font_bold);
            y -= 8.0;

            if let Some(openapi) = &api_results.openapi {
                if y > 20.0 {
                    current_layer.use_text(
                        &format!("OpenAPI: {} (v{})", openapi.title, openapi.version),
                        11.0,
                        Mm(margin),
                        Mm(y),
                        &font,
                    );
                    y -= 6.0;
                }
            }

            if let Some(graphql) = &api_results.graphql {
                if y > 20.0 {
                    current_layer.use_text(
                        &format!("GraphQL Endpoint: {}", graphql.url),
                        11.0,
                        Mm(margin),
                        Mm(y),
                        &font,
                    );
                    y -= 6.0;
                }
            }

            for endpoint in api_results.endpoints.iter().take(20) {
                if y < 20.0 {
                    break;
                }
                current_layer.use_text(&format!("  {}", endpoint), 10.0, Mm(margin), Mm(y), &font);
                y -= 5.0;
            }
            y -= 10.0;
        }

        if !cloud_results.services.is_empty() {
            current_layer.use_text("Cloud Infrastructure", 16.0, Mm(margin), Mm(y), &font_bold);
            y -= 8.0;
            for service in &cloud_results.services {
                if y < 20.0 {
                    break;
                }
                current_layer.use_text(&format!("- {}", service), 11.0, Mm(margin), Mm(y), &font);
                y -= 6.0;
            }
            if let Some(ip) = &cloud_results.ip {
                if y > 20.0 {
                    current_layer.use_text(
                        &format!("Resolved IP: {}", ip),
                        11.0,
                        Mm(margin),
                        Mm(y),
                        &font,
                    );
                    y -= 6.0;
                }
            }
        }

        let file = File::create(output_path)?;
        let mut writer = BufWriter::new(file);
        doc.save(&mut writer)?;

        Ok(())
    }
}