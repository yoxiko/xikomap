use crate::core::graph::ReconGraph;
use crate::detectors::api::ApiResult;
use crate::detectors::cloud::CloudResult;
use crate::prober::cors::CorsResult;
use crate::prober::favicon::FaviconResult;
use crate::prober::jarm::JarmResult;
use crate::prober::rdns::PtrRecord;
use crate::prober::screenshot::ScreenshotResult;
use crate::prober::security_headers::SecurityHeadersResult;
use crate::prober::ssh_fingerprint::SshFingerprint;
use crate::utils::log_collector::LogEntry;
use chrono::{DateTime, Utc};
use printpdf::*;
use std::fs::File;
use std::io::BufWriter;

const PAGE_W: f32 = 210.0;
const PAGE_H: f32 = 297.0;
const M: f32 = 15.0;
const R: f32 = 195.0;
const GITHUB_URL: &str = "https://github.com/yoxiko/xikomap";
const VERSION: &str = "0.4.0";

fn col(r: f32, g: f32, b: f32) -> Color {
    Color::Rgb(Rgb::new(r, g, b, None))
}

const DARK: (f32, f32, f32) = (0.13, 0.15, 0.19);
const GRAY: (f32, f32, f32) = (0.42, 0.45, 0.50);
const LIGHT: (f32, f32, f32) = (0.85, 0.87, 0.90);
const ACCENT: (f32, f32, f32) = (0.00, 0.47, 0.63);
const GREEN: (f32, f32, f32) = (0.00, 0.55, 0.30);
const RED: (f32, f32, f32) = (0.80, 0.20, 0.20);
const ORANGE: (f32, f32, f32) = (0.90, 0.55, 0.10);

fn service_name(port: u16) -> &'static str {
    match port {
        21 => "FTP",
        22 => "SSH",
        25 => "SMTP",
        53 => "DNS",
        80 => "HTTP",
        110 => "POP3",
        143 => "IMAP",
        443 => "HTTPS",
        465 => "SMTPS",
        587 => "SMTP Submission",
        993 => "IMAPS",
        995 => "POP3S",
        1883 => "MQTT",
        3306 => "MySQL",
        5432 => "PostgreSQL",
        5431 => "SolidServer",
        5683 => "CoAP",
        6379 => "Redis",
        8080 => "HTTP-Alt",
        8443 => "HTTPS-Alt",
        8883 => "MQTTS",
        9090 => "HTTP-Admin",
        27017 => "MongoDB",
        _ => "unknown",
    }
}

fn wrap(text: &str, max: usize) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    for word in text.split_whitespace() {
        if cur.is_empty() {
            cur = word.to_string();
        } else if cur.len() + 1 + word.len() <= max {
            cur.push(' ');
            cur.push_str(word);
        } else {
            out.push(cur.clone());
            cur = word.to_string();
        }
        while cur.len() > max {
            out.push(cur[..max].to_string());
            cur = cur[max..].to_string();
        }
    }
    if !cur.is_empty() {
        out.push(cur);
    }
    if out.is_empty() {
        out.push(String::new());
    }
    out
}

pub struct PdfReporter;

#[allow(unused_mut, unused_assignments)]
impl PdfReporter {
    pub fn generate(
        graph: &ReconGraph,
        target: &str,
        output_path: &str,
        scan_type: &str,
        open_ports: &[u16],
        ports_scanned: usize,
        concurrency: usize,
        technologies: &[(String, String)],
        api_results: &ApiResult,
        cloud_results: &CloudResult,
        ssh_results: &[SshFingerprint],
        jarm_results: &[JarmResult],
        security_results: &[SecurityHeadersResult],
        ptr_results: &[PtrRecord],
        favicon_results: &[FaviconResult],
        cors_results: &[CorsResult],
        screenshot_results: &[ScreenshotResult],
        start_time: DateTime<Utc>,
        end_time: DateTime<Utc>,
        logs: &[LogEntry],
    ) -> Result<(), Box<dyn std::error::Error>> {
        let (mut doc, mut current_page, mut current_layer_idx) =
            PdfDocument::new("Xikomap Report", Mm(PAGE_W), Mm(PAGE_H), "Layer 1");
        let mut current_layer = doc.get_page(current_page).get_layer(current_layer_idx);
        let font = doc.add_builtin_font(BuiltinFont::Helvetica)?;
        let font_bold = doc.add_builtin_font(BuiltinFont::HelveticaBold)?;
        let font_mono = doc.add_builtin_font(BuiltinFont::Courier)?;

        let mut y: f32 = 285.0;
        let mut page_number = 1;

        macro_rules! footer {
            () => {
                current_layer.set_outline_color(col(LIGHT.0, LIGHT.1, LIGHT.2));
                current_layer.set_outline_thickness(0.3_f32);
                current_layer.add_line(Line {
                    points: vec![
                        (Point::new(Mm(M), Mm(12.0_f32)), false),
                        (Point::new(Mm(R), Mm(12.0_f32)), false),
                    ],
                    is_closed: false,
                });
                current_layer.set_fill_color(col(GRAY.0, GRAY.1, GRAY.2));
                current_layer.use_text(
                    &format!("Xikomap v{}  |  {}", VERSION, GITHUB_URL),
                    7.5_f32,
                    Mm(M),
                    Mm(8.0_f32),
                    &font,
                );
                current_layer.use_text(
                    &format!("Page {}", page_number),
                    7.5_f32,
                    Mm(R - 14.0_f32),
                    Mm(8.0_f32),
                    &font,
                );
            };
        }

        macro_rules! new_page {
            () => {
                let (new_page, new_layer) = doc.add_page(Mm(PAGE_W), Mm(PAGE_H), "Layer 1");
                current_page = new_page;
                current_layer_idx = new_layer;
                current_layer = doc.get_page(current_page).get_layer(current_layer_idx);
                y = 285.0_f32;
                page_number += 1;
                footer!();
            };
        }

        macro_rules! check_page {
            ($needed_height:expr) => {
                if y < $needed_height {
                    new_page!();
                }
            };
        }

        macro_rules! rule {
            ($th:expr, $c:expr) => {
                current_layer.set_outline_color(col($c.0, $c.1, $c.2));
                current_layer.set_outline_thickness($th);
                current_layer.add_line(Line {
                    points: vec![
                        (Point::new(Mm(M), Mm(y)), false),
                        (Point::new(Mm(R), Mm(y)), false),
                    ],
                    is_closed: false,
                });
            };
        }

        macro_rules! section {
            ($num:expr, $title:expr) => {
                check_page!(40.0_f32);
                y -= 6.0_f32;
                current_layer.set_fill_color(col(ACCENT.0, ACCENT.1, ACCENT.2));
                current_layer.use_text($num, 12.0_f32, Mm(M), Mm(y), &font_bold);
                current_layer.set_fill_color(col(DARK.0, DARK.1, DARK.2));
                current_layer.use_text($title, 12.0_f32, Mm(M + 10.0_f32), Mm(y), &font_bold);
                y -= 3.0_f32;
                current_layer.set_outline_color(col(ACCENT.0, ACCENT.1, ACCENT.2));
                current_layer.set_outline_thickness(0.8_f32);
                current_layer.add_line(Line {
                    points: vec![
                        (Point::new(Mm(M), Mm(y)), false),
                        (Point::new(Mm(M + 42.0_f32), Mm(y)), false),
                    ],
                    is_closed: false,
                });
                current_layer.set_outline_color(col(LIGHT.0, LIGHT.1, LIGHT.2));
                current_layer.set_outline_thickness(0.3_f32);
                current_layer.add_line(Line {
                    points: vec![
                        (Point::new(Mm(M + 42.0_f32), Mm(y)), false),
                        (Point::new(Mm(R), Mm(y)), false),
                    ],
                    is_closed: false,
                });
                y -= 7.0_f32;
            };
        }

        macro_rules! body {
            ($t:expr) => {
                for ln in wrap($t, 118) {
                    check_page!(20.0_f32);
                    current_layer.set_fill_color(col(DARK.0, DARK.1, DARK.2));
                    current_layer.use_text(&ln, 9.0_f32, Mm(M), Mm(y), &font);
                    y -= 4.5_f32;
                }
            };
        }

        macro_rules! kv {
            ($label:expr, $value:expr) => {
                let lines = wrap(&$value, 92);
                check_page!(20.0_f32 + 4.5_f32 * lines.len() as f32);
                current_layer.set_fill_color(col(GRAY.0, GRAY.1, GRAY.2));
                current_layer.use_text($label, 9.0_f32, Mm(M), Mm(y), &font_bold);
                let mut first = true;
                for ln in lines {
                    if !first {
                        check_page!(20.0_f32);
                    }
                    current_layer.set_fill_color(col(DARK.0, DARK.1, DARK.2));
                    current_layer.use_text(&ln, 9.0_f32, Mm(M + 48.0_f32), Mm(y), &font);
                    y -= 4.5_f32;
                    first = false;
                }
            };
        }

        footer!();

        current_layer.set_outline_color(col(ACCENT.0, ACCENT.1, ACCENT.2));
        current_layer.set_outline_thickness(2.0_f32);
        current_layer.add_line(Line {
            points: vec![
                (Point::new(Mm(M), Mm(y)), false),
                (Point::new(Mm(R), Mm(y)), false),
            ],
            is_closed: false,
        });
        y -= 14.0_f32;

        current_layer.set_fill_color(col(DARK.0, DARK.1, DARK.2));
        current_layer.use_text("XIKOMAP", 30.0_f32, Mm(M), Mm(y), &font_bold);
        y -= 8.0_f32;
        current_layer.set_fill_color(col(ACCENT.0, ACCENT.1, ACCENT.2));
        current_layer.use_text("Network Reconnaissance Report", 13.0_f32, Mm(M), Mm(y), &font);
        y -= 6.0_f32;
        current_layer.set_fill_color(col(GRAY.0, GRAY.1, GRAY.2));
        current_layer.use_text(GITHUB_URL, 8.5_f32, Mm(M), Mm(y), &font);
        y -= 8.0_f32;

        rule!(0.5_f32, DARK);
        y -= 10.0_f32;

        let duration = end_time.signed_duration_since(start_time);

        kv!("Target", &target.to_string());
        kv!("Scan Type", &scan_type.to_string());
        kv!(
            "Start Time",
            &start_time.format("%Y-%m-%d %H:%M:%S UTC").to_string()
        );
        kv!(
            "End Time",
            &end_time.format("%Y-%m-%d %H:%M:%S UTC").to_string()
        );
        kv!(
            "Duration",
            &format!("{}m {}s", duration.num_minutes(), duration.num_seconds() % 60)
        );
        kv!("Ports Scanned", &ports_scanned.to_string());
        y -= 6.0_f32;

        check_page!(50.0_f32);
        let issues = cors_results.len()
            + security_results
                .iter()
                .filter(|s| !s.missing_critical.is_empty())
                .count();

        let stats: [(String, String); 4] = [
            (open_ports.len().to_string(), "OPEN PORTS".to_string()),
            (technologies.len().to_string(), "TECHNOLOGIES".to_string()),
            (issues.to_string(), "SECURITY ISSUES".to_string()),
            (screenshot_results.len().to_string(), "SCREENSHOTS".to_string()),
        ];

        let xs: [f32; 4] = [M, M + 47.0_f32, M + 94.0_f32, M + 141.0_f32];
        for (i, (num, label)) in stats.iter().enumerate() {
            current_layer.set_fill_color(col(ACCENT.0, ACCENT.1, ACCENT.2));
            current_layer.use_text(num, 22.0_f32, Mm(xs[i]), Mm(y), &font_bold);
            current_layer.set_fill_color(col(GRAY.0, GRAY.1, GRAY.2));
            current_layer.use_text(label, 7.5_f32, Mm(xs[i]), Mm(y - 6.0_f32), &font);
        }
        y -= 16.0_f32;

        current_layer.set_fill_color(col(GRAY.0, GRAY.1, GRAY.2));
        current_layer.use_text(
            "This report was generated automatically by Xikomap. For source code and",
            8.0_f32,
            Mm(M),
            Mm(y),
            &font,
        );
        y -= 4.0_f32;
        current_layer.use_text(
            "updates visit the project repository linked above.",
            8.0_f32,
            Mm(M),
            Mm(y),
            &font,
        );

        section!("01", "Open Ports");
        if open_ports.is_empty() {
            body!("No open ports found on the target.");
        } else {
            current_layer.set_fill_color(col(GRAY.0, GRAY.1, GRAY.2));
            current_layer.use_text("PORT", 8.5_f32, Mm(M), Mm(y), &font_bold);
            current_layer.use_text("SERVICE", 8.5_f32, Mm(M + 25.0_f32), Mm(y), &font_bold);
            current_layer.use_text("STATE", 8.5_f32, Mm(M + 95.0_f32), Mm(y), &font_bold);
            current_layer.use_text("TRANSPORT", 8.5_f32, Mm(M + 125.0_f32), Mm(y), &font_bold);
            y -= 2.5_f32;
            rule!(0.5_f32, DARK);
            y -= 5.5_f32;
            for p in open_ports {
                check_page!(22.0_f32);
                current_layer.set_fill_color(col(DARK.0, DARK.1, DARK.2));
                current_layer.use_text(&p.to_string(), 9.0_f32, Mm(M), Mm(y), &font);
                current_layer.use_text(service_name(*p), 9.0_f32, Mm(M + 25.0_f32), Mm(y), &font);
                current_layer.set_fill_color(col(GREEN.0, GREEN.1, GREEN.2));
                current_layer.use_text("open", 9.0_f32, Mm(M + 95.0_f32), Mm(y), &font_bold);
                current_layer.set_fill_color(col(GRAY.0, GRAY.1, GRAY.2));
                current_layer.use_text("tcp", 9.0_f32, Mm(M + 125.0_f32), Mm(y), &font);
                y -= 5.0_f32;
            }
            rule!(0.3_f32, LIGHT);
        }

        section!("02", "Reverse DNS (PTR)");
        if ptr_results.is_empty() {
            body!("No PTR records resolved for the target.");
        } else {
            for ptr in ptr_results {
                kv!(&ptr.ip, &ptr.hostname);
            }
        }

        section!("03", "Scan Configuration");
        kv!("Ports Scanned", &ports_scanned.to_string());
        kv!("Concurrency", &concurrency.to_string());
        kv!("Scan Type", &scan_type.to_string());
        kv!(
            "Modules",
            "tcp, ptr, ssh, jarm, tls-ja3, http2, security-headers, favicon, cors, websocket, grpc, quic, iot, screenshots"
        );
        kv!("Graph Size", &format!("{} nodes, {} edges", graph.node_count(), graph.edge_count()));

        section!("04", "SSH Fingerprinting");
        if ssh_results.is_empty() {
            body!("No SSH services detected.");
        } else {
            for ssh in ssh_results {
                kv!(&format!("Port {}", ssh.port), &format!("{} {}", ssh.software, ssh.version));
                kv!("Banner", &ssh.banner);
                if !ssh.kex_algorithms.is_empty() {
                    kv!("KEX", &ssh.kex_algorithms.join(", "));
                }
                if !ssh.encryption_ciphers.is_empty() {
                    kv!("Ciphers", &ssh.encryption_ciphers.join(", "));
                }
                y -= 3.0_f32;
            }
        }

        section!("05", "JARM Fingerprints");
        if jarm_results.is_empty() {
            body!("No JARM fingerprints captured.");
        } else {
            for jarm in jarm_results {
                kv!(&format!("Port {}", jarm.port), &jarm.hash);
            }
        }

        section!("06", "Favicon Fingerprints");
        if favicon_results.is_empty() {
            body!("No favicons retrieved.");
        } else {
            for fav in favicon_results {
                let tech = fav.technology.clone().unwrap_or_else(|| "no local match".to_string());
                kv!(&format!("Port {}", fav.port), &format!("hash {} ({})", fav.hash, tech));
                kv!("Shodan query", &format!("http.favicon.hash:{}", fav.hash));
            }
        }

        section!("07", "Security Headers Analysis");
        if security_results.is_empty() {
            body!("No HTTP services available for header auditing.");
        } else {
            for sec in security_results {
                kv!("URL", &sec.url);
                kv!("Grade", &format!("{} ({}/{})", sec.grade, sec.total_score, sec.max_total_score));
                if !sec.missing_critical.is_empty() {
                    kv!("Missing critical", &sec.missing_critical.join(", "));
                }
                for check in &sec.checks {
                    if !check.present && !check.recommendation.is_empty() {
                        kv!(&format!("[MISSING] {}", check.name), &check.recommendation);
                    }
                }
                y -= 3.0_f32;
            }
        }

        section!("08", "CORS Misconfigurations");
        if cors_results.is_empty() {
            body!("No CORS misconfigurations detected.");
        } else {
            for cors in cors_results {
                kv!("URL", &cors.url);
                kv!("Severity", &cors.severity);
                for issue in &cors.issues {
                    body!(&format!("- {}", issue));
                }
                y -= 3.0_f32;
            }
        }

        section!("09", "Technologies & Fingerprinting");
        if technologies.is_empty() {
            body!("No technologies identified.");
        } else {
            for (tech, version) in technologies {
                kv!(tech, version);
            }
        }

        section!("10", "API Discovery");
        if api_results.endpoints.is_empty()
            && api_results.openapi.is_none()
            && api_results.graphql.is_none()
        {
            body!("No API endpoints discovered.");
        } else {
            if let Some(openapi) = &api_results.openapi {
                kv!("OpenAPI", &format!("{} (v{})", openapi.title, openapi.version));
            }
            if let Some(graphql) = &api_results.graphql {
                kv!("GraphQL", &graphql.url);
            }
            for endpoint in api_results.endpoints.iter() {
                body!(&format!("- {}", endpoint));
            }
        }

        section!("11", "Cloud Infrastructure");
        if cloud_results.services.is_empty() {
            body!("No cloud provider indicators detected.");
        } else {
            for service in &cloud_results.services {
                body!(&format!("- {}", service));
            }
            if let Some(ip) = &cloud_results.ip {
                kv!("Resolved IP", ip);
            }
        }

        section!("12", "Screenshots");
        if screenshot_results.is_empty() {
            body!("No screenshots captured.");
        } else {
            for ss in screenshot_results {
                kv!("URL", &ss.url);
                kv!("Title", &ss.title);
                kv!("File", &ss.file_path);
                y -= 3.0_f32;
            }
        }

        section!("13", "Recommendations");
        let mut recs: Vec<String> = Vec::new();
        for p in open_ports {
            match p {
                53 => recs.push("Port 53 (DNS) is open: verify zone transfers (AXFR) are restricted and recursion is limited to trusted clients.".to_string()),
                22 => recs.push("Port 22 (SSH) is open: enforce key-based authentication and disable password login.".to_string()),
                21 => recs.push("Port 21 (FTP) is open: disable anonymous access and prefer SFTP.".to_string()),
                3306 | 5432 | 6379 | 27017 => recs.push(format!(
                    "Port {} ({}) is open: database services should not be internet-facing; restrict access via firewall.",
                    p,
                    service_name(*p)
                )),
                80 => recs.push("Port 80 (HTTP) is open: configure a redirect to HTTPS.".to_string()),
                443 | 8443 => recs.push(format!(
                    "Port {} ({}): ensure a strict TLS configuration and complete security headers.",
                    p,
                    service_name(*p)
                )),
                _ => {}
            }
        }
        for cors in cors_results {
            recs.push(format!("Fix CORS misconfiguration on {} (severity: {}).", cors.url, cors.severity));
        }
        for sec in security_results {
            if !sec.missing_critical.is_empty() {
                recs.push(format!(
                    "Add missing critical headers on {}: {}.",
                    sec.url,
                    sec.missing_critical.join(", ")
                ));
            }
        }
        if recs.is_empty() {
            recs.push("No specific recommendations; continue periodic monitoring.".to_string());
        }
        for (i, rec) in recs.iter().enumerate() {
            for (j, ln) in wrap(rec, 112).iter().enumerate() {
                check_page!(20.0_f32);
                if j == 0 {
                    current_layer.set_fill_color(col(ORANGE.0, ORANGE.1, ORANGE.2));
                    current_layer.use_text(&format!("{}.", i + 1), 9.0_f32, Mm(M), Mm(y), &font_bold);
                    current_layer.set_fill_color(col(DARK.0, DARK.1, DARK.2));
                    current_layer.use_text(ln, 9.0_f32, Mm(M + 6.0_f32), Mm(y), &font);
                } else {
                    current_layer.set_fill_color(col(DARK.0, DARK.1, DARK.2));
                    current_layer.use_text(ln, 9.0_f32, Mm(M + 6.0_f32), Mm(y), &font);
                }
                y -= 4.5_f32;
            }
        }

        section!("14", "Full Scan Log");
        kv!("Total entries", &logs.len().to_string());
        y -= 2.0_f32;
        for entry in logs {
            let timestamp = entry.timestamp.format("%H:%M:%S%.3f").to_string();
            let raw = format!("[{}] [{}] {}", timestamp, entry.level, entry.message);
            for ln in wrap(&raw, 118) {
                check_page!(20.0_f32);
                let c = match entry.level.as_str() {
                    "ERROR" => RED,
                    "WARN" => ORANGE,
                    _ => DARK,
                };
                current_layer.set_fill_color(col(c.0, c.1, c.2));
                current_layer.use_text(&ln, 7.0_f32, Mm(M), Mm(y), &font_mono);
                y -= 3.4_f32;
            }
        }

        let file = File::create(output_path)?;
        let mut writer = BufWriter::new(file);
        doc.save(&mut writer)?;

        Ok(())
    }
}