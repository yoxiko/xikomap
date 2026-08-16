#![allow(dead_code)]

mod core;
mod detectors;
mod prober;
mod reporter;
mod scanner;
mod utils;

use crate::core::graph::{GraphEdge, GraphNode, ReconGraph};
use crate::detectors::api::{ApiDiscovery, ApiResult};
use crate::detectors::cloud::{CloudDetector, CloudResult};
use crate::detectors::fingerprinting::FingerprintingDetector;
use crate::detectors::iot::IoTDetector;
use crate::prober::cors::{CorsResult, CorsScanner};
use crate::prober::dns_enumerator::DnsEnumerator;
use crate::prober::favicon::{FaviconProber, FaviconResult};
use crate::prober::grpc as grpc_prober;
use crate::prober::http2_fingerprint::HTTP2Fingerprint;
use crate::prober::jarm::{JarmResult, JarmScanner};
use crate::prober::quic as quic_prober;
use crate::prober::rdns::{PtrRecord, RdnsProber};
use crate::prober::screenshot::{ScreenshotCapture, ScreenshotResult};
use crate::prober::security_headers::{SecurityHeadersAnalyzer, SecurityHeadersResult};
use crate::prober::ssh_fingerprint::{SshFingerprint, SshProber};
use crate::prober::tls_fingerprint::TLSFingerprint;
use crate::prober::websocket as websocket_prober;
use crate::reporter::{graphml_reporter, json_reporter, pdf_reporter};
use crate::scanner::{ScannerEngine, SynScanner};
use crate::utils::cli::Cli;
use crate::utils::logger::{get_log_collector, init_logger};
use crate::utils::logo::print_logo;
use chrono::Utc;
use clap::Parser;
use colored::Colorize;
use futures::StreamExt;
use petgraph::graph::NodeIndex;
use std::collections::HashMap;
use std::process;
use std::time::Duration;
use tracing::{debug, error, info, warn};

const WEB_PORTS: [u16; 9] = [80, 443, 8080, 8443, 3000, 8000, 9090, 50051, 10000];
const HTTP_PORTS: [u16; 4] = [80, 443, 8080, 8443];
const TLS_PORTS: [u16; 2] = [443, 8443];
const SSH_PORTS: [u16; 4] = [22, 2222, 2200, 8022];
const JARM_PORTS: [u16; 3] = [443, 8443, 4443];

fn format_url(target: &str, port: u16, scheme: &str) -> String {
    if target.contains(':') && !target.contains('[') {
        format!("{}://[{}]:{}", scheme, target, port)
    } else {
        format!("{}://{}:{}", scheme, target, port)
    }
}

fn normalize_args() -> Vec<String> {
    std::env::args()
        .map(|a| match a.as_str() {
            "-pdf" => "--pdf".to_string(),
            "-json" => "--json".to_string(),
            "-all" => "--all".to_string(),
            "-stealth" => "--stealth".to_string(),
            "-verbose" => "--verbose".to_string(),
            "-screenshot" => "--screenshot".to_string(),
            _ => a,
        })
        .collect()
}

enum RawFinding {
    Service { name: String, detail: String },
    Technology { name: String, version: String },
    Ssh(SshFingerprint),
    Jarm(JarmResult),
    Security(SecurityHeadersResult),
    Favicon(FaviconResult),
    Cors(CorsResult),
    ApiOpenApi { title: String, version: String },
    ApiGraphql { url: String },
    ApiEndpoint(String),
}

struct PortReport {
    port: u16,
    findings: Vec<RawFinding>,
}

async fn probe_port(
    target: String,
    port: u16,
    all: bool,
    http_client: reqwest::Client,
) -> PortReport {
    let mut findings: Vec<RawFinding> = Vec::new();

    let is_web = all || WEB_PORTS.contains(&port);
    let is_tls = TLS_PORTS.contains(&port);
    let is_http = HTTP_PORTS.contains(&port);
    let scheme = if is_tls { "https" } else { "http" };
    let url = format_url(&target, port, scheme);

    let ssh_fut = async {
        if SSH_PORTS.contains(&port) {
            SshProber::probe(&target, port).await
        } else {
            None
        }
    };

    let jarm_fut = async {
        if JARM_PORTS.contains(&port) {
            JarmScanner::scan(&target, port).await
        } else {
            None
        }
    };

    let tls_fut = async {
        if is_tls {
            TLSFingerprint::analyze(&target, port).ok()
        } else {
            None
        }
    };

    let ws_fut = async {
        if is_web {
            websocket_prober::probe_websocket(&target, port).await
        } else {
            None
        }
    };

    let grpc_fut = async {
        if is_web {
            grpc_prober::probe_grpc(&target, port, &http_client).await
        } else {
            None
        }
    };

    let quic_fut = async {
        if all || [80, 443, 8443].contains(&port) {
            if let Some(ep) = quic_prober::create_quic_endpoint() {
                return quic_prober::probe_quic(&target, port, &ep).await;
            }
        }
        None
    };

    let http2_fut = async {
        if is_http {
            HTTP2Fingerprint::analyze(&target, port).await.ok()
        } else {
            None
        }
    };

    let sec_fut = async {
        if is_http {
            SecurityHeadersAnalyzer::new(http_client.clone())
                .analyze(&url)
                .await
        } else {
            None
        }
    };

    let fav_fut = async {
        if is_http {
            FaviconProber::probe(&http_client, &target, port, scheme).await
        } else {
            None
        }
    };

    let cors_fut = async {
        if is_http {
            CorsScanner::new(http_client.clone()).analyze(&url).await
        } else {
            None
        }
    };

    let fp_fut = async {
        if is_http {
            FingerprintingDetector::new(http_client.clone())
                .detect(&url)
                .await
                .ok()
        } else {
            None
        }
    };

    let api_fut = async {
        if is_http {
            ApiDiscovery::new(http_client.clone()).discover(&url).await
        } else {
            ApiResult {
                openapi: None,
                graphql: None,
                endpoints: Vec::new(),
            }
        }
    };

    let mqtt_fut = async {
        if [1883, 8883].contains(&port) {
            Some(IoTDetector::detect_mqtt(&target, port, Duration::from_secs(3)).await)
        } else {
            None
        }
    };

    let coap_fut = async {
        if [5683, 5684].contains(&port) {
            Some(IoTDetector::detect_coap(&target, port, Duration::from_secs(3)).await)
        } else {
            None
        }
    };

    let (ssh, jarm, tls, ws, grpc, quic, http2, sec, fav, cors, fp, api, mqtt, coap) = tokio::join!(
        ssh_fut, jarm_fut, tls_fut, ws_fut, grpc_fut, quic_fut, http2_fut, sec_fut, fav_fut,
        cors_fut, fp_fut, api_fut, mqtt_fut, coap_fut
    );

    if let Some(ssh_fp) = ssh {
        findings.push(RawFinding::Ssh(ssh_fp));
    }

    if let Some(jarm_res) = jarm {
        findings.push(RawFinding::Jarm(jarm_res));
    }

    if let Some(tls_fp) = tls {
        if let Some(ja3) = tls_fp.ja3 {
            findings.push(RawFinding::Technology {
                name: "TLS".to_string(),
                version: ja3,
            });
        }
    }

    if let Some(ws_res) = ws {
        findings.push(RawFinding::Service {
            name: "websocket".to_string(),
            detail: format!("{}://{}:{}{}", ws_res.scheme, target, port, ws_res.path),
        });
    }

    if let Some(grpc_res) = grpc {
        findings.push(RawFinding::Service {
            name: "grpc".to_string(),
            detail: format!("status={}", grpc_res.status),
        });
    }

    if let Some(quic_res) = quic {
        findings.push(RawFinding::Technology {
            name: quic_res.protocol,
            version: quic_res.alpn.join(","),
        });
    }

    if let Some(http2_fp) = http2 {
        if !http2_fp.alpn.is_empty() {
            findings.push(RawFinding::Technology {
                name: "HTTP/2".to_string(),
                version: http2_fp.alpn.join(","),
            });
        }
    }

    if let Some(sec_res) = sec {
        findings.push(RawFinding::Security(sec_res));
    }

    if let Some(fav_res) = fav {
        findings.push(RawFinding::Favicon(fav_res));
    }

    if let Some(cors_res) = cors {
        findings.push(RawFinding::Cors(cors_res));
    }

    if let Some(fp_res) = fp {
        if !fp_res.detected.is_empty() {
            for tech in &fp_res.detected {
                let version = fp_res
                    .versions
                    .get(tech)
                    .cloned()
                    .unwrap_or_else(|| "unknown".to_string());
                findings.push(RawFinding::Technology {
                    name: tech.clone(),
                    version,
                });
            }
        }
    }

    if let Some(openapi) = &api.openapi {
        findings.push(RawFinding::ApiOpenApi {
            title: openapi.title.clone(),
            version: openapi.version.clone(),
        });
    }
    if let Some(graphql) = &api.graphql {
        findings.push(RawFinding::ApiGraphql {
            url: graphql.url.clone(),
        });
    }
    for endpoint in &api.endpoints {
        findings.push(RawFinding::ApiEndpoint(endpoint.clone()));
    }

    if let Some(mqtt_res) = mqtt {
        if mqtt_res.detected {
            findings.push(RawFinding::Service {
                name: "mqtt".to_string(),
                detail: format!("{:?} {:?}", mqtt_res.version, mqtt_res.features),
            });
        }
    }

    if let Some(coap_res) = coap {
        if coap_res.detected {
            findings.push(RawFinding::Service {
                name: "coap".to_string(),
                detail: format!("{:?}", coap_res.resources),
            });
        }
    }

    PortReport { port, findings }
}

#[tokio::main]
async fn main() {
    print_logo();
    init_logger();

    let start_time = Utc::now();

    let cli = Cli::parse_from(normalize_args());

    let target = cli.target.clone();
    let ports: Vec<u16> = if cli.all {
        (1..=65535).collect()
    } else if cli.ports.is_empty() {
        vec![22, 80, 443, 8080, 8443, 3000, 8000, 8888]
    } else {
        cli.ports.clone()
    };

    if cli.all {
        info!("Full scan mode enabled: scanning all 65535 ports");
    } else {
        info!("Target ports: {:?}", ports);
    }

    let scan_type_str = if cli.stealth { "SYN (stealth)" } else { "Connect" };
    info!("Starting advanced scan for target: {}", target);
    info!("Scan type: {}", scan_type_str);

    let target_ip = match tokio::net::lookup_host(format!("{}:0", target)).await {
        Ok(mut addrs) => addrs.next().map(|a| a.ip()),
        Err(e) => {
            error!("DNS resolution failed: {}", e);
            process::exit(1);
        }
    };

    let open_ports = if cli.stealth {
        if let Some(ip) = target_ip {
            match SynScanner::new(2000, 1000).run(ip, &ports).await {
                Ok(p) => p,
                Err(e) => {
                    warn!("SYN scan unavailable: {}. Falling back to connect scan.", e);
                    let engine = ScannerEngine::new(if cli.all { 1000 } else { 100 });
                    match engine.run(&target, ports.clone()).await {
                        Ok(p) => p,
                        Err(e) => {
                            error!("Scan failed: {}", e);
                            process::exit(1);
                        }
                    }
                }
            }
        } else {
            warn!("Could not resolve target to IP for SYN scan. Falling back to connect scan.");
            let engine = ScannerEngine::new(if cli.all { 1000 } else { 100 });
            match engine.run(&target, ports.clone()).await {
                Ok(p) => p,
                Err(e) => {
                    error!("Scan failed: {}", e);
                    process::exit(1);
                }
            }
        }
    } else {
        let engine = ScannerEngine::new(if cli.all { 1000 } else { 100 });
        match engine.run(&target, ports.clone()).await {
            Ok(p) => p,
            Err(e) => {
                error!("Scan failed: {}", e);
                process::exit(1);
            }
        }
    };

    info!(
        "{} {}",
        "[+]".green().bold(),
        format!("TCP scan completed. Found {} open ports.", open_ports.len())
    );

    let mut graph = ReconGraph::new();
    let target_node = graph.add_node(GraphNode::Domain(target.clone()));

    let http_client = match reqwest::Client::builder()
        .timeout(Duration::from_secs(4))
        .danger_accept_invalid_certs(true)
        .pool_max_idle_per_host(16)
        .build()
    {
        Ok(c) => c,
        Err(e) => {
            error!("Failed to create HTTP client: {}", e);
            process::exit(1);
        }
    };

    let mut all_cloud_results = CloudResult {
        services: Vec::new(),
        cdn: None,
        hosting: None,
        buckets: Vec::new(),
        ip: None,
        hostname: None,
    };

    let cloud_detector = CloudDetector::new();
    let cloud_results = cloud_detector.detect(&target);
    if !cloud_results.services.is_empty() {
        info!(
            "{} Cloud services: {:?}",
            "[+]".green().bold(),
            cloud_results.services
        );
        all_cloud_results = cloud_results;
    }

    if let Ok(dns_enum) = DnsEnumerator::new() {
        let subdomains = dns_enum.enumerate_subdomains(&target).await;
        if !subdomains.is_empty() {
            info!(
                "{} Found {} subdomains",
                "[+]".green().bold(),
                subdomains.len()
            );
            for subdomain in subdomains.iter().take(10) {
                let subdomain_node = graph.add_node(GraphNode::Domain(subdomain.clone()));
                graph.add_edge(target_node, subdomain_node, GraphEdge::Related);
            }
        }
    }

    let mut all_ptr_results: Vec<PtrRecord> = Vec::new();
    if let Some(ip) = target_ip {
        if let Some(prober) = RdnsProber::new() {
            if let Some(ptr) = prober.lookup(&ip.to_string()).await {
                info!(
                    "{} PTR record: {} -> {}",
                    "[+]".green().bold(),
                    ptr.ip,
                    ptr.hostname
                );
                let ptr_node = graph.add_node(GraphNode::PtrRecord {
                    ip: ptr.ip.clone(),
                    hostname: ptr.hostname.clone(),
                });
                graph.add_edge(target_node, ptr_node, GraphEdge::ResolvesTo);
                all_ptr_results.push(ptr);
            }
        }
    }

    info!("Probing {} open ports in parallel...", open_ports.len());

    let mut reports: Vec<PortReport> = futures::stream::iter(open_ports.clone())
        .map(|port| probe_port(target.clone(), port, cli.all, http_client.clone()))
        .buffer_unordered(8)
        .collect()
        .await;

    reports.sort_by_key(|r| r.port);

    let mut all_technologies: Vec<(String, String)> = Vec::new();
    let mut all_api_results = ApiResult {
        openapi: None,
        graphql: None,
        endpoints: Vec::new(),
    };
    let mut all_ssh_results: Vec<SshFingerprint> = Vec::new();
    let mut all_jarm_results: Vec<JarmResult> = Vec::new();
    let mut all_security_results: Vec<SecurityHeadersResult> = Vec::new();
    let mut all_favicon_results: Vec<FaviconResult> = Vec::new();
    let mut all_cors_results: Vec<CorsResult> = Vec::new();
    let mut port_nodes: HashMap<u16, NodeIndex> = HashMap::new();

    for report in reports {
        let port = report.port;
        let port_node = graph.add_node(GraphNode::Port {
            ip: target.clone(),
            port,
        });
        graph.add_edge(target_node, port_node, GraphEdge::Hosts);
        port_nodes.insert(port, port_node);

        if cli.verbose {
            debug!("{} Open TCP port: {}", "[+]".green().bold(), port);
        } else {
            info!("{} Open TCP port: {}", "[+]".green().bold(), port);
        }

        for finding in report.findings {
            match finding {
                RawFinding::Service { name, detail } => {
                    info!("{} {}: {}", "[+]".green().bold(), name, detail);
                    let node = graph.add_node(GraphNode::Service {
                        port,
                        name: name.clone(),
                    });
                    graph.add_edge(port_node, node, GraphEdge::Runs);
                }
                RawFinding::Technology { name, version } => {
                    info!("{} {}: {}", "[+]".green().bold(), name, version);
                    let node = graph.add_node(GraphNode::Technology {
                        name: name.clone(),
                        version: version.clone(),
                    });
                    graph.add_edge(port_node, node, GraphEdge::Uses);
                    if name != "TLS" && name != "HTTP/2" {
                        all_technologies.push((name, version));
                    }
                }
                RawFinding::Ssh(ssh_fp) => {
                    info!(
                        "{} SSH: {} {} (banner: {})",
                        "[+]".green().bold(),
                        ssh_fp.software,
                        ssh_fp.version,
                        ssh_fp.banner
                    );
                    let node = graph.add_node(GraphNode::SshService {
                        port,
                        banner: ssh_fp.banner.clone(),
                        software: ssh_fp.software.clone(),
                        version: ssh_fp.version.clone(),
                    });
                    graph.add_edge(port_node, node, GraphEdge::Runs);
                    all_ssh_results.push(ssh_fp);
                }
                RawFinding::Jarm(jarm_res) => {
                    info!(
                        "{} JARM: {} (port {})",
                        "[+]".green().bold(),
                        &jarm_res.hash[..16],
                        port
                    );
                    let node = graph.add_node(GraphNode::JarmHash {
                        port,
                        hash: jarm_res.hash.clone(),
                    });
                    graph.add_edge(port_node, node, GraphEdge::Uses);
                    all_jarm_results.push(jarm_res);
                }
                RawFinding::Security(sec_res) => {
                    info!(
                        "{} Security Headers: grade {} ({}/{})",
                        "[+]".green().bold(),
                        sec_res.grade,
                        sec_res.total_score,
                        sec_res.max_total_score
                    );
                    let node = graph.add_node(GraphNode::SecurityGrade {
                        url: sec_res.url.clone(),
                        grade: sec_res.grade.clone(),
                        score: sec_res.total_score,
                        max_score: sec_res.max_total_score,
                    });
                    graph.add_edge(port_node, node, GraphEdge::Uses);
                    all_security_results.push(sec_res);
                }
                RawFinding::Favicon(fav_res) => {
                    if let Some(tech) = &fav_res.technology {
                        info!(
                            "{} Favicon: {} (hash {})",
                            "[+]".green().bold(),
                            tech,
                            fav_res.hash
                        );
                    } else {
                        info!("{} Favicon hash: {}", "[+]".green().bold(), fav_res.hash);
                    }
                    let node = graph.add_node(GraphNode::Favicon {
                        port,
                        hash: fav_res.hash.clone(),
                        technology: fav_res.technology.clone(),
                    });
                    graph.add_edge(port_node, node, GraphEdge::Uses);
                    all_favicon_results.push(fav_res);
                }
                RawFinding::Cors(cors_res) => {
                    warn!(
                        "{} CORS misconfiguration on {} (severity: {})",
                        "[!]".yellow().bold(),
                        cors_res.url,
                        cors_res.severity
                    );
                    let node = graph.add_node(GraphNode::CorsIssue {
                        url: cors_res.url.clone(),
                        severity: cors_res.severity.clone(),
                        issues: cors_res.issues.clone(),
                    });
                    graph.add_edge(port_node, node, GraphEdge::Exposes);
                    all_cors_results.push(cors_res);
                }
                RawFinding::ApiOpenApi { title, version } => {
                    info!("{} OpenAPI: {} ({})", "[+]".green().bold(), title, version);
                    all_api_results.openapi = Some(crate::detectors::api::OpenApiSpec {
                        title,
                        version,
                        url: String::new(),
                    });
                }
                RawFinding::ApiGraphql { url } => {
                    info!("{} GraphQL: {}", "[+]".green().bold(), url);
                    all_api_results.graphql = Some(crate::detectors::api::GraphQLInfo {
                        url,
                        introspection: false,
                    });
                }
                RawFinding::ApiEndpoint(endpoint) => {
                    all_api_results.endpoints.push(endpoint);
                }
            }
        }
    }

    if cli.screenshot {
        let web_targets: Vec<(String, u16)> = open_ports
            .iter()
            .filter(|p| HTTP_PORTS.contains(p))
            .map(|p| {
                let scheme = if TLS_PORTS.contains(p) { "https" } else { "http" };
                (format_url(&target, *p, scheme), *p)
            })
            .collect();

        if !web_targets.is_empty() {
            info!("Launching headless browser for screenshots...");
            if let Some(mut browser) = ScreenshotCapture::launch().await {
                for (url, port) in &web_targets {
                    if let Some(ss) = ScreenshotCapture::capture_with_browser(
                        &mut browser,
                        url,
                        "./screenshots",
                        &target.replace(['.', ':', '/'], "_"),
                        *port,
                    )
                    .await
                    {
                        info!(
                            "{} Screenshot saved: {} (title: {})",
                            "[+]".green().bold(),
                            ss.file_path,
                            ss.title
                        );
                        if let Some(pn) = port_nodes.get(port) {
                            let ss_node = graph.add_node(GraphNode::Screenshot {
                                url: ss.url.clone(),
                                file_path: ss.file_path.clone(),
                                title: ss.title.clone(),
                            });
                            graph.add_edge(*pn, ss_node, GraphEdge::HasScreenshot);
                        }
                    }
                }
                let _ = browser.close().await;
            } else {
                warn!("Failed to launch browser, screenshots disabled");
            }
        }
    }

    let safe_target_name = target.replace(['.', ':', '/'], "_");

    if cli.export_json {
        let json_output = format!("{}_graph.json", safe_target_name);
        match json_reporter::export(&graph, &json_output) {
            Ok(_) => info!("JSON saved to: {}", json_output),
            Err(e) => error!("Failed to write JSON: {}", e),
        }

        let graphml_output = format!("{}_graph.graphml", safe_target_name);
        match graphml_reporter::export(&graph, &graphml_output) {
            Ok(_) => info!("GraphML saved to: {}", graphml_output),
            Err(e) => error!("Failed to write GraphML: {}", e),
        }
    }

    let end_time = Utc::now();
    let duration = end_time.signed_duration_since(start_time);
    info!(
        "Scan completed in {}m {}s. Graph nodes: {}, edges: {}",
        duration.num_minutes(),
        duration.num_seconds() % 60,
        graph.node_count(),
        graph.edge_count()
    );

    if cli.export_pdf {
        let pdf_output = format!("{}_report.pdf", safe_target_name);
        let logs = get_log_collector()
            .map(|c| c.entries())
            .unwrap_or_default();
        match pdf_reporter::PdfReporter::generate(
            &graph,
            &target,
            &pdf_output,
            scan_type_str,
            &open_ports,
            &all_technologies,
            &all_api_results,
            &all_cloud_results,
            &all_ssh_results,
            &all_jarm_results,
            &all_security_results,
            &all_ptr_results,
            &all_favicon_results,
            &all_cors_results,
            &all_screenshot_results,
            start_time,
            end_time,
            &logs,
        ) {
            Ok(_) => info!("PDF report saved to: {}", pdf_output),
            Err(e) => error!("Failed to generate PDF: {}", e),
        }
    }
}