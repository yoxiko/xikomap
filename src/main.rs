mod core;
mod detectors;
mod prober;
mod reporter;
mod scanner;
mod utils;

use crate::core::findings::Finding;
use crate::core::graph::{GraphEdge, GraphNode, ReconGraph};
use crate::core::probing::{format_url, probe_port};
use crate::detectors::api::ApiResult;
use crate::detectors::cloud::{CloudDetector, CloudResult};
use crate::prober::cors::CorsResult;
use crate::prober::dns_enumerator::DnsEnumerator;
use crate::prober::favicon::FaviconResult;
use crate::prober::jarm::JarmResult;
use crate::prober::rdns::{PtrRecord, RdnsProber};
use crate::prober::screenshot::{ScreenshotCapture, ScreenshotResult};
use crate::prober::security_headers::SecurityHeadersResult;
use crate::prober::ssh_fingerprint::SshFingerprint;
use crate::reporter::{graphml_reporter, json_reporter, pdf_reporter};
use crate::scanner::{ScannerEngine, SynScanner};
use crate::utils::cli::Cli;
use crate::utils::logger::{get_log_collector, init_logger};
use crate::utils::logo::print_logo;

use anyhow::{Context, Result};
use chrono::Utc;
use clap::Parser;
use colored::Colorize;
use futures::StreamExt;
use petgraph::graph::NodeIndex;
use std::collections::HashMap;
use std::time::Duration;
use tracing::{debug, error, info, warn};

const TLS_PORTS: [u16; 2] = [443, 8443];

#[tokio::main]
async fn main() -> Result<()> {
    print_logo();
    init_logger();
    let start_time = Utc::now();

    let cli = Cli::parse();
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

    let target_ip = tokio::net::lookup_host(format!("{}:0", target))
        .await
        .context("DNS resolution failed")?
        .next()
        .map(|a| a.ip());

    let open_ports = if cli.stealth {
        if let Some(ip) = target_ip {
            match SynScanner::new(2000, 1000).run(ip, &ports).await {
                Ok(p) => p,
                Err(e) => {
                    warn!("SYN scan unavailable: {}. Falling back to connect scan.", e);
                    let engine = ScannerEngine::new(if cli.all { 1000 } else { 100 });
                    engine.run(&target, ports.clone()).await?
                }
            }
        } else {
            warn!("Could not resolve target to IP for SYN scan. Falling back to connect scan.");
            let engine = ScannerEngine::new(if cli.all { 1000 } else { 100 });
            engine.run(&target, ports.clone()).await?
        }
    } else {
        let engine = ScannerEngine::new(if cli.all { 1000 } else { 100 });
        engine.run(&target, ports.clone()).await?
    };

    info!(
        "{} {}",
        "[+]".green().bold(),
        format!("TCP scan completed. Found {} open ports.", open_ports.len())
    );

    let mut graph = ReconGraph::new();
    let target_node = graph.add_node(GraphNode::Domain(target.clone()));

    let http_client = reqwest::Client::builder()
        .timeout(Duration::from_secs(15))
        .danger_accept_invalid_certs(true)
        .pool_max_idle_per_host(16)
        .build()
        .context("Failed to create HTTP client")?;

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
        let txt_records = dns_enum.get_txt_records(&target).await;
        let mx_records = dns_enum.get_mx_records(&target).await;
        
        if !subdomains.is_empty() {
            info!("{} Found {} subdomains", "[+]".green().bold(), subdomains.len());
            for subdomain in subdomains.iter().take(10) {
                let subdomain_node = graph.add_node(GraphNode::Domain(subdomain.clone()));
                graph.add_edge(target_node, subdomain_node, GraphEdge::Related);
            }
        }
        
        if !txt_records.is_empty() {
            info!("{} Found {} TXT records", "[+]".green().bold(), txt_records.len());
        }
        
        if !mx_records.is_empty() {
            info!("{} Found {} MX records", "[+]".green().bold(), mx_records.len());
        }
    }

    let mut all_ptr_results: Vec<PtrRecord> = Vec::new();
    if let Some(ip) = target_ip {
        if let Some(prober) = RdnsProber::new() {
            if let Some(ptr) = prober.lookup(&ip.to_string()).await {
                info!("{} PTR record: {} -> {}", "[+]".green().bold(), ptr.ip, ptr.hostname);
                let ptr_node = graph.add_node(GraphNode::PtrRecord {
                    ip: ptr.ip.clone(),
                    hostname: ptr.hostname.clone(),
                });
                graph.add_edge(target_node, ptr_node, GraphEdge::ResolvesTo);
                all_ptr_results.push(ptr);
            }
            
            let rdns_results = prober.lookup_multiple(&[ip.to_string()]).await;
            if !rdns_results.records.is_empty() {
                info!("{} rDNS lookup completed for {} IPs", "[+]".green().bold(), rdns_results.records.len());
            }
        }
    }

    info!("Probing {} open ports in parallel...", open_ports.len());

    let mut reports: Vec<crate::core::findings::PortReport> = futures::stream::iter(open_ports.clone())
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
    let mut all_screenshot_results: Vec<ScreenshotResult> = Vec::new();
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
                Finding::Service { name, detail } => {
                    info!("{} {}: {}", "[+]".green().bold(), name, detail);
                    let node = graph.add_node(GraphNode::Service {
                        port,
                        name: name.clone(),
                    });
                    graph.add_edge(port_node, node, GraphEdge::Runs);
                }
                Finding::Technology { name, version } => {
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
                Finding::Ssh(ssh_fp) => {
                    info!("{} SSH: {} {} (banner: {})", "[+]".green().bold(), ssh_fp.software, ssh_fp.version, ssh_fp.banner);
                    let node = graph.add_node(GraphNode::SshService {
                        port,
                        banner: ssh_fp.banner.clone(),
                        software: ssh_fp.software.clone(),
                        version: ssh_fp.version.clone(),
                    });
                    graph.add_edge(port_node, node, GraphEdge::Runs);
                    all_ssh_results.push(ssh_fp);
                }
                Finding::Jarm(jarm_res) => {
                    let hash_preview = if jarm_res.hash.len() >= 16 { &jarm_res.hash[..16] } else { &jarm_res.hash };
                    info!("{} JARM: {} (port {})", "[+]".green().bold(), hash_preview, port);
                    let node = graph.add_node(GraphNode::JarmHash { port, hash: jarm_res.hash.clone() });
                    graph.add_edge(port_node, node, GraphEdge::Uses);
                    all_jarm_results.push(jarm_res);
                }
                Finding::Security(sec_res) => {
                    info!("{} Security Headers: grade {} ({}/{})", "[+]".green().bold(), sec_res.grade, sec_res.total_score, sec_res.max_total_score);
                    let node = graph.add_node(GraphNode::SecurityGrade {
                        url: sec_res.url.clone(),
                        grade: sec_res.grade.clone(),
                        score: sec_res.total_score,
                        max_score: sec_res.max_total_score,
                    });
                    graph.add_edge(port_node, node, GraphEdge::Uses);
                    all_security_results.push(sec_res);
                }
                Finding::Favicon(fav_res) => {
                    if let Some(tech) = &fav_res.technology {
                        info!("{} Favicon: {} (hash {})", "[+]".green().bold(), tech, fav_res.hash);
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
                Finding::Cors(cors_res) => {
                    warn!("{} CORS misconfiguration on {} (severity: {})", "[!]".yellow().bold(), cors_res.url, cors_res.severity);
                    let node = graph.add_node(GraphNode::CorsIssue {
                        url: cors_res.url.clone(),
                        severity: cors_res.severity.clone(),
                        issues: cors_res.issues.clone(),
                    });
                    graph.add_edge(port_node, node, GraphEdge::Exposes);
                    all_cors_results.push(cors_res);
                }
                Finding::ApiOpenApi { title, version } => {
                    info!("{} OpenAPI: {} ({})", "[+]".green().bold(), title, version);
                    all_api_results.openapi = Some(crate::detectors::api::OpenApiSpec {
                        title,
                        version,
                        url: String::new(),
                    });
                }
                Finding::ApiGraphql { url } => {
                    info!("{} GraphQL: {}", "[+]".green().bold(), url);
                    all_api_results.graphql = Some(crate::detectors::api::GraphQLInfo {
                        url,
                        introspection: false,
                    });
                }
                Finding::ApiEndpoint(endpoint) => {
                    all_api_results.endpoints.push(endpoint);
                }
            }
        }
    }

    if let Some(openapi) = &all_api_results.openapi {
        info!("{} OpenAPI URL: {}", "[+]".green().bold(), openapi.url);
    }
    if let Some(graphql) = &all_api_results.graphql {
        info!("{} GraphQL Introspection: {}", "[+]".green().bold(), graphql.introspection);
    }

    if cli.screenshot && !open_ports.is_empty() {
        info!("Preparing screenshots for {} open ports...", open_ports.len());
        let safe_name = target.replace(['.', ':', '/'], "_");
        let screenshot_dir = "./screenshots";
        std::fs::create_dir_all(screenshot_dir).ok();
        
        match ScreenshotCapture::launch().await {
            Some(mut browser) => {
                info!("Browser launched successfully, capturing {} screenshots...", open_ports.len());
                for port in &open_ports {
                    let scheme = if TLS_PORTS.contains(port) { "https" } else { "http" };
                    let url = format_url(&target, *port, scheme);
                    info!("Capturing screenshot for {} (port {})...", url, port);
                    match ScreenshotCapture::capture_with_browser(&mut browser, &url, screenshot_dir, &safe_name, *port).await {
                        Some(ss) => {
                            info!("{} Screenshot saved: {} (title: {})", "[+]".green().bold(), ss.file_path, ss.title);
                            if let Some(pn) = port_nodes.get(port) {
                                let ss_node = graph.add_node(GraphNode::Screenshot {
                                    url: ss.url.clone(),
                                    file_path: ss.file_path.clone(),
                                    title: ss.title.clone(),
                                });
                                graph.add_edge(*pn, ss_node, GraphEdge::HasScreenshot);
                            }
                            all_screenshot_results.push(ss);
                        }
                        None => {
                            warn!("Chrome failed for {} (port {}), trying HTTP fallback...", url, port);
                            if let Some(fallback_ss) = capture_fallback(&http_client, &url, screenshot_dir, &safe_name, *port).await {
                                info!("{} HTTP fallback saved: {} (title: {})", "[+]".green().bold(), fallback_ss.file_path, fallback_ss.title);
                                if let Some(pn) = port_nodes.get(port) {
                                    let ss_node = graph.add_node(GraphNode::Screenshot {
                                        url: fallback_ss.url.clone(),
                                        file_path: fallback_ss.file_path.clone(),
                                        title: fallback_ss.title.clone(),
                                    });
                                    graph.add_edge(*pn, ss_node, GraphEdge::HasScreenshot);
                                }
                                all_screenshot_results.push(fallback_ss);
                            }
                        }
                    }
                }
                let _ = browser.close().await;
                info!("Screenshots completed: {} successful", all_screenshot_results.len());
            }
            None => {
                warn!("Chrome/Chromium not available, using HTTP fallback for all ports");
                for port in &open_ports {
                    let scheme = if TLS_PORTS.contains(port) { "https" } else { "http" };
                    let url = format_url(&target, *port, scheme);
                    if let Some(fallback_ss) = capture_fallback(&http_client, &url, screenshot_dir, &safe_name, *port).await {
                        info!("{} HTTP fallback saved: {} (title: {})", "[+]".green().bold(), fallback_ss.file_path, fallback_ss.title);
                        if let Some(pn) = port_nodes.get(port) {
                            let ss_node = graph.add_node(GraphNode::Screenshot {
                                url: fallback_ss.url.clone(),
                                file_path: fallback_ss.file_path.clone(),
                                title: fallback_ss.title.clone(),
                            });
                            graph.add_edge(*pn, ss_node, GraphEdge::HasScreenshot);
                        }
                        all_screenshot_results.push(fallback_ss);
                    }
                }
                info!("HTTP fallback completed: {} successful", all_screenshot_results.len());
            }
        }
    }

    let safe_target_name = target.replace(['.', '/', ':'], "_");

    if cli.export_json {
        let json_output = format!("{}_graph.json", safe_target_name);
        if let Err(e) = json_reporter::export(&graph, &json_output) {
            error!("Failed to write JSON: {}", e);
        }
        let graphml_output = format!("{}_graph.graphml", safe_target_name);
        if let Err(e) = graphml_reporter::export(&graph, &graphml_output) {
            error!("Failed to write GraphML: {}", e);
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
            .map(|c| c.drain())
            .unwrap_or_default();
        let concurrency = if cli.all { 1000 } else { 100 };
        if let Err(e) = pdf_reporter::PdfReporter::generate(
            &graph,
            &target,
            &pdf_output,
            scan_type_str,
            &open_ports,
            ports.len(),
            concurrency,
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
            error!("Failed to generate PDF: {}", e);
        }
    }

    Ok(())
}

async fn capture_fallback(
    client: &reqwest::Client,
    url: &str,
    dir: &str,
    safe_name: &str,
    port: u16,
) -> Option<ScreenshotResult> {
    let resp = client.get(url).send().await.ok()?;
    let status_code = Some(resp.status().as_u16());
    let final_url = resp.url().to_string();
    let text = resp.text().await.ok()?;

    let title = text
        .lines()
        .find(|l| l.contains("<title>"))
        .and_then(|l| l.split("<title>").nth(1))
        .and_then(|l| l.split("</title>").next())
        .unwrap_or("Untitled")
        .trim()
        .to_string();

    let file_name = format!("{}_{}.html", safe_name, port);
    let path = format!("{}/{}", dir, file_name);
    tokio::fs::write(&path, text).await.ok()?;

    Some(ScreenshotResult {
        url: url.to_string(),
        file_path: path,
        title,
        status_code,
        final_url,
    })
}