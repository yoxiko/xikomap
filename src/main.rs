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
use crate::prober::dns_enumerator::DnsEnumerator;
use crate::prober::grpc as grpc_prober;
use crate::prober::http2_fingerprint::HTTP2Fingerprint;
use crate::prober::jarm::JarmScanner;
use crate::prober::quic as quic_prober;
use crate::prober::rdns::RdnsProber;
use crate::prober::screenshot::ScreenshotCapture;
use crate::prober::security_headers::SecurityHeadersAnalyzer;
use crate::prober::ssh_fingerprint::SshProber;
use crate::prober::tls_fingerprint::TLSFingerprint;
use crate::prober::websocket as websocket_prober;
use crate::reporter::{graphml_reporter, json_reporter, pdf_reporter};
use crate::scanner::{ScannerEngine, SynScanner};
use crate::utils::cli::Cli;
use crate::utils::logger::init_logger;
use crate::utils::logo::print_logo;
use clap::Parser;
use colored::Colorize;
use std::process;
use std::time::Duration;
use tracing::{debug, error, info, warn};

fn format_url(target: &str, port: u16, scheme: &str) -> String {
    if target.contains(':') && !target.contains('[') {
        format!("{}://[{}]:{}", scheme, target, port)
    } else {
        format!("{}://{}:{}", scheme, target, port)
    }
}

#[tokio::main]
async fn main() {
    print_logo();
    init_logger();

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
        .http2_prior_knowledge()
        .timeout(Duration::from_secs(4))
        .danger_accept_invalid_certs(true)
        .build()
    {
        Ok(c) => c,
        Err(e) => {
            error!("Failed to create HTTP client: {}", e);
            process::exit(1);
        }
    };

    let quic_endpoint = quic_prober::create_quic_endpoint();
    if quic_endpoint.is_none() {
        warn!("QUIC endpoint unavailable, QUIC probing disabled");
    }

    let fp_detector = FingerprintingDetector::new(http_client.clone());
    let api_detector = ApiDiscovery::new(http_client.clone());
    let security_analyzer = SecurityHeadersAnalyzer::new(http_client.clone());

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

    let mut all_technologies: Vec<(String, String)> = Vec::new();
    let mut all_api_results = ApiResult {
        openapi: None,
        graphql: None,
        endpoints: Vec::new(),
    };
    let mut all_ssh_results = Vec::new();
    let mut all_jarm_results = Vec::new();
    let mut all_security_results = Vec::new();
    let mut all_ptr_results = Vec::new();
    let mut all_screenshot_results = Vec::new();

    if let Some(ip) = target_ip {
        let rdns_prober = RdnsProber::new();
        if let Some(prober) = rdns_prober {
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

    for port in &open_ports {
        let port_node = graph.add_node(GraphNode::Port {
            ip: target.clone(),
            port: *port,
        });
        graph.add_edge(target_node, port_node, GraphEdge::Hosts);

        if cli.verbose {
            debug!("{} Open TCP port: {}", "[+]".green().bold(), port);
        } else {
            info!("{} Open TCP port: {}", "[+]".green().bold(), port);
        }

        if [22, 2222, 2200, 8022].contains(port) {
            if let Some(ssh_fp) = SshProber::probe(&target, *port).await {
                info!(
                    "{} SSH: {} {} (banner: {})",
                    "[+]".green().bold(),
                    ssh_fp.software,
                    ssh_fp.version,
                    ssh_fp.banner
                );
                let ssh_node = graph.add_node(GraphNode::SshService {
                    port: *port,
                    banner: ssh_fp.banner.clone(),
                    software: ssh_fp.software.clone(),
                    version: ssh_fp.version.clone(),
                });
                graph.add_edge(port_node, ssh_node, GraphEdge::Runs);
                all_ssh_results.push(ssh_fp);
            }
        }

        if [443, 8443, 4443].contains(port) {
            if let Some(jarm) = JarmScanner::scan(&target, *port).await {
                info!(
                    "{} JARM: {} (port {})",
                    "[+]".green().bold(),
                    &jarm.hash[..16],
                    port
                );
                let jarm_node = graph.add_node(GraphNode::JarmHash {
                    port: *port,
                    hash: jarm.hash.clone(),
                });
                graph.add_edge(port_node, jarm_node, GraphEdge::Uses);
                all_jarm_results.push(jarm);
            }
        }

        if cli.all || [80, 443, 8080, 8443, 3000, 8000, 9090, 50051, 10000].contains(port) {
            if let Some(ws) = websocket_prober::probe_websocket(&target, *port).await {
                info!(
                    "{} WebSocket detected: {}://{}:{}{}",
                    "[+]".green().bold(),
                    ws.scheme,
                    target,
                    port,
                    ws.path
                );
                let ws_node = graph.add_node(GraphNode::Service {
                    port: *port,
                    name: "websocket".to_string(),
                });
                graph.add_edge(port_node, ws_node, GraphEdge::Runs);
            }

            if let Some(grpc) = grpc_prober::probe_grpc(&target, *port, &http_client).await {
                info!(
                    "{} gRPC detected: status={}",
                    "[+]".green().bold(),
                    grpc.status
                );
                let grpc_node = graph.add_node(GraphNode::Service {
                    port: *port,
                    name: "grpc".to_string(),
                });
                graph.add_edge(port_node, grpc_node, GraphEdge::Runs);
            }
        }

        if cli.all || [80, 443, 8443].contains(port) {
            if let Some(ep) = &quic_endpoint {
                if let Some(quic) = quic_prober::probe_quic(&target, *port, ep).await {
                    info!(
                        "{} QUIC/HTTP3 detected: {} (ALPN: {:?})",
                        "[+]".green().bold(),
                        quic.protocol,
                        quic.alpn
                    );
                    let quic_node = graph.add_node(GraphNode::Technology {
                        name: quic.protocol,
                        version: quic.alpn.join(","),
                    });
                    graph.add_edge(port_node, quic_node, GraphEdge::Uses);
                }
            }
        }

        if [443, 8443].contains(port) {
            match TLSFingerprint::analyze(&target, *port) {
                Ok(fp) => {
                    if let Some(ja3) = &fp.ja3 {
                        info!("{} TLS JA3: {}", "[+]".green().bold(), ja3);
                        let tls_node = graph.add_node(GraphNode::Technology {
                            name: "TLS".to_string(),
                            version: ja3.clone(),
                        });
                        graph.add_edge(port_node, tls_node, GraphEdge::Uses);
                    }
                }
                Err(e) => debug!("TLS fingerprint failed: {}", e),
            }
        }

        if [80, 443, 8080, 8443].contains(port) {
            match HTTP2Fingerprint::analyze(&target, *port).await {
                Ok(fp) => {
                    if !fp.alpn.is_empty() {
                        info!(
                            "{} HTTP/2 ALPN: {:?}",
                            "[+]".green().bold(),
                            fp.alpn
                        );
                    }
                }
                Err(e) => debug!("HTTP/2 fingerprint failed: {}", e),
            }

            let scheme = if [443, 8443].contains(port) { "https" } else { "http" };
            let url = format_url(&target, *port, scheme);

            if let Some(sec_result) = security_analyzer.analyze(&url).await {
                info!(
                    "{} Security Headers: grade {} ({}/{})",
                    "[+]".green().bold(),
                    sec_result.grade,
                    sec_result.total_score,
                    sec_result.max_total_score
                );
                let sec_node = graph.add_node(GraphNode::SecurityGrade {
                    url: url.clone(),
                    grade: sec_result.grade.clone(),
                    score: sec_result.total_score,
                    max_score: sec_result.max_total_score,
                });
                graph.add_edge(port_node, sec_node, GraphEdge::Uses);
                all_security_results.push(sec_result);
            }

            if cli.screenshot {
                let safe_name = target.replace(['.', ':', '/'], "_");
                if let Some(ss) = ScreenshotCapture::capture(&url, "./screenshots", &safe_name, *port).await {
                    info!(
                        "{} Screenshot saved: {} (title: {})",
                        "[+]".green().bold(),
                        ss.file_path,
                        ss.title
                    );
                    let ss_node = graph.add_node(GraphNode::Screenshot {
                        url: ss.url.clone(),
                        file_path: ss.file_path.clone(),
                        title: ss.title.clone(),
                    });
                    graph.add_edge(port_node, ss_node, GraphEdge::HasScreenshot);
                    all_screenshot_results.push(ss);
                }
            }

            match fp_detector.detect(&url).await {
                Ok(results) => {
                    if !results.detected.is_empty() {
                        info!(
                            "{} Fingerprinting: {:?}",
                            "[+]".green().bold(),
                            results.detected
                        );
                        for tech in &results.detected {
                            let version = results
                                .versions
                                .get(tech)
                                .cloned()
                                .unwrap_or_else(|| "unknown".to_string());

                            all_technologies.push((tech.clone(), version.clone()));

                            let tech_node = graph.add_node(GraphNode::Technology {
                                name: tech.clone(),
                                version: version.clone(),
                            });
                            graph.add_edge(port_node, tech_node, GraphEdge::Uses);
                        }
                    }
                }
                Err(e) => debug!("Fingerprinting failed: {}", e),
            }

            let api_results = api_detector.discover(&url).await;
            if api_results.openapi.is_some() || api_results.graphql.is_some() {
                info!("{} API endpoints discovered", "[+]".green().bold());
                if let Some(openapi) = &api_results.openapi {
                    info!(
                        "{} OpenAPI: {} ({})",
                        "[+]".green().bold(),
                        openapi.title,
                        openapi.version
                    );
                    all_api_results.openapi = Some(openapi.clone());
                }
                if let Some(graphql) = &api_results.graphql {
                    info!("{} GraphQL: {}", "[+]".green().bold(), graphql.url);
                    all_api_results.graphql = Some(graphql.clone());
                }
                all_api_results.endpoints.extend(api_results.endpoints.clone());
            }
        }

        if [1883, 8883].contains(port) {
            let mqtt_result =
                IoTDetector::detect_mqtt(&target, *port, Duration::from_secs(3)).await;
            if mqtt_result.detected {
                info!(
                    "{} MQTT detected: {:?} {:?}",
                    "[+]".green().bold(),
                    mqtt_result.version,
                    mqtt_result.features
                );
                let mqtt_node = graph.add_node(GraphNode::Service {
                    port: *port,
                    name: "mqtt".to_string(),
                });
                graph.add_edge(port_node, mqtt_node, GraphEdge::Runs);
            }
        }

        if [5683, 5684].contains(port) {
            let coap_result =
                IoTDetector::detect_coap(&target, *port, Duration::from_secs(3)).await;
            if coap_result.detected {
                info!(
                    "{} CoAP detected: {:?}",
                    "[+]".green().bold(),
                    coap_result.resources
                );
                let coap_node = graph.add_node(GraphNode::Service {
                    port: *port,
                    name: "coap".to_string(),
                });
                graph.add_edge(port_node, coap_node, GraphEdge::Runs);
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

    if cli.export_pdf {
        let pdf_output = format!("{}_report.pdf", safe_target_name);
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
            &all_screenshot_results,
        ) {
            Ok(_) => info!("PDF report saved to: {}", pdf_output),
            Err(e) => error!("Failed to generate PDF: {}", e),
        }
    }

    info!(
        "Scan completed. Graph nodes: {}, edges: {}",
        graph.node_count(),
        graph.edge_count()
    );
}