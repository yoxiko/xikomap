pub mod core;
pub mod prober;
pub mod reporter;
pub mod scanner;
pub mod python_bridge;
pub mod utils;

use crate::core::graph::{GraphEdge, GraphNode, ReconGraph};
use crate::prober::{grpc_prober, quic_prober, websocket_prober};
use crate::scanner::{ScannerEngine, SynScanner};
use crate::utils::logger::init_logger;
use std::env;
use std::time::Duration;
use tracing::{debug, info};

#[tokio::main]
async fn main() {
    init_logger();

    let args: Vec<String> = env::args().collect();

    if args.len() < 2 {
        println!("Usage: xikomap <target> [ports] [flags]");
        println!("Example: xikomap scanme.nmap.org 22,80,443,8080 -sS -v -x");
        println!();
        println!("Scan types:");
        println!("  -sS      SYN stealth scan (requires admin / Npcap)");
        println!("  -sT      Connect scan (default)");
        println!();
        println!("Flags:");
        println!("  -x       Save graph to JSON / GraphML");
        println!("  -v       Verbose output");
        println!("  -all     Scan all 65535 ports and probe every technology");
        return;
    }

    let mut target = String::new();
    let mut ports: Vec<u16> = Vec::new();
    let mut export_json = false;
    let mut verbose = false;
    let mut scan_all = false;
    let mut syn_scan = false;

    for arg in args.iter().skip(1) {
        match arg.as_str() {
            "-x" => export_json = true,
            "-v" => verbose = true,
            "-all" => scan_all = true,
            "-sS" => syn_scan = true,
            "-sT" => syn_scan = false,
            a if !a.starts_with('-') => {
                if target.is_empty() {
                    target = a.to_string();
                } else if ports.is_empty() {
                    ports = a
                        .split(',')
                        .filter_map(|p| p.trim().parse().ok())
                        .collect();
                }
            }
            _ => {}
        }
    }

    if target.is_empty() {
        println!("Error: no target specified");
        return;
    }

    if scan_all {
        ports = (1..=65535).collect();
        info!("Full scan mode enabled: scanning all 65535 ports");
    } else if ports.is_empty() {
        ports = vec![22, 80, 443, 8080, 8443, 3000, 8000, 8888];
        info!("No ports specified. Using default common ports: {:?}", ports);
    } else {
        info!("Target ports: {:?}", ports);
    }

    info!("Starting advanced scan for target: {}", target);

    if syn_scan {
        info!("Scan type: SYN (stealth)");
    } else {
        info!("Scan type: Connect");
    }

    let open_ports = if syn_scan {
        match SynScanner::new().run(&target, ports.clone()).await {
            Ok(p) => p,
            Err(e) => {
                tracing::warn!("SYN scan unavailable: {}. Falling back to connect scan.", e);
                let engine = ScannerEngine::new(if scan_all { 1000 } else { 100 });
                match engine.run(&target, ports.clone()).await {
                    Ok(p) => p,
                    Err(e) => {
                        tracing::error!("Scan failed: {}", e);
                        return;
                    }
                }
            }
        }
    } else {
        let engine = ScannerEngine::new(if scan_all { 1000 } else { 100 });
        match engine.run(&target, ports.clone()).await {
            Ok(p) => p,
            Err(e) => {
                tracing::error!("Scan failed: {}", e);
                return;
            }
        }
    };

    info!("TCP scan completed. Found {} open ports.", open_ports.len());

    let mut graph = ReconGraph::new();
    let target_node = graph.add_node(GraphNode::Domain(target.clone()));

    let http_client = reqwest::Client::builder()
        .http2_prior_knowledge()
        .timeout(Duration::from_secs(4))
        .danger_accept_invalid_certs(true)
        .build()
        .expect("Failed to create HTTP client");

    let quic_endpoint = quic_prober::create_quic_endpoint();
    if quic_endpoint.is_none() {
        tracing::warn!("QUIC endpoint unavailable, QUIC probing disabled");
    }

    for port in &open_ports {
        let port_node = graph.add_node(GraphNode::Port {
            ip: target.clone(),
            port: *port,
        });
        graph.add_edge(target_node, port_node, GraphEdge::Hosts);

        if verbose {
            debug!(" [+] Open TCP port: {}", port);
        } else {
            info!(" [+] Open TCP port: {}", port);
        }

        if scan_all || [80, 443, 8080, 8443, 3000, 8000, 9090, 50051, 10000].contains(port) {
            if let Some(ws) = websocket_prober::probe_websocket(&target, *port).await {
                info!(" [+] WebSocket detected: {}://{}:{}{}", ws.scheme, target, port, ws.path);
                let ws_node = graph.add_node(GraphNode::Service {
                    port: *port,
                    name: "websocket".to_string(),
                });
                graph.add_edge(port_node, ws_node, GraphEdge::Runs);

                if verbose {
                    if let Some(server) = &ws.server_header {
                        debug!("     Server header: {}", server);
                    }
                }
            }

            if let Some(grpc) = grpc_prober::probe_grpc(&target, *port, &http_client).await {
                info!(" [+] gRPC detected: status={}", grpc.status);
                let grpc_node = graph.add_node(GraphNode::Service {
                    port: *port,
                    name: "grpc".to_string(),
                });
                graph.add_edge(port_node, grpc_node, GraphEdge::Runs);

                if verbose {
                    debug!("     HTTP version: {}", grpc.http_version);
                    debug!("     Content-Type: {}", grpc.content_type);
                }
            }
        }

        if scan_all || [80, 443, 8443].contains(port) {
            if let Some(ep) = &quic_endpoint {
                if let Some(quic) = quic_prober::probe_quic(&target, *port, ep).await {
                    info!(" [+] QUIC/HTTP3 detected: {} (ALPN: {:?})", quic.protocol, quic.alpn);
                    let quic_node = graph.add_node(GraphNode::Technology {
                        name: quic.protocol,
                        version: quic.alpn,
                    });
                    graph.add_edge(port_node, quic_node, GraphEdge::Uses);
                }
            }
        }
    }

    if export_json {
        let safe_target_name = target.replace(['.', ':', '/'], "_");
        let json_output = format!("{}_graph.json", safe_target_name);
        if let Ok(json_data) = graph.export_to_json() {
            if let Err(e) = std::fs::write(&json_output, json_data) {
                tracing::error!("Failed to write graph JSON: {}", e);
            } else {
                info!("Graph saved to: {}", json_output);
            }
        }

        let graphml_output = format!("{}_graph.graphml", safe_target_name);
        let graphml_data = graph.export_to_graphml();
        if let Err(e) = std::fs::write(&graphml_output, graphml_data) {
            tracing::error!("Failed to write GraphML: {}", e);
        } else {
            info!("GraphML saved to: {}", graphml_output);
        }
    }

    info!(
        "Scan completed. Graph nodes: {}, edges: {}",
        graph.node_count(),
        graph.edge_count()
    );
}