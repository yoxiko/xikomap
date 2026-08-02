pub mod core;
pub mod prober;
pub mod reporter;
pub mod scanner;
pub mod python_bridge;
pub mod utils;

use crate::core::graph::{GraphEdge, GraphNode, ReconGraph};
use crate::prober::{grpc_prober, quic_prober, websocket_prober};
use crate::scanner::ScannerEngine;
use crate::utils::logger::init_logger;
use std::env;
use tracing::info;

#[tokio::main]
async fn main() {
    init_logger();

    let args: Vec<String> = env::args().collect();

    if args.len() < 2 {
        println!("Usage: xikomap <target> [ports]");
        println!("Example: xikomap scanme.nmap.org 22,80,443,8080");
        return;
    }

    let target = &args[1];

    let mut ports: Vec<u16> = if args.len() > 2 {
        args[2]
            .split(',')
            .filter_map(|p| p.trim().parse().ok())
            .collect()
    } else {
        Vec::new()
    };

    if ports.is_empty() {
        ports = vec![22, 80, 443, 8080, 8443, 3000, 8000, 8888];
        info!("No valid ports specified. Using default common ports: {:?}", ports);
    } else {
        info!("Target ports: {:?}", ports);
    }

    info!("Starting advanced scan for target: {}", target);

    let engine = ScannerEngine::new(100);

    match engine.run(target, ports.clone()).await {
        Ok(open_ports) => {
            info!("TCP scan completed. Found {} open ports.", open_ports.len());

            let mut graph = ReconGraph::new();
            let target_node = graph.add_node(GraphNode::Domain(target.clone()));

            for port in &open_ports {
                let port_node = graph.add_node(GraphNode::Port {
                    ip: target.clone(),
                    port: *port,
                });
                graph.add_edge(target_node, port_node, GraphEdge::Hosts);
                info!("  [+] Open TCP port: {}", port);

                if [80, 443, 8080, 8443, 3000, 8000].contains(port) {
                    if let Some(ws) = websocket_prober::probe_websocket(target, *port).await {
                        info!("      [+] WebSocket detected: {}://{}:{}{}", ws.scheme, target, port, ws.path);
                        let ws_node = graph.add_node(GraphNode::Service { port: *port, name: "websocket".to_string() });
                        graph.add_edge(port_node, ws_node, GraphEdge::Runs);
                    }

                    if let Some(grpc) = grpc_prober::probe_grpc(target, *port).await {
                        info!("      [+] gRPC detected: status={}", grpc.status);
                        let grpc_node = graph.add_node(GraphNode::Service { port: *port, name: "grpc".to_string() });
                        graph.add_edge(port_node, grpc_node, GraphEdge::Runs);
                    }
                }

                if let Some(quic) = quic_prober::probe_quic(target, *port).await {
                    info!("      [+] QUIC/HTTP3 detected: {} (ALPN: {:?})", quic.protocol, quic.alpn);
                    let quic_node = graph.add_node(GraphNode::Technology { 
                        name: quic.protocol, 
                        version: quic.alpn 
                    });
                    graph.add_edge(port_node, quic_node, GraphEdge::Uses);
                }
            }

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
        Err(e) => {
            tracing::error!("Scan failed: {}", e);
        }
    }
}