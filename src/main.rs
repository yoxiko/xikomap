pub mod core;
pub mod prober;
pub mod reporter;
pub mod scanner;
pub mod python_bridge;
pub mod utils;

use crate::core::graph::{GraphEdge, GraphNode, ReconGraph};
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
        println!("Example: xikomap scanme.nmap.org 80,443,8080,8443");
        return;
    }

    let target = &args[1];

    let ports: Vec<u16> = if args.len() > 2 {
        args[2]
            .split(',')
            .filter_map(|p| p.trim().parse().ok())
            .collect()
    } else {
        vec![80, 443, 8080, 8443, 3000, 8000]
    };

    info!("Starting scan for target: {}", target);
    info!("Ports to scan: {:?}", ports);

    let engine = ScannerEngine::new(100);

    match engine.run(target, ports).await {
        Ok(open_ports) => {
            info!("Scan completed. Found {} open ports.", open_ports.len());

            let mut graph = ReconGraph::new();
            let target_node = graph.add_node(GraphNode::Domain(target.clone()));

            for port in &open_ports {
                let port_node = graph.add_node(GraphNode::Port {
                    ip: target.clone(),
                    port: *port,
                });
                graph.add_edge(target_node, port_node, GraphEdge::Hosts);
                
                info!("[+] Open port: {}", port);
            }

            let json_output = format!("{}_graph.json", target.replace(['.', ':'], "_"));
            if let Ok(json_data) = graph.export_to_json() {
                if let Err(e) = std::fs::write(&json_output, json_data) {
                    tracing::error!("Failed to write graph JSON: {}", e);
                } else {
                    info!("Graph saved to: {}", json_output);
                }
            }

            let graphml_output = format!("{}_graph.graphml", target.replace(['.', ':'], "_"));
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