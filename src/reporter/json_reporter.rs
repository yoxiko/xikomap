use crate::core::graph::ReconGraph;
use anyhow::Result;
use serde::Serialize;
use std::fs;

#[derive(Serialize)]
struct ExportableNode {
    id: usize,
    data: String,
}

#[derive(Serialize)]
struct ExportableEdge {
    source: usize,
    target: usize,
    label: String,
}

#[derive(Serialize)]
struct ExportableGraph {
    nodes: Vec<ExportableNode>,
    edges: Vec<ExportableEdge>,
}

pub fn export(graph: &ReconGraph, output_path: &str) -> Result<()> {
    let g = graph.get_graph();
    let mut nodes = Vec::new();
    let mut edges = Vec::new();

    for (idx, node) in g.node_indices().zip(g.node_weights()) {
        nodes.push(ExportableNode {
            id: idx.index(),
            data: format!("{:?}", node),
        });
    }

    for edge in g.edge_indices() {
        let (source, target) = g.edge_endpoints(edge).unwrap();
        let weight = g.edge_weight(edge).unwrap();
        edges.push(ExportableEdge {
            source: source.index(),
            target: target.index(),
            label: format!("{:?}", weight),
        });
    }

    let exportable = ExportableGraph { nodes, edges };
    let json = serde_json::to_string_pretty(&exportable)?;
    fs::write(output_path, json)?;
    Ok(())
}