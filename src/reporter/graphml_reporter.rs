use crate::core::graph::ReconGraph;
use std::fs;

pub fn export(graph: &ReconGraph, output_path: &str) -> Result<(), Box<dyn std::error::Error>> {
    let graphml = graph.export_to_graphml();
    fs::write(output_path, graphml)?;
    Ok(())
}