use crate::core::graph::ReconGraph;
use std::fs;

pub fn export(graph: &ReconGraph, output_path: &str) -> Result<(), Box<dyn std::error::Error>> {
    let json = graph.export_to_json()?;
    fs::write(output_path, json)?;
    Ok(())
}