use crate::core::graph::ReconGraph;
use anyhow::Result;
use std::fs;

pub fn export(graph: &ReconGraph, output_path: &str) -> Result<()> {
    let g = graph.get_graph();
    let mut xml = String::new();
    
    xml.push_str("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
    xml.push_str("<graphml xmlns=\"http://graphml.graphstruct.org/graphml\" xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:schemaLocation=\"http://graphml.graphstruct.org/graphml\">\n");
    xml.push_str("  <key id=\"label\" for=\"all\" attr.name=\"label\" attr.type=\"string\"/>\n");
    xml.push_str("  <graph id=\"G\" edgedefault=\"directed\">\n");

    for (idx, node) in g.node_indices().zip(g.node_weights()) {
        xml.push_str(&format!("    <node id=\"n{}\">\n", idx.index()));
        xml.push_str(&format!("      <data key=\"label\">{}</data>\n", escape_xml(&format!("{:?}", node))));
        xml.push_str("    </node>\n");
    }

    for edge in g.edge_indices() {
        let (source, target) = g.edge_endpoints(edge).unwrap();
        let weight = g.edge_weight(edge).unwrap();
        xml.push_str(&format!("    <edge id=\"e{}\" source=\"n{}\" target=\"n{}\">\n", edge.index(), source.index(), target.index()));
        xml.push_str(&format!("      <data key=\"label\">{}</data>\n", escape_xml(&format!("{:?}", weight))));
        xml.push_str("    </edge>\n");
    }

    xml.push_str("  </graph>\n");
    xml.push_str("</graphml>\n");

    fs::write(output_path, xml)?;
    Ok(())
}

fn escape_xml(s: &str) -> String {
    s.replace('&', "&amp;")
     .replace('<', "&lt;")
     .replace('>', "&gt;")
     .replace('"', "&quot;")
     .replace('\'', "&apos;")
}