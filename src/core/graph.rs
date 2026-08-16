use petgraph::graph::{DiGraph, NodeIndex};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum GraphNode {
    Domain(String),
    Port { ip: String, port: u16 },
    Service { port: u16, name: String },
    Technology { name: String, version: String },
    Subdomain(String),
    Vulnerability { cve: String, severity: String },
    SshService { port: u16, banner: String, software: String, version: String },
    JarmHash { port: u16, hash: String },
    SecurityGrade { url: String, grade: String, score: u32, max_score: u32 },
    PtrRecord { ip: String, hostname: String },
    Screenshot { url: String, file_path: String, title: String },
    Favicon { port: u16, hash: String, technology: Option<String> },
    CorsIssue { url: String, severity: String, issues: Vec<String> },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum GraphEdge {
    Hosts,
    Runs,
    Uses,
    Related,
    Exposes,
    ResolvesTo,
    HasScreenshot,
}

pub struct ReconGraph {
    pub graph: DiGraph<GraphNode, GraphEdge>,
}

impl ReconGraph {
    pub fn new() -> Self {
        ReconGraph {
            graph: DiGraph::new(),
        }
    }

    pub fn add_node(&mut self, node: GraphNode) -> NodeIndex {
        self.graph.add_node(node)
    }

    pub fn add_edge(&mut self, from: NodeIndex, to: NodeIndex, edge: GraphEdge) {
        self.graph.add_edge(from, to, edge);
    }

    pub fn node_count(&self) -> usize {
        self.graph.node_count()
    }

    pub fn edge_count(&self) -> usize {
        self.graph.edge_count()
    }

    pub fn nodes(&self) -> impl Iterator<Item = &GraphNode> {
        self.graph.node_weights()
    }

    pub fn edges(&self) -> impl Iterator<Item = &GraphEdge> {
        self.graph.edge_weights()
    }

    pub fn get_edges(&self) -> Vec<(usize, usize, &GraphEdge)> {
        self.graph
            .edge_indices()
            .map(|idx| {
                let (from, to) = self.graph.edge_endpoints(idx).unwrap();
                let edge = self.graph.edge_weight(idx).unwrap();
                (from.index(), to.index(), edge)
            })
            .collect()
    }

    fn node_type(node: &GraphNode) -> &'static str {
        match node {
            GraphNode::Domain(_) => "domain",
            GraphNode::Port { .. } => "port",
            GraphNode::Service { .. } => "service",
            GraphNode::Technology { .. } => "technology",
            GraphNode::Subdomain(_) => "subdomain",
            GraphNode::Vulnerability { .. } => "vulnerability",
            GraphNode::SshService { .. } => "ssh_service",
            GraphNode::JarmHash { .. } => "jarm_hash",
            GraphNode::SecurityGrade { .. } => "security_grade",
            GraphNode::PtrRecord { .. } => "ptr_record",
            GraphNode::Screenshot { .. } => "screenshot",
            GraphNode::Favicon { .. } => "favicon",
            GraphNode::CorsIssue { .. } => "cors_issue",
        }
    }

    pub fn export_to_json(&self) -> Result<String, serde_json::Error> {
        let nodes: Vec<serde_json::Value> = self
            .graph
            .node_weights()
            .enumerate()
            .map(|(i, node)| {
                serde_json::json!({
                    "id": i,
                    "type": Self::node_type(node),
                    "data": node,
                })
            })
            .collect();

        let edges: Vec<serde_json::Value> = self
            .graph
            .edge_indices()
            .map(|idx| {
                let (from, to) = self.graph.edge_endpoints(idx).unwrap();
                let edge = self.graph.edge_weight(idx).unwrap();
                serde_json::json!({
                    "from": from.index(),
                    "to": to.index(),
                    "type": edge,
                })
            })
            .collect();

        let output = serde_json::json!({
            "nodes": nodes,
            "edges": edges,
        });

        serde_json::to_string_pretty(&output)
    }

    pub fn export_to_graphml(&self) -> String {
        let mut xml = String::from("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
        xml.push_str("<graphml xmlns=\"http://graphml.graphdrawing.org/xmlns\">\n");
        xml.push_str("  <key id=\"d0\" for=\"node\" attr.name=\"type\" attr.type=\"string\"/>\n");
        xml.push_str("  <key id=\"d1\" for=\"edge\" attr.name=\"type\" attr.type=\"string\"/>\n");
        xml.push_str("  <graph id=\"G\" edgedefault=\"directed\">\n");

        for (i, node) in self.graph.node_weights().enumerate() {
            xml.push_str(&format!(
                "    <node id=\"n{}\"><data key=\"d0\">{}</data></node>\n",
                i,
                Self::node_type(node)
            ));
        }

        for (i, idx) in self.graph.edge_indices().enumerate() {
            let (from, to) = self.graph.edge_endpoints(idx).unwrap();
            let edge = self.graph.edge_weight(idx).unwrap();
            let edge_type = match edge {
                GraphEdge::Hosts => "hosts",
                GraphEdge::Runs => "runs",
                GraphEdge::Uses => "uses",
                GraphEdge::Related => "related",
                GraphEdge::Exposes => "exposes",
                GraphEdge::ResolvesTo => "resolves_to",
                GraphEdge::HasScreenshot => "has_screenshot",
            };
            xml.push_str(&format!(
                "    <edge id=\"e{}\" source=\"n{}\" target=\"n{}\"><data key=\"d1\">{}</data></edge>\n",
                i,
                from.index(),
                to.index(),
                edge_type
            ));
        }

        xml.push_str("  </graph>\n");
        xml.push_str("</graphml>\n");
        xml
    }
}