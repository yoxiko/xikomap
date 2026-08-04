use petgraph::graph::{Graph, NodeIndex};
use petgraph::Directed;
use serde::Serialize;
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, PartialEq, Eq, Hash)]
pub enum GraphNode {
    Domain(String),
    IpAddress(String),
    Port { ip: String, port: u16 },
    Service { port: u16, name: String },
    Technology { name: String, version: Option<String> },
}

#[derive(Debug, Clone, Serialize)]
pub enum GraphEdge {
    ResolvesTo,
    Hosts,
    Runs,
    Uses,
}

#[derive(Serialize)]
struct ExportNode {
    id: usize,
    label: String,
    node_type: String,
    data: GraphNode,
}

#[derive(Serialize)]
struct ExportEdge {
    source: usize,
    target: usize,
    relation: String,
    data: GraphEdge,
}

#[derive(Serialize)]
struct GraphExport {
    nodes: Vec<ExportNode>,
    edges: Vec<ExportEdge>,
}

pub struct ReconGraph {
    graph: Graph<GraphNode, GraphEdge, Directed>,
    node_map: HashMap<GraphNode, NodeIndex>,
}

impl ReconGraph {
    pub fn new() -> Self {
        Self {
            graph: Graph::new(),
            node_map: HashMap::new(),
        }
    }

    pub fn add_node(&mut self, node: GraphNode) -> NodeIndex {
        if let Some(&idx) = self.node_map.get(&node) {
            return idx;
        }
        let idx = self.graph.add_node(node.clone());
        self.node_map.insert(node, idx);
        idx
    }

    pub fn add_edge(&mut self, from: NodeIndex, to: NodeIndex, edge: GraphEdge) {
        if !self.graph.contains_edge(from, to) {
            self.graph.add_edge(from, to, edge);
        }
    }

    pub fn node_count(&self) -> usize {
        self.graph.node_count()
    }

    pub fn edge_count(&self) -> usize {
        self.graph.edge_count()
    }

    pub fn export_to_json(&self) -> Result<String, serde_json::Error> {
        let nodes: Vec<ExportNode> = self
            .graph
            .node_indices()
            .map(|idx| {
                let node = &self.graph[idx];
                let (label, node_type) = match node {
                    GraphNode::Domain(d) => (d.clone(), "domain".to_string()),
                    GraphNode::IpAddress(ip) => (ip.clone(), "ip".to_string()),
                    GraphNode::Port { ip, port } => (format!("{}:{}", ip, port), "port".to_string()),
                    GraphNode::Service { port, name } => (format!("{}:{}", name, port), "service".to_string()),
                    GraphNode::Technology { name, version } => (
                        match version {
                            Some(v) => format!("{}/{}", name, v),
                            None => name.clone(),
                        },
                        "technology".to_string(),
                    ),
                };
                ExportNode {
                    id: idx.index(),
                    label,
                    node_type,
                    data: node.clone(),
                }
            })
            .collect();

        let edges: Vec<ExportEdge> = self
            .graph
            .edge_indices()
            .map(|idx| {
                let (source, target) = self.graph.edge_endpoints(idx).unwrap();
                let edge = &self.graph[idx];
                let relation = match edge {
                    GraphEdge::ResolvesTo => "resolves_to".to_string(),
                    GraphEdge::Hosts => "hosts".to_string(),
                    GraphEdge::Runs => "runs".to_string(),
                    GraphEdge::Uses => "uses".to_string(),
                };
                ExportEdge {
                    source: source.index(),
                    target: target.index(),
                    relation,
                    data: edge.clone(),
                }
            })
            .collect();

        let export = GraphExport { nodes, edges };
        serde_json::to_string_pretty(&export)
    }

    pub fn export_to_graphml(&self) -> String {
        let mut xml = String::new();
        xml.push_str("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
        xml.push_str("<graphml xmlns=\"http://graphml.graphdrawing.org/xmlns\">\n");
        xml.push_str("  <key id=\"label\" for=\"node\" attr.name=\"label\" attr.type=\"string\"/>\n");
        xml.push_str("  <key id=\"type\" for=\"node\" attr.name=\"type\" attr.type=\"string\"/>\n");
        xml.push_str("  <key id=\"relation\" for=\"edge\" attr.name=\"relation\" attr.type=\"string\"/>\n");
        xml.push_str("  <graph id=\"G\" edgedefault=\"directed\">\n");

        for idx in self.graph.node_indices() {
            let node = &self.graph[idx];
            let (label, ntype) = match node {
                GraphNode::Domain(d) => (escape_xml(d), "domain"),
                GraphNode::IpAddress(ip) => (escape_xml(ip), "ip"),
                GraphNode::Port { ip, port } => (escape_xml(&format!("{}:{}", ip, port)), "port"),
                GraphNode::Service { port, name } => (escape_xml(&format!("{}:{}", name, port)), "service"),
                GraphNode::Technology { name, version } => (
                    match version {
                        Some(v) => escape_xml(&format!("{}/{}", name, v)),
                        None => escape_xml(name),
                    },
                    "technology",
                ),
            };
            xml.push_str(&format!(
                "    <node id=\"n{}\">\n      <data key=\"label\">{}</data>\n      <data key=\"type\">{}</data>\n    </node>\n",
                idx.index(),
                label,
                ntype
            ));
        }

        for idx in self.graph.edge_indices() {
            let (source, target) = self.graph.edge_endpoints(idx).unwrap();
            let edge = &self.graph[idx];
            let relation = match edge {
                GraphEdge::ResolvesTo => "resolves_to",
                GraphEdge::Hosts => "hosts",
                GraphEdge::Runs => "runs",
                GraphEdge::Uses => "uses",
            };
            xml.push_str(&format!(
                "    <edge source=\"n{}\" target=\"n{}\">\n      <data key=\"relation\">{}</data>\n    </edge>\n",
                source.index(),
                target.index(),
                relation
            ));
        }

        xml.push_str("  </graph>\n");
        xml.push_str("</graphml>\n");
        xml
    }
}

fn escape_xml(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}