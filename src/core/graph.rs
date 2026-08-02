use petgraph::graph::{Graph, NodeIndex};
use petgraph::Directed;
use serde::Serialize;

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
}

impl ReconGraph {
    pub fn new() -> Self {
        Self {
            graph: Graph::new(),
        }
    }

    pub fn add_node(&mut self, node: GraphNode) -> NodeIndex {
        if let Some(idx) = self.graph.node_indices().find(|&i| self.graph[i] == node) {
            return idx;
        }
        self.graph.add_node(node)
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
        xml.push_str("<graphml xmlns=\"http://graphml.graphstruct.org/xmlns\">\n");
        xml.push_str("  <key id=\"d0\" for=\"node\" attr.name=\"label\" attr.type=\"string\"/>\n");
        xml.push_str("  <key id=\"d1\" for=\"node\" attr.name=\"type\" attr.type=\"string\"/>\n");
        xml.push_str("  <key id=\"d2\" for=\"edge\" attr.name=\"relation\" attr.type=\"string\"/>\n");
        xml.push_str("  <graph id=\"G\" edgedefault=\"directed\">\n");

        for idx in self.graph.node_indices() {
            let node = &self.graph[idx];
            let (label, ntype) = match node {
                GraphNode::Domain(d) => (d.clone(), "domain"),
                GraphNode::IpAddress(ip) => (ip.clone(), "ip"),
                GraphNode::Port { ip, port } => (format!("{}:{}", ip, port), "port"),
                GraphNode::Service { port, name } => (format!("{}:{}", name, port), "service"),
                GraphNode::Technology { name, version } => (
                    match version {
                        Some(v) => format!("{}/{}", name, v),
                        None => name.clone(),
                    },
                    "technology",
                ),
            };
            xml.push_str(&format!(
                "    <node id=\"n{}\">\n      <data key=\"d0\">{}</data>\n      <data key=\"d1\">{}</data>\n    </node>\n",
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
                "    <edge source=\"n{}\" target=\"n{}\">\n      <data key=\"d2\">{}</data>\n    </edge>\n",
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