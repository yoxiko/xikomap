use petgraph::graph::{Graph, NodeIndex};
use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
pub enum GraphNode {
    Domain(String),
    Port { ip: String, port: u16 },
    Service { port: u16, name: String },
    Technology { name: String, version: String },
    SshService { port: u16, banner: String, software: String, version: String },
    JarmHash { port: u16, hash: String },
    SecurityGrade { url: String, grade: String, score: u32, max_score: u32 },
    Favicon { port: u16, hash: String, technology: Option<String> },
    CorsIssue { url: String, severity: String, issues: Vec<String> },
    Screenshot { url: String, file_path: String, title: String },
    PtrRecord { ip: String, hostname: String },
}

#[derive(Debug, Clone, Serialize)]
pub enum GraphEdge {
    Related,
    ResolvesTo,
    Hosts,
    Runs,
    Uses,
    Exposes,
    HasScreenshot,
}

pub struct ReconGraph {
    graph: Graph<GraphNode, GraphEdge>,
}

impl ReconGraph {
    pub fn new() -> Self {
        Self {
            graph: Graph::new(),
        }
    }

    pub fn add_node(&mut self, node: GraphNode) -> NodeIndex {
        self.graph.add_node(node)
    }

    pub fn add_edge(&mut self, source: NodeIndex, target: NodeIndex, edge: GraphEdge) {
        self.graph.add_edge(source, target, edge);
    }

    pub fn node_count(&self) -> usize {
        self.graph.node_count()
    }

    pub fn edge_count(&self) -> usize {
        self.graph.edge_count()
    }

    pub fn get_graph(&self) -> &Graph<GraphNode, GraphEdge> {
        &self.graph
    }
}