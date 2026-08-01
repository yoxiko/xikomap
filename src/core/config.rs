use crate::scanner::PortStrategy;

pub struct ScanConfig {
    pub targets: Vec<String>,
    pub exclude: Vec<String>,
    pub timeout_ms: u64,
    pub concurrency: usize,
    pub randomize: bool,
    pub port_strategy: PortStrategy,
}