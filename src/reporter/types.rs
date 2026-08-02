use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanMetadata {
    pub target: String,
    pub start_time: DateTime<Utc>,
    pub end_time: DateTime<Utc>,
    pub duration_seconds: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanReport {
    pub metadata: ScanMetadata,
    pub open_ports: Vec<u16>,
    pub technologies: Vec<String>,
    pub graph_data: String,
}