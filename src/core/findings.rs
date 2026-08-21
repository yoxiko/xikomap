use crate::prober::{CorsResult, FaviconResult, JarmResult, SecurityHeadersResult, SshFingerprint};

#[derive(Debug, Clone)]
pub struct PortReport {
    pub port: u16,
    pub findings: Vec<Finding>,
}

#[derive(Debug, Clone)]
pub enum Finding {
    Service { name: String, detail: String },
    Technology { name: String, version: String },
    Ssh(SshFingerprint),
    Jarm(JarmResult),
    Security(SecurityHeadersResult),
    Favicon(FaviconResult),
    Cors(CorsResult),
    ApiOpenApi { title: String, version: String },
    ApiGraphql { url: String },
    ApiEndpoint(String),
}