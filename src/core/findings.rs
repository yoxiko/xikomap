use crate::prober::ssh_fingerprint::SshFingerprint;
use crate::prober::jarm::JarmResult;
use crate::prober::security_headers::SecurityHeadersResult;
use crate::prober::favicon::FaviconResult;
use crate::prober::cors::CorsResult;

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

#[derive(Debug, Clone)]
pub struct PortReport {
    pub port: u16,
    pub findings: Vec<Finding>,
}