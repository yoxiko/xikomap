use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum PortState {
    Open,
    Closed,
    Filtered,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PortResult {
    pub port: u16,
    pub is_udp: bool,
    pub state: PortState,
    pub banner: Option<String>,
    pub service: String,
    pub version: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HostResult {
    pub ip: String,
    pub ports: Vec<PortResult>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanSummary {
    pub hosts: Vec<HostResult>,
}

impl ScanSummary {
    pub fn new() -> Self {
        Self { hosts: Vec::new() }
    }

    pub fn add_result(&mut self, ip: String, port: u16, state: PortState, banner: Option<String>, service: String, version: String, is_udp: bool) {
        if let Some(host) = self.hosts.iter_mut().find(|h| h.ip == ip) {
            host.ports.push(PortResult { port, is_udp, state, banner, service, version });
        } else {
            self.hosts.push(HostResult {
                ip,
                ports: vec![PortResult { port, is_udp, state, banner, service, version }],
            });
        }
    }
}