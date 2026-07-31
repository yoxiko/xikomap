use crate::core::results::PortState;

pub mod ping;
pub mod tcp_connect;
pub mod udp_scan;

#[derive(Debug, Clone)]
pub struct ScanResult {
    pub port: u16,
    pub state: PortState,
}