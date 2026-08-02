use ipnetwork::IpNetwork;
use rand::seq::SliceRandom;
use rand::thread_rng;
use std::net::IpAddr;
use std::str::FromStr;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum TargetError {
    #[error("Invalid IP or CIDR: {0}")]
    InvalidIp(String),
    #[error("DNS resolution failed: {0}")]
    DnsResolutionFailed(String),
}

pub struct TargetGenerator {
    targets: Vec<IpAddr>,
}

impl TargetGenerator {
    pub fn new(input: &str) -> Result<Self, TargetError> {
        let mut targets = Vec::new();

        if let Ok(network) = IpNetwork::from_str(input) {
            for ip in network.iter() {
                targets.push(ip);
            }
        } else if let Ok(ip) = input.parse::<IpAddr>() {
            targets.push(ip);
        } else {
            return Err(TargetError::InvalidIp(input.to_string()));
        }

        targets.shuffle(&mut thread_rng());

        Ok(Self { targets })
    }

    pub fn into_iter(self) -> std::vec::IntoIter<IpAddr> {
        self.targets.into_iter()
    }
}