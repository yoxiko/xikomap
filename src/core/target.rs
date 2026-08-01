use ipnetwork::IpNetwork;
use rand::seq::SliceRandom;
use rand::thread_rng;
use std::net::{IpAddr, ToSocketAddrs};
use std::str::FromStr;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum TargetError {
    #[error("Failed to resolve hostname: {0}")]
    ResolutionFailed(String),
    #[error("Invalid target format: {0}")]
    InvalidFormat(String),
}

pub struct TargetResolver {
    targets: Vec<IpAddr>,
    excluded: Vec<IpNetwork>,
}

impl TargetResolver {
    pub fn new(raw_targets: &[String], raw_exclusions: &[String]) -> Result<Self, TargetError> {
        let mut targets = Vec::new();
        let mut excluded = Vec::new();

        for exc in raw_exclusions {
            if let Ok(net) = IpNetwork::from_str(exc) {
                excluded.push(net);
            }
        }

        for target in raw_targets {
            let target = target.trim();
            if target.is_empty() {
                continue;
            }

            if target.contains('-') && !target.contains('/') {
                let parts: Vec<&str> = target.split('-').collect();
                if parts.len() == 2 {
                    if let Ok(start) = parts[0].parse::<IpAddr>() {
                        if let Ok(end) = parts[1].parse::<IpAddr>() {
                            targets.extend(generate_ip_range(start, end));
                        }
                    }
                }
            } else if let Ok(net) = IpNetwork::from_str(target) {
                targets.extend(net.iter());
            } else if let Ok(ip) = target.parse::<IpAddr>() {
                targets.push(ip);
            } else {
                let resolved = resolve_hostname(target);
                if resolved.is_empty() {
                    return Err(TargetError::ResolutionFailed(target.to_string()));
                }
                targets.extend(resolved);
            }
        }

        targets.retain(|ip| {
            !excluded.iter().any(|net| net.contains(*ip))
        });

        targets.sort();
        targets.dedup();

        Ok(Self { targets, excluded })
    }

    pub fn resolve(&self, randomize: bool) -> Vec<IpAddr> {
        let mut resolved = self.targets.clone();
        if randomize {
            resolved.shuffle(&mut thread_rng());
        }
        resolved
    }

    pub fn count(&self) -> usize {
        self.targets.len()
    }
}

fn resolve_hostname(hostname: &str) -> Vec<IpAddr> {
    let mut ips = Vec::new();
    if let Ok(addrs) = (hostname, 0).to_socket_addrs() {
        for addr in addrs {
            ips.push(addr.ip());
        }
    }
    ips.dedup();
    ips
}

fn generate_ip_range(start: IpAddr, end: IpAddr) -> Vec<IpAddr> {
    let mut ips = Vec::new();
    let start_u32 = match start {
        IpAddr::V4(ip) => u32::from(ip),
        IpAddr::V6(_) => return ips,
    };
    let end_u32 = match end {
        IpAddr::V4(ip) => u32::from(ip),
        IpAddr::V6(_) => return ips,
    };

    if start_u32 <= end_u32 {
        for i in start_u32..=end_u32 {
            ips.push(IpAddr::V4(i.into()));
        }
    }
    ips
}