use anyhow::{Context, Result};
use ipnetwork::IpNetwork;
use std::net::{IpAddr, ToSocketAddrs};

pub async fn resolve_targets(target_str: &str) -> Result<Vec<IpAddr>> {
    let mut resolved_ips = Vec::new();

    if let Ok(network) = target_str.parse::<IpNetwork>() {
        for ip in network.iter() {
            resolved_ips.push(ip);
        }
        return Ok(resolved_ips);
    }

    if let Ok(ip) = target_str.parse::<IpAddr>() {
        resolved_ips.push(ip);
        return Ok(resolved_ips);
    }

    let socket_addr_str = format!("{}:0", target_str);
    let addrs = socket_addr_str
        .to_socket_addrs()
        .with_context(|| format!("Failed to resolve hostname: {}", target_str))?;

    for addr in addrs {
        resolved_ips.push(addr.ip());
    }

    if resolved_ips.is_empty() {
        anyhow::bail!("No IP addresses found for target: {}", target_str);
    }

    Ok(resolved_ips)
}