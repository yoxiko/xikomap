use clap::Parser;
use std::time::Instant;

mod core;
mod scanner;
mod detectors;
mod python_bridge;

use crate::core::target::resolve_targets;
use crate::core::results::{ScanSummary, PortState};
use crate::scanner::ping::ping_host;
use crate::scanner::tcp_connect::scan_tcp_connect;
use crate::scanner::udp_scan::scan_udp;
use crate::detectors::banner::grab_banner;
use crate::detectors::service::parse_service_version;
use crate::python_bridge::run_python_detectors;

#[derive(Parser, Debug)]
#[command(name = "xikomap")]
#[command(about = "Professional network scanner")]
struct Args {
    target: String,
    #[arg(short = 'p', long)]
    ports: Option<String>,
    #[arg(short = 'F', long, default_value_t = false)]
    fast: bool,
    #[arg(long, default_value_t = false)]
    all_ports: bool,
    #[arg(short = 'T', long, default_value_t = 1000)]
    threads: usize,
    #[arg(long, default_value_t = 1000)]
    timeout: u64,
    #[arg(short = 'o', long = "full", default_value_t = false)]
    full_output: bool,
    #[arg(short = 'P', long, default_value_t = false)]
    skip_ping: bool,
    #[arg(short = 's', long, default_value = "T")]
    scan_type: String,
}

fn get_ports(args: &Args) -> Vec<u16> {
    if args.all_ports {
        return (1..=65535).collect();
    }
    
    if args.fast {
        return vec![
            21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995, 1723, 3306, 3389, 5900, 8080
        ];
    }

    if let Some(ports_str) = &args.ports {
        let mut ports = Vec::new();
        for part in ports_str.split(',') {
            if part.contains('-') {
                let range: Vec<&str> = part.split('-').collect();
                let start: u16 = range[0].parse().unwrap();
                let end: u16 = range[1].parse().unwrap();
                ports.extend(start..=end);
            } else {
                ports.push(part.parse().unwrap());
            }
        }
        return ports;
    }

    vec![80, 443, 8080]
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    println!("Starting xikomap 2.1.0 ( https://github.com/yoxiko/xikomap )");
    
    let targets = resolve_targets(&args.target).await?;
    let ports = get_ports(&args);
    
    let start_time = Instant::now();
    let mut summary = ScanSummary::new();
    let target_count = targets.len();
    let is_udp = args.scan_type.to_uppercase() == "U";

    for target_ip in &targets {
        let target_str = target_ip.to_string();
        println!("Scanning target: {}", target_str);

        let (is_up, latency_ms) = if args.skip_ping {
            (true, 0.0)
        } else {
            ping_host(&target_str, args.timeout).await
        };

        if !is_up {
            println!("Host seems down. If it is really up, but blocking our ping probes, try -P");
            continue;
        }

        println!("Host is up ({:.3}s latency).", latency_ms / 1000.0);

        let port_results = if is_udp {
            scan_udp(&target_str, ports.clone(), args.timeout, args.threads).await?
        } else {
            scan_tcp_connect(&target_str, ports.clone(), args.timeout, args.threads).await?
        };

        for port_res in port_results {
            if port_res.state == PortState::Open && !is_udp {
                let banner = grab_banner(&target_str, port_res.port, args.timeout).await;
                let banner_str = banner.as_deref().unwrap_or("");
                let version = parse_service_version(banner_str, port_res.port);
                let service = run_python_detectors(&target_str, port_res.port, banner.as_deref());
                
                summary.add_result(
                    target_str.clone(), 
                    port_res.port, 
                    port_res.state, 
                    banner, 
                    service, 
                    version, 
                    is_udp
                );
            } else {
                summary.add_result(
                    target_str.clone(), 
                    port_res.port, 
                    port_res.state, 
                    None, 
                    "unknown".to_string(), 
                    "unknown".to_string(), 
                    is_udp
                );
            }
        }
    }

    let duration = start_time.elapsed();
    println!("\nNmap done: {} IP address ({} host up) scanned in {:.2} seconds", 
        target_count, 
        summary.hosts.len(), 
        duration.as_secs_f32()
    );

    if args.full_output {
        println!("{}", serde_json::to_string_pretty(&summary)?);
    } else {
        for host in &summary.hosts {
            println!("\nNmap scan report for {}", host.ip);
            println!("{:<8} {:<10} {:<15} {}", "PORT", "STATE", "SERVICE", "VERSION");
            println!("{}", "-".repeat(55));
            
            let mut filtered_count = 0;
            for port_res in &host.ports {
                if port_res.state == PortState::Filtered {
                    filtered_count += 1;
                    continue;
                }
                
                let proto = if port_res.is_udp { "udp" } else { "tcp" };
                let state_str = format!("{:?}", port_res.state).to_lowercase();
                println!("{:<8} {:<10} {:<15} {}", 
                    format!("{}/{}", port_res.port, proto), 
                    state_str, 
                    port_res.service, 
                    port_res.version
                );
            }
            
            if filtered_count > 0 {
                println!("Not shown: {} filtered ports (no-response)", filtered_count);
            }
        }
    }

    Ok(())
}