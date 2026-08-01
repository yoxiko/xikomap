use clap::Parser;
use serde::{Deserialize, Serialize};
use std::time::Duration;
use tokio::time::timeout;
use xikomap::core::target::TargetResolver;
use xikomap::python_bridge::run_python_detectors_batch;
use xikomap::scanner::RateLimiter;
use xikomap::detectors::http_probe::probe_http;

#[derive(Parser, Debug)]
#[command(name = "xikomap")]
#[command(about = "High-performance hybrid network scanner")]
struct Args {
    #[arg(index = 1)]
    target: String,

    #[arg(short, long, default_value = "")]
    exclude: String,

    #[arg(long, default_value = "500")]
    timeout: u64,

    #[arg(long)]
    min_rate: Option<usize>,

    #[arg(long)]
    max_rate: Option<usize>,

    #[arg(long)]
    randomize: bool,

    #[arg(short, long, default_value = "text")]
    format: String,

    #[arg(short, long, default_value = "top100")]
    ports: String,

    #[arg(long)]
    custom_ports: Option<String>,

    #[arg(short, long)]
    quiet: bool,
}

#[derive(Serialize, Deserialize, Debug)]
struct PortInfo {
    ip: String,
    port: u16,
    protocol: String,
    banner: String,
    http_body: String,
    http_headers: String,
}

#[derive(Serialize, Deserialize, Debug)]
struct DetectionResult {
    ip: String,
    port: u16,
    protocol: String,
    service: String,
    cms: Option<String>,
}

#[tokio::main]
async fn main() {
    let args = Args::parse();
    
    if !args.quiet {
        eprintln!("[*] Resolving target: {}", args.target);
    }
    
    let target_list: Vec<String> = args.target.split(',').map(|s| s.trim().to_string()).collect();
    let exclude_list: Vec<String> = args.exclude.split(',').filter(|s| !s.is_empty()).map(|s| s.trim().to_string()).collect();

    let resolver = match TargetResolver::new(&target_list, &exclude_list) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("Error: {}", e);
            std::process::exit(1);
        }
    };
    
    let targets = resolver.resolve(args.randomize);
    
    if targets.is_empty() {
        eprintln!("Error: No valid targets found.");
        std::process::exit(1);
    }

    if !args.quiet {
        eprintln!("[+] Resolved {} IP address(es)", targets.len());
    }

    let mut rate_limiter = RateLimiter::new(args.min_rate, args.max_rate);
    let mut open_ports: Vec<PortInfo> = Vec::new();

    let port_strategy = xikomap::scanner::PortStrategy::from_str(&args.ports, args.custom_ports.as_deref());
    let ports_to_scan = port_strategy.get_ports();
    
    if !args.quiet {
        eprintln!("[*] Scanning {} port(s) per target (timeout: {}ms)", ports_to_scan.len(), args.timeout);
    }

    for target in targets {
        let ip_str = target.to_string();
        
        if !args.quiet {
            eprintln!("[*] Scanning {}", ip_str);
        }
        
        for (idx, port) in ports_to_scan.iter().enumerate() {
            if !args.quiet && idx > 0 && idx % 20 == 0 {
                eprint!(".");
            }
            
            rate_limiter.wait().await;
            let ip_clone = ip_str.clone();
            let port_clone = *port;
            
            let connect_result = timeout(
                Duration::from_millis(args.timeout),
                tokio::net::TcpStream::connect(format!("{}:{}", ip_clone, port_clone))
            ).await;
            
            if let Ok(Ok(_stream)) = connect_result {
                if !args.quiet {
                    eprint!("+");
                }
                
                let mut banner = "Open".to_string();
                let mut http_body = String::new();
                let mut http_headers = String::new();

                if port_clone == 80 || port_clone == 443 || port_clone == 8080 || port_clone == 8443 {
                    if let Some(probe) = probe_http(&ip_clone, port_clone).await {
                        http_body = probe.body_snippet;
                        http_headers = probe.headers;
                        banner = format!("HTTP {}", probe.status_code);
                    }
                }

                open_ports.push(PortInfo {
                    ip: ip_clone,
                    port: port_clone,
                    protocol: "tcp".to_string(),
                    banner,
                    http_body,
                    http_headers,
                });
            }
        }
        if !args.quiet {
            eprintln!();
        }
    }

    if open_ports.is_empty() {
        eprintln!("[!] No open ports found on {}", args.target);
        return;
    }

    if !args.quiet {
        eprintln!("[*] Found {} open port(s), analyzing with Python detectors...", open_ports.len());
    }

    let json_payload = serde_json::to_string(&open_ports).expect("Failed to serialize ports");
    let detection_results = match run_python_detectors_batch(&json_payload) {
        Ok(results) => results,
        Err(e) => {
            if !args.quiet {
                eprintln!("[!] Python detection failed (ensure py_detectors/ is in current directory): {}", e);
                eprintln!("[*] Showing raw scan results instead:");
            }
            for port in open_ports {
                println!("{}:{} [tcp] {}", port.ip, port.port, port.banner);
            }
            return;
        }
    };
    
    let detections: Vec<DetectionResult> = match serde_json::from_value(detection_results) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("[!] Failed to parse detection results: {}", e);
            for port in open_ports {
                println!("{}:{} [tcp] {}", port.ip, port.port, port.banner);
            }
            return;
        }
    };

    match args.format.as_str() {
        "json" => {
            println!("{}", serde_json::to_string_pretty(&detections).unwrap());
        }
        "csv" => {
            println!("ip,port,protocol,service,cms");
            for d in detections {
                let cms = d.cms.unwrap_or_else(|| "None".to_string());
                println!("{},{},{},{},{}", d.ip, d.port, d.protocol, d.service, cms);
            }
        }
        "xml" => {
            println!("<?xml version=\"1.0\" encoding=\"UTF-8\"?>");
            println!("<scan_results>");
            for d in detections {
                let cms = d.cms.unwrap_or_else(|| "None".to_string());
                println!("  <host ip=\"{}\" port=\"{}\" protocol=\"{}\" service=\"{}\" cms=\"{}\" />", 
                    d.ip, d.port, d.protocol, d.service, cms);
            }
            println!("</scan_results>");
        }
        _ => {
            for d in detections {
                let cms = d.cms.map(|c| format!(" (CMS: {})", c)).unwrap_or_default();
                println!("{}:{} [{}] {}{}", d.ip, d.port, d.protocol, d.service, cms);
            }
        }
    }
}