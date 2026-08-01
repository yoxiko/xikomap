use clap::Parser;
use serde::{Deserialize, Serialize};
use xikomap::core::target::TargetResolver;
use xikomap::python_bridge::run_python_detectors_batch;
use xikomap::scanner::RateLimiter;
use xikomap::detectors::http_probe::probe_http;

#[derive(Parser, Debug)]
#[command(name = "xikomap")]
#[command(about = "High-performance hybrid network scanner")]
struct Args {
    #[arg(short, long)]
    targets: String,

    #[arg(short, long, default_value = "")]
    exclude: String,

    #[arg(long)]
    min_rate: Option<usize>,

    #[arg(long)]
    max_rate: Option<usize>,

    #[arg(long)]
    randomize: bool,

    #[arg(short, long, default_value = "text")]
    format: String,
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
    let target_list: Vec<String> = args.targets.split(',').map(|s| s.trim().to_string()).collect();
    let exclude_list: Vec<String> = args.exclude.split(',').filter(|s| !s.is_empty()).map(|s| s.trim().to_string()).collect();

    let resolver = TargetResolver::new(&target_list, &exclude_list).expect("Failed to resolve targets");
    let targets = resolver.resolve(args.randomize);

    let mut rate_limiter = RateLimiter::new(args.min_rate, args.max_rate);
    let mut open_ports: Vec<PortInfo> = Vec::new();

    let ports_to_scan = vec![21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 995, 3306, 5432, 8080, 8443];

    for target in targets {
        let ip_str = target.to_string();
        for port in &ports_to_scan {
            rate_limiter.wait().await;
            let ip_clone = ip_str.clone();
            let port_clone = *port;
            
            let result = tokio::net::TcpStream::connect(format!("{}:{}", ip_clone, port_clone)).await;
            if result.is_ok() {
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
    }

    if !open_ports.is_empty() {
        let json_payload = serde_json::to_string(&open_ports).expect("Failed to serialize ports");
        let detection_results = run_python_detectors_batch(&json_payload).expect("Python batch processing failed");
        
        let detections: Vec<DetectionResult> = serde_json::from_value(detection_results).expect("Failed to parse detection results");

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
}