use clap::Parser;
use serde::{Deserialize, Serialize};
use xikomap::core::config::ScanConfig;
use xikomap::python_bridge::run_python_detectors_batch;
use xikomap::scanner::{PortStrategy, ScanEngine};

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

    #[arg(short, long, default_value = "1000")]
    concurrency: usize,

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
        eprintln!("[*] Initializing scan engine...");
    }
    
    let target_list: Vec<String> = args.target.split(',').map(|s| s.trim().to_string()).collect();
    let exclude_list: Vec<String> = args.exclude.split(',').filter(|s| !s.is_empty()).map(|s| s.trim().to_string()).collect();
    let port_strategy = PortStrategy::from_str(&args.ports, args.custom_ports.as_deref());

    let config = ScanConfig {
        targets: target_list,
        exclude: exclude_list,
        timeout_ms: args.timeout,
        concurrency: args.concurrency,
        randomize: args.randomize,
        port_strategy,
    };

    let engine = ScanEngine::new(config);
    
    if !args.quiet {
        eprintln!("[*] Resolving targets and starting concurrent scan...");
    }

    let scan_results = match engine.run().await {
        Ok(results) => results,
        Err(e) => {
            eprintln!("Error: {}", e);
            std::process::exit(1);
        }
    };

    if scan_results.is_empty() {
        eprintln!("[!] No open ports found on {}", args.target);
        return;
    }

    if !args.quiet {
        eprintln!("[+] Found {} open port(s). Analyzing with Python detectors...", scan_results.len());
    }

    let json_payload = serde_json::to_string(&scan_results).expect("Failed to serialize ports");
    let detection_results = match run_python_detectors_batch(&json_payload) {
        Ok(results) => results,
        Err(e) => {
            if !args.quiet {
                eprintln!("[!] Python detection failed: {}", e);
                eprintln!("[*] Showing raw scan results instead:");
            }
            for res in scan_results {
                println!("{}:{} [tcp] {}", res.ip, res.port, res.banner);
            }
            return;
        }
    };
    
    let detections: Vec<DetectionResult> = match serde_json::from_value(detection_results) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("[!] Failed to parse detection results: {}", e);
            for res in scan_results {
                println!("{}:{} [tcp] {}", res.ip, res.port, res.banner);
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