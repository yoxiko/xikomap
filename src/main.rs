use clap::Parser;
use std::path::PathBuf;
use std::time::Instant;
use tracing::{error, info, warn};
use xikomap::core::config::ScanConfig;
use xikomap::python_bridge::run_python_detectors_batch;
use xikomap::reporter::{JsonReporter, MarkdownReporter, ScanReport};
use xikomap::scanner::{PortStrategy, ScanEngine};
use xikomap::utils::logger::init_logger;
use xikomap::utils::signals::ShutdownHandler;

#[derive(Parser, Debug)]
#[command(name = "xikomap")]
#[command(about = "Professional hybrid network scanner")]
#[command(version = "2.3.0")]
struct Args {
    #[arg(index = 1)]
    target: String,

    #[arg(short, long, default_value = "")]
    exclude: String,

    #[arg(long, default_value = "500")]
    timeout: u64,

    #[arg(long, default_value = "3")]
    retries: u8,

    #[arg(short, long, default_value = "1000")]
    concurrency: usize,

    #[arg(long)]
    randomize: bool,

    #[arg(short, long, default_value = "top100")]
    ports: String,

    #[arg(long)]
    custom_ports: Option<String>,

    #[arg(short, long)]
    verbose: bool,

    #[arg(long)]
    json_logs: bool,

    #[arg(long, default_value = "")]
    output: String,

    #[arg(short = 'x', long)]
    extended: bool,

    #[arg(long)]
    rate_limit: Option<usize>,
}

#[tokio::main]
async fn main() {
    let args = Args::parse();
    init_logger(args.verbose, args.json_logs);

    info!("Starting Xikomap v{}", env!("CARGO_PKG_VERSION"));

    let shutdown_handler = ShutdownHandler::new();
    let shutdown_arc = std::sync::Arc::new(shutdown_handler);

    let target_list: Vec<String> = args.target.split(',').map(|s| s.trim().to_string()).collect();
    let exclude_list: Vec<String> = args.exclude.split(',').filter(|s| !s.is_empty()).map(|s| s.trim().to_string()).collect();
    let port_strategy = PortStrategy::from_str(&args.ports, args.custom_ports.as_deref());

    let config = ScanConfig::builder()
        .targets(target_list)
        .exclude(exclude_list)
        .timeout_ms(args.timeout)
        .retries(args.retries)
        .concurrency(args.concurrency)
        .randomize(args.randomize)
        .port_strategy(port_strategy)
        .rate_limit(args.rate_limit)
        .build();

    let engine = ScanEngine::new(config, shutdown_arc.clone());

    let start_time = Instant::now();
    let ports_to_scan = args.ports.clone();
    let target_name = args.target.clone();

    let scan_results = match engine.run().await {
        Ok(results) => results,
        Err(e) => {
            error!("Scan failed: {}", e);
            std::process::exit(1);
        }
    };

    let duration = start_time.elapsed().as_secs_f64();

    if scan_results.is_empty() {
        info!("No open ports found on {}", args.target);
        return;
    }

    info!("Found {} open port(s) in {:.2}s", scan_results.len(), duration);

    let total_ports = match ports_to_scan.as_str() {
        "top10" => 10,
        "top100" => 100,
        "top1000" => 1000,
        "web" => 10,
        "database" => 10,
        _ => scan_results.len(),
    };

    let report = ScanReport::new(
        target_name.clone(),
        scan_results.clone(),
        total_ports,
        duration,
        args.concurrency,
        args.timeout,
        args.retries,
    );

    let json_payload = serde_json::to_string(&scan_results).expect("Failed to serialize");
    let detection_results = match run_python_detectors_batch(&json_payload) {
        Ok(results) => results,
        Err(e) => {
            warn!("Python detection failed: {}", e);
            return;
        }
    };

    if args.extended {
        println!("\n============================================================");
        println!(" EXTENDED SCAN RESULTS");
        println!("============================================================");
        
        if let Some(ports) = detection_results.get("ports") {
            if let Some(ports_array) = ports.as_array() {
                for port_info in ports_array {
                    let ip = port_info["ip"].as_str().unwrap_or("N/A");
                    let port = port_info["port"].as_u64().unwrap_or(0);
                    let proto = port_info["protocol"].as_str().unwrap_or("tcp");
                    let service = port_info["service"].as_str().unwrap_or("Unknown");
                    let risk = port_info["risk_level"].as_str().unwrap_or("low");
                    
                    println!("\n[{}] {}:{} ({})", risk.to_uppercase(), ip, port, service.to_uppercase());
                    println!("  Protocol : {}", proto);
                    
                    if let Some(techs) = port_info.get("technologies") {
                        if let Some(tech_array) = techs.as_array() {
                            if !tech_array.is_empty() {
                                let tech_str: Vec<String> = tech_array.iter().filter_map(|t| t.as_str().map(String::from)).collect();
                                println!("  Tech     : {}", tech_str.join(", "));
                            }
                        }
                    }
                    
                    if let Some(orig) = scan_results.iter().find(|r| r.ip == ip && r.port as u64 == port) {
                        println!("  Banner   : {}", orig.banner);
                    }
                }
            }
        }
        
        if let Some(misconfigs) = detection_results.get("misconfigurations") {
            if let Some(mc_array) = misconfigs.as_array() {
                if !mc_array.is_empty() {
                    println!("\n------------------------------------------------------------");
                    println!(" MISCONFIGURATIONS DETECTED");
                    println!("------------------------------------------------------------");
                    for mc in mc_array {
                        let severity = mc["severity"].as_str().unwrap_or("unknown");
                        let desc = mc["description"].as_str().unwrap_or("N/A");
                        let rec = mc["recommendation"].as_str().unwrap_or("N/A");
                        println!("  [{}] {}", severity.to_uppercase(), desc);
                        println!("    -> Recommendation: {}", rec);
                    }
                }
            }
        }
        
        if let Some(ssl) = detection_results.get("ssl_analysis") {
            if ssl.get("has_ssl").and_then(|v| v.as_bool()).unwrap_or(false) {
                println!("\n------------------------------------------------------------");
                println!(" SSL/TLS ANALYSIS");
                println!("------------------------------------------------------------");
                let risk = ssl["risk_level"].as_str().unwrap_or("unknown");
                println!("  Risk Level : {}", risk.to_uppercase());
                if let Some(prots) = ssl.get("protocols_supported").and_then(|v| v.as_array()) {
                    let p: Vec<String> = prots.iter().filter_map(|v| v.as_str().map(String::from)).collect();
                    println!("  Protocols  : {}", p.join(", "));
                }
                if let Some(recs) = ssl.get("recommendations").and_then(|v| v.as_array()) {
                    println!("  Recommendations:");
                    for rec in recs {
                        if let Some(r) = rec.as_str() {
                            println!("    - {}", r);
                        }
                    }
                }
            }
        }
        println!("============================================================\n");
    } else {
        println!("\n=== SCAN RESULTS ===");
        for res in &scan_results {
            println!("{}:{} [{}] {}", res.ip, res.port, res.protocol, res.banner);
        }
    }

    if !args.output.is_empty() {
        let output_path = PathBuf::from(&args.output);
        
        if args.output.ends_with(".json") {
            if let Err(e) = JsonReporter::generate(&report, &output_path) {
                warn!("Failed to generate JSON report: {}", e);
            }
        } else if args.output.ends_with(".md") {
            if let Err(e) = MarkdownReporter::generate(&report, &output_path) {
                warn!("Failed to generate Markdown report: {}", e);
            }
        } else {
            warn!("Unsupported output format. Use .md or .json");
        }
    }

    println!("Total: {} open ports | Duration: {:.2}s", scan_results.len(), duration);
}