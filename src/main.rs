use clap::Parser;
use std::path::PathBuf;
use std::time::Instant;
use tracing::{error, info, warn};
use xikomap::core::config::ScanConfig;
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
        target_name,
        scan_results.clone(),
        total_ports,
        duration,
        args.concurrency,
        args.timeout,
        args.retries,
    );

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

    println!("\n=== SCAN RESULTS ===");
    for res in &scan_results {
        println!("{}:{} [{}] {}", res.ip, res.port, res.protocol, res.banner);
    }
    println!("\nTotal: {} open ports | Duration: {:.2}s", scan_results.len(), duration);
}