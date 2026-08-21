use clap::Parser;

#[derive(Parser, Debug, Clone)]
#[command(name = "xikomap", version = "0.4.0", about = "Network Reconnaissance Tool")]
pub struct Cli {
    #[arg(help = "Target domain or IP address")]
    pub target: String,

    #[arg(short = 'a', long = "all", help = "Scan all 65535 ports")]
    pub all: bool,

    #[arg(short = 'p', long = "ports", value_delimiter = ',', help = "Custom ports to scan (comma-separated)")]
    pub ports: Vec<u16>,

    #[arg(short = 's', long = "stealth", help = "Use SYN stealth scan")]
    pub stealth: bool,

    #[arg(short = 'v', long = "verbose", help = "Enable verbose output")]
    pub verbose: bool,

    #[arg(short = 'S', long = "screenshot", help = "Capture screenshots of web services")]
    pub screenshot: bool,

    #[arg(short = 'j', long = "export-json", help = "Export results to JSON and GraphML")]
    pub export_json: bool,

    #[arg(short = 'P', long = "export-pdf", help = "Generate PDF report")]
    pub export_pdf: bool,
}