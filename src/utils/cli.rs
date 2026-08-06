use clap::Parser;

#[derive(Parser, Debug)]
#[command(name = "xikomap")]
#[command(about = "Advanced network reconnaissance tool", long_about = None)]
pub struct Cli {
    #[arg(help = "Target host (IP or domain)")]
    pub target: String,

    #[arg(short = 'p', long, value_delimiter = ',', help = "Comma-separated list of ports")]
    pub ports: Vec<u16>,

    #[arg(long, help = "Scan all 65535 ports")]
    pub all: bool,

    #[arg(short = 's', long = "stealth", help = "Use SYN stealth scan")]
    pub stealth: bool,

    #[arg(short = 'v', long, help = "Verbose output")]
    pub verbose: bool,

    #[arg(short = 'x', long = "export-json", help = "Export results to JSON")]
    pub export_json: bool,

    #[arg(short = 'P', long = "export-pdf", help = "Export results to PDF")]
    pub export_pdf: bool,
}