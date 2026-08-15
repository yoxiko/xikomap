use clap::Parser;

#[derive(Parser, Debug, Clone)]
#[command(author, version, about = "Advanced network reconnaissance tool", long_about = None)]
pub struct Cli {
    #[arg(short, long)]
    pub target: String,

    #[arg(short, long, value_delimiter = ',')]
    pub ports: Vec<u16>,

    #[arg(long)]
    pub all: bool,

    #[arg(long)]
    pub stealth: bool,

    #[arg(short, long)]
    pub verbose: bool,

    #[arg(long)]
    pub export_json: bool,

    #[arg(long)]
    pub export_pdf: bool,

    #[arg(long)]
    pub screenshot: bool,
}