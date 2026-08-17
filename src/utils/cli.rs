use clap::Parser;

#[derive(Parser, Debug)]
#[command(
    name = "xikomap",
    author = "yoxiko",
    version = "0.4.0",
    about = "Advanced Recon & Fingerprinting Framework",
    long_about = None
)]
pub struct Cli {
    pub target: String,

    #[arg(short, long, value_delimiter = ',')]
    pub ports: Vec<u16>,

    #[arg(long, visible_alias = "all")]
    pub all: bool,

    #[arg(long, visible_alias = "stealth")]
    pub stealth: bool,

    #[arg(long, visible_alias = "verbose")]
    pub verbose: bool,

    #[arg(long, visible_alias = "pdf")]
    pub export_pdf: bool,

    #[arg(long, visible_alias = "json")]
    pub export_json: bool,

    #[arg(long, visible_alias = "screenshot")]
    pub screenshot: bool,
}