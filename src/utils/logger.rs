use super::log_collector::LogCollector;
use std::sync::OnceLock;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

static COLLECTOR: OnceLock<LogCollector> = OnceLock::new();

pub fn init_logger() {
    let collector = LogCollector::new();
    let _ = COLLECTOR.set(collector.clone());

    tracing_subscriber::registry()
        .with(EnvFilter::from_default_env().add_directive("xikomap=info".parse().unwrap()))
        .with(tracing_subscriber::fmt::layer())
        .with(collector)
        .init();
}

pub fn get_log_collector() -> Option<&'static LogCollector> {
    COLLECTOR.get()
}