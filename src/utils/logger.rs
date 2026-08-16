use super::log_collector::LogCollector;
use std::sync::OnceLock;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

static COLLECTOR: OnceLock<LogCollector> = OnceLock::new();

pub fn init_logger() {
    let collector = LogCollector::new();
    let _ = COLLECTOR.set(collector.clone());

    let filter = EnvFilter::from_default_env()
        .add_directive("xikomap=info".parse().unwrap())
        .add_directive("chromiumoxide=error".parse().unwrap())  // Скрываем ошибки chromium
        .add_directive("tungstenite=error".parse().unwrap())    // Скрываем ошибки WebSocket
        .add_directive("reqwest=warn".parse().unwrap());

    tracing_subscriber::registry()
        .with(filter)
        .with(tracing_subscriber::fmt::layer().with_target(false))
        .with(collector)
        .init();
}

pub fn get_log_collector() -> Option<&'static LogCollector> {
    COLLECTOR.get()
}