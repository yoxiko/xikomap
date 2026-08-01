use tracing_subscriber::{fmt, EnvFilter};

pub fn init_logger(verbose: bool, json_output: bool) {
    let env_filter = if verbose {
        EnvFilter::new("xikomap=debug,tokio=info")
    } else {
        EnvFilter::new("xikomap=info")
    };

    if json_output {
        fmt()
            .with_env_filter(env_filter)
            .with_target(false)
            .with_thread_ids(false)
            .with_thread_names(false)
            .json()
            .init();
    } else {
        fmt()
            .with_env_filter(env_filter)
            .with_target(false)
            .with_thread_ids(false)
            .with_thread_names(false)
            .init();
    }
}