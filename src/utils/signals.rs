use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tracing::info;

pub struct ShutdownHandler {
    pub shutdown_flag: Arc<AtomicBool>,
}

impl ShutdownHandler {
    pub fn new() -> Self {
        let flag = Arc::new(AtomicBool::new(false));
        let flag_clone = Arc::clone(&flag);

        ctrlc::set_handler(move || {
            info!("Received SIGINT. Gracefully shutting down...");
            flag_clone.store(true, Ordering::SeqCst);
        })
        .expect("Error setting Ctrl-C handler");

        Self { shutdown_flag: flag }
    }

    pub fn is_shutdown_requested(&self) -> bool {
        self.shutdown_flag.load(Ordering::SeqCst)
    }
}

impl Default for ShutdownHandler {
    fn default() -> Self {
        Self::new()
    }
}