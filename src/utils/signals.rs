use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tracing::info;

pub struct ShutdownSignal {
    flag: Arc<AtomicBool>,
}

impl ShutdownSignal {
    pub fn new() -> Self {
        let flag = Arc::new(AtomicBool::new(false));
        let flag_clone = flag.clone();

        ctrlc::set_handler(move || {
            info!("Received shutdown signal, terminating gracefully...");
            flag_clone.store(true, Ordering::SeqCst);
        })
        .expect("Error setting Ctrl-C handler");

        Self { flag }
    }

    pub fn is_shutdown_requested(&self) -> bool {
        self.flag.load(Ordering::SeqCst)
    }
}