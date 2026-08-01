use std::time::{Duration, Instant};
use tokio::time::sleep;

pub struct RateLimiter {
    max_rate: Option<usize>,
    min_rate: Option<usize>,
    last_packet: Instant,
}

impl RateLimiter {
    pub fn new(min_rate: Option<usize>, max_rate: Option<usize>) -> Self {
        Self {
            max_rate,
            min_rate,
            last_packet: Instant::now(),
        }
    }

    pub async fn wait(&mut self) {
        let now = Instant::now();
        let elapsed = now.duration_since(self.last_packet);

        if let Some(max) = self.max_rate {
            let min_interval = Duration::from_secs_f64(1.0 / (max as f64));
            if elapsed < min_interval {
                sleep(min_interval - elapsed).await;
            }
        }

        if let Some(min) = self.min_rate {
            let max_interval = Duration::from_secs_f64(1.0 / (min as f64));
            if elapsed > max_interval {
                sleep(max_interval - elapsed).await;
            }
        }
        
        self.last_packet = Instant::now();
    }
}