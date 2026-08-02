use crate::core::target::{TargetError, TargetGenerator};
use crate::prober::tcp::ProbeError;
use crate::scanner::worker::{ScanResult, Worker};
use futures::stream::{self, StreamExt};
use std::time::Instant;
use thiserror::Error;
use tracing::info;

#[derive(Error, Debug)]
pub enum ScanError {
    #[error("Target error: {0}")]
    Target(#[from] TargetError),
    #[error("Probe error: {0}")]
    Probe(#[from] ProbeError),
}

pub struct ScannerEngine {
    concurrency: usize,
}

impl ScannerEngine {
    pub fn new(concurrency: usize) -> Self {
        Self { concurrency }
    }

    pub async fn run(&self, target_input: &str, ports: Vec<u16>) -> Result<Vec<u16>, ScanError> {
        let start_time = Instant::now();

        let generator = TargetGenerator::new(target_input)?;
        let targets: Vec<_> = generator.into_iter().map(|ip| ip.to_string()).collect();

        let mut open_ports = Vec::new();

        for target in targets {
            let results: Vec<ScanResult> = stream::iter(ports.clone())
                .map(|port| {
                    let target_clone = target.clone();
                    async move {
                        let worker = Worker::new(1);
                        match worker.process_task(&target_clone, port).await {
                            Ok(result) => Some(result),
                            Err(_) => None,
                        }
                    }
                })
                .buffer_unordered(self.concurrency)
                .filter_map(|x| async move { x })
                .collect()
                .await;

            for res in results {
                if res.is_open {
                    open_ports.push(res.port);
                }
            }
        }

        let duration = start_time.elapsed().as_secs_f64();
        info!("TCP scan completed in {:.2} seconds.", duration);

        Ok(open_ports)
    }
}