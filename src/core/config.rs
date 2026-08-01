use crate::scanner::PortStrategy;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanConfig {
    pub targets: Vec<String>,
    pub exclude: Vec<String>,
    pub timeout_ms: u64,
    pub retries: u8,
    pub concurrency: usize,
    pub randomize: bool,
    pub port_strategy: PortStrategy,
    pub rate_limit: Option<usize>,
}

impl ScanConfig {
    pub fn builder() -> ScanConfigBuilder {
        ScanConfigBuilder::default()
    }
}

#[derive(Default)]
pub struct ScanConfigBuilder {
    targets: Vec<String>,
    exclude: Vec<String>,
    timeout_ms: u64,
    retries: u8,
    concurrency: usize,
    randomize: bool,
    port_strategy: PortStrategy,
    rate_limit: Option<usize>,
}

impl ScanConfigBuilder {
    pub fn targets(mut self, targets: Vec<String>) -> Self {
        self.targets = targets;
        self
    }

    pub fn exclude(mut self, exclude: Vec<String>) -> Self {
        self.exclude = exclude;
        self
    }

    pub fn timeout_ms(mut self, timeout_ms: u64) -> Self {
        self.timeout_ms = timeout_ms;
        self
    }

    pub fn retries(mut self, retries: u8) -> Self {
        self.retries = retries;
        self
    }

    pub fn concurrency(mut self, concurrency: usize) -> Self {
        self.concurrency = concurrency;
        self
    }

    pub fn randomize(mut self, randomize: bool) -> Self {
        self.randomize = randomize;
        self
    }

    pub fn port_strategy(mut self, strategy: PortStrategy) -> Self {
        self.port_strategy = strategy;
        self
    }

    pub fn rate_limit(mut self, limit: Option<usize>) -> Self {
        self.rate_limit = limit;
        self
    }

    pub fn build(self) -> ScanConfig {
        ScanConfig {
            targets: self.targets,
            exclude: self.exclude,
            timeout_ms: self.timeout_ms,
            retries: self.retries,
            concurrency: self.concurrency,
            randomize: self.randomize,
            port_strategy: self.port_strategy,
            rate_limit: self.rate_limit,
        }
    }
}