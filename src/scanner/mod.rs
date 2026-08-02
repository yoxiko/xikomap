pub mod engine;
pub mod worker;

pub use engine::ScannerEngine;
pub use worker::ScanResult;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub enum PortStrategy {
    #[default]
    Top100,
    Top1000,
    Custom(Vec<u16>),
}