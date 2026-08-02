use std::time::Duration;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum ProbeError {
    #[error("Connection timeout")]
    Timeout,
    #[error("Connection refused")]
    Refused,
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
}

pub async fn probe_tcp(host: &str, port: u16) -> Result<bool, ProbeError> {
    let addr = format!("{}:{}", host, port);
    let timeout = Duration::from_secs(3);
    
    match tokio::time::timeout(timeout, tokio::net::TcpStream::connect(&addr)).await {
        Ok(Ok(_)) => Ok(true),
        Ok(Err(_)) => Ok(false),
        Err(_) => Err(ProbeError::Timeout),
    }
}