pub struct SynScanner {
    timeout_ms: u64,
}

impl SynScanner {
    pub fn new() -> Self {
        SynScanner { timeout_ms: 1000 }
    }

    pub async fn run(&self, target: &str, ports: Vec<u16>) -> Result<Vec<u16>, String> {
        #[cfg(not(target_os = "windows"))]
        {
            use pnet::datalink;
            use pnet::transport::{transport_channel, TransportChannelType};

            let interfaces = datalink::interfaces();
            let _interface = interfaces
                .into_iter()
                .find(|iface| !iface.ips.is_empty())
                .ok_or("No suitable interface found")?;

            let channel_type = TransportChannelType::Layer4(pnet::transport::Layer4Channel {
                protocol: pnet::transport::Layer4Protocol::Tcp,
            });

            let (mut _tx, _rx) = transport_channel(4096, channel_type)
                .map_err(|e| format!("Failed to create channel: {}", e))?;

            let mut open_ports = Vec::new();
            for port in ports {
                if self.send_syn(target, port).await? {
                    open_ports.push(port);
                }
            }
            Ok(open_ports)
        }

        #[cfg(target_os = "windows")]
        {
            let _ = target;
            let _ = ports;
            Err("SYN scan not yet implemented on Windows".to_string())
        }
    }

    #[cfg(not(target_os = "windows"))]
    async fn send_syn(&self, target: &str, port: u16) -> Result<bool, String> {
        use std::net::{SocketAddr, TcpStream};
        use std::net::ToSocketAddrs;
        use tokio::time::{timeout, Duration};

        let addr: SocketAddr = format!("{}:{}", target, port)
            .to_socket_addrs()
            .map_err(|e| e.to_string())?
            .next()
            .ok_or("Could not resolve address")?;

        match timeout(
            Duration::from_millis(self.timeout_ms),
            TcpStream::connect(addr),
        )
        .await
        {
            Ok(Ok(_)) => Ok(true),
            _ => Ok(false),
        }
    }
}