use crate::prober::{
    dns_enumerator::DnsEnumerator, grpc_prober, http2_fingerprint::HTTP2Fingerprint,
    quic_prober, tls_fingerprint::TLSFingerprint, websocket_prober,
};
use crate::python_bridge::detector::PythonDetectorBridge;
use crate::utils::cli::Cli;
use crate::{ServiceInfo, TechInfo};
use futures::stream::{self, StreamExt};
use std::net::IpAddr;
use tracing::debug;

pub struct Fingerprinter {
    concurrency: usize,
    verbose: bool,
    target_ip: IpAddr,
}

impl Fingerprinter {
    pub fn new(cli: &Cli, target_ip: IpAddr) -> Self {
        Self {
            concurrency: if cli.all { 100 } else { 50 },
            verbose: cli.verbose,
            target_ip,
        }
    }

    pub async fn analyze(&self, target: &str, ports: &[u16]) -> Vec<ServiceInfo> {
        let py_bridge = PythonDetectorBridge::new().ok();
        let quic_endpoint = quic_prober::create_quic_endpoint();

        stream::iter(ports.iter().copied())
            .map(|port| {
                self.probe_single_port(target, port, py_bridge.as_ref(), quic_endpoint.as_ref())
            })
            .buffer_unordered(self.concurrency)
            .collect()
            .await
    }

    async fn probe_single_port(
        &self,
        target: &str,
        port: u16,
        py_bridge: Option<&PythonDetectorBridge>,
        quic_endpoint: Option<&quinn::Endpoint>,
    ) -> ServiceInfo {
        let mut service = ServiceInfo {
            port,
            protocol: None,
            technologies: Vec::new(),
        };

        let (ws, grpc, tls, http2, quic, py_finger) = tokio::join!(
            self.try_websocket(target, port),
            self.try_grpc(target, port),
            self.try_tls(target, port),
            self.try_http2(target, port),
            self.try_quic(target, port, quic_endpoint),
            self.try_python_finger(target, port, py_bridge),
        );

        if let Some(ws) = ws {
            service.protocol = Some("websocket".into());
            service.technologies.push(ws);
        }
        if let Some(grpc) = grpc {
            service.protocol = Some("grpc".into());
            service.technologies.push(grpc);
        }
        if let Some(tls) = tls {
            service.technologies.push(tls);
        }
        if let Some(h2) = http2 {
            service.technologies.push(h2);
        }
        if let Some(q) = quic {
            service.technologies.push(q);
        }
        if let Some(mut py) = py_finger {
            service.technologies.append(&mut py);
        }

        service
    }

    async fn try_websocket(&self, target: &str, port: u16) -> Option<TechInfo> {
        websocket_prober::probe_websocket(target, port)
            .await
            .map(|ws| TechInfo {
                name: format!("websocket@{}{}", ws.scheme, ws.path),
                version: None,
            })
    }

    async fn try_grpc(&self, target: &str, port: u16) -> Option<TechInfo> {
        let client = reqwest::Client::builder()
            .http2_prior_knowledge()
            .timeout(std::time::Duration::from_secs(4))
            .danger_accept_invalid_certs(true)
            .build()
            .ok()?;
        grpc_prober::probe_grpc(target, port, &client)
            .await
            .map(|grpc| TechInfo {
                name: "grpc".into(),
                version: Some(grpc.status.to_string()),
            })
    }

    async fn try_tls(&self, target: &str, port: u16) -> Option<TechInfo> {
        if ![443, 8443, 9443].contains(&port) {
            return None;
        }
        TLSFingerprint::analyze(target, port).ok().and_then(|fp| {
            fp.ja3.map(|ja3| TechInfo {
                name: "TLS/JA3".into(),
                version: Some(ja3),
            })
        })
    }

    async fn try_http2(&self, target: &str, port: u16) -> Option<TechInfo> {
        if ![80, 443, 8080, 8443].contains(&port) {
            return None;
        }
        HTTP2Fingerprint::analyze(target, port)
            .await
            .ok()
            .and_then(|fp| {
                if fp.alpn.is_empty() {
                    None
                } else {
                    Some(TechInfo {
                        name: "HTTP/2".into(),
                        version: Some(fp.alpn.join(",")),
                    })
                }
            })
    }

    async fn try_quic(
        &self,
        target: &str,
        port: u16,
        endpoint: Option<&quinn::Endpoint>,
    ) -> Option<TechInfo> {
        if ![443, 8443].contains(&port) {
            return None;
        }
        let ep = endpoint?;
        quic_prober::probe_quic(target, port, ep)
            .await
            .map(|q| TechInfo {
                name: format!("QUIC/{}", q.protocol),
                version: Some(q.alpn.join(",")),
            })
    }

    async fn try_python_finger(
        &self,
        target: &str,
        port: u16,
        bridge: Option<&PythonDetectorBridge>,
    ) -> Option<Vec<TechInfo>> {
        let bridge = bridge?;
        if ![80, 443, 8080, 8443].contains(&port) {
            return None;
        }
        let results = bridge.run_fingerprinting(target, port).ok()?;
        Some(
            results
                .detected
                .into_iter()
                .map(|tech| TechInfo {
                    name: tech.clone(),
                    version: results.versions.get(&tech).cloned(),
                })
                .collect(),
        )
    }
}