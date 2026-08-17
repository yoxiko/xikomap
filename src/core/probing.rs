use crate::core::findings::{Finding, PortReport};
use crate::detectors::api::ApiDiscovery;
use crate::detectors::fingerprinting::FingerprintingDetector;
use crate::detectors::iot::IoTDetector;
use crate::prober::{
    cors, favicon, grpc, http2_fingerprint, jarm, quic, security_headers, ssh_fingerprint,
    tls_fingerprint, websocket,
};

use std::time::Duration;
use tokio::time::timeout;

const WEB_PORTS: [u16; 9] = [80, 443, 8080, 8443, 3000, 8000, 9090, 50051, 10000];
const HTTP_PORTS: [u16; 4] = [80, 443, 8080, 8443];
const TLS_PORTS: [u16; 2] = [443, 8443];
const SSH_PORTS: [u16; 4] = [22, 2222, 2200, 8022];
const JARM_PORTS: [u16; 3] = [443, 8443, 4443];

const PROBE_TIMEOUT: Duration = Duration::from_secs(10);

pub fn format_url(target: &str, port: u16, scheme: &str) -> String {
    if target.contains(':') && !target.contains('[') {
        format!("{}://[{}]:{}", scheme, target, port)
    } else {
        format!("{}://{}:{}", scheme, target, port)
    }
}

pub async fn probe_port(
    target: String,
    port: u16,
    all: bool,
    http_client: reqwest::Client,
) -> PortReport {
    let mut findings: Vec<Finding> = Vec::new();

    let is_web = all || WEB_PORTS.contains(&port);
    let is_tls = TLS_PORTS.contains(&port);
    let is_http = HTTP_PORTS.contains(&port);
    let scheme = if is_tls { "https" } else { "http" };
    let url = format_url(&target, port, scheme);

    let ssh_fut = async {
        if SSH_PORTS.contains(&port) {
            match timeout(PROBE_TIMEOUT, ssh_fingerprint::SshProber::probe(&target, port)).await {
                Ok(Some(fp)) => Some(Finding::Ssh(fp)),
                _ => None,
            }
        } else {
            None
        }
    };

    let jarm_fut = async {
        if JARM_PORTS.contains(&port) {
            match timeout(PROBE_TIMEOUT, jarm::JarmScanner::scan(&target, port)).await {
                Ok(Some(res)) => Some(Finding::Jarm(res)),
                _ => None,
            }
        } else {
            None
        }
    };

    // ИСПРАВЛЕНО: TLSFingerprint::analyze - синхронный метод
    let tls_fut = async {
        if is_tls {
            match tls_fingerprint::TLSFingerprint::analyze(&target, port) {
                Ok(fp) => {
                    if let Some(ja3) = fp.ja3 {
                        return Some(Finding::Technology {
                            name: "TLS".to_string(),
                            version: ja3,
                        });
                    }
                }
                Err(_) => {}
            }
        }
        None
    };

    let ws_fut = async {
        if is_web {
            match timeout(PROBE_TIMEOUT, websocket::probe_websocket(&target, port)).await {
                Ok(Some(res)) => Some(Finding::Service {
                    name: "websocket".to_string(),
                    detail: format!("{}://{}:{}{}", res.scheme, target, port, res.path),
                }),
                _ => None,
            }
        } else {
            None
        }
    };

    let grpc_fut = async {
        if is_web {
            match timeout(PROBE_TIMEOUT, grpc::probe_grpc(&target, port, &http_client)).await {
                Ok(Some(res)) => Some(Finding::Service {
                    name: "grpc".to_string(),
                    detail: format!("status={}", res.status),
                }),
                _ => None,
            }
        } else {
            None
        }
    };

    let quic_fut = async {
        if all || [80, 443, 8443].contains(&port) {
            if let Some(ep) = quic::create_quic_endpoint() {
                match timeout(PROBE_TIMEOUT, quic::probe_quic(&target, port, &ep)).await {
                    Ok(Some(res)) => {
                        return Some(Finding::Technology {
                            name: res.protocol,
                            version: res.alpn.join(","),
                        })
                    }
                    _ => {}
                }
            }
        }
        None
    };

    let http2_fut = async {
        if is_http {
            match timeout(PROBE_TIMEOUT, http2_fingerprint::HTTP2Fingerprint::analyze(&target, port)).await {
                Ok(Ok(fp)) => {
                    if !fp.alpn.is_empty() {
                        return Some(Finding::Technology {
                            name: "HTTP/2".to_string(),
                            version: fp.alpn.join(","),
                        });
                    }
                }
                _ => {}
            }
        }
        None
    };

    let sec_fut = async {
        if is_http {
            match timeout(PROBE_TIMEOUT, security_headers::SecurityHeadersAnalyzer::new(http_client.clone()).analyze(&url)).await {
                Ok(Some(res)) => Some(Finding::Security(res)),
                _ => None,
            }
        } else {
            None
        }
    };

    let fav_fut = async {
        if is_http {
            match timeout(PROBE_TIMEOUT, favicon::FaviconProber::probe(&http_client, &target, port, scheme)).await {
                Ok(Some(res)) => Some(Finding::Favicon(res)),
                _ => None,
            }
        } else {
            None
        }
    };

    let cors_fut = async {
        if is_http {
            match timeout(PROBE_TIMEOUT, cors::CorsScanner::new(http_client.clone()).analyze(&url)).await {
                Ok(Some(res)) => Some(Finding::Cors(res)),
                _ => None,
            }
        } else {
            None
        }
    };

    let fp_fut = async {
        let mut local_findings = Vec::new();
        if is_http {
            match timeout(PROBE_TIMEOUT, FingerprintingDetector::new(http_client.clone()).detect(&url)).await {
                Ok(Ok(res)) => {
                    for tech in &res.detected {
                        let version = res
                            .versions
                            .get(tech)
                            .cloned()
                            .unwrap_or_else(|| "unknown".to_string());
                        local_findings.push(Finding::Technology {
                            name: tech.clone(),
                            version,
                        });
                    }
                }
                _ => {}
            }
        }
        local_findings
    };

    let api_fut = async {
        let mut local_findings = Vec::new();
        if is_http {
            match timeout(PROBE_TIMEOUT, ApiDiscovery::new(http_client.clone()).discover(&url)).await {
                Ok(res) => {
                    if let Some(openapi) = res.openapi {
                        local_findings.push(Finding::ApiOpenApi {
                            title: openapi.title.clone(),
                            version: openapi.version.clone(),
                        });
                    }
                    if let Some(graphql) = res.graphql {
                        local_findings.push(Finding::ApiGraphql {
                            url: graphql.url.clone(),
                        });
                    }
                    for endpoint in res.endpoints {
                        local_findings.push(Finding::ApiEndpoint(endpoint));
                    }
                }
                _ => {}
            }
        }
        local_findings
    };

    let mqtt_fut = async {
        if [1883, 8883].contains(&port) {
            match timeout(PROBE_TIMEOUT, IoTDetector::detect_mqtt(&target, port, Duration::from_secs(3))).await {
                Ok(res) => {
                    if res.detected {
                        return Some(Finding::Service {
                            name: "mqtt".to_string(),
                            detail: format!("{:?} {:?}", res.version, res.features),
                        });
                    }
                }
                _ => {}
            }
        }
        None
    };

    let coap_fut = async {
        if [5683, 5684].contains(&port) {
            match timeout(PROBE_TIMEOUT, IoTDetector::detect_coap(&target, port, Duration::from_secs(3))).await {
                Ok(res) => {
                    if res.detected {
                        return Some(Finding::Service {
                            name: "coap".to_string(),
                            detail: format!("{:?}", res.resources),
                        });
                    }
                }
                _ => {}
            }
        }
        None
    };

    let (ssh, jarm, tls, ws, grpc, quic, http2, sec, fav, cors, fp_res, api_res, mqtt, coap) = tokio::join!(
        ssh_fut, jarm_fut, tls_fut, ws_fut, grpc_fut, quic_fut, http2_fut, sec_fut, fav_fut,
        cors_fut, fp_fut, api_fut, mqtt_fut, coap_fut
    );

    for f in [ssh, jarm, tls, ws, grpc, quic, http2, sec, fav, cors, mqtt, coap] {
        if let Some(finding) = f {
            findings.push(finding);
        }
    }
    
    findings.extend(fp_res);
    findings.extend(api_res);

    PortReport { port, findings }
}