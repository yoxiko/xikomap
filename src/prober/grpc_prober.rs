use std::time::Duration;

pub struct GrpcProbeResult {
    pub status: String,
    pub content_type: String,
    pub http_version: String,
}

pub async fn probe_grpc(host: &str, port: u16) -> Option<GrpcProbeResult> {
    let scheme = if port == 443 || port == 8443 {
        "https"
    } else {
        "http"
    };

    let url = format!(
        "{}://{}:{}/grpc.health.v1.Health/Check",
        scheme, host, port
    );

    let client = reqwest::Client::builder()
        .http2_prior_knowledge()
        .timeout(Duration::from_secs(4))
        .danger_accept_invalid_certs(true)
        .build()
        .ok()?;

    let grpc_body: Vec<u8> = vec![0x00, 0x00, 0x00, 0x00, 0x00];

    let response = client
        .post(&url)
        .header("content-type", "application/grpc")
        .header("te", "trailers")
        .header("grpc-encoding", "identity")
        .header("grpc-accept-encoding", "identity")
        .body(grpc_body)
        .send()
        .await;

    match response {
        Ok(resp) => {
            let content_type = resp
                .headers()
                .get("content-type")
                .and_then(|v| v.to_str().ok())
                .unwrap_or("")
                .to_string();

            if !content_type.starts_with("application/grpc") {
                return None;
            }

            let grpc_status = resp
                .headers()
                .get("grpc-status")
                .and_then(|v| v.to_str().ok())
                .unwrap_or("unknown")
                .to_string();

            let http_version = format!("{:?}", resp.version());

            Some(GrpcProbeResult {
                status: grpc_status,
                content_type,
                http_version,
            })
        }
        Err(_) => None,
    }
}