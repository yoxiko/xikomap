use reqwest::Client;
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct GrpcInfo {
    pub status: u16,
    pub http_version: String,
    pub content_type: Option<String>,
}

pub async fn probe_grpc(host: &str, port: u16, client: &Client) -> Option<GrpcInfo> {
    let paths = vec!["/", "/grpc.health.v1.Health/Check"];

    for path in paths {
        let url = format!("https://{}:{}{}", host, port, path);

        match client
            .post(&url)
            .header("content-type", "application/grpc")
            .header("te", "trailers")
            .body(vec![0u8; 5])
            .send()
            .await
        {
            Ok(response) => {
                let content_type = response
                    .headers()
                    .get("content-type")
                    .and_then(|v| v.to_str().ok())
                    .map(|s| s.to_string());

                if let Some(ct) = &content_type {
                    if ct.contains("grpc") {
                        return Some(GrpcInfo {
                            status: response.status().as_u16(),
                            http_version: format!("{:?}", response.version()),
                            content_type,
                        });
                    }
                }
            }
            Err(_) => {
                let url_http = format!("http://{}:{}{}", host, port, path);
                if let Ok(response) = client
                    .post(&url_http)
                    .header("content-type", "application/grpc")
                    .header("te", "trailers")
                    .body(vec![0u8; 5])
                    .send()
                    .await
                {
                    let content_type = response
                        .headers()
                        .get("content-type")
                        .and_then(|v| v.to_str().ok())
                        .map(|s| s.to_string());

                    if let Some(ct) = &content_type {
                        if ct.contains("grpc") {
                            return Some(GrpcInfo {
                                status: response.status().as_u16(),
                                http_version: format!("{:?}", response.version()),
                                content_type,
                            });
                        }
                    }
                }
            }
        }
    }

    None
}