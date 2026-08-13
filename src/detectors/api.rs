use reqwest::Client;
use serde_json::Value;

#[derive(Clone)]
pub struct ApiDiscovery {
    client: Client,
    common_paths: Vec<&'static str>,
}

#[derive(Clone)]
pub struct ApiResult {
    pub openapi: Option<OpenApiSpec>,
    pub graphql: Option<GraphQLInfo>,
    pub endpoints: Vec<String>,
}

#[derive(Clone)]
pub struct OpenApiSpec {
    pub url: String,
    pub version: String,
    pub title: String,
}

#[derive(Clone)]
pub struct GraphQLInfo {
    pub url: String,
    pub introspection: bool,
}

impl ApiDiscovery {
    pub fn new(client: Client) -> Self {
        Self {
            client,
            common_paths: vec![
                "/api",
                "/api/v1",
                "/api/v2",
                "/graphql",
                "/openapi.json",
                "/swagger.json",
                "/swagger.yaml",
                "/api-docs",
                "/docs",
                "/api/swagger.json",
                "/api/openapi.json",
                "/redoc",
            ],
        }
    }

    pub async fn discover(&self, base_url: &str) -> ApiResult {
        let mut result = ApiResult {
            openapi: None,
            graphql: None,
            endpoints: Vec::new(),
        };

        let base_url = base_url.trim_end_matches('/');

        for &path in &self.common_paths {
            let url = format!("{}{}", base_url, path);

            if let Ok(response) = self.client.get(&url).send().await {
                if response.status().is_success() {
                    if path.contains("openapi") || path.contains("swagger") {
                        if let Ok(text) = response.text().await {
                            if let Ok(spec) = serde_json::from_str::<Value>(&text) {
                                if spec.get("openapi").is_some() || spec.get("swagger").is_some() {
                                    let version = spec
                                        .get("openapi")
                                        .or_else(|| spec.get("swagger"))
                                        .and_then(|v| v.as_str())
                                        .unwrap_or("unknown")
                                        .to_string();

                                    let title = spec
                                        .get("info")
                                        .and_then(|i| i.get("title"))
                                        .and_then(|t| t.as_str())
                                        .unwrap_or("Unknown")
                                        .to_string();

                                    result.openapi = Some(OpenApiSpec {
                                        url: url.clone(),
                                        version,
                                        title,
                                    });

                                    if let Some(paths) = spec.get("paths").and_then(|p| p.as_object())
                                    {
                                        for (path_name, methods) in paths {
                                            if let Some(methods_obj) = methods.as_object() {
                                                for method in methods_obj.keys() {
                                                    result
                                                        .endpoints
                                                        .push(format!("{} {}", method.to_uppercase(), path_name));
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }

                    if path == "/graphql" {
                        let graphql_query = r#"{"query": "{ __schema { types { name } } }"}"#;
                        if let Ok(gql_resp) = self
                            .client
                            .post(&url)
                            .header("Content-Type", "application/json")
                            .body(graphql_query)
                            .send()
                            .await
                        {
                            if gql_resp.status().is_success() {
                                if let Ok(gql_json) = gql_resp.json::<Value>().await {
                                    if gql_json.get("data").is_some() {
                                        result.graphql = Some(GraphQLInfo {
                                            url: url.clone(),
                                            introspection: true,
                                        });
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        result
    }
}