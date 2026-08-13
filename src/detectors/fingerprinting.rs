use regex::Regex;
use reqwest::Client;
use std::collections::HashMap;

pub struct TechRule {
    pub name: String,
    pub patterns: Vec<Regex>,
    pub headers: Vec<(String, String)>,
    pub html_patterns: Vec<Regex>,
    pub paths: Vec<String>,
}

pub struct FingerprintingDetector {
    client: Client,
    rules: Vec<TechRule>,
}

pub struct FingerprintResult {
    pub detected: Vec<String>,
    pub versions: HashMap<String, String>,
}

impl FingerprintingDetector {
    pub fn new(client: Client) -> Self {
        let mut rules = Vec::new();

        rules.push(TechRule {
            name: "jQuery".to_string(),
            patterns: vec![
                Regex::new(r"(?i)jquery[.-]([\d.]+)\.js").unwrap(),
                Regex::new(r"(?i)jquery/([\d.]+)").unwrap(),
            ],
            headers: vec![("X-Powered-By".to_string(), "jQuery".to_string())],
            html_patterns: vec![],
            paths: vec![],
        });

        rules.push(TechRule {
            name: "React".to_string(),
            patterns: vec![
                Regex::new(r"(?i)react(?:\.production|\.development)?\.min\.js").unwrap(),
                Regex::new(r"(?i)__REACT").unwrap(),
            ],
            headers: vec![],
            html_patterns: vec![
                Regex::new(r"(?i)data-reactroot").unwrap(),
                Regex::new(r"(?i)__NEXT_DATA__").unwrap(),
            ],
            paths: vec![],
        });

        rules.push(TechRule {
            name: "WordPress".to_string(),
            patterns: vec![
                Regex::new(r"(?i)/wp-content/").unwrap(),
                Regex::new(r"(?i)/wp-includes/").unwrap(),
            ],
            headers: vec![],
            html_patterns: vec![
                Regex::new(r#"(?i)<meta name="generator" content="WordPress ([\d.]+)""#).unwrap(),
            ],
            paths: vec!["/wp-login.php".to_string(), "/wp-admin/".to_string()],
        });

        rules.push(TechRule {
            name: "Bootstrap".to_string(),
            patterns: vec![
                Regex::new(r"(?i)bootstrap[.-]([\d.]+)\.min\.css").unwrap(),
                Regex::new(r"(?i)bootstrap/([\d.]+)").unwrap(),
            ],
            headers: vec![],
            html_patterns: vec![],
            paths: vec![],
        });

        rules.push(TechRule {
            name: "Vue.js".to_string(),
            patterns: vec![
                Regex::new(r"(?i)vue[.-]([\d.]+)\.js").unwrap(),
            ],
            headers: vec![],
            html_patterns: vec![
                Regex::new(r"(?i)__vue__").unwrap(),
                Regex::new(r#"(?i)<div id="app">"#).unwrap(),
            ],
            paths: vec![],
        });

        rules.push(TechRule {
            name: "Angular".to_string(),
            patterns: vec![
                Regex::new(r"(?i)angular[.-]([\d.]+)\.js").unwrap(),
            ],
            headers: vec![],
            html_patterns: vec![
                Regex::new(r"(?i)ng-version=").unwrap(),
                Regex::new(r"(?i)ng-app").unwrap(),
            ],
            paths: vec![],
        });

        rules.push(TechRule {
            name: "Django".to_string(),
            patterns: vec![],
            headers: vec![("Set-Cookie".to_string(), "csrftoken".to_string())],
            html_patterns: vec![
                Regex::new(r"(?i)csrfmiddlewaretoken").unwrap(),
            ],
            paths: vec![],
        });

        rules.push(TechRule {
            name: "Express".to_string(),
            patterns: vec![],
            headers: vec![("X-Powered-By".to_string(), "Express".to_string())],
            html_patterns: vec![],
            paths: vec![],
        });

        rules.push(TechRule {
            name: "Nginx".to_string(),
            patterns: vec![],
            headers: vec![("Server".to_string(), "nginx".to_string())],
            html_patterns: vec![],
            paths: vec![],
        });

        rules.push(TechRule {
            name: "Apache".to_string(),
            patterns: vec![],
            headers: vec![("Server".to_string(), "Apache".to_string())],
            html_patterns: vec![],
            paths: vec![],
        });

        Self { client, rules }
    }

    pub async fn detect(&self, url: &str) -> Result<FingerprintResult, reqwest::Error> {
        let mut results = FingerprintResult {
            detected: Vec::new(),
            versions: HashMap::new(),
        };

        let response = self.client.get(url).send().await?;
        let headers = response.headers().clone();
        let html = response.text().await?;

        for rule in &self.rules {
            let mut detected = false;
            let mut version = None;

            for pattern in &rule.patterns {
                if let Some(caps) = pattern.captures(&html) {
                    detected = true;
                    if let Some(v) = caps.get(1) {
                        version = Some(v.as_str().to_string());
                    }
                    break;
                }
            }

            if !detected {
                for (key, val) in &rule.headers {
                    if let Some(header_val) = headers.get(key) {
                        if let Ok(s) = header_val.to_str() {
                            if s.to_lowercase().contains(&val.to_lowercase()) {
                                detected = true;
                                break;
                            }
                        }
                    }
                }
            }

            if !detected {
                for pattern in &rule.html_patterns {
                    if pattern.is_match(&html) {
                        detected = true;
                        if let Some(caps) = pattern.captures(&html) {
                            if let Some(v) = caps.get(1) {
                                version = Some(v.as_str().to_string());
                            }
                        }
                        break;
                    }
                }
            }

            if detected {
                results.detected.push(rule.name.clone());
                if let Some(v) = version {
                    results.versions.insert(rule.name.clone(), v);
                }
            }
        }

        Ok(results)
    }
}