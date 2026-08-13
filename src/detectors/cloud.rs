use regex::Regex;
use std::net::ToSocketAddrs;

pub struct CloudDetector {
    rules: Vec<(String, Vec<Regex>)>,
}

pub struct CloudResult {
    pub services: Vec<String>,
    pub cdn: Option<String>,
    pub hosting: Option<String>,
    pub buckets: Vec<String>,
    pub ip: Option<String>,
    pub hostname: Option<String>,
}

impl CloudDetector {
    pub fn new() -> Self {
        let mut rules = Vec::new();

        let aws_s3 = vec![
            Regex::new(r"(?i)s3\.amazonaws\.com").unwrap(),
            Regex::new(r"(?i)s3-[a-z]{2}-[a-z]+-\d\.amazonaws\.com").unwrap(),
            Regex::new(r"(?i)bucket\.s3\.amazonaws\.com").unwrap(),
        ];
        rules.push(("AWS S3".to_string(), aws_s3));

        let aws_ec2 = vec![
            Regex::new(r"(?i)ec2-\d+-\d+-\d+-\d+\.[a-z]+-compute-\d+\.amazonaws\.com").unwrap(),
            Regex::new(r"(?i)\.compute\.amazonaws\.com").unwrap(),
        ];
        rules.push(("AWS EC2".to_string(), aws_ec2));

        let aws_cf = vec![
            Regex::new(r"(?i)\.cloudfront\.net").unwrap(),
        ];
        rules.push(("AWS CloudFront".to_string(), aws_cf));

        let gcp_storage = vec![
            Regex::new(r"(?i)\.storage\.googleapis\.com").unwrap(),
            Regex::new(r"(?i)\.appspot\.com").unwrap(),
        ];
        rules.push(("GCP Storage".to_string(), gcp_storage));

        let gcp_compute = vec![
            Regex::new(r"(?i)\.c\.[a-z]+-cloud\.google\.com").unwrap(),
        ];
        rules.push(("GCP Compute".to_string(), gcp_compute));

        let azure_blob = vec![
            Regex::new(r"(?i)\.blob\.core\.windows\.net").unwrap(),
        ];
        rules.push(("Azure Blob".to_string(), azure_blob));

        let azure_web = vec![
            Regex::new(r"(?i)\.azurewebsites\.net").unwrap(),
        ];
        rules.push(("Azure Web Apps".to_string(), azure_web));

        let azure_cdn = vec![
            Regex::new(r"(?i)\.azureedge\.net").unwrap(),
        ];
        rules.push(("Azure CDN".to_string(), azure_cdn));

        let heroku = vec![
            Regex::new(r"(?i)\.herokuapp\.com").unwrap(),
        ];
        rules.push(("Heroku".to_string(), heroku));

        let vercel = vec![
            Regex::new(r"(?i)\.vercel\.app").unwrap(),
        ];
        rules.push(("Vercel".to_string(), vercel));

        let netlify = vec![
            Regex::new(r"(?i)\.netlify\.app").unwrap(),
        ];
        rules.push(("Netlify".to_string(), netlify));

        let digitalocean = vec![
            Regex::new(r"(?i)\.ondigitalocean\.app").unwrap(),
            Regex::new(r"(?i)\.do\.digitalocean\.com").unwrap(),
        ];
        rules.push(("DigitalOcean".to_string(), digitalocean));

        let oracle_cloud = vec![
            Regex::new(r"(?i)\.oraclecloud\.com").unwrap(),
        ];
        rules.push(("Oracle Cloud".to_string(), oracle_cloud));

        let ibm_cloud = vec![
            Regex::new(r"(?i)\.mybluemix\.net").unwrap(),
        ];
        rules.push(("IBM Cloud".to_string(), ibm_cloud));

        let linode = vec![
            Regex::new(r"(?i)\.linode\.com").unwrap(),
        ];
        rules.push(("Linode".to_string(), linode));

        Self { rules }
    }

    pub fn detect(&self, target: &str) -> CloudResult {
        let mut result = CloudResult {
            services: Vec::new(),
            cdn: None,
            hosting: None,
            buckets: Vec::new(),
            ip: None,
            hostname: None,
        };

        result.hostname = Some(target.to_string());

        for (service, patterns) in &self.rules {
            for pattern in patterns {
                if pattern.is_match(target) {
                    result.services.push(service.clone());

                    if service.contains("CloudFront") || service.contains("CDN") || service.contains("Akamai") {
                        result.cdn = Some(service.clone());
                    } else {
                        result.hosting = Some(service.clone());
                    }

                    if service.contains("S3")
                        || service.contains("Storage")
                        || service.contains("Blob")
                    {
                        result.buckets.push(target.to_string());
                    }
                    break;
                }
            }
        }

        let addr = format!("{}:0", target);
        if let Ok(mut addrs) = addr.to_socket_addrs() {
            if let Some(first_addr) = addrs.next() {
                let ip = first_addr.ip();
                result.ip = Some(ip.to_string());
            }
        }

        result
    }
}