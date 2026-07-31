use regex::Regex;

pub fn detect_web(banner: &str, port: u16) -> Option<String> {
    if port != 80 && port != 443 && port != 8080 && port != 8443 && port != 8000 {
        return None;
    }

    let nginx_re = Regex::new(r"(?i)Server:\s*nginx/([^\r\n]+)").unwrap();
    if let Some(caps) = nginx_re.captures(banner) {
        return Some(format!("Nginx {}", caps.get(1).unwrap().as_str().trim()));
    }

    let apache_re = Regex::new(r"(?i)Server:\s*Apache/([^\r\n]+)").unwrap();
    if let Some(caps) = apache_re.captures(banner) {
        return Some(format!("Apache {}", caps.get(1).unwrap().as_str().trim()));
    }

    let iis_re = Regex::new(r"(?i)Server:\s*Microsoft-IIS/([^\r\n]+)").unwrap();
    if let Some(caps) = iis_re.captures(banner) {
        return Some(format!("Microsoft IIS {}", caps.get(1).unwrap().as_str().trim()));
    }

    let tomcat_re = Regex::new(r"(?i)Server:\s*Apache-Coyote/([^\r\n]+)").unwrap();
    if let Some(caps) = tomcat_re.captures(banner) {
        return Some(format!("Apache Tomcat {}", caps.get(1).unwrap().as_str().trim()));
    }

    let cloudflare_re = Regex::new(r"(?i)Server:\s*cloudflare").unwrap();
    if cloudflare_re.is_match(banner) {
        return Some("Cloudflare".to_string());
    }

    None
}