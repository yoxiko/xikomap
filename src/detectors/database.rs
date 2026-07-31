use regex::Regex;

pub fn detect_database(banner: &str, port: u16) -> Option<String> {
    if port != 3306 && port != 5432 && port != 6379 && port != 27017 && port != 1433 && port != 9200 {
        return None;
    }

    let mysql_re = Regex::new(r"(?i)(\d+\.\d+\.\d+).*mysql").unwrap();
    if mysql_re.is_match(banner) || port == 3306 {
        if let Some(caps) = Regex::new(r"(\d+\.\d+\.\d+)").unwrap().captures(banner) {
            return Some(format!("MySQL {}", caps.get(1).unwrap().as_str()));
        }
        return Some("MySQL".to_string());
    }

    let postgres_re = Regex::new(r"(?i)PostgreSQL").unwrap();
    if postgres_re.is_match(banner) || port == 5432 {
        return Some("PostgreSQL".to_string());
    }

    let redis_re = Regex::new(r"(?i)redis_version:([^\r\n]+)").unwrap();
    if let Some(caps) = redis_re.captures(banner) {
        return Some(format!("Redis {}", caps.get(1).unwrap().as_str().trim()));
    }
    if port == 6379 {
        return Some("Redis".to_string());
    }

    let mongo_re = Regex::new(r"(?i)mongodb").unwrap();
    if mongo_re.is_match(banner) || port == 27017 {
        return Some("MongoDB".to_string());
    }

    let mssql_re = Regex::new(r"(?i)Microsoft SQL Server").unwrap();
    if mssql_re.is_match(banner) || port == 1433 {
        return Some("Microsoft SQL Server".to_string());
    }

    let elastic_re = Regex::new(r"(?i)elasticsearch").unwrap();
    if elastic_re.is_match(banner) || port == 9200 {
        return Some("Elasticsearch".to_string());
    }

    None
}