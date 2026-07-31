use regex::Regex;

pub fn detect_ssh_ftp(banner: &str, port: u16) -> Option<String> {
    if port != 21 && port != 22 && port != 23 && port != 69 {
        return None;
    }

    let openssh_re = Regex::new(r"(?i)SSH-([\d\.]+)\s+OpenSSH_([^\r\n]+)").unwrap();
    if let Some(caps) = openssh_re.captures(banner) {
        return Some(format!("OpenSSH {} (Protocol {})", caps.get(2).unwrap().as_str().trim(), caps.get(1).unwrap().as_str()));
    }

    if port == 22 && banner.to_lowercase().contains("ssh") {
        return Some("SSH".to_string());
    }

    let vsftpd_re = Regex::new(r"(?i)vsFTPd\s+([^\r\n]+)").unwrap();
    if let Some(caps) = vsftpd_re.captures(banner) {
        return Some(format!("vsftpd {}", caps.get(1).unwrap().as_str().trim()));
    }

    let proftpd_re = Regex::new(r"(?i)ProFTPD\s+([^\r\n]+)").unwrap();
    if let Some(caps) = proftpd_re.captures(banner) {
        return Some(format!("ProFTPD {}", caps.get(1).unwrap().as_str().trim()));
    }

    let filezilla_re = Regex::new(r"(?i)FileZilla").unwrap();
    if filezilla_re.is_match(banner) {
        return Some("FileZilla FTP".to_string());
    }

    if port == 21 {
        return Some("FTP".to_string());
    }
    if port == 23 {
        return Some("Telnet".to_string());
    }

    None
}