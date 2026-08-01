pub fn get_probe_payload(port: u16) -> Vec<u8> {
    match port {
        80 | 8080 | 8000 | 8888 => b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\nUser-Agent: Xikomap/2.3\r\n\r\n".to_vec(),
        443 | 8443 => b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\nUser-Agent: Xikomap/2.3\r\n\r\n".to_vec(),
        21 => b"FEAT\r\n".to_vec(),
        22 => b"SSH-2.0-OpenSSH_9.0\r\n".to_vec(),
        25 | 587 => b"EHLO scanner.local\r\n".to_vec(),
        110 => b"USER test\r\n".to_vec(),
        143 => b"1 CAPABILITY\r\n".to_vec(),
        993 => b"EHLO scanner.local\r\n".to_vec(),
        995 => b"USER test\r\n".to_vec(),
        3306 => vec![],
        5432 => vec![],
        6379 => b"INFO\r\n".to_vec(),
        27017 => vec![],
        _ => vec![],
    }
}

pub fn guess_protocol(port: u16, banner: &str) -> String {
    let b = banner.to_lowercase();
    
    if port == 22 || b.contains("ssh") {
        return "ssh".to_string();
    }
    if port == 21 || b.contains("ftp") {
        return "ftp".to_string();
    }
    if port == 23 || b.contains("telnet") {
        return "telnet".to_string();
    }
    if port == 25 || port == 587 || b.contains("smtp") {
        return "smtp".to_string();
    }
    if port == 53 {
        return "dns".to_string();
    }
    if port == 80 || port == 443 || port == 8080 || port == 8443 || b.contains("http") {
        return "http".to_string();
    }
    if port == 110 || b.contains("pop3") {
        return "pop3".to_string();
    }
    if port == 143 || b.contains("imap") {
        return "imap".to_string();
    }
    if port == 993 {
        return "imaps".to_string();
    }
    if port == 995 {
        return "pop3s".to_string();
    }
    if port == 3306 || b.contains("mysql") {
        return "mysql".to_string();
    }
    if port == 5432 || b.contains("postgres") {
        return "postgresql".to_string();
    }
    if port == 1433 || b.contains("mssql") {
        return "mssql".to_string();
    }
    if port == 6379 || b.contains("redis") {
        return "redis".to_string();
    }
    if port == 27017 || b.contains("mongodb") {
        return "mongodb".to_string();
    }
    if port == 111 || b.contains("rpc") {
        return "rpc".to_string();
    }
    if port == 135 || b.contains("msrpc") {
        return "msrpc".to_string();
    }
    if port == 139 || b.contains("netbios") {
        return "netbios".to_string();
    }
    if port == 445 || b.contains("smb") {
        return "smb".to_string();
    }
    if port == 3389 || b.contains("rdp") {
        return "rdp".to_string();
    }
    if port == 5900 || b.contains("vnc") {
        return "vnc".to_string();
    }
    
    "tcp".to_string()
}