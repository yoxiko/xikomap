use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SshFingerprint {
    pub port: u16,
    pub banner: String,
    pub protocol_version: String,
    pub software: String,
    pub version: String,
    pub kex_algorithms: Vec<String>,
    pub host_key_algorithms: Vec<String>,
    pub encryption_ciphers: Vec<String>,
    pub mac_algorithms: Vec<String>,
}

pub struct SshProber;

impl SshProber {
    pub async fn probe(host: &str, port: u16) -> Option<SshFingerprint> {
        let addr = if host.contains(':') && !host.contains('[') {
            format!("[{}]:{}", host, port)
        } else {
            format!("{}:{}", host, port)
        };

        let stream = match timeout(Duration::from_secs(5), TcpStream::connect(&addr)).await {
            Ok(Ok(s)) => s,
            _ => return None,
        };

        let mut reader = stream;
        let mut banner_buf = vec![0u8; 1024];
        let banner = match timeout(Duration::from_secs(5), reader.read(&mut banner_buf)).await {
            Ok(Ok(n)) if n > 0 => {
                let raw = String::from_utf8_lossy(&banner_buf[..n]).to_string();
                raw.lines().next().unwrap_or("").trim().to_string()
            }
            _ => return None,
        };

        if !banner.starts_with("SSH-") {
            return None;
        }

        let parts: Vec<&str> = banner.splitn(3, '-').collect();
        let protocol_version = if parts.len() > 1 { parts[1].to_string() } else { String::new() };
        let software_version = if parts.len() > 2 { parts[2].to_string() } else { String::new() };

        let (software, version) = parse_software(&software_version);

        let kex_result = timeout(Duration::from_secs(3), Self::send_kexinit(&mut reader)).await;
        let (kex_algorithms, host_key_algorithms, encryption_ciphers, mac_algorithms) =
            match kex_result {
                Ok(Ok(algs)) => algs,
                _ => (Vec::new(), Vec::new(), Vec::new(), Vec::new()),
            };

        Some(SshFingerprint {
            port,
            banner: banner.clone(),
            protocol_version,
            software,
            version,
            kex_algorithms,
            host_key_algorithms,
            encryption_ciphers,
            mac_algorithms,
        })
    }

    async fn send_kexinit(
        stream: &mut TcpStream,
    ) -> std::io::Result<(Vec<String>, Vec<String>, Vec<String>, Vec<String>)> {
        let cookie: [u8; 16] = rand::random();
        let mut payload = Vec::new();

        payload.push(20); // SSH_MSG_KEXINIT

        payload.extend_from_slice(&cookie);

        let kex_algs = "curve25519-sha256,curve25519-sha256@libssh.org,ecdh-sha2-nistp256,ecdh-sha2-nistp384,ecdh-sha2-nistp521,diffie-hellman-group-exchange-sha256,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512,diffie-hellman-group14-sha256,diffie-hellman-group14-sha1";
        let host_key_algs = "ssh-ed25519,ecdsa-sha2-nistp256,ecdsa-sha2-nistp384,ecdsa-sha2-nistp521,rsa-sha2-512,rsa-sha2-256,ssh-rsa";
        let enc_c2s = "chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr";
        let enc_s2c = "chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr";
        let mac_c2s = "hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,hmac-sha2-256,hmac-sha2-512";
        let mac_s2c = "hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,hmac-sha2-256,hmac-sha2-512";
        let comp = "none";

        for list in &[kex_algs, host_key_algs, enc_c2s, enc_s2c, mac_c2s, mac_s2c, comp, comp] {
            let bytes = list.as_bytes();
            payload.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
            payload.extend_from_slice(bytes);
        }

        payload.extend_from_slice(&[0u8; 4]); // languages c2s
        payload.extend_from_slice(&[0u8; 4]); // languages s2c
        payload.push(0); // first_kex_packet_follows
        payload.extend_from_slice(&[0u8; 4]); // reserved

        let packet_len = (payload.len() + 1) as u32;
        let mut padding = 8 - ((packet_len + 4) % 8);
        if padding < 4 { padding += 8; }

        let mut packet = Vec::new();
        packet.extend_from_slice(&(packet_len + padding).to_be_bytes());
        packet.push(padding as u8);
        packet.extend_from_slice(&payload);
        packet.extend_from_slice(&vec![0u8; padding as usize]); // <--- ИСПРАВЛЕНО

        stream.write_all(&packet).await?;
        stream.flush().await?;

        let mut resp_buf = vec![0u8; 8192];
        let n = stream.read(&mut resp_buf).await?;
        if n < 5 {
            return Ok((Vec::new(), Vec::new(), Vec::new(), Vec::new()));
        }

        let msg_start = 5;
        if resp_buf.len() > msg_start && resp_buf[msg_start] == 20 {
            let data = &resp_buf[msg_start + 1..];
            if data.len() > 16 {
                let alg_data = &data[16..];
                return parse_kexinit_lists(alg_data);
            }
        }

        Ok((Vec::new(), Vec::new(), Vec::new(), Vec::new()))
    }
}

fn parse_kexinit_lists(data: &[u8]) -> std::io::Result<(Vec<String>, Vec<String>, Vec<String>, Vec<String>)> {
    let mut offset = 0;
    let mut lists = Vec::new();

    for _ in 0..10 {
        if offset + 4 > data.len() {
            break;
        }
        let len = u32::from_be_bytes([
            data[offset],
            data[offset + 1],
            data[offset + 2],
            data[offset + 3],
        ]) as usize;
        offset += 4;

        if offset + len > data.len() {
            break;
        }

        let s = String::from_utf8_lossy(&data[offset..offset + len]).to_string();
        lists.push(s.split(',').map(|x| x.trim().to_string()).collect::<Vec<String>>());
        offset += len;
    }

    let kex = lists.get(0).cloned().unwrap_or_default();
    let host_key = lists.get(1).cloned().unwrap_or_default();
    let enc = lists.get(2).cloned().unwrap_or_default();
    let mac = lists.get(4).cloned().unwrap_or_default();

    Ok((kex, host_key, enc, mac))
}

fn parse_software(raw: &str) -> (String, String) {
    let lower = raw.to_lowercase();

    if lower.contains("openssh") {
        let version = raw
            .split("OpenSSH_")
            .nth(1)
            .unwrap_or("")
            .split_whitespace()
            .next()
            .unwrap_or("unknown");
        return ("OpenSSH".to_string(), version.to_string());
    }

    if lower.contains("dropbear") {
        let version = raw
            .split("dropbear_")
            .nth(1)
            .unwrap_or("")
            .split_whitespace()
            .next()
            .unwrap_or("unknown");
        return ("Dropbear".to_string(), version.to_string());
    }

    if lower.contains("cisco") {
        return ("Cisco SSH".to_string(), raw.to_string());
    }

    if lower.contains("putty") {
        return ("PuTTY".to_string(), raw.to_string());
    }

    if lower.contains("libssh") {
        return ("libssh".to_string(), raw.to_string());
    }

    if lower.contains("paramiko") {
        return ("Paramiko".to_string(), raw.to_string());
    }

    ("Unknown".to_string(), raw.to_string())
}