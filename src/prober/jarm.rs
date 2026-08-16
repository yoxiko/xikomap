use sha2::{Digest, Sha256};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct JarmResult {
    pub port: u16,
    pub hash: String,
    pub raw_responses: Vec<String>,
}

struct JarmProbe {
    tls_version: u16,
    cipher_suites: Vec<u16>,
    extensions: bool,
    grease: bool,
    alpn: bool,
    supported_versions: bool,
}

pub struct JarmScanner;

impl JarmScanner {
    fn build_probes() -> Vec<JarmProbe> {
        let all_ciphers_v12: Vec<u16> = vec![
            0xc02c, 0xc02b, 0xc030, 0xc02f, 0x009f, 0x009e, 0xc024, 0xc023,
            0xc028, 0xc027, 0xc00a, 0xc009, 0xc014, 0xc013, 0x009d, 0x009c,
            0x003d, 0x003c, 0x0035, 0x002f, 0x00ff,
        ];

        let all_ciphers_v13: Vec<u16> = vec![
            0x1302, 0x1303, 0x1301, 0xc02c, 0xc02b, 0xc030, 0xc02f,
            0x009f, 0x009e, 0x0035, 0x002f, 0x00ff,
        ];

        let top_half: Vec<u16> = all_ciphers_v12[..all_ciphers_v12.len() / 2].to_vec();
        let bottom_half: Vec<u16> = all_ciphers_v12[all_ciphers_v12.len() / 2..].to_vec();

        let mut middle_out = Vec::new();
        let mid = all_ciphers_v12.len() / 2;
        for i in 0..all_ciphers_v12.len() {
            let idx = if i % 2 == 0 { mid + i / 2 } else { mid - 1 - i / 2 };
            if idx < all_ciphers_v12.len() {
                middle_out.push(all_ciphers_v12[idx]);
            }
        }

        vec![
            JarmProbe { tls_version: 0x0303, cipher_suites: all_ciphers_v12.clone(), extensions: true, grease: true, alpn: true, supported_versions: false },
            JarmProbe { tls_version: 0x0303, cipher_suites: all_ciphers_v12.clone(), extensions: true, grease: true, alpn: false, supported_versions: false },
            JarmProbe { tls_version: 0x0303, cipher_suites: top_half, extensions: true, grease: false, alpn: true, supported_versions: false },
            JarmProbe { tls_version: 0x0303, cipher_suites: bottom_half, extensions: true, grease: false, alpn: true, supported_versions: false },
            JarmProbe { tls_version: 0x0303, cipher_suites: middle_out, extensions: true, grease: true, alpn: true, supported_versions: false },
            JarmProbe { tls_version: 0x0302, cipher_suites: all_ciphers_v12.clone(), extensions: true, grease: false, alpn: false, supported_versions: false },
            JarmProbe { tls_version: 0x0303, cipher_suites: all_ciphers_v13.clone(), extensions: true, grease: true, alpn: true, supported_versions: true },
            JarmProbe { tls_version: 0x0303, cipher_suites: vec![0x00ff], extensions: false, grease: false, alpn: false, supported_versions: false },
            JarmProbe { tls_version: 0x0303, cipher_suites: all_ciphers_v13, extensions: true, grease: true, alpn: true, supported_versions: true },
            JarmProbe { tls_version: 0x0303, cipher_suites: all_ciphers_v12, extensions: false, grease: false, alpn: false, supported_versions: false },
        ]
    }

    pub async fn scan(target: &str, port: u16) -> Option<JarmResult> {
        let addr_str = if target.contains(':') && !target.contains('[') {
            format!("[{}]:{}", target, port)
        } else {
            format!("{}:{}", target, port)
        };

        let probes = Self::build_probes();

        let raw_responses: Vec<String> = futures::future::join_all(
            probes.iter().map(|probe| Self::send_probe(&addr_str, probe)),
        )
        .await;

        let concatenated = raw_responses.join("");

        if concatenated.is_empty() || concatenated.chars().all(|c| c == '0') {
            return Some(JarmResult {
                port,
                hash: "00000000000000000000000000000000000000000000000000000000000000".to_string(),
                raw_responses,
            });
        }

        let mut hasher = Sha256::new();
        hasher.update(concatenated.as_bytes());
        let hash = hex::encode(hasher.finalize());

        Some(JarmResult {
            port,
            hash,
            raw_responses,
        })
    }

    async fn send_probe(addr: &str, probe: &JarmProbe) -> String {
        let stream = match timeout(Duration::from_secs(3), TcpStream::connect(addr)).await {
            Ok(Ok(s)) => s,
            _ => return "000".to_string(),
        };

        let client_hello = Self::build_client_hello(probe);

        let mut stream = stream;
        if stream.write_all(&client_hello).await.is_err() {
            return "000".to_string();
        }
        if stream.flush().await.is_err() {
            return "000".to_string();
        }

        let mut buf = vec![0u8; 16384];
        let n = match timeout(Duration::from_secs(3), stream.read(&mut buf)).await {
            Ok(Ok(n)) => n,
            _ => return "000".to_string(),
        };

        if n < 5 {
            return "000".to_string();
        }

        Self::parse_server_hello(&buf[..n])
    }

    fn build_client_hello(probe: &JarmProbe) -> Vec<u8> {
        let mut hello_body = Vec::new();

        let client_version: u16 = if probe.supported_versions { 0x0303 } else { probe.tls_version };
        hello_body.extend_from_slice(&client_version.to_be_bytes());

        let random: [u8; 32] = rand::random();
        hello_body.extend_from_slice(&random);

        let session_id: [u8; 32] = rand::random();
        hello_body.push(32);
        hello_body.extend_from_slice(&session_id);

        let mut cipher_bytes = Vec::new();
        if probe.grease {
            cipher_bytes.extend_from_slice(&[0x0a, 0x0a]);
        }
        for cs in &probe.cipher_suites {
            cipher_bytes.extend_from_slice(&cs.to_be_bytes());
        }
        hello_body.extend_from_slice(&(cipher_bytes.len() as u16).to_be_bytes());
        hello_body.extend_from_slice(&cipher_bytes);

        hello_body.push(1);
        hello_body.push(0);

        if probe.extensions {
            let mut extensions = Vec::new();

            let sni_data = vec![0u8; 5];
            extensions.extend_from_slice(&0x0000u16.to_be_bytes());
            extensions.extend_from_slice(&(sni_data.len() as u16).to_be_bytes());
            extensions.extend_from_slice(&sni_data);

            if probe.supported_versions {
                let sv_data = vec![0x03, 0x04, 0x03, 0x03];
                extensions.extend_from_slice(&0x002bu16.to_be_bytes());
                extensions.extend_from_slice(&(sv_data.len() as u16).to_be_bytes());
                extensions.extend_from_slice(&sv_data);
            }

            if probe.alpn {
                let alpn_protos = b"\x02h2\x08http/1.1";
                let mut alpn_data = Vec::new();
                alpn_data.extend_from_slice(&(alpn_protos.len() as u16).to_be_bytes());
                alpn_data.extend_from_slice(alpn_protos);
                extensions.extend_from_slice(&0x0010u16.to_be_bytes());
                extensions.extend_from_slice(&(alpn_data.len() as u16).to_be_bytes());
                extensions.extend_from_slice(&alpn_data);
            }

            let ec_data: Vec<u8> = vec![0x00, 0x04, 0x00, 0x17, 0x00, 0x18];
            extensions.extend_from_slice(&0x000au16.to_be_bytes());
            extensions.extend_from_slice(&(ec_data.len() as u16).to_be_bytes());
            extensions.extend_from_slice(&ec_data);

            let pf_data: Vec<u8> = vec![0x00];
            extensions.extend_from_slice(&0x000bu16.to_be_bytes());
            extensions.extend_from_slice(&(pf_data.len() as u16).to_be_bytes());
            extensions.extend_from_slice(&pf_data);

            hello_body.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
            hello_body.extend_from_slice(&extensions);
        }

        let mut handshake = Vec::new();
        handshake.push(1);
        let body_len = hello_body.len() as u32;
        handshake.extend_from_slice(&body_len.to_be_bytes()[1..4]);
        handshake.extend_from_slice(&hello_body);

        let mut record = Vec::new();
        record.push(22);
        record.extend_from_slice(&probe.tls_version.to_be_bytes());
        record.extend_from_slice(&(handshake.len() as u16).to_be_bytes());
        record.extend_from_slice(&handshake);

        record
    }

    fn parse_server_hello(data: &[u8]) -> String {
        if data.len() < 5 {
            return "000".to_string();
        }

        let content_type = data[0];
        if content_type == 21 {
            return "err".to_string();
        }
        if content_type != 22 {
            return "000".to_string();
        }

        let record_len = u16::from_be_bytes([data[3], data[4]]) as usize;
        if data.len() < 5 + record_len {
            return "000".to_string();
        }

        let hs = &data[5..];
        if hs.is_empty() || hs[0] != 2 {
            return "000".to_string();
        }

        let mut offset = 4;
        if offset + 2 > hs.len() { return "000".to_string(); }
        let server_version = u16::from_be_bytes([hs[offset], hs[offset + 1]]);
        offset += 2;

        offset += 32;
        if offset >= hs.len() { return "000".to_string(); }
        let session_id_len = hs[offset] as usize;
        offset += 1 + session_id_len;

        if offset + 2 > hs.len() { return "000".to_string(); }
        let cipher_suite = u16::from_be_bytes([hs[offset], hs[offset + 1]]);
        offset += 2;

        if offset >= hs.len() { return "000".to_string(); }
        let compression = hs[offset];
        offset += 1;

        let mut selected_version = server_version;
        let mut ext_str = String::new();

        if offset + 2 <= hs.len() {
            let ext_total = u16::from_be_bytes([hs[offset], hs[offset + 1]]) as usize;
            offset += 2;
            let ext_end = offset + ext_total;

            while offset + 4 <= hs.len() && offset + 4 <= ext_end + 2 {
                if offset + 4 > hs.len() { break; }
                let ext_type = u16::from_be_bytes([hs[offset], hs[offset + 1]]);
                let ext_len = u16::from_be_bytes([hs[offset + 2], hs[offset + 3]]) as usize;
                offset += 4;

                if ext_type == 0x002b && ext_len >= 2 && offset + 2 <= hs.len() {
                    selected_version = u16::from_be_bytes([hs[offset], hs[offset + 1]]);
                }

                ext_str.push_str(&format!("{:04x}", ext_type));

                if offset + ext_len > hs.len() { break; }
                offset += ext_len;
            }
        }

        format!("{:04x}|{:04x}|{:02x}|{}", selected_version, cipher_suite, compression, ext_str)
    }
}