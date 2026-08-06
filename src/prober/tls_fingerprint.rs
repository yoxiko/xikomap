use md5::{Digest, Md5};
use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

pub struct TLSFingerprint {
    pub ja3: Option<String>,
    pub ja3s: Option<String>,
    pub cipher_suites: Vec<u16>,
    pub extensions: Vec<u16>,
    pub tls_version: Option<String>,
}

impl TLSFingerprint {
    pub fn new() -> Self {
        TLSFingerprint {
            ja3: None,
            ja3s: None,
            cipher_suites: Vec::new(),
            extensions: Vec::new(),
            tls_version: None,
        }
    }

    pub fn analyze(host: &str, port: u16) -> Result<Self, Box<dyn std::error::Error>> {
        let mut fp = TLSFingerprint::new();

        let addr = format!("{}:{}", host, port);
        let mut stream =
            TcpStream::connect_timeout(&addr.parse()?, Duration::from_secs(3))?;

        let client_hello = Self::build_client_hello();
        stream.write_all(&client_hello)?;

        let mut buffer = vec![0u8; 4096];
        if let Ok(n) = stream.read(&mut buffer) {
            if n > 0 {
                fp.parse_server_hello(&buffer[..n]);
            }
        }

        fp.ja3 = Some(Self::compute_ja3(
            771,
            &fp.cipher_suites,
            &fp.extensions,
            &[],
            &[],
        ));

        Ok(fp)
    }

    fn build_client_hello() -> Vec<u8> {
        let mut hello = Vec::new();

        hello.push(0x16);
        hello.push(0x03);
        hello.push(0x01);
        hello.extend_from_slice(&[0x00, 0x00]);

        hello.push(0x01);
        hello.extend_from_slice(&[0x00, 0x00, 0x00]);

        hello.push(0x03);
        hello.push(0x03);

        hello.extend_from_slice(&[0x00; 32]);

        hello.push(0x00);

        let ciphers: Vec<u16> = vec![
            0xc02c, 0xc02b, 0xc030, 0x009e, 0x009c, 0xc013, 0xc012, 0x002f, 0x0035,
        ];

        let cipher_len = (ciphers.len() * 2) as u16;
        hello.extend_from_slice(&cipher_len.to_be_bytes());
        for c in &ciphers {
            hello.extend_from_slice(&c.to_be_bytes());
        }

        hello.push(0x01);
        hello.push(0x00);

        hello.push(0x00);
        hello.push(0x00);

        let hello_len = (hello.len() - 5) as u16;
        hello[3..5].copy_from_slice(&hello_len.to_be_bytes());

        let hs_len = (hello.len() - 9) as u32;
        hello[6] = ((hs_len >> 16) & 0xff) as u8;
        hello[7] = ((hs_len >> 8) & 0xff) as u8;
        hello[8] = (hs_len & 0xff) as u8;

        hello
    }

    fn parse_server_hello(&mut self, data: &[u8]) {
        if data.len() < 44 {
            return;
        }

        self.tls_version = match (data[9], data[10]) {
            (0x03, 0x04) => Some("TLS 1.3".to_string()),
            (0x03, 0x03) => Some("TLS 1.2".to_string()),
            (0x03, 0x02) => Some("TLS 1.1".to_string()),
            (0x03, 0x01) => Some("TLS 1.0".to_string()),
            _ => Some(format!("0x{:02x}{:02x}", data[9], data[10])),
        };

        let session_id_len = data[43] as usize;
        let cipher_offset = 44 + session_id_len;

        if data.len() > cipher_offset + 1 {
            let cipher = ((data[cipher_offset] as u16) << 8) | (data[cipher_offset + 1] as u16);
            self.cipher_suites.push(cipher);
        }
    }

    fn compute_ja3(
        tls_version: u16,
        ciphers: &[u16],
        extensions: &[u16],
        elliptic_curves: &[u16],
        ec_point_formats: &[u8],
    ) -> String {
        let mut ja3_string = format!("{}", tls_version);

        ja3_string.push(',');
        ja3_string.push_str(
            &ciphers
                .iter()
                .map(|c| c.to_string())
                .collect::<Vec<_>>()
                .join("-"),
        );

        ja3_string.push(',');
        ja3_string.push_str(
            &extensions
                .iter()
                .map(|e| e.to_string())
                .collect::<Vec<_>>()
                .join("-"),
        );

        ja3_string.push(',');
        ja3_string.push_str(
            &elliptic_curves
                .iter()
                .map(|c| c.to_string())
                .collect::<Vec<_>>()
                .join("-"),
        );

        ja3_string.push(',');
        ja3_string.push_str(
            &ec_point_formats
                .iter()
                .map(|f| f.to_string())
                .collect::<Vec<_>>()
                .join("-"),
        );

        let mut hasher = Md5::new();
        hasher.update(ja3_string.as_bytes());
        format!("{:x}", hasher.finalize())
    }
}