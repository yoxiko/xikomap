use quinn::Endpoint;
use rustls::pki_types::CertificateDer;
use serde::{Deserialize, Serialize};
use std::net::{SocketAddr, UdpSocket};

#[derive(Debug, Serialize, Deserialize)]
pub struct QuicInfo {
    pub protocol: String,
    pub alpn: Vec<String>,
}

pub fn create_quic_endpoint() -> Option<Endpoint> {
    let socket = UdpSocket::bind("0.0.0.0:0").ok()?;
    Endpoint::new(
        quinn::EndpointConfig::default(),
        None,
        socket,
        quinn::default_runtime()?,
    )
    .ok()
}

pub async fn probe_quic(host: &str, port: u16, endpoint: &Endpoint) -> Option<QuicInfo> {
    let addr: SocketAddr = format!("{}:{}", host, port).parse().ok()?;

    let mut crypto = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(std::sync::Arc::new(SkipServerVerification))
        .with_no_client_auth();

    crypto.alpn_protocols = vec![b"h3".to_vec(), b"h3-29".to_vec()];

    let quic_client_config = quinn::crypto::rustls::QuicClientConfig::try_from(crypto).ok()?;
    let client_config = quinn::ClientConfig::new(std::sync::Arc::new(quic_client_config));

    let connection = endpoint
        .connect_with(client_config, addr, host)
        .ok()?
        .await
        .ok()?;

    let alpn = connection
        .handshake_data()
        .and_then(|data| {
            data.downcast::<quinn::crypto::rustls::HandshakeData>()
                .ok()
        })
        .and_then(|data| data.protocol)
        .and_then(|p| String::from_utf8(p).ok());

    let alpn_list = alpn.map(|a| vec![a]).unwrap_or_default();

    connection.close(0u32.into(), b"done");

    Some(QuicInfo {
        protocol: "HTTP/3".to_string(),
        alpn: alpn_list,
    })
}

#[derive(Debug)]
struct SkipServerVerification;

impl rustls::client::danger::ServerCertVerifier for SkipServerVerification {
    fn verify_server_cert(
        &self,
        _: &CertificateDer<'_>,
        _: &[CertificateDer<'_>],
        _: &rustls::pki_types::ServerName<'_>,
        _: &[u8],
        _: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _: &[u8],
        _: &CertificateDer<'_>,
        _: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _: &[u8],
        _: &CertificateDer<'_>,
        _: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![
            rustls::SignatureScheme::RSA_PKCS1_SHA256,
            rustls::SignatureScheme::RSA_PKCS1_SHA384,
            rustls::SignatureScheme::RSA_PKCS1_SHA512,
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::ECDSA_NISTP384_SHA384,
            rustls::SignatureScheme::ECDSA_NISTP521_SHA512,
            rustls::SignatureScheme::RSA_PSS_SHA256,
            rustls::SignatureScheme::RSA_PSS_SHA384,
            rustls::SignatureScheme::RSA_PSS_SHA512,
            rustls::SignatureScheme::ED25519,
            rustls::SignatureScheme::ED448,
        ]
    }
}