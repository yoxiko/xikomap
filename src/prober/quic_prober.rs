use quinn::crypto::rustls::QuicClientConfig;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig as RustlsClientConfig, DigitallySignedStruct, SignatureScheme};
use std::sync::Arc;
use std::time::Duration;

#[derive(Debug)]
struct SkipServerVerification;

impl ServerCertVerifier for SkipServerVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![
            SignatureScheme::RSA_PKCS1_SHA256,
            SignatureScheme::RSA_PKCS1_SHA384,
            SignatureScheme::RSA_PKCS1_SHA512,
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::ECDSA_NISTP384_SHA384,
            SignatureScheme::ECDSA_NISTP521_SHA512,
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::RSA_PSS_SHA384,
            SignatureScheme::RSA_PSS_SHA512,
            SignatureScheme::ED25519,
        ]
    }
}

pub struct QuicProbeResult {
    pub protocol: String,
    pub alpn: Option<String>,
}

pub async fn probe_quic(host: &str, port: u16) -> Option<QuicProbeResult> {
    let mut crypto = RustlsClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(SkipServerVerification))
        .with_no_client_auth();

    crypto.alpn_protocols = vec![b"h3".to_vec(), b"h3-29".to_vec(), b"hq-interop".to_vec()];

    let quic_config = QuicClientConfig::try_from(crypto).ok()?;
    let client_config = quinn::ClientConfig::new(Arc::new(quic_config));

    let mut endpoint = quinn::Endpoint::client("0.0.0.0:0".parse().ok()?).ok()?;
    endpoint.set_default_client_config(client_config);

    let addr = format!("{}:{}", host, port).parse().ok()?;

    let connect_future = endpoint.connect(addr, host);
    let connecting = match connect_future {
        Ok(c) => c,
        Err(_) => return None,
    };

    match tokio::time::timeout(Duration::from_secs(4), connecting).await {
        Ok(Ok(conn)) => {
            let alpn = conn
                .handshake_data()
                .and_then(|hd| {
                    hd.downcast::<quinn::crypto::rustls::HandshakeData>()
                        .ok()
                })
                .and_then(|hd| {
                    hd.protocol
                        .map(|p| String::from_utf8_lossy(&p).into_owned())
                });

            let protocol = match &alpn {
                Some(a) if a.starts_with("h3") => "HTTP/3".to_string(),
                Some(a) => a.clone(),
                None => "QUIC".to_string(),
            };

            Some(QuicProbeResult { protocol, alpn })
        }
        _ => None,
    }
}