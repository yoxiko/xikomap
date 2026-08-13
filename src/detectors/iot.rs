use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::net::UdpSocket;

pub struct IoTDetector;

pub struct MqttResult {
    pub detected: bool,
    pub version: Option<String>,
    pub features: Vec<String>,
}

pub struct CoapResult {
    pub detected: bool,
    pub resources: Vec<String>,
}

pub struct IotResult {
    pub mqtt: Option<MqttResult>,
    pub coap: Option<CoapResult>,
}

impl IoTDetector {
    pub async fn detect_mqtt(host: &str, port: u16, timeout: Duration) -> MqttResult {
        let mut result = MqttResult {
            detected: false,
            version: None,
            features: Vec::new(),
        };

        let addr = format!("{}:{}", host, port);
        if let Ok(stream) = TcpStream::connect(&addr).await {
            if let Ok(stream) = tokio::time::timeout(timeout, async { Ok::<_, std::io::Error>(stream) }).await {
                let mut stream = stream.unwrap();

                let connect_packet: [u8; 19] = [
                    0x10, 0x0F, 0x00, 0x04, 0x4D, 0x51, 0x54, 0x54, 0x04, 0x02, 0x00, 0x3C, 0x00,
                    0x04, 0x74, 0x65, 0x73, 0x74, 0x00,
                ];

                if stream.write_all(&connect_packet).await.is_ok() {
                    let mut response = [0u8; 4];
                    if let Ok(Ok(n)) = tokio::time::timeout(timeout, stream.read(&mut response)).await
                    {
                        if n >= 2 {
                            let packet_type = response[0] >> 4;
                            if packet_type == 2 {
                                let return_code = response[3];
                                result.detected = true;
                                result.version = Some("MQTT 3.1.1".to_string());
                                if return_code == 0 {
                                    result
                                        .features
                                        .push("Authentication: None/Open".to_string());
                                } else {
                                    result.features.push(format!(
                                        "Authentication required (code: {})",
                                        return_code
                                    ));
                                }
                            }
                        }
                    }
                }
            }
        }

        result
    }

    pub async fn detect_coap(host: &str, port: u16, timeout: Duration) -> CoapResult {
        let mut result = CoapResult {
            detected: false,
            resources: Vec::new(),
        };

        let addr = format!("{}:{}", host, port);
        if let Ok(socket) = UdpSocket::bind("0.0.0.0:0").await {
            if socket.connect(&addr).await.is_ok() {
                let get_request: [u8; 11] = [
                    0x40, 0x01, 0x30, 0x39, 0xB1, 0x2E, 0x77, 0x65, 0x6C, 0x6C, 0x6E,
                ];

                if socket.send(&get_request).await.is_ok() {
                    let mut buf = [0u8; 1024];
                    if let Ok(Ok(n)) = tokio::time::timeout(timeout, socket.recv(&mut buf)).await {
                        if n > 0 {
                            result.detected = true;
                            if buf[0] & 0x70 == 0x40 {
                                result
                                    .resources
                                    .push("CoAP response received".to_string());
                            }
                        }
                    }
                }
            }
        }

        result
    }
}