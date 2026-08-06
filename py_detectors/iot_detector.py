import socket
import json
import sys
from typing import Dict, List

class IoTDetector:
    def __init__(self):
        self.mqtt_port = 1883
        self.coap_port = 5683

    def detect_mqtt(self, host, port=1883, timeout=3):
        result = {"detected": False, "version": None, "features": []}

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            sock.connect((host, port))

            connect_packet = bytearray(
                [
                    0x10,
                    0x0F,
                    0x00,
                    0x04,
                    0x4D,
                    0x51,
                    0x54,
                    0x54,
                    0x04,
                    0x02,
                    0x00,
                    0x3C,
                    0x00,
                    0x04,
                    0x74,
                    0x65,
                    0x73,
                    0x74,
                ]
            )

            sock.send(connect_packet)
            response = sock.recv(4)

            if response and len(response) >= 2:
                packet_type = response[0] >> 4
                if packet_type == 2:
                    return_code = response[3]
                    result["detected"] = True
                    result["version"] = "MQTT 3.1.1"
                    if return_code == 0:
                        result["features"].append("Authentication: None/Open")
                    else:
                        result["features"].append(
                            f"Authentication required (code: {return_code})"
                        )

            sock.close()

        except Exception as e:
            result["error"] = str(e)

        return result

    def detect_coap(self, host, port=5683, timeout=3):
        result = {"detected": False, "resources": []}

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(timeout)

            coap_request = bytearray(
                [
                    0x40,
                    0x01,
                    0x00,
                    0x01,
                    0xB4,
                    0x2E,
                    0x77,
                    0x65,
                    0x6C,
                    0x6C,
                    0x2D,
                    0x6B,
                    0x6E,
                    0x6F,
                    0x77,
                    0x6E,
                    0x04,
                    0x63,
                    0x6F,
                    0x72,
                    0x65,
                ]
            )

            sock.sendto(coap_request, (host, port))

            try:
                response, _ = sock.recvfrom(1024)
                if response and len(response) > 4:
                    result["detected"] = True
                    try:
                        payload = response[4:].decode("utf-8", errors="ignore")
                        resources = [r.split('"')[1] for r in payload.split("<") if '"' in r]
                        result["resources"] = resources[:5]
                    except Exception:
                        pass
            except socket.timeout:
                pass

            sock.close()

        except Exception as e:
            result["error"] = str(e)

        return result

    def detect(self, host, ports=None):
        if ports is None:
            ports = []

        results = {"iot_devices": [], "mqtt": None, "coap": None}

        if self.mqtt_port in ports or not ports:
            mqtt_result = self.detect_mqtt(host, self.mqtt_port)
            if mqtt_result["detected"]:
                results["mqtt"] = mqtt_result
                results["iot_devices"].append("MQTT Broker")

        if self.coap_port in ports or not ports:
            coap_result = self.detect_coap(host, self.coap_port)
            if coap_result["detected"]:
                results["coap"] = coap_result
                results["iot_devices"].append("CoAP Device")

        iot_ports = [8080, 8883, 5684, 5685]
        for port in iot_ports:
            if port in ports:
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(2)
                    connect_result = sock.connect_ex((host, port))
                    if connect_result == 0:
                        results["iot_devices"].append(f"IoT Service on port {port}")
                    sock.close()
                except Exception:
                    pass

        return results


if __name__ == "__main__":
    if len(sys.argv) > 1:
        detector = IoTDetector()
        ports = [int(p) for p in sys.argv[2].split(",")] if len(sys.argv) > 2 else []
        result = detector.detect(sys.argv[1], ports)
        print(json.dumps(result, indent=2))