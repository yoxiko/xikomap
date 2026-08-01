import sys
import os
import json

current_dir = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, current_dir)

from service_classifier import classify_service
from cms_framework_detector import detect_cms

def process_batch(input_data):
    results = []
    for item in input_data:
        ip = item.get("ip")
        port = item.get("port")
        protocol = item.get("protocol")
        banner = item.get("banner", "")
        http_body = item.get("http_body", "")
        http_headers = item.get("http_headers", "")
        
        service = classify_service(port, banner)
        cms = detect_cms(port, banner, http_body, http_headers)
        
        results.append({
            "ip": ip,
            "port": port,
            "protocol": protocol,
            "service": service,
            "cms": cms
        })
    return json.dumps(results)

if __name__ == "__main__":
    input_json = sys.stdin.read()
    try:
        data = json.loads(input_json)
        output = process_batch(data)
        print(output)
    except json.JSONDecodeError:
        print("[]")