import sys
import os
import json
from typing import List, Dict, Any

current_dir = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, current_dir)

from service_classifier import classify_service
from cms_framework_detector import detect_cms

def process_batch(input_data_str: str) -> str:
    try:
        data: List[Dict[str, Any]] = json.loads(input_data_str)
    except json.JSONDecodeError:
        return json.dumps([])
    
    results = []
    for item in data:
        ip = str(item.get("ip", ""))
        port = int(item.get("port", 0))
        protocol = str(item.get("protocol", "tcp"))
        banner = str(item.get("banner", ""))
        http_body = str(item.get("http_body", ""))
        http_headers = str(item.get("http_headers", ""))
        
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
    print(process_batch(input_json))