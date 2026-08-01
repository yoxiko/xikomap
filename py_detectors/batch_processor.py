import sys
import os
import json
from typing import List, Dict, Any

current_dir = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, current_dir)

from service_classifier import classify_service
from cms_framework_detector import detect_cms
from technology_detector import TechnologyDetector
from misconfiguration_detector import MisconfigurationDetector
from ssl_tls_analyzer import SSLTLSAnalyzer

tech_detector = TechnologyDetector()
misconfig_detector = MisconfigurationDetector()
ssl_analyzer = SSLTLSAnalyzer()

def process_batch(input_data_str: str) -> str:
    try:
        data: List[Dict[str, Any]] = json.loads(input_data_str)
    except json.JSONDecodeError:
        return json.dumps([])
    
    results = []
    all_misconfigurations = []
    all_technologies = []
    last_ssl_analysis = {}
    
    for item in data:
        ip = str(item.get("ip", ""))
        port = int(item.get("port", 0))
        protocol = str(item.get("protocol", "tcp"))
        banner = str(item.get("banner", ""))
        http_body = str(item.get("http_body", ""))
        http_headers = str(item.get("http_headers", ""))
        
        service = classify_service(port, banner)
        cms = detect_cms(port, banner, http_body, http_headers)
        
        techs = tech_detector.detect(http_body, http_headers, banner)
        tech_names = [t.name for t in techs]
        all_technologies.extend(tech_names)
        
        misconfigs = misconfig_detector.detect(port, service, banner, http_body, http_headers)
        all_misconfigurations.extend([m.__dict__ for m in misconfigs])
        
        ssl_analysis = ssl_analyzer.analyze(port, http_headers, http_body, banner)
        last_ssl_analysis = ssl_analysis.__dict__
        
        risk_level = "low"
        if port in (21, 23, 3389, 445, 1433, 3306, 5432, 6379, 27017):
            risk_level = "high"
        elif port in (80, 443, 8080, 8443):
            risk_level = "medium"
            
        results.append({
            "ip": ip,
            "port": port,
            "protocol": protocol,
            "service": service,
            "cms": cms,
            "risk_level": risk_level,
            "technologies": tech_names,
            "misconfigurations_count": len(misconfigs),
            "ssl_risk": ssl_analysis.risk_level
        })
    
    output = {
        "target": data[0].get("ip", "unknown") if data else "unknown",
        "ports": results,
        "vulnerabilities": [],
        "misconfigurations": all_misconfigurations,
        "technologies": list(set(all_technologies)),
        "ssl_analysis": last_ssl_analysis
    }
    
    return json.dumps(output, default=str)

if __name__ == "__main__":
    input_json = sys.stdin.read()
    print(process_batch(input_json))