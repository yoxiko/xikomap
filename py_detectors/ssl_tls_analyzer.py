from dataclasses import dataclass
from typing import List, Dict, Optional
import re

@dataclass
class SSLAnalysis:
    has_ssl: bool
    port: int
    protocols_supported: List[str]
    weak_protocols: List[str]
    security_headers: Dict[str, bool]
    certificate_info: Optional[Dict[str, str]]
    recommendations: List[str]
    risk_level: str

class SSLTLSAnalyzer:
    def __init__(self):
        self.ssl_ports = {443, 8443, 993, 995, 465, 587, 636, 3389}
        
        self.security_headers = {
            "strict-transport-security": "Enforces HTTPS connections",
            "x-content-type-options": "Prevents MIME-type sniffing",
            "x-frame-options": "Prevents clickjacking attacks",
            "content-security-policy": "Prevents XSS and data injection",
            "x-xss-protection": "Enables browser XSS filtering",
            "referrer-policy": "Controls referrer information",
            "permissions-policy": "Controls browser features",
            "cache-control": "Prevents sensitive data caching"
        }
        
        self.weak_protocols = ["SSLv2", "SSLv3", "TLSv1.0", "TLSv1.1"]
        self.strong_protocols = ["TLSv1.2", "TLSv1.3"]
    
    def analyze(self, port: int, http_headers: str, http_body: str, banner: str) -> SSLAnalysis:
        has_ssl = port in self.ssl_ports
        protocols = self._detect_protocols(port, banner, http_headers)
        weak = [p for p in protocols if p in self.weak_protocols]
        headers_analysis = self._check_security_headers(http_headers)
        cert_info = self._extract_certificate_info(http_headers)
        recommendations = self._generate_recommendations(has_ssl, weak, headers_analysis)
        risk = self._calculate_risk(has_ssl, weak, headers_analysis)
        
        return SSLAnalysis(
            has_ssl=has_ssl,
            port=port,
            protocols_supported=protocols,
            weak_protocols=weak,
            security_headers=headers_analysis,
            certificate_info=cert_info,
            recommendations=recommendations,
            risk_level=risk
        )
    
    def _detect_protocols(self, port: int, banner: str, headers: str) -> List[str]:
        protocols = []
        text = (banner + headers).lower()
        
        if "tls/1.3" in text or "tlsv1.3" in text:
            protocols.append("TLSv1.3")
        if "tls/1.2" in text or "tlsv1.2" in text:
            protocols.append("TLSv1.2")
        if "tls/1.1" in text or "tlsv1.1" in text:
            protocols.append("TLSv1.1")
        if "tls/1.0" in text or "tlsv1.0" in text:
            protocols.append("TLSv1.0")
        if "sslv3" in text or "ssl-v3" in text:
            protocols.append("SSLv3")
        if "sslv2" in text or "ssl-v2" in text:
            protocols.append("SSLv2")
        
        if port in self.ssl_ports and not protocols:
            protocols.append("TLSv1.2")
        
        return protocols
    
    def _check_security_headers(self, headers: str) -> Dict[str, bool]:
        headers_lower = headers.lower()
        analysis = {}
        
        for header in self.security_headers.keys():
            analysis[header] = header in headers_lower
        
        return analysis
    
    def _extract_certificate_info(self, headers: str) -> Optional[Dict[str, str]]:
        cert_info = {}
        
        if "x-ssl" in headers.lower():
            cert_info["ssl_enabled"] = "true"
        
        if "strict-transport-security" in headers.lower():
            match = re.search(r'max-age=(\d+)', headers, re.IGNORECASE)
            if match:
                cert_info["hsts_max_age"] = match.group(1)
        
        return cert_info if cert_info else None
    
    def _generate_recommendations(self, has_ssl: bool, weak_protocols: List[str], headers: Dict[str, bool]) -> List[str]:
        recommendations = []
        
        if not has_ssl:
            recommendations.append("Enable SSL/TLS encryption for this service")
        
        if "SSLv2" in weak_protocols or "SSLv3" in weak_protocols:
            recommendations.append("Disable SSLv2 and SSLv3 - they have critical vulnerabilities")
        
        if "TLSv1.0" in weak_protocols or "TLSv1.1" in weak_protocols:
            recommendations.append("Upgrade from TLS 1.0/1.1 to TLS 1.2 or 1.3")
        
        if not headers.get("strict-transport-security"):
            recommendations.append("Add Strict-Transport-Security header to enforce HTTPS")
        
        if not headers.get("content-security-policy"):
            recommendations.append("Implement Content-Security-Policy to prevent XSS")
        
        if not headers.get("x-frame-options"):
            recommendations.append("Add X-Frame-Options header to prevent clickjacking")
        
        return recommendations
    
    def _calculate_risk(self, has_ssl: bool, weak_protocols: List[str], headers: Dict[str, bool]) -> str:
        if not has_ssl:
            return "critical"
        
        if any(p in weak_protocols for p in ["SSLv2", "SSLv3"]):
            return "high"
        
        missing_headers = sum(1 for v in headers.values() if not v)
        
        if missing_headers >= 5:
            return "high"
        elif missing_headers >= 3:
            return "medium"
        elif missing_headers >= 1:
            return "low"
        
        return "secure"
    
    def get_secure_score(self, analysis: SSLAnalysis) -> float:
        score = 100.0
        
        if not analysis.has_ssl:
            score -= 50
        
        score -= len(analysis.weak_protocols) * 15
        
        missing_headers = sum(1 for v in analysis.security_headers.values() if not v)
        score -= missing_headers * 5
        
        return max(0, min(100, score))