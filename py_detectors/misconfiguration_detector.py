from dataclasses import dataclass
from typing import List, Dict, Optional

@dataclass
class Misconfiguration:
    type: str
    severity: str
    description: str
    port: int
    service: str
    recommendation: str
    cvss_score: Optional[float] = None

class MisconfigurationDetector:
    def __init__(self):
        self.high_risk_ports = {
            21: {"service": "FTP", "issue": "Unencrypted file transfer protocol"},
            23: {"service": "Telnet", "issue": "Unencrypted remote access"},
            3389: {"service": "RDP", "issue": "Remote Desktop exposed to network"},
            445: {"service": "SMB", "issue": "Windows file sharing (WannaCry vector)"},
            1433: {"service": "MSSQL", "issue": "Database exposed to network"},
            3306: {"service": "MySQL", "issue": "Database exposed to network"},
            5432: {"service": "PostgreSQL", "issue": "Database exposed to network"},
            6379: {"service": "Redis", "issue": "In-memory database (often unauthenticated)"},
            27017: {"service": "MongoDB", "issue": "NoSQL database (often unauthenticated)"},
            9200: {"service": "Elasticsearch", "issue": "Search engine exposed (data leakage)"},
            11211: {"service": "Memcached", "issue": "DDoS amplification vector"},
            2181: {"service": "Zookeeper", "issue": "Coordination service exposed"},
            5601: {"service": "Kibana", "issue": "Elasticsearch UI exposed"},
            8086: {"service": "InfluxDB", "issue": "Time-series database exposed"},
            9090: {"service": "Prometheus", "issue": "Monitoring system exposed"},
        }
        
        self.admin_paths = [
            "/admin", "/administrator", "/phpmyadmin", "/wp-admin",
            "/manager", "/console", "/login", "/dashboard",
            "/cpanel", "/whm", "/pma", "/dbadmin"
        ]
    
    def detect(self, port: int, service: str, banner: str, http_body: str, http_headers: str) -> List[Misconfiguration]:
        misconfigs = []
        
        misconfigs.extend(self._check_exposed_services(port, service, banner))
        misconfigs.extend(self._check_admin_panels(port, http_body))
        misconfigs.extend(self._check_debug_mode(port, http_body))
        misconfigs.extend(self._check_default_credentials(port, service, banner))
        misconfigs.extend(self._check_missing_security_headers(port, http_headers))
        
        return misconfigs
    
    def _check_exposed_services(self, port: int, service: str, banner: str) -> List[Misconfiguration]:
        misconfigs = []
        
        if port in self.high_risk_ports:
            port_info = self.high_risk_ports[port]
            
            if "no password" in banner.lower() or "authentication disabled" in banner.lower():
                misconfigs.append(Misconfiguration(
                    type="unauthenticated_access",
                    severity="critical",
                    description=f"{port_info['service']} exposed without authentication",
                    port=port,
                    service=service,
                    recommendation="Enable authentication and restrict access to trusted IPs",
                    cvss_score=9.8
                ))
            else:
                misconfigs.append(Misconfiguration(
                    type="exposed_service",
                    severity="high",
                    description=f"{port_info['service']} exposed to network: {port_info['issue']}",
                    port=port,
                    service=service,
                    recommendation="Restrict access using firewall rules or VPN",
                    cvss_score=7.5
                ))
        
        return misconfigs
    
    def _check_admin_panels(self, port: int, http_body: str) -> List[Misconfiguration]:
        misconfigs = []
        
        if port in (80, 443, 8080, 8443, 3000, 5000):
            body_lower = http_body.lower()
            
            for path in self.admin_paths:
                if path in body_lower:
                    misconfigs.append(Misconfiguration(
                        type="admin_panel_exposed",
                        severity="high",
                        description=f"Admin panel accessible at {path}",
                        port=port,
                        service="HTTP",
                        recommendation="Restrict admin panel access with authentication and IP whitelisting",
                        cvss_score=7.0
                    ))
                    break
        
        return misconfigs
    
    def _check_debug_mode(self, port: int, http_body: str) -> List[Misconfiguration]:
        misconfigs = []
        
        if port in (80, 443, 8080, 8443):
            body_lower = http_body.lower()
            
            debug_indicators = [
                ("debug=true", "Application running in debug mode"),
                ("debug: true", "Debug mode enabled in configuration"),
                ("stack trace", "Stack trace exposed (information leakage)"),
                ("error_details", "Detailed error messages exposed"),
                ("var_dump", "PHP debug output exposed"),
                ("console.log", "JavaScript debug logs in production")
            ]
            
            for indicator, description in debug_indicators:
                if indicator in body_lower:
                    misconfigs.append(Misconfiguration(
                        type="debug_mode",
                        severity="medium",
                        description=description,
                        port=port,
                        service="HTTP",
                        recommendation="Disable debug mode in production environment",
                        cvss_score=5.0
                    ))
                    break
        
        return misconfigs
    
    def _check_default_credentials(self, port: int, service: str, banner: str) -> List[Misconfiguration]:
        misconfigs = []
        
        default_creds_indicators = {
            "FTP": ["anonymous", "230 login successful"],
            "MySQL": ["access denied for user 'root'@'localhost'"],
            "PostgreSQL": ["password authentication failed"],
            "Redis": ["no password set", "authentication disabled"],
            "MongoDB": ["no auth required", "authentication disabled"]
        }
        
        if service in default_creds_indicators:
            for indicator in default_creds_indicators[service]:
                if indicator in banner.lower():
                    misconfigs.append(Misconfiguration(
                        type="default_credentials",
                        severity="critical",
                        description=f"{service} may be using default or weak credentials",
                        port=port,
                        service=service,
                        recommendation="Change default credentials immediately and enforce strong password policy",
                        cvss_score=9.0
                    ))
                    break
        
        return misconfigs
    
    def _check_missing_security_headers(self, port: int, http_headers: str) -> List[Misconfiguration]:
        misconfigs = []
        
        if port not in (80, 443, 8080, 8443):
            return misconfigs
        
        required_headers = {
            "strict-transport-security": ("Missing HSTS header", "Add Strict-Transport-Security header to enforce HTTPS", 6.0),
            "x-content-type-options": ("Missing X-Content-Type-Options", "Add X-Content-Type-Options: nosniff header", 4.0),
            "x-frame-options": ("Missing X-Frame-Options", "Add X-Frame-Options header to prevent clickjacking", 5.0),
            "content-security-policy": ("Missing Content-Security-Policy", "Implement CSP to prevent XSS attacks", 6.5),
            "x-xss-protection": ("Missing X-XSS-Protection", "Add X-XSS-Protection header", 4.5)
        }
        
        headers_lower = http_headers.lower()
        
        for header, (description, recommendation, cvss) in required_headers.items():
            if header not in headers_lower:
                misconfigs.append(Misconfiguration(
                    type="missing_security_header",
                    severity="low",
                    description=description,
                    port=port,
                    service="HTTP",
                    recommendation=recommendation,
                    cvss_score=cvss
                ))
        
        return misconfigs
    
    def get_critical(self, misconfigs: List[Misconfiguration]) -> List[Misconfiguration]:
        return [m for m in misconfigs if m.severity == "critical"]
    
    def get_high(self, misconfigs: List[Misconfiguration]) -> List[Misconfiguration]:
        return [m for m in misconfigs if m.severity == "high"]