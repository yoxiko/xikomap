import socket
import ssl
import struct
import re
from typing import Dict, Any, List, Optional
from core.constants import PROTOCOL_SIGNATURES

class ServiceDetector:
    def __init__(self, timeout: float = 3.0, verbose: bool = False):
        self.timeout = timeout
        self.verbose = verbose
        self.detection_plugins = {
            'http': self.detect_http_advanced,
            'ssh': self.detect_ssh_advanced,
            'ftp': self.detect_ftp_advanced,
            'smtp': self.detect_smtp_advanced,
            'database': self.detect_database_advanced,
        }
    
    def deep_detect(self, target: str, port: int, initial_service: str) -> List[Dict[str, Any]]:
        if initial_service in self.detection_plugins:
            return self.detection_plugins[initial_service](target, port)
        return []
    
    def detect_http_advanced(self, target: str, port: int) -> List[Dict[str, Any]]:
        results = []
        
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((target, port))
            
            sock.send(b"GET / HTTP/1.1\r\nHost: " + target.encode() + b"\r\n\r\n")
            response = sock.recv(4096).decode('utf-8', errors='ignore')
            sock.close()
            
            if 'HTTP/' in response:
                server_info = "Unknown"
                if 'Server:' in response:
                    server_match = re.search(r'Server:\s*([^\r\n]+)', response)
                    if server_match:
                        server_info = server_match.group(1)
                
                technologies = self.analyze_http_technologies(response)
                
                results.append({
                    'service': 'http',
                    'confidence': 0.95,
                    'banner': f"HTTP Server: {server_info}",
                    'technologies': technologies
                })
                
        except Exception:
            pass
        
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            with socket.create_connection((target, port), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=target) as ssock:
                    cert = ssock.getpeercert()
                    ssock.send(b"GET / HTTP/1.1\r\nHost: " + target.encode() + b"\r\n\r\n")
                    response = ssock.recv(4096).decode('utf-8', errors='ignore')
                    
                    if 'HTTP/' in response:
                        results.append({
                            'service': 'https',
                            'confidence': 0.98,
                            'banner': "HTTPS with SSL/TLS",
                            'certificate': bool(cert)
                        })
        except Exception:
            pass
        
        return results
    
    def detect_ssh_advanced(self, target: str, port: int) -> List[Dict[str, Any]]:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((target, port))
            
            banner = sock.recv(1024).decode('utf-8', errors='ignore')
            sock.close()
            
            if 'SSH-' in banner:
                ssh_version = "Unknown"
                if 'OpenSSH' in banner:
                    ssh_version = "OpenSSH"
                elif 'Dropbear' in banner:
                    ssh_version = "Dropbear"
                
                return [{
                    'service': 'ssh',
                    'confidence': 0.98,
                    'banner': banner.strip(),
                    'version': ssh_version
                }]
        except Exception:
            pass
        
        return []
    
    def detect_ftp_advanced(self, target: str, port: int) -> List[Dict[str, Any]]:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((target, port))
            
            banner = sock.recv(1024).decode('utf-8', errors='ignore')
            
            sock.send(b"SYST\r\n")
            syst_response = sock.recv(1024).decode('utf-8', errors='ignore')
            
            sock.close()
            
            if '220' in banner:
                ftp_type = "Unknown"
                if 'vsFTPd' in banner:
                    ftp_type = "vsFTPd"
                elif 'ProFTPD' in banner:
                    ftp_type = "ProFTPD"
                elif 'Pure-FTPd' in banner:
                    ftp_type = "Pure-FTPd"
                
                return [{
                    'service': 'ftp',
                    'confidence': 0.95,
                    'banner': banner.strip(),
                    'syst_response': syst_response.strip(),
                    'type': ftp_type
                }]
        except Exception:
            pass
        
        return []
    
    def detect_smtp_advanced(self, target: str, port: int) -> List[Dict[str, Any]]:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((target, port))
            
            banner = sock.recv(1024).decode('utf-8', errors='ignore')
            
            sock.send(b"EHLO example.com\r\n")
            ehlo_response = sock.recv(2048).decode('utf-8', errors='ignore')
            
            sock.close()
            
            if '220' in banner:
                smtp_type = "Unknown"
                if 'Postfix' in banner:
                    smtp_type = "Postfix"
                elif 'Exim' in banner:
                    smtp_type = "Exim"
                elif 'Sendmail' in banner:
                    smtp_type = "Sendmail"
                
                return [{
                    'service': 'smtp',
                    'confidence': 0.92,
                    'banner': banner.strip(),
                    'type': smtp_type,
                    'capabilities': ehlo_response
                }]
        except Exception:
            pass
        
        return []
    
    def detect_database_advanced(self, target: str, port: int) -> List[Dict[str, Any]]:
        results = []
        
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((target, port))
            
            banner = sock.recv(1024)
            if len(banner) > 4 and banner[4] == 10:
                results.append({
                    'service': 'mysql',
                    'confidence': 0.90,
                    'banner': "MySQL Database",
                    'version': f"Protocol {banner[4]}"
                })
            sock.close()
        except Exception:
            pass
        
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((target, port))
            
            sock.send(struct.pack('!I', 8) + b'\x00\x03\x00\x00' + b'user\0test\0\0')
            response = sock.recv(1024)
            
            if b'PostgreSQL' in response or response[0] == 'E':
                results.append({
                    'service': 'postgresql',
                    'confidence': 0.88,
                    'banner': "PostgreSQL Database"
                })
            sock.close()
        except Exception:
            pass
        
        return results
    
    def analyze_http_technologies(self, response: str) -> List[str]:
        technologies = []
        
        tech_patterns = {
            'Apache': [r'Apache', r'httpd'],
            'Nginx': [r'nginx'],
            'IIS': [r'Microsoft-IIS', r'IIS'],
            'PHP': [r'PHP', r'X-Powered-By:\s*PHP'],
            'ASP.NET': [r'ASP.NET', r'X-AspNet-Version'],
            'WordPress': [r'wp-', r'wordpress'],
            'Django': [r'CSRF_TOKEN', r'django'],
            'React': [r'React', r'_next/static'],
            'Node.js': [r'Express', r'X-Powered-By:\s*Express'],
        }
        
        for tech, patterns in tech_patterns.items():
            for pattern in patterns:
                if re.search(pattern, response, re.IGNORECASE):
                    technologies.append(tech)
                    break
        
        return technologies