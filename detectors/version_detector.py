import re
import socket
import requests
from typing import Dict, List, Optional, Tuple, Any
from urllib.parse import urljoin, urlparse
import ssl
import struct
import json

class VersionDetector:
    def __init__(self, timeout: float = 5.0):
        self.timeout = timeout
        self.detection_cache = {}
        
        self.version_patterns = {
            'nginx': {
                'patterns': [r'nginx/(\d+\.\d+\.\d+)', r'nginx/(\d+\.\d+)'],
                'headers': ['server'],
                'ports': [80, 443, 8080, 8443]
            },
            'apache': {
                'patterns': [
                    r'Apache/(\d+\.\d+\.\d+)', 
                    r'Apache/(\d+\.\d+)',
                    r'Apache/(\d+)'
                ],
                'headers': ['server'],
                'ports': [80, 443, 8080]
            },
            'iis': {
                'patterns': [
                    r'Microsoft-IIS/(\d+\.\d+)',
                    r'IIS/(\d+\.\d+)'
                ],
                'headers': ['server'],
                'ports': [80, 443]
            },
            'lighttpd': {
                'patterns': [r'lighttpd/(\d+\.\d+\.\d+)'],
                'headers': ['server'],
                'ports': [80, 443]
            },
            'caddy': {
                'patterns': [r'Caddy/(\d+\.\d+\.\d+)'],
                'headers': ['server'],
                'ports': [80, 443, 2019]
            },
            
            'php': {
                'patterns': [
                    r'PHP/(\d+\.\d+\.\d+)',
                    r'PHP/(\d+\.\d+)',
                    r'X-Powered-By: PHP/(\d+\.\d+\.\d+)'
                ],
                'headers': ['x-powered-by'],
                'ports': [80, 443, 8080]
            },
            'python': {
                'patterns': [
                    r'Python/(\d+\.\d+\.\d+)',
                    r'Python/(\d+\.\d+)',
                    r'WSGIServer/(\d+\.\d+\.\d+)'
                ],
                'headers': ['server'],
                'ports': [80, 443, 8000, 8080]
            },
            'node.js': {
                'patterns': [
                    r'Node\.js/(\d+\.\d+\.\d+)',
                    r'Node/(\d+\.\d+\.\d+)'
                ],
                'headers': ['x-powered-by'],
                'ports': [80, 443, 3000, 5000]
            },
            
            'mysql': {
                'patterns': [
                    r'(\d+\.\d+\.\d+).*MySQL',
                    r'MySQL.*(\d+\.\d+\.\d+)'
                ],
                'banner_ports': [3306, 3307],
                'protocol': 'mysql'
            },
            'postgresql': {
                'patterns': [r'PostgreSQL (\d+\.\d+\.\d+)'],
                'banner_ports': [5432, 5433],
                'protocol': 'postgresql'
            },
            'mongodb': {
                'patterns': [r'MongoDB (\d+\.\d+\.\d+)'],
                'banner_ports': [27017, 27018],
                'protocol': 'mongodb'
            },
            'redis': {
                'patterns': [r'redis_version:(\d+\.\d+\.\d+)'],
                'banner_ports': [6379],
                'protocol': 'redis'
            },
            'elasticsearch': {
                'patterns': [
                    r'"number"\s*:\s*"(\d+\.\d+\.\d+)"',
                    r'"version"\s*:\s*{"number"\s*:\s*"(\d+\.\d+\.\d+)"'
                ],
                'api_ports': [9200, 9300],
                'api_path': '/'
            },
            
            'wordpress': {
                'patterns': [
                    r'WordPress (\d+\.\d+\.\d+)',
                    r'wp-includes/js/wp-embed\.js\?ver=(\d+\.\d+\.\d+)',
                    r'content="WordPress (\d+\.\d+\.\d+)'
                ],
                'file_patterns': {
                    '/readme.html': r'Version (\d+\.\d+\.\d+)',
                    '/wp-includes/version.php': r'\$wp_version\s*=\s*[\'"](\d+\.\d+\.\d+)[\'"]'
                },
                'ports': [80, 443]
            },
            'joomla': {
                'patterns': [
                    r'Joomla! (\d+\.\d+\.\d+)',
                    r'content="Joomla! (\d+\.\d+\.\d+)'
                ],
                'file_patterns': {
                    '/administrator/manifests/files/joomla.xml': r'<version>(\d+\.\d+\.\d+)</version>'
                },
                'ports': [80, 443]
            },
            'drupal': {
                'patterns': [
                    r'Drupal (\d+\.\d+\.\d+)',
                    r'content="Drupal (\d+\.\d+\.\d+)'
                ],
                'file_patterns': {
                    '/core/CHANGELOG.txt': r'Drupal (\d+\.\d+\.\d+)',
                    '/misc/drupal.js': r'Drupal (\d+\.\d+\.\d+)'
                },
                'ports': [80, 443]
            },
            
            'tomcat': {
                'patterns': [r'Apache Tomcat/(\d+\.\d+\.\d+)'],
                'headers': ['server'],
                'ports': [8080, 8009, 8443]
            },
            'jetty': {
                'patterns': [r'Jetty/(\d+\.\d+\.\d+)'],
                'headers': ['server'],
                'ports': [8080, 8443]
            },
            'glassfish': {
                'patterns': [r'GlassFish Server Open Source Edition (\d+\.\d+\.\d+)'],
                'headers': ['server'],
                'ports': [8080, 4848, 8181]
            },
            
            'docker': {
                'patterns': [r'"Version":"(\d+\.\d+\.\d+)"'],
                'api_ports': [2375, 2376],
                'api_path': '/version'
            },
            'kubernetes': {
                'patterns': [r'"gitVersion":"v(\d+\.\d+\.\d+)"'],
                'api_ports': [6443, 8080],
                'api_path': '/version'
            },
            'jenkins': {
                'patterns': [r'Jenkins ver\. (\d+\.\d+)'],
                'ports': [8080, 8081],
                'headers': ['x-jenkins']
            },
            
            # Security Devices
            'fortinet': {
                'patterns': [r'FortiGate(\d+\.\d+\.\d+)'],
                'ports': [443],
                'headers': ['server']
            },
            'paloalto': {
                'patterns': [r'Palo Alto Networks (\d+\.\d+\.\d+)'],
                'ports': [443],
                'headers': ['server']
            }
        }
        
        self.common_version_files = [
            '/readme.html',
            '/CHANGELOG.txt',
            '/RELEASE_NOTES.txt',
            '/version.txt',
            '/VERSION',
            '/build.txt',
            '/meta/version',
            '/api/version',
            '/status',
            '/info'
        ]

    def detect_versions(self, target: str, port: int, service: str = None, 
                       protocol: str = 'tcp', use_ssl: bool = False) -> Dict[str, Any]:
        cache_key = f"{target}:{port}:{service}:{protocol}:{use_ssl}"
        if cache_key in self.detection_cache:
            return self.detection_cache[cache_key]
        
        results = {
            'service': service,
            'versions': [],
            'confidence': 0,
            'methods_used': [],
            'raw_data': {}
        }
        
        if service and service.lower() in self.version_patterns:
            service_info = self.version_patterns[service.lower()]
            results.update(self._service_specific_detection(target, port, service_info, use_ssl))
        
        general_results = self._general_detection(target, port, protocol, use_ssl)
        results['versions'].extend(general_results.get('versions', []))
        results['methods_used'].extend(general_results.get('methods_used', []))
        results['raw_data'].update(general_results.get('raw_data', {}))
        
        if results['versions']:
            results['confidence'] = self._calculate_confidence(results)
        
        self.detection_cache[cache_key] = results
        return results

    def _service_specific_detection(self, target: str, port: int, 
                                  service_info: Dict, use_ssl: bool) -> Dict[str, Any]:
        results = {
            'versions': [],
            'methods_used': [],
            'raw_data': {}
        }
        
        if service_info.get('ports') and port in service_info['ports']:
            http_versions = self._detect_http_versions(target, port, service_info, use_ssl)
            results['versions'].extend(http_versions.get('versions', []))
            results['methods_used'].extend(http_versions.get('methods_used', []))
            results['raw_data'].update(http_versions.get('raw_data', {}))
        
        if service_info.get('banner_ports') and port in service_info['banner_ports']:
            banner_versions = self._detect_banner_versions(target, port, service_info)
            results['versions'].extend(banner_versions.get('versions', []))
            results['methods_used'].extend(banner_versions.get('methods_used', []))
            results['raw_data'].update(banner_versions.get('raw_data', {}))
        
        if service_info.get('api_ports') and port in service_info['api_ports']:
            api_versions = self._detect_api_versions(target, port, service_info, use_ssl)
            results['versions'].extend(api_versions.get('versions', []))
            results['methods_used'].extend(api_versions.get('methods_used', []))
            results['raw_data'].update(api_versions.get('raw_data', {}))
        
        if service_info.get('protocol'):
            protocol_versions = self._detect_protocol_versions(target, port, service_info)
            results['versions'].extend(protocol_versions.get('versions', []))
            results['methods_used'].extend(protocol_versions.get('methods_used', []))
            results['raw_data'].update(protocol_versions.get('raw_data', {}))
        
        return results

    def _general_detection(self, target: str, port: int, protocol: str, use_ssl: bool) -> Dict[str, Any]:
        results = {
            'versions': [],
            'methods_used': [],
            'raw_data': {}
        }
        
        banner_result = self._grab_banner(target, port, protocol)
        if banner_result:
            results['raw_data']['banner'] = banner_result
            results['methods_used'].append('banner_grabbing')
            
            banner_versions = self._extract_versions_from_text(banner_result)
            results['versions'].extend(banner_versions)
        
        if protocol == 'tcp' and port in [80, 443, 8080, 8443, 8000, 3000]:
            http_result = self._detect_http_versions_general(target, port, use_ssl)
            results['versions'].extend(http_result.get('versions', []))
            results['methods_used'].extend(http_result.get('methods_used', []))
            results['raw_data'].update(http_result.get('raw_data', {}))
        
        if use_ssl or port in [443, 8443, 993, 995]:
            ssl_result = self._check_ssl_certificate(target, port)
            if ssl_result:
                results['raw_data']['ssl_info'] = ssl_result
                results['methods_used'].append('ssl_inspection')
        
        return results

    def _detect_http_versions(self, target: str, port: int, service_info: Dict, use_ssl: bool) -> Dict[str, Any]:
        results = {
            'versions': [],
            'methods_used': [],
            'raw_data': {}
        }
        
        protocol = "https" if use_ssl else "http"
        base_url = f"{protocol}://{target}:{port}"
        
        try:
            response = requests.get(
                base_url,
                timeout=self.timeout,
                headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'},
                verify=False
            )
            
            results['raw_data']['http_response'] = {
                'headers': dict(response.headers),
                'status_code': response.status_code,
                'content_sample': response.text[:1000]
            }
            

            headers_str = str(response.headers)
            header_versions = self._extract_versions_with_patterns(headers_str, service_info['patterns'])
            results['versions'].extend(header_versions)
            
            if header_versions:
                results['methods_used'].append('http_headers')
            
            content_versions = self._extract_versions_with_patterns(response.text, service_info['patterns'])
            results['versions'].extend(content_versions)
            
            if content_versions:
                results['methods_used'].append('http_content')
            
            if service_info.get('file_patterns'):
                file_versions = self._check_version_files(target, port, service_info['file_patterns'], use_ssl)
                results['versions'].extend(file_versions)
                
                if file_versions:
                    results['methods_used'].append('version_files')
        
        except Exception as e:
            results['raw_data']['http_error'] = str(e)
        
        return results

    def _detect_banner_versions(self, target: str, port: int, service_info: Dict) -> Dict[str, Any]:
        results = {
            'versions': [],
            'methods_used': [],
            'raw_data': {}
        }
        
        try:
            banner = self._grab_banner(target, port, 'tcp')
            if banner:
                results['raw_data']['banner'] = banner
                banner_versions = self._extract_versions_with_patterns(banner, service_info['patterns'])
                results['versions'].extend(banner_versions)
                
                if banner_versions:
                    results['methods_used'].append('banner_analysis')
        
        except Exception as e:
            results['raw_data']['banner_error'] = str(e)
        
        return results

    def _detect_api_versions(self, target: str, port: int, service_info: Dict, use_ssl: bool) -> Dict[str, Any]:
        results = {
            'versions': [],
            'methods_used': [],
            'raw_data': {}
        }
        
        protocol = "https" if use_ssl else "http"
        api_path = service_info.get('api_path', '/')
        api_url = f"{protocol}://{target}:{port}{api_path}"
        
        try:
            response = requests.get(
                api_url,
                timeout=self.timeout,
                verify=False
            )
            
            if response.status_code == 200:
                results['raw_data']['api_response'] = response.text
                
                api_versions = self._extract_versions_with_patterns(response.text, service_info['patterns'])
                results['versions'].extend(api_versions)
                
                if api_versions:
                    results['methods_used'].append('api_query')
        
        except Exception as e:
            results['raw_data']['api_error'] = str(e)
        
        return results

    def _detect_protocol_versions(self, target: str, port: int, service_info: Dict) -> Dict[str, Any]:
        results = {
            'versions': [],
            'methods_used': [],
            'raw_data': {}
        }
        
        protocol = service_info.get('protocol', '').lower()
        
        try:
            if protocol == 'mysql':
                mysql_version = self._get_mysql_version(target, port)
                if mysql_version:
                    results['versions'].append({
                        'version': mysql_version,
                        'method': 'mysql_protocol',
                        'confidence': 90
                    })
                    results['methods_used'].append('mysql_protocol')
            
            elif protocol == 'ssh':
                ssh_version = self._get_ssh_version(target, port)
                if ssh_version:
                    results['versions'].append({
                        'version': ssh_version,
                        'method': 'ssh_banner',
                        'confidence': 95
                    })
                    results['methods_used'].append('ssh_banner')
                    
        except Exception as e:
            results['raw_data']['protocol_error'] = str(e)
        
        return results

    def _detect_http_versions_general(self, target: str, port: int, use_ssl: bool) -> Dict[str, Any]:
        results = {
            'versions': [],
            'methods_used': [],
            'raw_data': {}
        }
        
        protocol = "https" if use_ssl else "http"
        base_url = f"{protocol}://{target}:{port}"
        
        try:
            response = requests.get(
                base_url,
                timeout=self.timeout,
                headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'},
                verify=False
            )
            

            headers_str = str(response.headers)
            for service_name, service_info in self.version_patterns.items():
                if service_info.get('headers'):
                    versions = self._extract_versions_with_patterns(headers_str, service_info['patterns'])
                    for version in versions:
                        version['service'] = service_name
                        results['versions'].append(version)
            
            content_versions = self._extract_versions_from_text(response.text)
            results['versions'].extend(content_versions)
            
            if results['versions']:
                results['methods_used'].extend(['http_headers', 'http_content'])
            
            file_versions = self._check_common_version_files(target, port, use_ssl)
            results['versions'].extend(file_versions)
            
            if file_versions:
                results['methods_used'].append('common_files')
        
        except Exception as e:
            results['raw_data']['general_http_error'] = str(e)
        
        return results

    def _grab_banner(self, target: str, port: int, protocol: str) -> str:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((target, port))
            
            banner = sock.recv(1024).decode('utf-8', errors='ignore')
            sock.close()
            return banner
            
        except Exception:
            return ""

    def _extract_versions_with_patterns(self, text: str, patterns: List[str]) -> List[Dict]:
        versions = []
        
        for pattern in patterns:
            matches = re.finditer(pattern, text, re.IGNORECASE)
            for match in matches:
                if match.groups():
                    version_str = match.group(1)
                    confidence = self._assess_version_confidence(version_str, pattern)
                    
                    versions.append({
                        'version': version_str,
                        'method': 'pattern_match',
                        'pattern': pattern,
                        'confidence': confidence
                    })
        
        return versions

    def _extract_versions_from_text(self, text: str) -> List[Dict]:
        versions = []
        
        general_patterns = [
            r'v?(\d+\.\d+\.\d+)',  
            r'v?(\d+\.\d+)',       
            r'version\s*[=:]\s*[\'"]?v?(\d+\.\d+\.\d+)[\'"]?',
            r'ver\.?\s*(\d+\.\d+\.\d+)',
            r'release\s*(\d+\.\d+\.\d+)'
        ]
        
        for pattern in general_patterns:
            matches = re.finditer(pattern, text, re.IGNORECASE)
            for match in matches:
                if match.groups():
                    version_str = match.group(1)
                    confidence = self._assess_version_confidence(version_str, pattern)
                    
                    versions.append({
                        'version': version_str,
                        'method': 'general_pattern',
                        'pattern': pattern,
                        'confidence': confidence
                    })
        
        return versions

    def _check_version_files(self, target: str, port: int, file_patterns: Dict[str, str], use_ssl: bool) -> List[Dict]:
        versions = []
        protocol = "https" if use_ssl else "http"
        base_url = f"{protocol}://{target}:{port}"
        
        for file_path, pattern in file_patterns.items():
            try:
                file_url = urljoin(base_url, file_path)
                response = requests.get(file_url, timeout=3, verify=False)
                
                if response.status_code == 200:
                    match = re.search(pattern, response.text, re.IGNORECASE)
                    if match and match.groups():
                        versions.append({
                            'version': match.group(1),
                            'method': 'version_file',
                            'file': file_path,
                            'confidence': 85
                        })
            
            except Exception:
                continue
        
        return versions

    def _check_common_version_files(self, target: str, port: int, use_ssl: bool) -> List[Dict]:
        versions = []
        protocol = "https" if use_ssl else "http"
        base_url = f"{protocol}://{target}:{port}"
        
        for file_path in self.common_version_files:
            try:
                file_url = urljoin(base_url, file_path)
                response = requests.get(file_url, timeout=2, verify=False)
                
                if response.status_code == 200:
                    file_versions = self._extract_versions_from_text(response.text)
                    for version in file_versions:
                        version['file'] = file_path
                        version['confidence'] = min(version['confidence'] + 10, 95)
                        versions.append(version)
            
            except Exception:
                continue
        
        return versions

    def _check_ssl_certificate(self, target: str, port: int) -> Dict[str, Any]:
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            with socket.create_connection((target, port), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=target) as ssock:
                    cert = ssock.getpeercert()
                    cipher = ssock.cipher()
                    
                    return {
                        'certificate': cert,
                        'cipher': cipher,
                        'tls_version': ssock.version()
                    }
        
        except Exception:
            return {}

    def _get_mysql_version(self, target: str, port: int) -> str:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((target, port))
            banner = sock.recv(1024)
            sock.close()

            if len(banner) > 5:
                version_end = banner.find(b'\x00', 5)
                if version_end != -1:
                    return banner[5:version_end].decode('utf-8', errors='ignore')
        
        except Exception:
            pass
        
        return ""

    def _get_ssh_version(self, target: str, port: int) -> str:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((target, port))
            
            banner = sock.recv(1024).decode('utf-8', errors='ignore')
            sock.close()
            
            match = re.search(r'SSH-(\d+\.\d+)-', banner)
            if match:
                return match.group(1)
        
        except Exception:
            pass
        
        return ""

    def _assess_version_confidence(self, version_str: str, pattern: str) -> int:
        confidence = 50 
        
        if re.match(r'\d+\.\d+\.\d+', version_str):
            confidence += 20
        elif re.match(r'\d+\.\d+', version_str):
            confidence += 10
        
        if 'version' in pattern.lower() or 'ver' in pattern.lower():
            confidence += 15
        if 'release' in pattern.lower():
            confidence += 10
        
        return min(confidence, 95)

    def _calculate_confidence(self, results: Dict) -> int:
        if not results['versions']:
            return 0
        
        max_version_confidence = max([v.get('confidence', 0) for v in results['versions']])
        
        method_bonus = min(len(results['methods_used']) * 5, 15)
        
        return min(max_version_confidence + method_bonus, 100)

    def get_service_supported(self, service_name: str) -> bool:
        return service_name.lower() in self.version_patterns

    def get_supported_services(self) -> List[str]:
        return list(self.version_patterns.keys())

    def clear_cache(self):
        self.detection_cache.clear()

    def get_detection_stats(self) -> Dict[str, int]:
        return {
            'supported_services': len(self.version_patterns),
            'cache_size': len(self.detection_cache),
            'common_files': len(self.common_version_files)
        }

def quick_version_detect(target: str, port: int, service: str = None) -> Dict:
    detector = VersionDetector()
    return detector.detect_versions(target, port, service)