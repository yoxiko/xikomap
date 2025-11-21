import socket
import ssl
import time
from typing import Dict, Any, Optional
from core.constants import PROTOCOL_SIGNATURES

class ProtocolDetector:
    def __init__(self, timeout: float = 3.0, verbose: bool = False):
        self.timeout = timeout
        self.verbose = verbose
        self.detection_cache = {}
    
    def detect_protocol(self, target: str, port: int, protocol: str = 'tcp') -> Dict[str, Any]:
        cache_key = f"{target}:{port}:{protocol}"
        if cache_key in self.detection_cache:
            return self.detection_cache[cache_key]
        
        detected = self._perform_detection(target, port, protocol)
        
        if not isinstance(detected, dict):
            detected = {'service': 'unknown', 'confidence': 0, 'banner': 'Detection error'}
        
        self.detection_cache[cache_key] = detected
        return detected
    
    def _perform_detection(self, target: str, port: int, protocol: str) -> Dict[str, Any]:
        best_match = {'service': 'unknown', 'confidence': 0, 'banner': ''}
        
        for proto_name, signature in PROTOCOL_SIGNATURES.items():
            if signature.get('udp', False) and protocol != 'udp':
                continue
            if not signature.get('udp', False) and protocol == 'udp':
                continue
            
            if signature['ports'] and port not in signature['ports']:
                continue
            
            confidence, banner = self._check_protocol(target, port, proto_name, signature, protocol)
            
            if confidence > best_match['confidence']:
                best_match = {
                    'service': proto_name,
                    'confidence': confidence,
                    'banner': banner
                }
        
        if best_match['confidence'] < 0.6:
            fallback = self._fallback_detection(target, port, protocol)
            if fallback.get('confidence', 0) > best_match['confidence']:
                best_match = fallback
        
        return best_match
    
    def _check_protocol(self, target: str, port: int, proto_name: str, signature: Dict[str, Any], protocol: str):
        try:
            if protocol == 'tcp':
                return self._check_tcp_protocol(target, port, proto_name, signature)
            else:
                return self._check_udp_protocol(target, port, proto_name, signature)
        except Exception as e:
            return 0, f"Ошибка проверки: {str(e)}"
    
    def _check_tcp_protocol(self, target: str, port: int, proto_name: str, signature: Dict[str, Any]):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(self.timeout)
            
            try:
                sock.connect((target, port))
                
                if signature.get('ssl', False):
                    try:
                        context = ssl.create_default_context()
                        context.check_hostname = False
                        context.verify_mode = ssl.CERT_NONE
                        with context.wrap_socket(sock, server_hostname=target) as ssock:
                            cert = ssock.getpeercert()
                            if cert:
                                return signature['confidence'], f"SSL: {cert}"
                    except Exception:
                        pass
                
                if 'request' in signature:
                    sock.send(signature['request'])
                    time.sleep(0.5)
                
                banner = self._receive_banner(sock)
                
                if signature['response_patterns']:
                    for pattern in signature['response_patterns']:
                        if pattern in banner:
                            return signature['confidence'], banner[:200].decode('utf-8', errors='ignore')
                
                if banner:
                    return signature['confidence'] * 0.8, banner[:200].decode('utf-8', errors='ignore')
                
                return signature['confidence'] * 0.6, ""
                
            except Exception as e:
                return 0, f"Ошибка подключения: {str(e)}"
    
    def _check_udp_protocol(self, target: str, port: int, proto_name: str, signature: Dict[str, Any]):
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(self.timeout)
            
            try:
                if 'request' in signature:
                    sock.sendto(signature['request'], (target, port))
                try:
                    data, addr = sock.recvfrom(1024)
                    banner = data.decode('utf-8', errors='ignore')
                    
                    if signature['response_patterns']:
                        for pattern in signature['response_patterns']:
                            if pattern in data:
                                return signature['confidence'], banner[:200]
                    
                    return signature['confidence'] * 0.7, banner[:200]
                except socket.timeout:
                    return signature['confidence'] * 0.5, "Нет ответа"
                    
            except Exception as e:
                return 0, f"Ошибка UDP: {str(e)}"
    
    def _receive_banner(self, sock: socket.socket) -> bytes:
        banner = b""
        try:
            sock.settimeout(1.0)
            while True:
                chunk = sock.recv(1024)
                if not chunk:
                    break
                banner += chunk
                if len(banner) > 4096:
                    break
        except:
            pass
        return banner
    
    def _fallback_detection(self, target: str, port: int, protocol: str) -> Dict[str, Any]:
        try:
            if protocol == 'tcp':
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                    sock.settimeout(2)
                    sock.connect((target, port))
                    
                    banner = self._receive_banner(sock)
                    if banner:
                        try:
                            banner_str = banner.decode('utf-8', errors='ignore').lower()
                        except:
                            banner_str = str(banner).lower()
                        
                        if any(word in banner_str for word in ['http', 'html', 'server']):
                            return {'service': 'http', 'confidence': 0.7, 'banner': banner_str[:200]}
                        elif any(word in banner_str for word in ['ssh', 'openssh']):
                            return {'service': 'ssh', 'confidence': 0.8, 'banner': banner_str[:200]}
                        elif any(word in banner_str for word in ['ftp', 'vsftpd']):
                            return {'service': 'ftp', 'confidence': 0.8, 'banner': banner_str[:200]}
                        elif any(word in banner_str for word in ['smtp', 'esmtp']):
                            return {'service': 'smtp', 'confidence': 0.7, 'banner': banner_str[:200]}
                        
                        return {'service': 'unknown-tcp', 'confidence': 0.5, 'banner': banner_str[:200]}
                    
                    return {'service': 'unknown-tcp', 'confidence': 0.3, 'banner': ''}
            
            else:
                return {'service': 'unknown-udp', 'confidence': 0.2, 'banner': ''}
                
        except Exception as e:
            return {'service': 'unknown', 'confidence': 0, 'banner': f'Connection error: {str(e)}'}
    
    def clear_cache(self):
        self.detection_cache.clear()