import socket
import ssl
import time
from typing import Dict, Any, List, Optional
from core.constants import PROTOCOL_SIGNATURES

class AdvancedProtocolDetector:
    
    def __init__(self, timeout: float = 3.0, verbose: bool = False):
        self.timeout = timeout
        self.verbose = verbose
        self.detection_cache = {}
        
        self.port_index = self._build_port_index()
    
    def _build_port_index(self) -> Dict[int, List[str]]:
        index = {}
        for proto_name, signature in PROTOCOL_SIGNATURES.items():
            for port in signature.get('ports', []):
                if port not in index:
                    index[port] = []
                index[port].append(proto_name)
        return index
    
    def detect_protocol(self, target: str, port: int, protocol: str = 'tcp') -> Dict[str, Any]:
        cache_key = f"{target}:{port}:{protocol}"
        if cache_key in self.detection_cache:
            return self.detection_cache[cache_key]
        
        port_specific_results = self._check_port_specific_protocols(target, port, protocol)

        if port_specific_results and port_specific_results['confidence'] > 0.8:
            self.detection_cache[cache_key] = port_specific_results
            return port_specific_results
        
        all_protocols_results = self._check_all_protocols(target, port, protocol)
        
        best_result = self._select_best_result(port_specific_results, all_protocols_results)
        
        self.detection_cache[cache_key] = best_result
        return best_result
    
    def _check_port_specific_protocols(self, target: str, port: int, protocol: str) -> Optional[Dict[str, Any]]:
        best_match = {'service': 'unknown', 'confidence': 0, 'banner': ''}

        protocols_for_port = self.port_index.get(port, [])
        
        for proto_name in protocols_for_port:
            signature = PROTOCOL_SIGNATURES[proto_name]
            
            if signature.get('udp', False) and protocol != 'udp':
                continue
            if not signature.get('udp', False) and protocol == 'udp':
                continue
            
            confidence, banner = self._check_single_protocol(target, port, proto_name, signature, protocol)
            
            if confidence > best_match['confidence']:
                best_match = {
                    'service': proto_name,
                    'confidence': confidence,
                    'banner': banner
                }
        
        return best_match if best_match['confidence'] > 0 else None
    
    def _check_all_protocols(self, target: str, port: int, protocol: str) -> Dict[str, Any]:
        best_match = {'service': 'unknown', 'confidence': 0, 'banner': ''}
        
        for proto_name, signature in PROTOCOL_SIGNATURES.items():
            if signature.get('udp', False) and protocol != 'udp':
                continue
            if not signature.get('udp', False) and protocol == 'udp':
                continue
            
            confidence, banner = self._check_single_protocol(target, port, proto_name, signature, protocol)
            
            if confidence > best_match['confidence']:
                best_match = {
                    'service': proto_name,
                    'confidence': confidence,
                    'banner': banner
                }
        
        return best_match
    
    def _check_single_protocol(self, target: str, port: int, proto_name: str, 
                             signature: Dict[str, Any], protocol: str):
        try:
            if protocol == 'tcp':
                return self._check_tcp_protocol(target, port, proto_name, signature)
            else:
                return self._check_udp_protocol(target, port, proto_name, signature)
        except Exception as e:
            if self.verbose:
                print(f"Ошибка проверки {proto_name}: {e}")
            return 0, f"Ошибка: {str(e)}"
    
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
                    time.sleep(0.3)  
                
                banner = self._receive_banner(sock)
                
        
                if signature['response_patterns']:
                    for pattern in signature['response_patterns']:
                        if pattern in banner:
                            banner_text = banner[:500].decode('utf-8', errors='ignore')
                            return signature['confidence'], banner_text
                

                if banner:
                    banner_text = banner[:500].decode('utf-8', errors='ignore')
                    return signature['confidence'] * 0.7, banner_text
                
                return signature['confidence'] * 0.5, ""
                
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
                    
                    if signature['response_patterns']:
                        for pattern in signature['response_patterns']:
                            if pattern in data:
                                banner_text = data[:500].decode('utf-8', errors='ignore')
                                return signature['confidence'], banner_text
                    
                    if data:
                        banner_text = data[:500].decode('utf-8', errors='ignore')
                        return signature['confidence'] * 0.8, banner_text
                    
                    return signature['confidence'] * 0.6, "Пустой ответ"
                    
                except socket.timeout:
                    return signature['confidence'] * 0.4, "Таймаут"
                    
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
    
    def _select_best_result(self, port_specific: Optional[Dict], all_protocols: Dict) -> Dict[str, Any]:

        if not port_specific:
            return all_protocols
        
        if port_specific['confidence'] > all_protocols['confidence']:
            return port_specific
        else:
            return all_protocols
    
    def clear_cache(self):
        self.detection_cache.clear()