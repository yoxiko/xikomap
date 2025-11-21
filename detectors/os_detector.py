import socket
import time
from typing import Dict, Any, List, Tuple, Optional

class OSDetector:
    def __init__(self):
        self.os_fingerprints = {
            'Linux': {
                'ttl_range': (30, 64),
                'window_sizes': [5840, 5720, 65535],
                'df_flag': True,
                'common_ports': [22, 631, 25]
            },
            'Windows': {
                'ttl_range': (100, 128),
                'window_sizes': [64240, 65535, 8192],
                'df_flag': True,
                'common_ports': [135, 139, 445, 3389]
            },
            'FreeBSD': {
                'ttl_range': (60, 64),
                'window_sizes': [65535, 16384, 8760],
                'df_flag': True,
                'common_ports': [22, 25, 111]
            },
            'Cisco': {
                'ttl_range': (200, 255),
                'window_sizes': [4128, 5720],
                'df_flag': False,
                'common_ports': [23, 22, 161]
            },
            'macOS': {
                'ttl_range': (60, 64),
                'window_sizes': [65535, 32768, 16384],
                'df_flag': True,
                'common_ports': [22, 548, 5900]
            }
        }
    
    def detect_os(self, target: str, open_ports: List[int], ttl_guess: Optional[int] = None, 
                  window_size: Optional[int] = None) -> Tuple[str, float]:
        scores = {os: 0 for os in self.os_fingerprints}
        
        if ttl_guess:
            for os_name, fingerprint in self.os_fingerprints.items():
                min_ttl, max_ttl = fingerprint['ttl_range']
                if min_ttl <= ttl_guess <= max_ttl:
                    scores[os_name] += 30
        
        if window_size:
            for os_name, fingerprint in self.os_fingerprints.items():
                if window_size in fingerprint['window_sizes']:
                    scores[os_name] += 25
        
        for os_name, fingerprint in self.os_fingerprints.items():
            common_matches = len(set(open_ports) & set(fingerprint['common_ports']))
            scores[os_name] += common_matches * 10
        
        if scores:
            best_os = max(scores.items(), key=lambda x: x[1])
            if best_os[1] > 0:
                confidence = min(100, best_os[1])
                return best_os[0], confidence
        
        return "Unknown", 0
    
    def estimate_ttl(self, target: str) -> int:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            start_time = time.time()
            result = sock.connect_ex((target, 80))
            sock.close()
            
            response_time = (time.time() - start_time) * 1000
            if response_time < 10:
                return 64
            elif response_time < 100:
                return 128
            else:
                return 255
                
        except:
            return 64
    
    def analyze_tcp_stack(self, target: str, port: int = 80) -> Dict[str, Any]:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3)
            sock.connect((target, port))
            
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            
            try:
                sock.send(b"HEAD / HTTP/1.0\r\n\r\n")
                response = sock.recv(1024)
            except:
                pass
            
            sock.close()
            
            return {
                'connected': True,
                'window_size_guess': 65535,
                'ttl_guess': self.estimate_ttl(target)
            }
        except Exception as e:
            return {
                'connected': False,
                'error': str(e)
            }
    
    def get_os_characteristics(self, os_name: str) -> Dict[str, Any]:
        fingerprint = self.os_fingerprints.get(os_name, {})
        
        characteristics = {
            'family': os_name,
            'ttl_range': fingerprint.get('ttl_range', (0, 0)),
            'typical_ports': fingerprint.get('common_ports', []),
            'window_sizes': fingerprint.get('window_sizes', []),
            'df_flag': fingerprint.get('df_flag', False)
        }
        
        if os_name == 'Linux':
            characteristics['description'] = 'Linux-based operating system'
            characteristics['examples'] = ['Ubuntu', 'Debian', 'CentOS', 'Red Hat']
        elif os_name == 'Windows':
            characteristics['description'] = 'Microsoft Windows operating system'
            characteristics['examples'] = ['Windows 10/11', 'Windows Server']
        elif os_name == 'macOS':
            characteristics['description'] = 'Apple macOS operating system'
            characteristics['examples'] = ['macOS Monterey', 'macOS Ventura']
        elif os_name == 'FreeBSD':
            characteristics['description'] = 'FreeBSD Unix-like operating system'
            characteristics['examples'] = ['FreeBSD', 'TrueNAS']
        elif os_name == 'Cisco':
            characteristics['description'] = 'Cisco network devices'
            characteristics['examples'] = ['Cisco IOS', 'Cisco Switches/Routers']
        else:
            characteristics['description'] = 'Unknown operating system'
            characteristics['examples'] = []
        
        return characteristics