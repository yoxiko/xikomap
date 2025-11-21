import socket
import time
from typing import Dict, Any
from .base_scanner import BaseScanner

class UDPScanner(BaseScanner):
    def __init__(self, timeout: float = 3.0, verbose: bool = False):
        super().__init__(timeout, verbose)
        self.udp_signatures = {
            53: b'\x00\x01\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07version\x04bind\x00\x00\x10\x00\x03',  # DNS
            161: b'\x30\x26\x02\x01\x01\x04\x06public\xa0\x19\x02\x04\x71\xb4\xb5\x1f\x02\x01\x00\x02\x01\x00\x30\x0b\x30\x09\x06\x05\x2b\x06\x01\x02\x01\x05\x00',  # SNMP
            123: b'\x1a\x03\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00',  # NTP
            67: b'\x01\x01\x06\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00',  # DHCP
        }

    def scan_port(self, target: str, port: int) -> Dict[str, Any]:
        self.stats['scanned_ports'] += 1
        
        is_open = self.udp_scan_advanced(target, port)
        
        if is_open:
            self.stats['open_ports'] += 1
            return {
                'state': 'open',
                'protocol': 'udp',
                'scan_type': 'udp'
            }
        
        return {'state': 'closed'}

    def udp_scan_advanced(self, target: str, port: int) -> bool:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(self.timeout)
            
            request_data = self.udp_signatures.get(port, b'')
            sock.sendto(request_data, (target, port))
            
            try:
                data, addr = sock.recvfrom(1024)
                sock.close()
                
                if self._validate_udp_response(port, data):
                    return True
                return False
                
            except socket.timeout:
                sock.close()
                return self._udp_heuristic_check(target, port)
                
        except Exception:
            return False

    def _validate_udp_response(self, port: int, data: bytes) -> bool:
        if not data:
            return False
            
        if port == 53:  
            return len(data) > 4 and data[2] & 0x80  
        elif port == 161: 
            return data.startswith(b'\x30')  
        elif port == 123:  
            return len(data) >= 48  
        elif port == 67:  
            return len(data) > 240  
        
      
        return len(data) > 0

    def _udp_heuristic_check(self, target: str, port: int) -> bool:
    
        common_udp_ports = {
            53: "DNS", 123: "NTP", 161: "SNMP", 500: "IPSec", 
            1701: "L2TP", 4500: "IPSec NAT-T", 514: "Syslog"
        }
        
        if port in common_udp_ports:
        
            return True
            
        return False

    def quick_udp_scan(self, target: str, ports: list) -> Dict[int, bool]:
        results = {}
        common_ports = [53, 67, 68, 69, 123, 135, 137, 138, 161, 162, 445, 514, 520, 631, 1434, 1900, 4500, 5353]
        
        if ports == 'common':
            ports_to_scan = common_ports
        else:
            ports_to_scan = [p for p in ports if p in common_ports]
        
        for port in ports_to_scan:
            results[port] = self.udp_scan_advanced(target, port)
            time.sleep(0.11)  
            
        return results