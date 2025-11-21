import socket
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Dict, Any, Optional
from .base_scanner import BaseScanner
from .tcp_scanner import TCPScanner
from .udp_scanner import UDPScanner

class AdvancedScanner(BaseScanner):
    def __init__(self, max_threads: int = 200, timeout: float = 2.0, verbose: bool = False):
        super().__init__(timeout, verbose)
        self.max_threads = max_threads
        self.tcp_scanner = TCPScanner(timeout, verbose)
        self.udp_scanner = UDPScanner(timeout, verbose)

    def scan_port(self, target: str, port: int, protocol: str = 'tcp') -> Dict[str, Any]:
        self.stats['scanned_ports'] += 1
        
        if protocol == 'tcp':
            result = self.tcp_scanner.scan_port(target, port)
        else:
            result = self.udp_scanner.scan_port(target, port)
            
        if result['state'] == 'open':
            self.stats['open_ports'] += 1
            
        return result

    def set_scan_type(self, scan_type: str):
        self.tcp_scanner.set_scan_type(scan_type)

    def batch_scan(self, targets: List[str], ports: List[int], protocol: str = 'tcp', 
                   scan_type: str = 'connect') -> Dict[str, List[Dict[str, Any]]]:
        
        self.start_scan()
        
        if protocol == 'tcp':
            self.set_scan_type(scan_type)
            scanner = self.tcp_scanner
        else:
            scanner = self.udp_scanner
        
        all_results = {}
        
        for target in targets:
            target_results = []
            
            with ThreadPoolExecutor(max_workers=min(self.max_threads, len(ports))) as executor:
                future_to_port = {
                    executor.submit(scanner.scan_port, target, port): port for port in ports
                }
                
                for future in as_completed(future_to_port):
                    result = future.result()
                    if result['state'] == 'open':
                        result['target'] = target
                        result['port'] = future_to_port[future]
                        result['protocol'] = protocol
                        target_results.append(result)
            
            if target_results:
                all_results[target] = target_results
        
        self.end_scan()
        return all_results

    def quick_scan(self, target: str, common_ports: bool = True, protocol: str = 'tcp') -> List[Dict[str, Any]]:
        if common_ports:
            if protocol == 'tcp':
                ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 995, 3306, 3389, 5432, 5900]
            else:
                ports = [53, 67, 68, 69, 123, 135, 137, 138, 161, 162, 445, 514, 520, 631, 1434]
        else:
            ports = list(range(1, 1024))
        
        return self.batch_scan([target], ports, protocol, 'connect').get(target, [])

    def comprehensive_scan(self, target: str) -> Dict[str, Any]:
        results = {
            'target': target,
            'tcp_ports': [],
            'udp_ports': [],
            'scan_info': {}
        }
        
        common_tcp_ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 995, 3306, 3389, 5432, 5900]
        common_udp_ports = [53, 67, 68, 69, 123, 135, 137, 138, 161, 162, 445, 514, 520, 631, 1434]
        
        tcp_results = self.batch_scan([target], common_tcp_ports, 'tcp', 'connect')
        udp_results = self.batch_scan([target], common_udp_ports, 'udp', 'connect')
        
        results['tcp_ports'] = tcp_results.get(target, [])
        results['udp_ports'] = udp_results.get(target, [])
        results['scan_info'] = self.get_stats()
        
        return results