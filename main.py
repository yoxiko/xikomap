
import socket
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
import ipaddress
import re
import time
import argparse
import sys
import json
import select
import ssl
import struct
from datetime import datetime

PROTOCOL_SIGNATURES = {
    'http': {
        'ports': [80, 8080, 8000, 8008, 8081, 8888, 8443],
        'request': b"GET / HTTP/1.0\r\nHost: example.com\r\n\r\n",
        'response_patterns': [b'HTTP/', b'Server:', b'Content-Type:'],
        'confidence': 0.9
    },
    'https': {
        'ports': [443, 8443],
        'ssl': True,
        'response_patterns': [b'HTTP/', b'Server:'],
        'confidence': 0.95
    },
    'ssh': {
        'ports': [22, 2222, 22222],
        'response_patterns': [b'SSH-', b'OpenSSH'],
        'confidence': 0.98
    },
    'ftp': {
        'ports': [21, 2121],
        'response_patterns': [b'220', b'FTP', b'vsFTPd', b'ProFTPD'],
        'confidence': 0.95
    },
    'smtp': {
        'ports': [25, 587, 465],
        'response_patterns': [b'220', b'ESMTP', b'SMTP', b'Postfix', b'Exim'],
        'confidence': 0.9
    },
    'dns': {
        'ports': [53],
        'udp': True,
        'request': b'\x00\x01\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07version\x04bind\x00\x00\x10\x00\x03',
        'response_patterns': [b'version.bind'],
        'confidence': 0.85
    },
    'mysql': {
        'ports': [3306, 3307, 33060],
        'response_patterns': [b'mysql', b'MariaDB'],
        'confidence': 0.9
    },
    'redis': {
        'ports': [6379, 63790],
        'response_patterns': [b'REDIS'],
        'confidence': 0.95
    },
    'mongodb': {
        'ports': [27017, 27018, 27019],
        'response_patterns': [],
        'confidence': 0.8
    },
    'rdp': {
        'ports': [3389, 33890],
        'response_patterns': [b'\x03\x00\x00'],
        'confidence': 0.9
    },
    'vnc': {
        'ports': [5900, 5901, 5902],
        'response_patterns': [b'RFB'],
        'confidence': 0.95
    },
    'elasticsearch': {
        'ports': [9200, 9300],
        'response_patterns': [b'"cluster_name"', b'"version"'],
        'confidence': 0.9
    }
}

class ProtocolDetector:
    
    def __init__(self, timeout=3):
        self.timeout = timeout
        self.detection_cache = {}
    
    def detect_protocol(self, target, port, protocol='tcp'):
        cache_key = f"{target}:{port}:{protocol}"
        if cache_key in self.detection_cache:
            return self.detection_cache[cache_key]
        
        detected = self._perform_detection(target, port, protocol)
        self.detection_cache[cache_key] = detected
        return detected
    
    def _perform_detection(self, target, port, protocol):
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
            if fallback['confidence'] > best_match['confidence']:
                best_match = fallback
        
        return best_match
    
    def _check_protocol(self, target, port, proto_name, signature, protocol):

        try:
            if protocol == 'tcp':
                return self._check_tcp_protocol(target, port, proto_name, signature)
            else:
                return self._check_udp_protocol(target, port, proto_name, signature)
        except:
            return 0, ""
    
    def _check_tcp_protocol(self, target, port, proto_name, signature):
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
                    except:
                        pass
                
                if 'request' in signature:
                    sock.send(signature['request'])
                    time.sleep(0.5)
                
                banner = self._receive_banner(sock)
                
                if signature['response_patterns']:
                    for pattern in signature['response_patterns']:
                        if pattern in banner:
                            return signature['confidence'], banner[:200]
                
                if banner:
                    return signature['confidence'] * 0.8, banner[:200]
                
                return signature['confidence'] * 0.6, ""
                
            except:
                return 0, ""
    
    def _check_udp_protocol(self, target, port, proto_name, signature):
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
                    return signature['confidence'] * 0.5, "No response"
                    
            except:
                return 0, ""
    
    def _receive_banner(self, sock):
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
    
    def _fallback_detection(self, target, port, protocol):
        try:
            if protocol == 'tcp':
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                    sock.settimeout(2)
                    sock.connect((target, port))
                    
                    banner = self._receive_banner(sock)
                    if banner:
                        banner_str = banner.decode('utf-8', errors='ignore').lower()
                        
                        if any(word in banner_str for word in ['http', 'html', 'server']):
                            return {'service': 'http', 'confidence': 0.7, 'banner': banner[:200]}
                        elif any(word in banner_str for word in ['ssh', 'openssh']):
                            return {'service': 'ssh', 'confidence': 0.8, 'banner': banner[:200]}
                        elif any(word in banner_str for word in ['ftp', 'vsftpd']):
                            return {'service': 'ftp', 'confidence': 0.8, 'banner': banner[:200]}
                        
                        return {'service': 'unknown-tcp', 'confidence': 0.5, 'banner': banner[:200]}
                    
                    return {'service': 'unknown-tcp', 'confidence': 0.3, 'banner': ''}
            
            else:  # UDP
                return {'service': 'unknown-udp', 'confidence': 0.2, 'banner': ''}
                
        except:
            return {'service': 'unknown', 'confidence': 0, 'banner': ''}

class Yoxiko:
    def __init__(self, max_threads=200, timeout=2, verbose=False):
        self.max_threads = max_threads
        self.timeout = timeout
        self.verbose = verbose
        self.detector = ProtocolDetector(timeout=timeout)
        self.results = []
        self.stats = {
            'hosts_scanned': 0,
            'ports_scanned': 0,
            'open_ports_found': 0,
            'start_time': None,
            'end_time': None
        }

    def print_banner(self):
        print("yoxiko - scaner ports for windows OS")
        print("=" * 50)

    def log(self, message, level="INFO"):
        if self.verbose or level in ["WARNING", "ERROR"]:
            timestamp = datetime.now().strftime('%H:%M:%S')
            print(f"[{timestamp}] {message}")

    def parse_ports(self, port_spec):
        ports = set()
        
        if port_spec.lower() == 'common':
            all_ports = set()
            for proto in PROTOCOL_SIGNATURES.values():
                all_ports.update(proto['ports'])
            return sorted(all_ports)[:50]  
        
        parts = port_spec.split(',')
        for part in parts:
            part = part.strip()
            if '-' in part:
                try:
                    start, end = map(int, part.split('-'))
                    ports.update(range(start, end + 1))
                except ValueError:
                    self.log(f"Invalid port range: {part}", "WARNING")
            else:
                try:
                    port = int(part)
                    ports.add(port)
                except ValueError:
                    self.log(f"Invalid port: {part}", "WARNING")
        
        return sorted(ports)

    def parse_targets(self, target_spec):
        targets = set()
        
        try:
            if '/' in target_spec:
                network = ipaddress.IPv4Network(target_spec, strict=False)
                targets.update(str(ip) for ip in network.hosts())
            elif '-' in target_spec and target_spec.count('.') == 3:
                base_ip, range_part = target_spec.rsplit('.', 1)
                if '-' in range_part:
                    start, end = map(int, range_part.split('-'))
                    for i in range(start, end + 1):
                        targets.add(f"{base_ip}.{i}")
                else:
                    targets.add(target_spec)
            else:
                try:
                    ip = socket.gethostbyname(target_spec)
                    targets.add(ip)
                except socket.gaierror:
                    self.log(f"Could not resolve: {target_spec}", "ERROR")
                    targets.add(target_spec)
        except Exception as e:
            self.log(f"Error parsing target {target_spec}: {e}", "ERROR")
            targets.add(target_spec)
            
        return list(targets)

    def smart_scan(self, target, port, protocol='tcp'):
        self.stats['ports_scanned'] += 1
        
        try:
            if protocol == 'tcp':
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                    sock.settimeout(self.timeout)
                    result = sock.connect_ex((target, port))
                    
                    if result == 0:
                        detection = self.detector.detect_protocol(target, port, 'tcp')
                        
                        return {
                            'target': target,
                            'port': port,
                            'state': 'open',
                            'protocol': 'tcp',
                            'service': detection['service'],
                            'confidence': detection['confidence'],
                            'banner': detection['banner']
                        }
                    else:
                        return None
            else:  # UDP
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                    sock.settimeout(self.timeout)
                    
                    sock.sendto(b'', (target, port))
                    
                    try:
                        data, addr = sock.recvfrom(1024)
                        detection = self.detector.detect_protocol(target, port, 'udp')
                        
                        return {
                            'target': target,
                            'port': port,
                            'state': 'open',
                            'protocol': 'udp',
                            'service': detection['service'],
                            'confidence': detection['confidence'],
                            'banner': detection['banner']
                        }
                    except socket.timeout:
                        detection = self.detector.detect_protocol(target, port, 'udp')
                        if detection['confidence'] > 0.3:
                            return {
                                'target': target,
                                'port': port,
                                'state': 'open|filtered',
                                'protocol': 'udp',
                                'service': detection['service'],
                                'confidence': detection['confidence'],
                                'banner': detection['banner']
                            }
                        return None
                    
        except Exception as e:
            if self.verbose:
                self.log(f"Scan error {target}:{port} - {e}", "ERROR")
            return None

    def run_scan(self, target_spec, port_spec='common', output_file=None, 
                 protocol='tcp', timing_template=3):
        self.stats['start_time'] = time.time()
        self.print_banner()
        
        self.timeout = max(0.5, 5 - timing_template)
        self.max_threads = min(1000, 50 * timing_template)
        
        targets = self.parse_targets(target_spec)
        ports = self.parse_ports(port_spec)
        
        print(f" Цели: {len(targets)} хост(ов)")
        print(f" Порты: {len(ports)} порт(ов)")
        print(f" Протокол: {protocol.upper()}")
        print()
        
        all_results = []
        
        for target in targets:
            print(f"Сканирование {target}...")
            target_results = []
            
            with ThreadPoolExecutor(max_workers=min(self.max_threads, len(ports))) as executor:
                future_to_port = {
                    executor.submit(self.smart_scan, target, port, protocol): port 
                    for port in ports
                }
                
                for future in as_completed(future_to_port):
                    result = future.result()
                    if result:
                        target_results.append(result)
                        
                        confidence_icon = "🟢" if result['confidence'] > 0.8 else "🟡" if result['confidence'] > 0.5 else "🟠"
                        print(f"  {confidence_icon} {result['port']:5} {result['protocol']:4} {result['service']:15} {result['banner'][:50]}")
            
            all_results.extend(target_results)
            print(f" Найдено: {len(target_results)} открытых портов\n")
        
        if output_file:
            self.save_results(all_results, output_file)
        
        self.stats['end_time'] = time.time()
        duration = self.stats['end_time'] - self.stats['start_time']
        
        print(f" Сканирование завершено за {duration:.2f} секунд")
        print(f" Всего найдено: {len(all_results)} открытых портов")

    def save_results(self, results, filename):
        """Сохранение результатов"""
        try:
            output = {
                'scan_info': {
                    'scanner': 'Yoxiko',
                    'timestamp': datetime.now().isoformat(),
                    'duration': self.stats['end_time'] - self.stats['start_time']
                },
                'results': results
            }
            
            with open(filename, 'w', encoding='utf-8') as f:
                json.dump(output, f, indent=2, ensure_ascii=False)
            
            self.log(f"Results saved to: {filename}", "INFO")
            
        except Exception as e:
            self.log(f"Error saving results: {e}", "ERROR")

def main():
    parser = argparse.ArgumentParser(
        description='yoxiko - scaner ports for windows OS',
        add_help=False
    )
    
    parser.add_argument('target', nargs='?', help='Цель сканирования')
    parser.add_argument('-p', '--ports', default='common', help='Порты для сканирования')
    parser.add_argument('-o', '--output', help='Файл для сохранения результатов')
    parser.add_argument('-t', '--tcp', action='store_true', help='TCP сканирование (по умолчанию)')
    parser.add_argument('-u', '--udp', action='store_true', help='UDP сканирование')
    parser.add_argument('-T', '--timing', type=int, default=3, help='Тайминг (0-5)')
    parser.add_argument('-v', '--verbose', action='store_true', help='Подробный вывод')
    parser.add_argument('-h', '--help', action='store_true', help='Показать справку')
    
    args = parser.parse_args()
    
    if args.help or not args.target:
        print("yoxiko - scaner ports for windows OS")
        print("\nИспользование: python yoxiko.py [ОПЦИИ] ЦЕЛЬ")
        print("\nПримеры:")
        print("  python yoxiko.py 192.168.1.1")
        print("  python yoxiko.py -p 80,443,22 example.com")
        print("  python yoxiko.py -u -o results.json 10.0.0.0/24")
        print("\nОпции:")
        print("  -p ПОРТЫ    Порты (common, 80,443 или 1-100)")
        print("  -o ФАЙЛ     Сохранить результаты в файл")
        print("  -t          TCP сканирование (по умолчанию)")
        print("  -u          UDP сканирование") 
        print("  -T 0-5      Настройка тайминга")
        print("  -v          Подробный вывод")
        return
    
    protocol = 'tcp'
    if args.udp:
        protocol = 'udp'
    
    scanner = Yoxiko(verbose=args.verbose)
    
    try:
        scanner.run_scan(
            target_spec=args.target,
            port_spec=args.ports,
            output_file=args.output,
            protocol=protocol,
            timing_template=args.timing
        )
    except KeyboardInterrupt:
        print("\n Сканирование прервано")
    except Exception as e:
        print(f" Ошибка: {e}")

if __name__ == "__main__":
    main()
