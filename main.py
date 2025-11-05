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
import logging
import csv
import os

try:
    from tqdm import tqdm
    TQDM_AVAILABLE = True
except ImportError:
    TQDM_AVAILABLE = False

def check_dependencies():
    if not TQDM_AVAILABLE:
        print("⚠️  Предупреждение: tqdm не установлен. Для красивого прогресс-бара установите: pip install tqdm")
    
    import sys
    if sys.version_info < (3, 6):
        print(" Ошибка: Требуется Python 3.6 или выше")
        sys.exit(1)

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
    },
    'postgresql': {
        'ports': [5432, 5433],
        'response_patterns': [b'PostgreSQL', b'user'],
        'confidence': 0.9
    },
    'telnet': {
        'ports': [23, 2323],
        'response_patterns': [b'Telnet', b'login:', b'Password:'],
        'confidence': 0.85
    },
    'sip': {
        'ports': [5060, 5061],
        'response_patterns': [b'SIP/2.0', b'INVITE', b'REGISTER'],
        'confidence': 0.8
    },
    'snmp': {
        'ports': [161, 162],
        'udp': True,
        'response_patterns': [b'public', b'private'],
        'confidence': 0.7
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
        except Exception as e:
            return 0, f"Ошибка проверки: {str(e)}"
    
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
                    except Exception as e:
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
                    return signature['confidence'] * 0.5, "Нет ответа"
                    
            except Exception as e:
                return 0, f"Ошибка UDP: {str(e)}"
    
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
                            return {'service': 'http', 'confidence': 0.7, 'banner': banner[:200].decode('utf-8', errors='ignore')}
                        elif any(word in banner_str for word in ['ssh', 'openssh']):
                            return {'service': 'ssh', 'confidence': 0.8, 'banner': banner[:200].decode('utf-8', errors='ignore')}
                        elif any(word in banner_str for word in ['ftp', 'vsftpd']):
                            return {'service': 'ftp', 'confidence': 0.8, 'banner': banner[:200].decode('utf-8', errors='ignore')}
                        
                        return {'service': 'unknown-tcp', 'confidence': 0.5, 'banner': banner[:200].decode('utf-8', errors='ignore')}
                    
                    return {'service': 'unknown-tcp', 'confidence': 0.3, 'banner': ''}
            
            else:  # UDP
                return {'service': 'unknown-udp', 'confidence': 0.2, 'banner': ''}
                
        except Exception as e:
            return {'service': 'unknown', 'confidence': 0, 'banner': f'Ошибка: {str(e)}'}

class Yoxiko:
    def __init__(self, max_threads=200, timeout=2, verbose=False, log_file=None):
        self.max_threads = max_threads
        self.timeout = timeout
        self.verbose = verbose
        self.detector = ProtocolDetector(timeout=timeout)
        self.results = []
        self.blacklist_ips = set()
        self.blacklist_ports = set()
        self.stats = {
            'hosts_scanned': 0,
            'ports_scanned': 0,
            'open_ports_found': 0,
            'start_time': None,
            'end_time': None
        }
        
        self.setup_logging(log_file)
        self.load_blacklists()

    def setup_logging(self, log_file=None):
        self.logger = logging.getLogger('yoxiko')
        self.logger.setLevel(logging.DEBUG if self.verbose else logging.INFO)
        

        formatter = logging.Formatter(
            '%(asctime)s - %(levelname)s - %(message)s',
            datefmt='%H:%M:%S'
        )
        

        console_handler = logging.StreamHandler()
        console_handler.setFormatter(formatter)
        self.logger.addHandler(console_handler)
        

        if log_file:
            file_handler = logging.FileHandler(log_file)
            file_handler.setFormatter(formatter)
            self.logger.addHandler(file_handler)

    def load_blacklists(self):
        try:
            if os.path.exists('blacklist_ips.txt'):
                with open('blacklist_ips.txt', 'r', encoding='utf-8') as f:
                    self.blacklist_ips = set(line.strip() for line in f if line.strip() and not line.startswith('#'))
                self.logger.info(f"Загружено {len(self.blacklist_ips)} IP в черный список")
        except Exception as e:
            self.logger.warning(f"Ошибка загрузки черного списка IP: {e}")
            
        try:
            if os.path.exists('blacklist_ports.txt'):
                with open('blacklist_ports.txt', 'r', encoding='utf-8') as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith('#'):
                            try:
                                self.blacklist_ports.add(int(line))
                            except ValueError:
                                pass
                self.logger.info(f"Загружено {len(self.blacklist_ports)} портов в черный список")
        except Exception as e:
            self.logger.warning(f"Ошибка загрузки черного списка портов: {e}")

    def is_blacklisted(self, target, port):
        return target in self.blacklist_ips or port in self.blacklist_ports

    def print_banner(self):
        print(" yoxiko - продвинутый сканер портов для Windows")
        print("=" * 60)
        print("  Используйте только для легального тестирования!")
        print("=" * 60)

    def log(self, message, level="INFO"):
        timestamp = datetime.now().strftime('%H:%M:%S')
        log_message = f"[{timestamp}] {message}"
        
        if level == "INFO":
            self.logger.info(message)
        elif level == "WARNING":
            self.logger.warning(message)
        elif level == "ERROR":
            self.logger.error(message)
        elif level == "DEBUG":
            self.logger.debug(message)
        
        if self.verbose or level in ["WARNING", "ERROR"]:
            print(log_message)

    def parse_ports(self, port_spec):
        ports = set()
        
        if port_spec.lower() == 'common':
            all_ports = set()
            for proto in PROTOCOL_SIGNATURES.values():
                all_ports.update(proto['ports'])
            return sorted(all_ports)[:100]  
        
        elif port_spec.lower() == 'top100':
            return list(range(1, 101)) + [443, 993, 995, 1723, 5060]
        
        elif port_spec.lower() == 'all':
            return list(range(1, 65536))
        
        parts = port_spec.split(',')
        for part in parts:
            part = part.strip()
            if '-' in part:
                try:
                    start, end = map(int, part.split('-'))
                    if start > end:
                        start, end = end, start
                    ports.update(range(start, end + 1))
                except ValueError:
                    self.log(f"Неверный диапазон портов: {part}", "WARNING")
            else:
                try:
                    port = int(part)
                    if 1 <= port <= 65535:
                        ports.add(port)
                    else:
                        self.log(f"Порт вне диапазона: {port}", "WARNING")
                except ValueError:
                    self.log(f"Неверный порт: {part}", "WARNING")
        
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
                    self.log(f"Не удалось разрешить: {target_spec}", "ERROR")
                    targets.add(target_spec)
        except Exception as e:
            self.log(f"Ошибка парсинга цели {target_spec}: {e}", "ERROR")
            targets.add(target_spec)
            
        filtered_targets = [t for t in targets if t not in self.blacklist_ips]
        if len(filtered_targets) != len(targets):
            self.log(f"Отфильтровано {len(targets) - len(filtered_targets)} целей по черному списку", "INFO")
            
        return filtered_targets

    def smart_scan(self, target, port, protocol='tcp'):
        self.stats['ports_scanned'] += 1
        
        # Проверка черного списка
        if self.is_blacklisted(target, port):
            return None
        
        try:
            if protocol == 'tcp':
                return self._tcp_scan(target, port)
            else: 
                return self._udp_scan(target, port)
                
        except Exception as e:
            if self.verbose:
                self.log(f"Ошибка сканирования {target}:{port} - {e}", "ERROR")
            return None

    def _tcp_scan(self, target, port):
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
                    'banner': detection['banner'],
                    'timestamp': datetime.now().isoformat()
                }
            else:
                return None

    def _udp_scan(self, target, port):
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(self.timeout)
            
            try:
                sock.sendto(b'', (target, port))
                data, addr = sock.recvfrom(1024)
                detection = self.detector.detect_protocol(target, port, 'udp')
                
                return {
                    'target': target,
                    'port': port,
                    'state': 'open',
                    'protocol': 'udp',
                    'service': detection['service'],
                    'confidence': detection['confidence'],
                    'banner': detection['banner'],
                    'timestamp': datetime.now().isoformat()
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
                        'banner': detection['banner'],
                        'timestamp': datetime.now().isoformat()
                    }
                return None
            except Exception:
                return None

    def run_scan(self, target_spec, port_spec='common', output_file=None, 
                 protocol='tcp', timing_template=3, output_format='json'):
        self.stats['start_time'] = time.time()
        self.print_banner()
        
        self.timeout = max(0.5, 5 - timing_template)
        self.max_threads = min(1000, 50 * timing_template)
        
        targets = self.parse_targets(target_spec)
        ports = self.parse_ports(port_spec)
        
        filtered_ports = [p for p in ports if p not in self.blacklist_ports]
        if len(filtered_ports) != len(ports):
            self.log(f"Отфильтровано {len(ports) - len(filtered_ports)} портов по черному списку", "INFO")
        ports = filtered_ports
        
        print(f" Цели: {len(targets)} хост(ов)")
        print(f" Порты: {len(ports)} порт(ов)")
        print(f" Протокол: {protocol.upper()}")
        print(f" Потоки: {self.max_threads}")
        print(f"⏱  Таймаут: {self.timeout}с")
        print()
        
        all_results = []
        
        for target in targets:
            self.stats['hosts_scanned'] += 1
            self.log(f"Сканирование {target}...", "INFO")
            target_results = []
            
            if TQDM_AVAILABLE:
                port_iterator = tqdm(ports, desc=f"Сканирование {target}")
            else:
                port_iterator = ports
                print(f"  Прогресс: 0/{len(ports)}", end='')
            
            completed = 0
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
                        banner_preview = result['banner'][:50] if result['banner'] else ''
                        print(f"  {confidence_icon} {result['port']:5} {result['protocol']:4} {result['service']:15} {banner_preview}")
                    
                    completed += 1
                    if not TQDM_AVAILABLE:
                        print(f"\r  Прогресс: {completed}/{len(ports)}", end='')
            
            if not TQDM_AVAILABLE:
                print()  
            
            all_results.extend(target_results)
            self.log(f"Найдено: {len(target_results)} открытых портов", "INFO")
            print()
        
        if output_file:
            self.save_results(all_results, output_file, output_format)
        
        self.stats['end_time'] = time.time()
        duration = self.stats['end_time'] - self.stats['start_time']
        
        print("=" * 50)
        print("СТАТИСТИКА СКАНИРОВАНИЯ")
        print("=" * 50)
        print(f"Время выполнения: {duration:.2f} секунд")
        print(f"Просканировано хостов: {self.stats['hosts_scanned']}")
        print(f"Просканировано портов: {self.stats['ports_scanned']}")
        print(f"Найдено открытых портов: {len(all_results)}")
        print(f"Эффективность: {(len(all_results)/self.stats['ports_scanned']*100 if self.stats['ports_scanned'] > 0 else 0):.1f}%")
        
        return all_results

    def save_results(self, results, filename, format='json'):
        try:
            if format.lower() == 'json':
                output = {
                    'scan_info': {
                        'scanner': 'Yoxiko',
                        'timestamp': datetime.now().isoformat(),
                        'duration': self.stats['end_time'] - self.stats['start_time'],
                        'stats': self.stats
                    },
                    'results': results
                }
                
                with open(filename, 'w', encoding='utf-8') as f:
                    json.dump(output, f, indent=2, ensure_ascii=False)
                
            elif format.lower() == 'csv':
                with open(filename, 'w', newline='', encoding='utf-8') as f:
                    writer = csv.writer(f)
                    writer.writerow(['Цель', 'Порт', 'Протокол', 'Служба', 'Уверенность', 'Баннер', 'Время'])
                    for result in results:
                        writer.writerow([
                            result['target'],
                            result['port'],
                            result['protocol'],
                            result['service'],
                            f"{result['confidence']:.2f}",
                            result['banner'],
                            result['timestamp']
                        ])
                        
            elif format.lower() == 'txt':
                with open(filename, 'w', encoding='utf-8') as f:
                    f.write("Yoxiko - Результаты сканирования\n")
                    f.write("=" * 50 + "\n")
                    f.write(f"Время: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                    f.write(f"Всего найдено: {len(results)} открытых портов\n\n")
                    
                    for result in results:
                        f.write(f"{result['target']}:{result['port']} - {result['service']} ({result['confidence']:.2f})\n")
                        if result['banner']:
                            f.write(f"  Баннер: {result['banner']}\n")
                        f.write("\n")
            
            self.log(f"Результаты сохранены в: {filename} ({format})", "INFO")
            
        except Exception as e:
            self.log(f"Ошибка сохранения результатов: {e}", "ERROR")

def main():
    check_dependencies()
    
    parser = argparse.ArgumentParser(
        description='yoxiko - продвинутый сканер портов для Windows OS',
        add_help=False,
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Примеры использования:
  python yoxiko.py 192.168.1.1
  python yoxiko.py -p 80,443,22 example.com
  python yoxiko.py -u -o results.json 10.0.0.0/24
  python yoxiko.py -p 1-1000 -T 4 -v --format csv -o scan.csv 192.168.1.0/24
  python yoxiko.py --log scan.log -p top100 -o results.json 192.168.1.1-192.168.1.50

Формат указания целей:
  IP адрес: 192.168.1.1
  Домен: example.com  
  CIDR: 192.168.1.0/24
  Диапазон: 192.168.1.1-192.168.1.100
        """
    )
    
    parser.add_argument('target', nargs='?', help='Цель сканирования (IP, домен, CIDR или диапазон)')
    parser.add_argument('-p', '--ports', default='common', 
                       help='Порты для сканирования (common, top100, all, 80,443 или 1-100)')
    parser.add_argument('-o', '--output', help='Файл для сохранения результатов')
    parser.add_argument('--format', choices=['json', 'csv', 'txt'], default='json',
                       help='Формат вывода результатов (по умолчанию: json)')
    parser.add_argument('-t', '--tcp', action='store_true', default=True,
                       help='TCP сканирование (включено по умолчанию)')
    parser.add_argument('-u', '--udp', action='store_true', help='UDP сканирование')
    parser.add_argument('-T', '--timing', type=int, default=3, choices=range(0, 6),
                       help='Шаблон тайминга (0-5, где 5 самый быстрый)')
    parser.add_argument('--max-threads', type=int, default=200,
                       help='Максимальное количество потоков')
    parser.add_argument('--timeout', type=float, default=2.0,
                       help='Таймаут подключения в секундах')
    parser.add_argument('--log', help='Файл для сохранения логов')
    parser.add_argument('-v', '--verbose', action='store_true', help='Подробный вывод')
    parser.add_argument('-h', '--help', action='store_true', help='Показать эту справку')
    
    args = parser.parse_args()
    
    if args.help or not args.target:
        parser.print_help()
        return
    
    protocol = 'tcp'
    if args.udp:
        protocol = 'udp'
        if args.tcp:
            print("  Внимание: Указаны оба протокола, но сканирование будет только UDP. Используйте отдельные запуски для TCP и UDP.")
    
    scanner = Yoxiko(
        max_threads=args.max_threads,
        timeout=args.timeout,
        verbose=args.verbose,
        log_file=args.log
    )
    
    try:
        results = scanner.run_scan(
            target_spec=args.target,
            port_spec=args.ports,
            output_file=args.output,
            protocol=protocol,
            timing_template=args.timing,
            output_format=args.format
        )
        
    except KeyboardInterrupt:
        print("\n Сканирование прервано пользователем")
    except Exception as e:
        print(f" Критическая ошибка: {e}")
        if args.verbose:
            import traceback
            traceback.print_exc()

if __name__ == "__main__":
    main()