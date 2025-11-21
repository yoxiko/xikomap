

import argparse
import sys
import os
import time

sys.path.append(os.path.join(os.path.dirname(__file__), '.'))

from core import parse_targets, parse_ports, PROTOCOL_DESCRIPTIONS
from core.results import ScanResult, ResultHandler
from config.blacklists import BlacklistManager
from scanner.advanced_scanner import AdvancedScanner
from detectors.advanced_protocol_detector import AdvancedProtocolDetector
from detectors.technology_detector import TechnologyDetector

class UltimateScanner:
    
    def __init__(self, max_threads=100, timeout=2, verbose=False):
        self.max_threads = max_threads
        self.timeout = timeout
        self.verbose = verbose
        self.blacklist = BlacklistManager()
        self.scanner = AdvancedScanner(max_threads, timeout, verbose)
        self.protocol_detector = AdvancedProtocolDetector(timeout, verbose)
        self.tech_detector = TechnologyDetector()
        self.results = []

    def print_banner(self):
        print(" Сканер портов -- by @yoxiko ")
        print("=" * 45)
        print("   Полная база протоколов • Детектирование технологий")
        print("   TCP/UDP сканирование • Умное определение служб")
        print()

    def scan_target(self, target, ports, protocol='tcp', scan_type='connect'):

        if self.blacklist.is_blacklisted(target):
            print(f"  Пропуск {target} (в черном списке)")
            return

        protocol_icon = "🔵" if protocol == 'tcp' else "🟣"
        print(f"\n{protocol_icon} Сканирование {target} ({protocol.upper()})...")
        
        open_ports = []
        scan_results = self.scanner.batch_scan([target], ports, protocol, scan_type)
        target_results = scan_results.get(target, [])

        for scan_result in target_results:
            port = scan_result['port']
            
            protocol_result = self.protocol_detector.detect_protocol(target, port, protocol)
            
            technologies = []
            service_info = ""
            
            if protocol_result.get('service') in ['http', 'https', 'http-alt']:
                technologies = self.tech_detector.detect_technologies(target, port)
                if technologies:
                    service_info = f" |  {', '.join(technologies[:3])}"
            
            result = ScanResult(
                target=target,
                port=port,
                protocol=protocol,
                state='open',
                service=protocol_result.get('service', 'неизвестно'),
                confidence=protocol_result.get('confidence', 0),
                banner=protocol_result.get('banner', ''),
                scan_type=scan_type,
                technologies=technologies
            )
            
            self.results.append(result)
            open_ports.append(result)
            
            confidence = protocol_result.get('confidence', 0)
            if confidence > 0.8:
                confidence_icon = "🟢"
            elif confidence > 0.6:
                confidence_icon = "🟡" 
            else:
                confidence_icon = "🟠"
            
            service_name = protocol_result.get('service', 'неизвестно')
            print(f"   {confidence_icon} {port}/{protocol} - {service_name}{service_info}")
            
            if self.verbose and protocol_result.get('banner'):
                banner_preview = protocol_result['banner'][:100] + "..." if len(protocol_result['banner']) > 100 else protocol_result['banner']
                print(f"       {banner_preview}")

        if not open_ports:
            print("    Открытых портов не найдено")
        else:
            print(f"    Найдено {len(open_ports)} открытых портов")

    def run_scan(self, target_spec, port_spec='common', protocol='tcp', scan_type='connect', info_mode=False):
        self.print_banner()
        
        targets = parse_targets(target_spec)
        ports = parse_ports(port_spec)
        
        print(f" Цели: {len(targets)} |  Порты: {len(ports)} |  Протокол: {protocol.upper()} | ⚡ Тип: {scan_type}")
        if self.verbose:
            print(f"   Таймаут: {self.timeout}с | Потоки: {self.max_threads}")
        print()
        
        start_time = time.time()
        
        for target in targets:
            self.scan_target(target, ports, protocol, scan_type)
        
        duration = time.time() - start_time
        
        total_open = len([r for r in self.results if r.state == 'open'])
        unique_services = len(set(r.service for r in self.results if r.state == 'open'))
        
        print(f"\n ИТОГ:")
        print(f"   Открытых портов: {total_open}")
        print(f"   Уникальных служб: {unique_services}") 
        print(f"   Время сканирования: {duration:.1f}с")
        
        if info_mode and self.results:
            print(f"\n ИНФОРМАЦИЯ О СЛУЖБАХ:")
            for result in self.results:
                if result.state == 'open':
                    description = PROTOCOL_DESCRIPTIONS.get(result.service, "Описание отсутствует")
                    print(f"   {result.port}/{result.protocol} - {result.service}: {description}")
        
        return self.results

def main():
    """Главная функция"""
    parser = argparse.ArgumentParser(description='Yoxiko - Продвинутый сканер портов')
    
    parser.add_argument('target', help='Цель сканирования (IP, домен, CIDR)')
    parser.add_argument('-p', '--ports', default='common', 
                       help='Порты: common, web, database, mail, remote, network, devops, iot, gaming, blockchain, all или 80,443,1-100')
    parser.add_argument('-s', '--scan-type', choices=['connect', 'syn'], 
                       default='connect', help='Тип сканирования')
    parser.add_argument('-u', '--udp', action='store_true', 
                       help='UDP сканирование (по умолчанию TCP)')
    parser.add_argument('-v', '--verbose', action='store_true',
                       help='Подробный вывод с баннерами')
    parser.add_argument('-info', '--info', action='store_true',
                       help='Показать информацию о найденных службах')
    
    args = parser.parse_args()
    
    try:
        scanner = UltimateScanner(verbose=args.verbose)
        protocol = 'udp' if args.udp else 'tcp'
        scanner.run_scan(args.target, args.ports, protocol, args.scan_type, args.info)
        
    except KeyboardInterrupt:
        print("\n Сканирование прервано")
    except Exception as e:
        print(f" Ошибка: {e}")
        if args.verbose:
            import traceback
            traceback.print_exc()

if __name__ == "__main__":
    main()