

import ipaddress
import socket
import re
import os
from typing import List, Set, Union, Tuple
from .constants import PORT_GROUPS, ERROR_CODES

def parse_targets(target_spec: str) -> List[str]:

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
                targets.add(target_spec)
                
    except Exception as e:
        targets.add(target_spec)
    
    return sorted(targets)

def parse_ports(port_spec: str) -> List[int]:
    ports = set()
    
    if port_spec.lower() in PORT_GROUPS:
        return PORT_GROUPS[port_spec.lower()]
    
    if port_spec.lower() == 'all':
        return list(range(1, 65536))
    
    parts = port_spec.split(',')
    
    for part in parts:
        part = part.strip()
        
        if '-' in part:
            try:
                start, end = map(int, part.split('-'))
                if 1 <= start <= 65535 and 1 <= end <= 65535:
                    if start > end:
                        start, end = end, start
                    ports.update(range(start, end + 1))
            except ValueError:
                continue  
        
        else:
            try:
                port = int(part)
                if 1 <= port <= 65535:
                    ports.add(port)
            except ValueError:
                continue 
    
    return sorted(ports)

def validate_port(port: int) -> bool:
    return 1 <= port <= 65535

def validate_ip(ip: str) -> bool:
    try:
        ipaddress.IPv4Address(ip)
        return True
    except ipaddress.AddressValueError:
        return False

def get_hostname(ip: str) -> str:
    try:
        return socket.gethostbyaddr(ip)[0]
    except (socket.herror, socket.gaierror):
        return ip

def is_private_ip(ip: str) -> bool:
    try:
        ip_obj = ipaddress.IPv4Address(ip)
        return ip_obj.is_private
    except ipaddress.AddressValueError:
        return False

def load_blacklist(file_path: str) -> Set[str]:
    blacklist = set()
    
    if not os.path.exists(file_path):
        return blacklist
    
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#'):
                    blacklist.add(line)
    except Exception:
        pass
    
    return blacklist

def save_blacklist(blacklist: Set[str], file_path: str):
    try:
        with open(file_path, 'w', encoding='utf-8') as f:
            f.write("# Blacklist file\n")
            for item in sorted(blacklist):
                f.write(f"{item}\n")
    except Exception:
        pass

def get_error_message(error_code: str) -> str:
    return ERROR_CODES.get(error_code, "Неизвестная ошибка")

def format_duration(seconds: float) -> str:
    if seconds < 60:
        return f"{seconds:.2f} сек"
    elif seconds < 3600:
        minutes = seconds / 60
        return f"{minutes:.1f} мин"
    else:
        hours = seconds / 3600
        return f"{hours:.1f} ч"

def format_confidence(confidence: float) -> Tuple[str, str]:
    if confidence > 0.8:
        return "🟢", "Высокая"
    elif confidence > 0.6:
        return "🟡", "Средняя"
    elif confidence > 0.4:
        return "🟠", "Низкая"
    else:
        return "🔴", "Очень низкая"

def create_banner() -> str:

    banner = """
╔══════════════════════════════════════════════╗
║                YOXIKO SCANNER                ║
║          https://github.com/yoxiko           ║
╚══════════════════════════════════════════════╝
"""
    return banner