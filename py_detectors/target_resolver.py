import ipaddress
import socket
from typing import List, Set


class TargetResolver:
    def __init__(self, exclude_targets: List[str] = None):
        self.exclude_ips: Set[str] = set()
        self.exclude_networks: List[ipaddress.IPv4Network] = []
        
        if exclude_targets:
            self._parse_exclusions(exclude_targets)

    def _parse_exclusions(self, exclude_list: List[str]):
        for item in exclude_list:
            try:
                self.exclude_networks.append(ipaddress.IPv4Network(item, strict=False))
            except ValueError:
                try:
                    self.exclude_ips.add(str(ipaddress.IPv4Address(item)))
                except ValueError:
                    pass 

    def _is_excluded(self, ip_str: str) -> bool:
        if ip_str in self.exclude_ips:
            return True
        
        try:
            ip_obj = ipaddress.IPv4Address(ip_str)
            for network in self.exclude_networks:
                if ip_obj in network:
                    return True
        except ValueError:
            pass
        return False

    def resolve(self, targets: List[str]) -> List[str]:
        resolved_ips: Set[str] = set()

        for target in targets:
            target = target.strip()
            if not target:
                continue

            if '/' in target:
                try:
                    network = ipaddress.IPv4Network(target, strict=False)
                    for ip in network.hosts():
                        ip_str = str(ip)
                        if not self._is_excluded(ip_str):
                            resolved_ips.add(ip_str)
                    continue
                except ValueError:
                    pass

            if '-' in target and '/' not in target:
                parts = target.split('-')
                if len(parts) == 2:
                    try:
                        base_ip = parts[0].rsplit('.', 1)[0]
                        start = int(parts[0].rsplit('.', 1)[1])
                        end = int(parts[1])
                        for i in range(start, end + 1):
                            ip_str = f"{base_ip}.{i}"
                            if not self._is_excluded(ip_str):
                                resolved_ips.add(ip_str)
                        continue
                    except (ValueError, IndexError):
                        pass

            try:
                ip_str = socket.gethostbyname(target)
                if not self._is_excluded(ip_str):
                    resolved_ips.add(ip_str)
            except socket.gaierror:
                try:
                    ip_str = str(ipaddress.IPv4Address(target))
                    if not self._is_excluded(ip_str):
                        resolved_ips.add(ip_str)
                except ValueError:
                    pass 

        return sorted(list(resolved_ips))