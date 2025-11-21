import socket
import time
from abc import ABC, abstractmethod
from typing import Optional, Dict, Any

class BaseScanner(ABC):
    def __init__(self, timeout: float = 2.0, verbose: bool = False):
        self.timeout = timeout
        self.verbose = verbose
        self.stats = {
            'scanned_ports': 0,
            'open_ports': 0,
            'start_time': None,
            'end_time': None
        }

    @abstractmethod
    def scan_port(self, target: str, port: int) -> Dict[str, Any]:
        pass

    def connect_scan(self, target: str, port: int) -> bool:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            result = sock.connect_ex((target, port))
            sock.close()
            return result == 0
        except Exception:
            return False

    def start_scan(self):
        self.stats['start_time'] = time.time()

    def end_scan(self):
        self.stats['end_time'] = time.time()

    def get_stats(self) -> Dict[str, Any]:
        if self.stats['start_time'] and self.stats['end_time']:
            self.stats['duration'] = self.stats['end_time'] - self.stats['start_time']
        return self.stats.copy()