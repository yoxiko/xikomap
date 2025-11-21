import socket
import struct
import random
import time
from typing import Dict, Any
from .base_scanner import BaseScanner

class TCPScanner(BaseScanner):
    def __init__(self, timeout: float = 2.0, verbose: bool = False):
        super().__init__(timeout, verbose)
        self.scan_type = 'connect'

    def set_scan_type(self, scan_type: str):
        self.scan_type = scan_type

    def scan_port(self, target: str, port: int) -> Dict[str, Any]:
        self.stats['scanned_ports'] += 1
        
        is_open = False
        
        if self.scan_type == 'syn':
            is_open = self.syn_scan(target, port)
        elif self.scan_type == 'fin':
            is_open = self.fin_scan(target, port)
        elif self.scan_type == 'xmas':
            is_open = self.xmas_scan(target, port)
        else:
            is_open = self.connect_scan(target, port)

        if is_open:
            self.stats['open_ports'] += 1
            return {
                'state': 'open',
                'protocol': 'tcp',
                'scan_type': self.scan_type
            }
        
        return {'state': 'closed'}

    def syn_scan(self, target: str, port: int) -> bool:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
            sock.settimeout(self.timeout)
            
            source_port = random.randint(1024, 65535)
            seq_num = random.randint(0, 4294967295)
            
            tcp_header = self._create_tcp_header(source_port, port, 0x02, seq_num)
            
            pseudo_header = struct.pack('!4s4sBBH',
                                      socket.inet_aton("127.0.0.1"),
                                      socket.inet_aton(target),
                                      0, 6, len(tcp_header))
            
            checksum_data = pseudo_header + tcp_header
            checksum = self._calculate_checksum(checksum_data)
            
            tcp_header = struct.pack('!HHLLBBHHH',
                                source_port, port, 
                                seq_num, 0,                    
                                (5 << 4), 0x02, 5840,        
                                checksum, 0)                   
            
            sock.sendto(tcp_header, (target, port))
            
            start_time = time.time()
            while time.time() - start_time < self.timeout:
                try:
                    response, addr = sock.recvfrom(1024)
                    if addr[0] == target:
                        tcp_response = response[20:]
                        if len(tcp_response) > 13:
                            flags = tcp_response[13]
                            if flags & 0x12:
                                sock.close()
                                return True
                            elif flags & 0x04:
                                sock.close()
                                return False
                except socket.timeout:
                    break
            
            sock.close()
            return False
            
        except PermissionError:
            if self.verbose:
                print("Для SYN-сканирования требуются права администратора")
            return self.connect_scan(target, port)
        except Exception as e:
            if self.verbose:
                print(f"Ошибка SYN-сканирования: {e}")
            return self.connect_scan(target, port)

    def fin_scan(self, target: str, port: int) -> bool:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            result = sock.connect_ex((target, port))
            
            if result == 0:
                try:
                    sock.shutdown(socket.SHUT_RDWR)
                except:
                    pass
            
            sock.close()
            return result == 0
        except Exception:
            return False

    def xmas_scan(self, target: str, port: int) -> bool:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            result = sock.connect_ex((target, port))
            
            if result == 0:
                try:
                    sock.send(b'XMAS' + b'\x00' * 10)
                    sock.recv(1024)
                    sock.close()
                    return True
                except:
                    sock.close()
                    return True
            
            sock.close()
            return False
        except Exception:
            return False

    def _create_tcp_header(self, source_port: int, dest_port: int, flags: int, seq: int = 0, ack: int = 0, window: int = 5840):
        offset_reserved = (5 << 4) + 0
        checksum = 0
        urg_ptr = 0
        
        tcp_header = struct.pack('!HHLLBBHHH',
                                source_port, dest_port,
                                seq, ack,
                                offset_reserved, flags,
                                window, checksum, urg_ptr)
        return tcp_header

    def _calculate_checksum(self, data: bytes) -> int:
        if len(data) % 2:
            data += b'\x00'
        
        checksum = 0
        for i in range(0, len(data), 2):
            word = (data[i] << 8) + data[i+1]
            checksum += word
            checksum = (checksum & 0xffff) + (checksum >> 16)
        
        return ~checksum & 0xffff