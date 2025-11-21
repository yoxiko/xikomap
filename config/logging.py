import logging
import os
import sys
from datetime import datetime
from typing import Optional, Dict, Any

class ColoredFormatter(logging.Formatter):
    COLORS = {
        'DEBUG': '\033[94m',    
        'INFO': '\033[92m',      
        'WARNING': '\033[93m',   
        'ERROR': '\033[91m',    
        'CRITICAL': '\033[95m',  
        'RESET': '\033[0m'       
    }

    def format(self, record):
        log_color = self.COLORS.get(record.levelname, self.COLORS['RESET'])
        message = super().format(record)
        return f"{log_color}{message}{self.COLORS['RESET']}"

def setup_logging(log_file: Optional[str] = None, 
                  level: str = 'INFO',
                  verbose: bool = False,
                  enable_colors: bool = True) -> logging.Logger:
    
    logger = logging.getLogger('yoxiko')
    
    if verbose:
        level = 'DEBUG'
    
    log_level = getattr(logging, level.upper(), logging.INFO)
    logger.setLevel(log_level)
    
    if logger.handlers:
        logger.handlers.clear()
    
    formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    
    if enable_colors and sys.stderr.isatty():
        formatter = ColoredFormatter(
            '%(asctime)s - %(levelname)s - %(message)s',
            datefmt='%H:%M:%S'
        )
    
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(log_level)
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)
    
    if log_file:
        try:
            log_dir = os.path.dirname(log_file)
            if log_dir and not os.path.exists(log_dir):
                os.makedirs(log_dir)
            
            file_formatter = logging.Formatter(
                '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
                datefmt='%Y-%m-%d %H:%M:%S'
            )
            
            file_handler = logging.FileHandler(log_file, encoding='utf-8')
            file_handler.setLevel(logging.DEBUG)
            file_handler.setFormatter(file_formatter)
            logger.addHandler(file_handler)
            
            logger.info(f"Логирование в файл: {log_file}")
            
        except Exception as e:
            logger.error(f"Не удалось настроить файловое логирование: {e}")
    
    logger.propagate = False
    return logger

def get_logger(name: str = 'yoxiko') -> logging.Logger:
    return logging.getLogger(name)

class ScanLogger:
    def __init__(self, logger: logging.Logger, verbose: bool = False):
        self.logger = logger
        self.verbose = verbose
        self.scan_start_time = None
        self.stats = {
            'hosts_scanned': 0,
            'ports_scanned': 0,
            'open_ports_found': 0
        }
    
    def start_scan(self, target: str, ports: list, scan_type: str):
        self.scan_start_time = datetime.now()
        self.logger.info(f"Начало сканирования: {target}")
        self.logger.info(f"Порты: {len(ports)}")
        self.logger.info(f"Тип сканирования: {scan_type}")
    
    def log_port_result(self, target: str, port: int, result: Dict[str, Any]):
        self.stats['ports_scanned'] += 1
        
        if result.get('state') == 'open':
            self.stats['open_ports_found'] += 1
            service = result.get('service', 'unknown')
            confidence = result.get('confidence', 0)
            
            if self.verbose:
                self.logger.info(f"🟢 {target}:{port} - {service} (уверенность: {confidence:.2f})")
            else:
                self.logger.debug(f"Открыт порт {port} - {service}")
    
    def log_host_complete(self, target: str, open_ports: list):
        self.stats['hosts_scanned'] += 1
        if open_ports:
            self.logger.info(f"Хост {target}: найдено {len(open_ports)} открытых портов")
        else:
            self.logger.debug(f"Хост {target}: открытых портов не найдено")
    
    def end_scan(self):
        if self.scan_start_time:
            duration = (datetime.now() - self.scan_start_time).total_seconds()
            self.logger.info(f"Сканирование завершено за {duration:.2f} сек")
            self.logger.info(f"Статистика: хостов - {self.stats['hosts_scanned']}, "
                           f"портов - {self.stats['ports_scanned']}, "
                           f"открытых - {self.stats['open_ports_found']}")
    
    def log_error(self, message: str, exception: Exception = None):
        if exception:
            self.logger.error(f"{message}: {exception}")
        else:
            self.logger.error(message)
    
    def log_warning(self, message: str):
        self.logger.warning(message)
    
    def log_debug(self, message: str):
        if self.verbose:
            self.logger.debug(message)