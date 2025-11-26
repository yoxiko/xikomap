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