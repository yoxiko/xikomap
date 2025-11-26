import json
import csv
import logging
from datetime import datetime
from typing import List, Dict, Any, Optional
from dataclasses import dataclass, asdict
from .constants import PROTOCOL_DESCRIPTIONS

@dataclass
class ScanResult:
    target: str
    port: int
    protocol: str = 'tcp'
    state: str = 'closed'
    service: str = 'unknown'
    confidence: float = 0.0
    banner: str = ''
    scan_type: str = 'connect'
    timestamp: str = None
    detected_os: str = None
    os_confidence: float = 0.0
    technologies: List[str] = None
    blockchain_info: Dict[str, Any] = None
    additional_info: Dict[str, Any] = None  
    
    def __post_init__(self):
        if self.timestamp is None:
            self.timestamp = datetime.now().isoformat()
        if self.technologies is None:
            self.technologies = []
        if self.additional_info is None: 
            self.additional_info = {}
    
    def to_dict(self) -> Dict[str, Any]:
        result = asdict(self)
        for key, value in result.items():
            if isinstance(value, datetime):
                result[key] = value.isoformat()
        return result
    
    def get_description(self) -> str:
        return PROTOCOL_DESCRIPTIONS.get(self.service, PROTOCOL_DESCRIPTIONS['unknown'])
    
    def is_high_confidence(self) -> bool:
        return self.confidence > 0.8

class ResultHandler:
    
    def __init__(self, logger: Optional[logging.Logger] = None):
        self.results: List[ScanResult] = []
        self.logger = logger or logging.getLogger(__name__)
        self.stats = {
            'total_scanned': 0,
            'open_ports': 0,
            'hosts_scanned': 0,
            'start_time': None,
            'end_time': None
        }
    
    def add_result(self, result: ScanResult):
        self.results.append(result)
        if result.state == 'open':
            self.stats['open_ports'] += 1
    
    def add_results(self, results: List[ScanResult]):
        for result in results:
            self.add_result(result)
    
    def get_open_ports(self) -> List[ScanResult]:
        return [r for r in self.results if r.state == 'open']
    
    def get_results_by_target(self, target: str) -> List[ScanResult]:
        return [r for r in self.results if r.target == target]
    
    def get_results_by_service(self, service: str) -> List[ScanResult]:
        return [r for r in self.results if r.service == service and r.state == 'open']
    
    def get_unique_targets(self) -> List[str]:
        return sorted(set(r.target for r in self.results))
    
    def get_stats(self) -> Dict[str, Any]:
        stats = self.stats.copy()
        
        if stats['start_time'] and isinstance(stats['start_time'], datetime):
            stats['start_time'] = stats['start_time'].isoformat()
        
        if stats['end_time'] and isinstance(stats['end_time'], datetime):
            stats['end_time'] = stats['end_time'].isoformat()
        
        if (self.stats['end_time'] and self.stats['start_time'] and 
            isinstance(self.stats['start_time'], datetime) and 
            isinstance(self.stats['end_time'], datetime)):
            
            duration = self.stats['end_time'] - self.stats['start_time']
            stats['duration_seconds'] = duration.total_seconds()
            stats['duration'] = str(duration)
        
        return stats
    
    def start_scan(self):
        self.stats['start_time'] = datetime.now()
    
    def end_scan(self):
        self.stats['end_time'] = datetime.now()
        self.stats['total_scanned'] = len(self.results)
        self.stats['hosts_scanned'] = len(self.get_unique_targets())
    
    def save_to_file(self, filename: str, format: str = 'json'):
        try:
            if format.lower() == 'json':
                self._save_json(filename)
            elif format.lower() == 'csv':
                self._save_csv(filename)
            elif format.lower() == 'txt':
                self._save_txt(filename)
            else:
                raise ValueError(f"Unsupported format: {format}")
            
            self.logger.info(f"Results saved to {filename} ({format.upper()})")
            return True
            
        except Exception as e:
            self.logger.error(f"Error saving results: {e}")
            return False
    
    def _save_json(self, filename: str):
        
        def datetime_serializer(obj):
            """Custom JSON serializer for datetime objects"""
            if isinstance(obj, datetime):
                return obj.isoformat()
            raise TypeError(f"Type {type(obj)} not serializable")
        
        output = {
            'metadata': {
                'scanner': 'Yoxiko Advanced',
                'version': '1.0.0',
                'timestamp': datetime.now().isoformat(),
                'stats': self.get_stats()
            },
            'results': [r.to_dict() for r in self.results]
        }
        
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(output, f, indent=2, ensure_ascii=False, default=datetime_serializer)
    
    def _save_csv(self, filename: str):
        with open(filename, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow([
                'Target', 'Port', 'Protocol', 'State', 'Service', 
                'Confidence', 'Banner', 'Scan Type', 'OS', 'OS Confidence', 'Timestamp'
            ])
            
            for result in self.results:
                writer.writerow([
                    result.target,
                    result.port,
                    result.protocol,
                    result.state,
                    result.service,
                    f"{result.confidence:.2f}",
                    result.banner[:100] if result.banner else '',
                    result.scan_type,
                    result.detected_os or '',
                    f"{result.os_confidence:.1f}" if result.os_confidence else '',
                    result.timestamp
                ])
    
    def _save_txt(self, filename: str):
        with open(filename, 'w', encoding='utf-8') as f:
            f.write("YOXIKO SCANNER - RESULTS\n")
            f.write("=" * 50 + "\n\n")
            
            f.write(f"Scan date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"Total results: {len(self.results)}\n")
            f.write(f"Open ports: {self.stats['open_ports']}\n")
            f.write(f"Hosts scanned: {self.stats['hosts_scanned']}\n\n")
            
            targets = self.get_unique_targets()
            for target in targets:
                target_results = self.get_results_by_target(target)
                open_ports = [r for r in target_results if r.state == 'open']
                
                if open_ports:
                    f.write(f"TARGET: {target}\n")
                    f.write("-" * 30 + "\n")
                    
                    for result in open_ports:
                        f.write(f"Port {result.port}/{result.protocol}: {result.service} ")
                        f.write(f"(confidence: {result.confidence:.2f})\n")
                        
                        if result.banner:
                            f.write(f"  Banner: {result.banner[:80]}\n")
                        
                        if result.detected_os:
                            f.write(f"  OS: {result.detected_os} ")
                            f.write(f"({result.os_confidence}% confidence)\n")
                        
                        if result.technologies:
                            f.write(f"  Technologies: {', '.join(result.technologies)}\n")
                        
                        f.write("\n")
                    
                    f.write("\n")
    
    def clear(self):
        self.results.clear()
        self.stats = {
            'total_scanned': 0,
            'open_ports': 0,
            'hosts_scanned': 0,
            'start_time': None,
            'end_time': None
        }
    
    def __len__(self) -> int:
        return len(self.results)
    
    def __iter__(self):
        return iter(self.results)