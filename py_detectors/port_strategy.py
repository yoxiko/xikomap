from typing import List, Dict

class PortStrategy:
    STRATEGIES: Dict[str, List[int]] = {
        'top10': [21, 22, 23, 25, 53, 80, 110, 143, 443, 3389],
        'top100': [
            21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995,
            1723, 3306, 3389, 5900, 8080
        ],
        'web': [80, 443, 8000, 8080, 8443, 8888, 3000, 5000],
        'database': [1433, 1521, 3306, 5432, 6379, 27017],
        'udp_common': [53, 67, 68, 123, 137, 138, 161, 500]
    }

    @classmethod
    def get_ports(cls, strategy: str, custom_ports: str = None) -> List[int]:
        if custom_ports:
            return cls._parse_custom_ports(custom_ports)
        
        strategy = strategy.lower()
        if strategy in cls.STRATEGIES:
            return cls.STRATEGIES[strategy]
        
        return cls.STRATEGIES['top100']

    @classmethod
    def _parse_custom_ports(cls, ports_str: str) -> List[int]:
        result = set()
        parts = ports_str.replace(' ', '').split(',')
        
        for part in parts:
            if '-' in part:
                start, end = part.split('-')
                result.update(range(int(start), int(end) + 1))
            else:
                result.add(int(part))
                
        return sorted(list(result))