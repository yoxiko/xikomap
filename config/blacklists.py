import os
import json
from typing import Set, List, Dict, Any
from pathlib import Path

class BlacklistManager:
    def __init__(self, config_dir: str = "config"):
        self.config_dir = Path(config_dir)
        self.config_dir.mkdir(exist_ok=True)
        
        self.blacklist_file = self.config_dir / 'blacklist.txt'
        self.blacklisted_sites: Set[str] = set()
        
        self.load_blacklist()

    def load_blacklist(self) -> bool:
        try:
            if self.blacklist_file.exists():
                with open(self.blacklist_file, 'r', encoding='utf-8') as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith('#'):
                            self.blacklisted_sites.add(line.lower())
                return True
        except Exception as e:
            print(f"Ошибка загрузки черного списка: {e}")
        return False

    def save_blacklist(self):
        try:
            with open(self.blacklist_file, 'w', encoding='utf-8') as f:
                f.write("# Черный список сайтов\n")
                f.write("# По одному сайту на строку\n")
                f.write("# Пример: example.com\n\n")
                for site in sorted(self.blacklisted_sites):
                    f.write(f"{site}\n")
        except Exception as e:
            print(f"Ошибка сохранения черного списка: {e}")

    def is_blacklisted(self, target: str) -> bool:
        return target.lower() in self.blacklisted_sites

    def add_to_blacklist(self, site: str) -> bool:
        try:
            self.blacklisted_sites.add(site.lower().strip())
            self.save_blacklist()
            return True
        except Exception:
            return False

    def remove_from_blacklist(self, site: str) -> bool:
        try:
            self.blacklisted_sites.discard(site.lower())
            self.save_blacklist()
            return True
        except Exception:
            return False

    def get_blacklist(self) -> List[str]:
        return sorted(self.blacklisted_sites)

    def clear_blacklist(self):
        self.blacklisted_sites.clear()
        self.save_blacklist()