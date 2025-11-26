import re
from typing import Dict, List, Optional

class CMSFrameworkDetector:
    def __init__(self):
        self.cms_patterns = {
            'WordPress': [r'wp-content', r'wp-includes', r'wp-json', r'wordpress'],
            'Joomla': [r'joomla', r'Joomla!', r'/media/joomla/'],
            'Drupal': [r'drupal', r'sites/all/', r'/sites/default/'],
            'Magento': [r'magento', r'static/version'],
            'Shopify': [r'shopify', r'Shopify'],
            # Добавь другие CMS
        }
        
        self.framework_patterns = {
            'React': [r'react', r'React', r'__NEXT_DATA__'],
            'Vue.js': [r'vue', r'Vue', r'__vue__'],
            'Angular': [r'angular', r'ng-'],
            'Django': [r'csrftoken', r'django'],
            'Laravel': [r'laravel', r'X-Powered-By: Laravel'],
            # Добавь другие фреймворки
        }

    def detect_cms(self, html_content: str, headers: Dict[str, str] = None) -> List[str]:
        # Реализация детектирования CMS
        pass

    def detect_framework(self, html_content: str, headers: Dict[str, str] = None) -> List[str]:
        # Реализация детектирования фреймворков
        pass