import re
import ssl
import socket
from typing import Dict, Any, List, Optional
from urllib.parse import urlparse

class TechnologyDetector:
    
    def __init__(self):
        self.tech_patterns = {
            'React': [r'react', r'__NEXT_DATA__', r'_next/static', r'ReactDOM'],
            'Vue.js': [r'vue', r'__vue__', r'v-model', r'vue-router'],
            'Angular': [r'angular', r'ng-', r'X-XSS-Protection'],
            'jQuery': [r'jquery', r'\$\.', r'jQuery\.[a-zA-Z]'],
            'Express.js': [r'Express', r'X-Powered-By: Express'],
            'Django': [r'csrftoken', r'django', r'X-Frame-Options: DENY'],
            'Flask': [r'flask', r'Werkzeug', r'Server: Werkzeug'],
            'Laravel': [r'laravel', r'X-Powered-By: Laravel', r'php artisan'],
            'Ruby on Rails': [r'rails', r'Ruby', r'X-Runtime: ruby'],
            'ASP.NET': [r'ASP\.NET', r'X-AspNet-Version', r'X-AspNetMvc-Version'],
            'Apache': [r'Apache', r'httpd', r'Server: Apache', r'mod_'],
            'Nginx': [r'nginx', r'Server: nginx'],
            'IIS': [r'Microsoft-IIS', r'Server: Microsoft-IIS'],
            'Caddy': [r'Server: Caddy'],
            'LiteSpeed': [r'LiteSpeed', r'Server: LiteSpeed'],
            'PHP': [r'PHP', r'X-Powered-By: PHP', r'\.php', r'PHPSESSID'],
            'Python': [r'Python', r'WSGIServer', r'mod_wsgi'],
            'Node.js': [r'Node\.js', r'X-Powered-By: Node\.js'],
            'Java': [r'JSESSIONID', r'Servlet', r'JBoss', r'Tomcat', r'GlassFish'],
            'Go': [r'Go', r'X-Powered-By: Go'],
            'Ruby': [r'Ruby', r'X-Runtime: ruby', r'Rack', r'Passenger'],
            'MySQL': [r'mysql', r'MySQL', r'phpMyAdmin'],
            'PostgreSQL': [r'PostgreSQL', r'psql', r'pg_'],
            'MongoDB': [r'mongodb', r'MongoDB'],
            'Redis': [r'redis', r'Redis'],
            'SQLite': [r'SQLite', r'sqlite3'],
            'WordPress': [r'wp-', r'wordpress', r'wp-content', r'wp-includes'],
            'Joomla': [r'joomla', r'Joomla', r'com_'],
            'Drupal': [r'Drupal', r'drupal', r'sites/all/'],
            'Magento': [r'magento', r'Magento', r'static/version'],
            'Shopify': [r'shopify', r'Shopify'],
            'WooCommerce': [r'woocommerce', r'WooCommerce'],
            'PrestaShop': [r'prestashop', r'PrestaShop'],
            'OpenCart': [r'opencart', r'OpenCart'],
            'BigCommerce': [r'bigcommerce', r'BigCommerce'],
            'Google Analytics': [r'google-analytics', r'ga\.js', r'gtag\.js'],
            'Google Tag Manager': [r'googletagmanager', r'gtm\.js'],
            'Yandex.Metrica': [r'yandex\.metrica', r'mc\.yandex\.ru'],
            'CloudFlare': [r'cloudflare', r'cf-ray', r'Server: cloudflare'],
            'Akamai': [r'akamai', r'X-Akamai'],
            'Fastly': [r'fastly', r'X-Fastly'],
            'Wordfence': [r'wordfence', r'wfwaf'],
            'Cloudflare WAF': [r'cf-waf', r'cf-country'],
            'Sucuri': [r'sucuri', r'X-Sucuri'],
            'Bootstrap': [r'bootstrap', r'bootstrap\.css', r'bootstrap\.min\.css'],
            'Font Awesome': [r'font-awesome', r'fa-'],
            'Google Fonts': [r'googleapis\.com/css', r'fonts\.googleapis'],
            'Docker': [r'docker', r'Docker', r'X-Docker'],
            'Kubernetes': [r'kubernetes', r'k8s'],
            'Jenkins': [r'jenkins', r'Jenkins'],
            'GitLab': [r'gitlab', r'GitLab'],
            'GitHub': [r'github', r'GitHub'],
        }

    def detect_technologies(self, target: str, port: int, html_content: str = '', headers: Dict[str, str] = None) -> List[str]:
        technologies = []
        
        if headers:
            technologies.extend(self._analyze_headers(headers))
            
        if html_content:
            technologies.extend(self._analyze_html(html_content))
            
        technologies.extend(self._probe_technologies(target, port))
        
        return list(set(technologies)) 

    def _analyze_headers(self, headers: Dict[str, str]) -> List[str]:
        tech_found = []
        server_header = headers.get('Server', '').lower()
        powered_by = headers.get('X-Powered-By', '').lower()
        x_generator = headers.get('X-Generator', '').lower()
        
        header_tech_map = {
            'apache': 'Apache',
            'nginx': 'Nginx', 
            'iis': 'IIS',
            'node.js': 'Node.js',
            'express': 'Express.js',
            'php': 'PHP',
            'tomcat': 'Java',
            'jetty': 'Java',
            'glassfish': 'Java',
            'werkzeug': 'Flask',
            'wordpress': 'WordPress',
            'drupal': 'Drupal',
            'joomla': 'Joomla',
        }
        
        for key, tech in header_tech_map.items():
            if (key in server_header or 
                key in powered_by or 
                key in x_generator):
                tech_found.append(tech)
                
        return tech_found

    def _analyze_html(self, html_content: str) -> List[str]:
        tech_found = []
        html_lower = html_content.lower()
        
        for tech, patterns in self.tech_patterns.items():
            for pattern in patterns:
                if re.search(pattern, html_lower, re.IGNORECASE):
                    tech_found.append(tech)
                    break
                    
        return tech_found

    def _probe_technologies(self, target: str, port: int) -> List[str]:
        tech_found = []
        
        if self._check_wordpress(target, port):
            tech_found.append('WordPress')
            
        if self._check_phpmyadmin(target, port):
            tech_found.append('phpMyAdmin')
            
        if self._check_docker(target, port):
            tech_found.append('Docker')
            
        return tech_found

    def _check_wordpress(self, target: str, port: int) -> bool:
        try:
            import requests
            response = requests.get(f"http://{target}:{port}/wp-login.php", timeout=3)
            return response.status_code == 200 and "wp-submit" in response.text
        except:
            return False

    def _check_phpmyadmin(self, target: str, port: int) -> bool:
        try:
            import requests
            response = requests.get(f"http://{target}:{port}/phpmyadmin/", timeout=3)
            return response.status_code == 200 and "phpMyAdmin" in response.text
        except:
            return False

    def _check_docker(self, target: str, port: int) -> bool:
        try:
            import requests
            response = requests.get(f"http://{target}:{port}/version", timeout=3)
            return response.status_code == 200 and "ApiVersion" in response.text
        except:
            return False

    def get_technology_info(self, tech_name: str) -> Dict[str, str]:
        tech_info = {
            'WordPress': 'Система управления контентом (CMS)',
            'React': 'JavaScript библиотека для создания пользовательских интерфейсов',
            'Vue.js': 'Прогрессивный фреймворк для создания пользовательских интерфейсов',
            'Angular': 'Платформа для создания мобильных и desktop приложений',
            'Node.js': 'Среда выполнения JavaScript на стороне сервера',
            'Express.js': 'Минималистичный веб-фреймворк для Node.js',
            'Django': 'Высокоуровневый Python веб-фреймворк',
            'Flask': 'Микрофреймворк для Python',
            'Laravel': 'PHP веб-фреймворк',
            'Apache': 'Веб-сервер с открытым исходным кодом',
            'Nginx': 'Высокопроизводительный веб-сервер и обратный прокси',
            'MySQL': 'Реляционная система управления базами данных',
            'MongoDB': 'Документоориентированная система управления базами данных',
            'Docker': 'Платформа для контейнеризации приложений',
            'Kubernetes': 'Система оркестрации контейнеров',
        }
        
        return {
            'name': tech_name,
            'description': tech_info.get(tech_name, 'Информация отсутствует'),
            'category': self._get_tech_category(tech_name)
        }

    def _get_tech_category(self, tech_name: str) -> str:
        categories = {
            'Frontend Frameworks': ['React', 'Vue.js', 'Angular', 'jQuery', 'Bootstrap'],
            'Backend Frameworks': ['Express.js', 'Django', 'Flask', 'Laravel', 'Ruby on Rails', 'ASP.NET'],
            'Web Servers': ['Apache', 'Nginx', 'IIS', 'Caddy', 'LiteSpeed'],
            'Programming Languages': ['PHP', 'Python', 'Node.js', 'Java', 'Go', 'Ruby'],
            'Databases': ['MySQL', 'PostgreSQL', 'MongoDB', 'Redis', 'SQLite'],
            'CMS': ['WordPress', 'Joomla', 'Drupal', 'Magento', 'Shopify'],
            'E-commerce': ['PrestaShop', 'OpenCart', 'BigCommerce', 'WooCommerce'],
            'Analytics': ['Google Analytics', 'Google Tag Manager', 'Yandex.Metrica'],
            'CDN': ['CloudFlare', 'Akamai', 'Fastly'],
            'Security': ['Wordfence', 'Cloudflare WAF', 'Sucuri'],
            'DevOps': ['Docker', 'Kubernetes', 'Jenkins', 'GitLab', 'GitHub'],
        }
        
        for category, tech_list in categories.items():
            if tech_name in tech_list:
                return category
                
        return 'Other'