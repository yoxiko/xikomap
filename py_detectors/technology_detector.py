from dataclasses import dataclass, field
from typing import List, Dict, Optional
import re

@dataclass
class TechnologySignature:
    name: str
    category: str
    patterns: List[str]
    confidence: float = 1.0

@dataclass
class DetectedTechnology:
    name: str
    category: str
    confidence: float
    version: Optional[str] = None
    evidence: str = ""

class TechnologyDetector:
    def __init__(self):
        self.signatures = self._load_signatures()
    
    def _load_signatures(self) -> List[TechnologySignature]:
        return [
            TechnologySignature("React", "Frontend Framework", ["react", "reactdom", "__react", "react-router"]),
            TechnologySignature("Vue.js", "Frontend Framework", ["vue", "vuex", "vuejs", "v-bind", "v-model"]),
            TechnologySignature("Angular", "Frontend Framework", ["angular", "ng-", "ngzone", "ng-app"]),
            TechnologySignature("Svelte", "Frontend Framework", ["svelte", "sveltekit"]),
            TechnologySignature("Next.js", "Frontend Framework", ["next", "nextjs", "__next"]),
            TechnologySignature("Nuxt.js", "Frontend Framework", ["nuxt", "nuxtjs"]),
            TechnologySignature("jQuery", "JavaScript Library", ["jquery", "jquery.min.js", "$.ajax"]),
            TechnologySignature("Bootstrap", "CSS Framework", ["bootstrap", "bootstrap.min.css", "btn-primary"]),
            TechnologySignature("Tailwind CSS", "CSS Framework", ["tailwind", "tw-", "tailwindcss"]),
            TechnologySignature("Material UI", "CSS Framework", ["mui", "material-ui", "@mui"]),
            TechnologySignature("Webpack", "Build Tool", ["webpack", "__webpack", "webpackJsonp"]),
            TechnologySignature("Vite", "Build Tool", ["vite", "vitejs", "@vite"]),
            TechnologySignature("Docker", "Container", ["docker", "container", "docker-compose"]),
            TechnologySignature("Kubernetes", "Orchestration", ["kubernetes", "k8s", "kubectl"]),
            TechnologySignature("Redis", "Database", ["redis", "redis_version", "redis-server"]),
            TechnologySignature("Elasticsearch", "Search Engine", ["elasticsearch", "lucene_version", "elastic"]),
            TechnologySignature("RabbitMQ", "Message Broker", ["rabbitmq", "amqp", "rabbit"]),
            TechnologySignature("Apache Kafka", "Message Broker", ["kafka", "zookeeper", "kafka-cluster"]),
            TechnologySignature("GraphQL", "API", ["graphql", "__schema", "graphql-playground"]),
            TechnologySignature("REST API", "API", ["swagger", "openapi", "api-docs", "petstore"]),
            TechnologySignature("WordPress", "CMS", ["wordpress", "wp-content", "wp-includes", "wp-json"]),
            TechnologySignature("Drupal", "CMS", ["drupal", "drupal.js", "sites/default"]),
            TechnologySignature("Joomla", "CMS", ["joomla", "mosconfig", "joomla.js"]),
            TechnologySignature("Shopify", "E-commerce", ["shopify", "cdn.shopify.com", "shopifycdn"]),
            TechnologySignature("WooCommerce", "E-commerce", ["woocommerce", "wc-", "woo-"]),
            TechnologySignature("Magento", "E-commerce", ["magento", "mage/", "static/version"]),
            TechnologySignature("Nginx", "Web Server", ["nginx", "server: nginx"]),
            TechnologySignature("Apache", "Web Server", ["apache", "server: apache"]),
            TechnologySignature("Cloudflare", "CDN", ["cloudflare", "cf-ray", "cloudflare-nginx"]),
            TechnologySignature("AWS", "Cloud Provider", ["aws", "x-amz", "amazonaws"]),
            TechnologySignature("Google Cloud", "Cloud Provider", ["google", "gcp", "googleapis"]),
            TechnologySignature("Node.js", "Runtime", ["node.js", "nodejs", "express"]),
            TechnologySignature("PHP", "Backend", ["php", "x-powered-by: php", "phpsessid"]),
            TechnologySignature("Python", "Backend", ["python", "django", "flask", "fastapi"]),
            TechnologySignature("Ruby", "Backend", ["ruby", "rails", "rack"]),
            TechnologySignature("Java", "Backend", ["java", "tomcat", "spring", "jsp"]),
            TechnologySignature(".NET", "Backend", ["asp.net", ".net", "x-aspnet-version"]),
            TechnologySignature("MySQL", "Database", ["mysql", "mysql-server", "mysqld"]),
            TechnologySignature("PostgreSQL", "Database", ["postgresql", "postgres", "psql"]),
            TechnologySignature("MongoDB", "Database", ["mongodb", "mongo", "mongod"]),
        ]
    
    def detect(self, http_body: str, http_headers: str, banner: str = "") -> List[DetectedTechnology]:
        text = (http_body + http_headers + banner).lower()
        detected = []
        
        for sig in self.signatures:
            for pattern in sig.patterns:
                if pattern.lower() in text:
                    version = self._extract_version(text, sig.name)
                    evidence = self._find_evidence(text, pattern)
                    detected.append(DetectedTechnology(
                        name=sig.name,
                        category=sig.category,
                        confidence=sig.confidence,
                        version=version,
                        evidence=evidence
                    ))
                    break
        
        return detected
    
    def _extract_version(self, text: str, tech_name: str) -> Optional[str]:
        patterns = [
            rf'{tech_name.lower()}[\s/:]*(\d+\.\d+(?:\.\d+)?)',
            rf'version[\s:=]*(\d+\.\d+(?:\.\d+)?)',
            rf'v?(\d+\.\d+(?:\.\d+)?)'
        ]
        
        for pattern in patterns:
            match = re.search(pattern, text, re.IGNORECASE)
            if match:
                return match.group(1)
        
        return None
    
    def _find_evidence(self, text: str, pattern: str) -> str:
        idx = text.find(pattern.lower())
        if idx != -1:
            start = max(0, idx - 20)
            end = min(len(text), idx + len(pattern) + 20)
            return text[start:end].strip()
        return ""
    
    def get_by_category(self, technologies: List[DetectedTechnology], category: str) -> List[DetectedTechnology]:
        return [t for t in technologies if t.category == category]
    
    def get_high_confidence(self, technologies: List[DetectedTechnology], threshold: float = 0.8) -> List[DetectedTechnology]:
        return [t for t in technologies if t.confidence >= threshold]