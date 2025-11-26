import pickle
import numpy as np
import re
import os
import json
from typing import Dict, List, Optional, Any, Tuple
from collections import Counter, defaultdict
from dataclasses import dataclass
from pathlib import Path

try:
    from sklearn.feature_extraction.text import TfidfVectorizer
    from sklearn.naive_bayes import MultinomialNB
    from sklearn.ensemble import RandomForestClassifier
    from sklearn.svm import SVC
    from sklearn.model_selection import train_test_split
    from sklearn.metrics import accuracy_score, classification_report
    from sklearn.pipeline import Pipeline
    SKLEARN_AVAILABLE = True
except ImportError:
    SKLEARN_AVAILABLE = False
    class TfidfVectorizer:
        def __init__(self, **kwargs): pass
        def fit(self, X, y=None): return self
        def transform(self, X): return np.zeros((len(X), 10))
        def fit_transform(self, X, y=None): return self.transform(X)
    
    class RandomForestClassifier:
        def __init__(self, **kwargs): pass
        def fit(self, X, y): return self
        def predict(self, X): return ['unknown'] * len(X)
        def predict_proba(self, X): return np.zeros((len(X), 1))
    
    class Pipeline:
        def __init__(self, steps): self.steps = steps
        def fit(self, X, y): return self
        def predict(self, X): return ['unknown'] * len(X)
        def predict_proba(self, X): return np.zeros((len(X), 1))

@dataclass
class TrainingSample:
    banner: str
    service: str
    port: int
    protocol: str
    confidence: float = 1.0

class MLClassifier:
    def __init__(self, model_dir: str = "ml_models", use_ml: bool = True):
        self.model_dir = Path(model_dir)
        self.model_dir.mkdir(exist_ok=True)
        self.use_ml = use_ml and SKLEARN_AVAILABLE
        self.models = {}
        self.vectorizers = {}
        
        self.service_categories = {
            'web_server': {
                'patterns': [
                    r'apache', r'nginx', r'iis', r'lightspeed', r'tomcat', 
                    r'jetty', r'caddy', r'cherokee', r'lighttpd', r'gws',
                    r'microsoft-iis', r'apache-coyote', r'undertow'
                ],
                'ports': [80, 443, 8080, 8443, 8000, 3000, 5000, 9000],
                'description': 'Web servers and HTTP services'
            },
            'database': {
                'patterns': [
                    r'mysql', r'postgresql', r'mongodb', r'redis', r'elasticsearch',
                    r'sql', r'mariadb', r'oracle', r'db2', r'sqlite', r'cassandra',
                    r'influxdb', r'couchdb', r'rethinkdb', r'clickhouse'
                ],
                'ports': [3306, 5432, 27017, 6379, 9200, 1433, 1521, 9042, 8086],
                'description': 'Database management systems'
            },
            'mail_server': {
                'patterns': [
                    r'smtp', r'pop3', r'imap', r'exchange', r'sendmail', r'postfix',
                    r'exim', r'dovecot', r'courier', r'zimbra', r'qmail', r'hmail'
                ],
                'ports': [25, 110, 143, 465, 587, 993, 995, 26, 2525],
                'description': 'Email servers and services'
            },
            'file_service': {
                'patterns': [
                    r'ftp', r'sftp', r'smb', r'nfs', r'afp', r'webdav', r'rsync',
                    r'vsftpd', r'proftpd', r'pure-ftpd', r'filezilla', r'samba'
                ],
                'ports': [21, 22, 139, 445, 2049, 548, 873, 989, 990],
                'description': 'File transfer and sharing services'
            },
            'remote_access': {
                'patterns': [
                    r'ssh', r'telnet', r'rdp', r'vnc', r'teamviewer', r'anydesk',
                    r'openssh', r'putty', r'x11', r'xdmcp', r'spice', r'nomachine'
                ],
                'ports': [22, 23, 3389, 5900, 5901, 5938, 4172, 5500],
                'description': 'Remote access and control services'
            },
            'messaging': {
                'patterns': [
                    r'mqtt', r'amqp', r'rabbitmq', r'activemq', r'kafka', r'zeromq',
                    r'nats', r'redis', r'websocket', r'stomp', r'xmpp', r'matrix'
                ],
                'ports': [1883, 5672, 61616, 9092, 4222, 6379, 80, 443, 5222],
                'description': 'Message brokers and real-time communication'
            },
            'monitoring': {
                'patterns': [
                    r'prometheus', r'grafana', r'nagios', r'zabbix', r'datadog',
                    r'newrelic', r'splunk', r'elastic', r'kibana', r'graphite'
                ],
                'ports': [9090, 3000, 5666, 10051, 8080, 8000, 9200, 5601, 2003],
                'description': 'Monitoring and observability tools'
            },
            'container': {
                'patterns': [
                    r'docker', r'kubernetes', r'podman', r'containerd', r'rkt',
                    r'mesos', r'nomad', r'swarm', r'openshift', r'rancher'
                ],
                'ports': [2375, 2376, 6443, 10250, 10255, 8080, 8443, 9090],
                'description': 'Container orchestration and runtime'
            }
        }
        
        self._initialize_models()

    def _initialize_models(self):
        if not self.use_ml:
            print("ℹ️  ML mode disabled - using pattern-based classification")
            return
        
        try:
            self.vectorizers['text'] = TfidfVectorizer(
                max_features=1000,
                min_df=2,
                max_df=0.8,
                stop_words='english',
                ngram_range=(1, 2)
            )
            
            self.models['service'] = Pipeline([
                ('vectorizer', self.vectorizers['text']),
                ('classifier', RandomForestClassifier(
                    n_estimators=100,
                    max_depth=20,
                    random_state=42
                ))
            ])
            print(" ML models initialized successfully")
            
        except Exception as e:
            print(f"  ML initialization failed: {e} - falling back to pattern-based")
            self.use_ml = False

    def predict_service(self, banner: str, port: int, protocol: str = 'tcp') -> Dict[str, Any]:
        rule_prediction = self._rule_based_prediction(banner, port, protocol)
        
        ml_prediction = None
        if self.use_ml and self.models.get('service'):
            try:
                ml_prediction = self._ml_prediction(banner, port)
            except Exception as e:
                print(f"  ML prediction failed: {e}")
                ml_prediction = None
        
        if ml_prediction and ml_prediction.get('confidence', 0) > rule_prediction['confidence']:
            final_prediction = ml_prediction
            final_prediction['method'] = 'ml_primary'
        else:
            final_prediction = rule_prediction
            final_prediction['method'] = 'rule_based_primary'
        
        final_prediction.update({
            'port': port,
            'protocol': protocol,
            'banner_length': len(banner),
            'banner_sample': banner[:200] if banner else ''
        })
        
        return final_prediction

    def _rule_based_prediction(self, banner: str, port: int, protocol: str) -> Dict[str, Any]:
        banner_lower = banner.lower() if banner else ""
        predictions = []
        
        for category, category_info in self.service_categories.items():
            confidence = 0.0
            evidence = []
            
            if port in category_info['ports']:
                confidence += 0.3
                evidence.append(f"Port {port} common for {category}")
            
            pattern_matches = 0
            for pattern in category_info['patterns']:
                if re.search(pattern, banner_lower, re.IGNORECASE):
                    pattern_matches += 1
                    evidence.append(f"Pattern matched: {pattern}")
            
            if pattern_matches > 0:
                confidence += min(0.6, pattern_matches * 0.2)
            
            if len(banner) > 20:
                confidence += 0.1
                evidence.append("Substantial banner received")
            elif len(banner) > 100:
                confidence += 0.2
                evidence.append("Detailed banner received")
            
            if protocol == 'udp' and category in ['dns', 'ntp', 'snmp', 'dhcp']:
                confidence += 0.2
                evidence.append("UDP protocol common for this service")
            
            if confidence >= 0.3:
                predictions.append({
                    'service': category,
                    'confidence': min(confidence, 1.0),
                    'evidence': evidence,
                    'pattern_matches': pattern_matches,
                    'description': category_info['description']
                })
        
        if predictions:
            best_prediction = max(predictions, key=lambda x: x['confidence'])
            best_prediction['all_predictions'] = predictions
            return best_prediction
        
        return {
            'service': 'unknown',
            'confidence': 0.1,
            'evidence': ['No strong patterns matched'],
            'pattern_matches': 0,
            'description': 'Unknown service type',
            'all_predictions': []
        }

    def _ml_prediction(self, banner: str, port: int) -> Dict[str, Any]:
        if not banner or not self.models.get('service'):
            return {
                'service': 'unknown',
                'confidence': 0.1,
                'evidence': ['No ML model or empty banner'],
                'method': 'ml_fallback'
            }
        
        try:
            service_prediction = self.models['service'].predict([banner])[0]
            
            if hasattr(self.models['service'], 'predict_proba'):
                service_probabilities = self.models['service'].predict_proba([banner])[0]
                confidence = max(service_probabilities)
                
                top_indices = np.argsort(service_probabilities)[-3:][::-1]
                top_predictions = []
                
                for idx in top_indices:
                    service_name = self.models['service'].classes_[idx]
                    prob = service_probabilities[idx]
                    top_predictions.append({
                        'service': service_name,
                        'confidence': float(prob)
                    })
            else:
                confidence = 0.7
                top_predictions = [{'service': service_prediction, 'confidence': confidence}]
            
            return {
                'service': service_prediction,
                'confidence': float(confidence),
                'evidence': [f"ML classification with {confidence:.2f} confidence"],
                'top_predictions': top_predictions,
                'method': 'ml'
            }
            
        except Exception as e:
            return {
                'service': 'unknown',
                'confidence': 0.1,
                'evidence': [f'ML prediction failed: {str(e)}'],
                'method': 'ml_error'
            }

    def train_models(self, training_data: List[TrainingSample], test_size: float = 0.2) -> Dict[str, Any]:
        if not self.use_ml:
            return {
                'status': 'sklearn_not_available',
                'message': 'scikit-learn is not available - using pattern-based classification only'
            }
        
        if not training_data:
            return {'error': 'No training data provided'}
        
        try:
            banners = [sample.banner for sample in training_data]
            services = [sample.service for sample in training_data]
            
            X_train, X_test, y_train, y_test = train_test_split(
                banners, services, test_size=test_size, random_state=42, stratify=services
            )
            
            self.models['service'].fit(X_train, y_train)
            
            y_pred = self.models['service'].predict(X_test)
            accuracy = accuracy_score(y_test, y_pred)
            
            report = classification_report(y_test, y_pred, output_dict=True)
            
            self._save_models()
            
            return {
                'status': 'success',
                'accuracy': accuracy,
                'training_samples': len(training_data),
                'test_samples': len(X_test),
                'classes_trained': len(set(services)),
                'classification_report': report
            }
            
        except Exception as e:
            return {
                'status': 'error',
                'error': str(e)
            }

    def batch_predict(self, samples: List[Dict]) -> List[Dict[str, Any]]:
        results = []
        
        for sample in samples:
            prediction = self.predict_service(
                sample.get('banner', ''),
                sample.get('port', 0),
                sample.get('protocol', 'tcp')
            )
            results.append(prediction)
        
        return results

    def extract_features(self, banner: str, port: int) -> Dict[str, Any]:
        features = {
            'banner_length': len(banner),
            'has_version': bool(re.search(r'\d+\.\d+\.\d+', banner)),
            'has_http': 'http' in banner.lower(),
            'has_ssl': any(word in banner.lower() for word in ['ssl', 'tls', 'https']),
            'word_count': len(banner.split()),
            'digit_count': sum(c.isdigit() for c in banner),
            'special_char_count': sum(not c.isalnum() for c in banner),
            'port': port,
            'common_port': port in self._get_all_common_ports()
        }
        
        for category, category_info in self.service_categories.items():
            pattern_count = 0
            for pattern in category_info['patterns']:
                if re.search(pattern, banner.lower()):
                    pattern_count += 1
            features[f'pattern_{category}'] = pattern_count
        
        return features

    def _get_all_common_ports(self) -> List[int]:
        ports = set()
        for category_info in self.service_categories.values():
            ports.update(category_info['ports'])
        return sorted(ports)

    def save_models(self) -> bool:
        try:
            model_data = {
                'service_categories': self.service_categories,
                'model_metadata': {
                    'trained_at': np.datetime64('now').astype(str),
                    'sklearn_available': SKLEARN_AVAILABLE,
                    'use_ml': self.use_ml
                }
            }
            
            with open(self.model_dir / 'model_metadata.json', 'w', encoding='utf-8') as f:
                json.dump(model_data, f, indent=2, ensure_ascii=False)
            
            if self.use_ml and self.models.get('service'):
                with open(self.model_dir / 'service_model.pkl', 'wb') as f:
                    pickle.dump(self.models['service'], f)
            
            return True
            
        except Exception as e:
            print(f"Error saving models: {e}")
            return False

    def load_models(self) -> bool:
        try:
            metadata_path = self.model_dir / 'model_metadata.json'
            if metadata_path.exists():
                with open(metadata_path, 'r', encoding='utf-8') as f:
                    model_data = json.load(f)
                    self.service_categories = model_data.get('service_categories', self.service_categories)
            
            if self.use_ml:
                model_path = self.model_dir / 'service_model.pkl'
                if model_path.exists():
                    with open(model_path, 'rb') as f:
                        self.models['service'] = pickle.load(f)
            
            return True
            
        except Exception as e:
            print(f"Error loading models: {e}")
            return False

    def get_model_info(self) -> Dict[str, Any]:
        info = {
            'ml_available': SKLEARN_AVAILABLE,
            'use_ml': self.use_ml,
            'service_categories_count': len(self.service_categories),
            'model_trained': self.models.get('service') is not None,
            'common_ports_count': len(self._get_all_common_ports())
        }
        
        if (self.models.get('service') and 
            hasattr(self.models['service'], 'classes_') and
            self.models['service'].classes_ is not None):
            info['trained_classes'] = list(self.models['service'].classes_)
        
        return info

    def analyze_banner_patterns(self, banners: List[str]) -> Dict[str, Any]:
        if not banners:
            return {}
        
        all_text = ' '.join(banners).lower()
        
        words = re.findall(r'\b[a-z]{3,15}\b', all_text)
        word_freq = Counter(words)
        
        versions = re.findall(r'\d+\.\d+\.\d+', all_text)
        version_freq = Counter(versions)
        
        phrases = re.findall(r'[a-z]+[ /-][a-z]+', all_text)
        phrase_freq = Counter(phrases)
        
        return {
            'total_banners': len(banners),
            'total_words': len(words),
            'unique_words': len(set(words)),
            'common_words': word_freq.most_common(20),
            'common_versions': version_freq.most_common(10),
            'common_phrases': phrase_freq.most_common(15),
            'avg_banner_length': np.mean([len(b) for b in banners]) if banners else 0
        }

    def _save_models(self):
        if self.use_ml:
            self.save_models()

    def get_service_categories(self) -> List[str]:
        return list(self.service_categories.keys())

    def get_category_info(self, category: str) -> Dict[str, Any]:
        category_info = self.service_categories.get(category, {})
        return {
            'name': category,
            'patterns': category_info.get('patterns', []),
            'ports': category_info.get('ports', []),
            'description': category_info.get('description', 'Unknown category'),
            'pattern_count': len(category_info.get('patterns', [])),
            'port_count': len(category_info.get('ports', []))
        }

def create_sample_training_data() -> List[TrainingSample]:
    samples = [
        TrainingSample('Apache/2.4.41 (Ubuntu)', 'web_server', 80, 'tcp'),
        TrainingSample('nginx/1.18.0', 'web_server', 443, 'tcp'),
        TrainingSample('Microsoft-IIS/10.0', 'web_server', 80, 'tcp'),
        TrainingSample('Apache/2.2.22 (Debian)', 'web_server', 8080, 'tcp'),
        TrainingSample('MySQL 8.0.25', 'database', 3306, 'tcp'),
        TrainingSample('PostgreSQL 13.3', 'database', 5432, 'tcp'),
        TrainingSample('Redis 6.2.4', 'database', 6379, 'tcp'),
        TrainingSample('MongoDB 4.4.6', 'database', 27017, 'tcp'),
        TrainingSample('220 smtp.example.com ESMTP', 'mail_server', 25, 'tcp'),
        TrainingSample('+OK Dovecot ready', 'mail_server', 110, 'tcp'),
        TrainingSample('* OK [CAPABILITY IMAP4rev1]', 'mail_server', 143, 'tcp'),
        TrainingSample('SSH-2.0-OpenSSH_8.2', 'remote_access', 22, 'tcp'),
        TrainingSample('RFB 003.008', 'remote_access', 5900, 'tcp'),
        TrainingSample('Microsoft Terminal Services', 'remote_access', 3389, 'tcp'),
        TrainingSample('220 vsFTPd 3.0.3', 'file_service', 21, 'tcp'),
        TrainingSample('220 ProFTPD Server', 'file_service', 21, 'tcp'),
        TrainingSample('MQTT Connection', 'messaging', 1883, 'tcp'),
        TrainingSample('AMQP Connection', 'messaging', 5672, 'tcp'),
        TrainingSample('Prometheus Time Series', 'monitoring', 9090, 'tcp'),
        TrainingSample('Grafana Dashboard', 'monitoring', 3000, 'tcp'),
        TrainingSample('Docker API', 'container', 2375, 'tcp'),
        TrainingSample('Kubernetes API', 'container', 6443, 'tcp'),
    ]
    
    return samples

def quick_ml_classify(banner: str, port: int) -> Dict[str, Any]:
    classifier = MLClassifier()
    return classifier.predict_service(banner, port)