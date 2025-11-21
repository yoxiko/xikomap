import socket
import struct
import time
from typing import Dict, Any, Optional, List

class BlockchainDetector:  
    def __init__(self, timeout: float = 5.0):
        self.timeout = timeout
        self.blockchain_signatures = {
            'bitcoin': {
                'ports': [8333, 18333, 18444, 8334, 28333],
                'request': self.create_bitcoin_version_msg,
                'response_patterns': [b'version', b'verack'],
                'confidence': 0.9
            },
            'ethereum': {
                'ports': [30303, 30304, 30305],
                'request': self.create_ethereum_handshake,
                'response_patterns': [b'ETH', b'Ethereum'],
                'confidence': 0.85
            }
        }
    
    def detect_blockchain(self, target: str, port: int) -> Optional[Dict[str, Any]]:
        for coin, signature in self.blockchain_signatures.items():
            if port in signature['ports']:
                result = self._check_blockchain_protocol(target, port, coin, signature)
                if result and result['confidence'] > 0.5:
                    return result
        return None
    
    def _check_blockchain_protocol(self, target: str, port: int, coin: str, signature: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((target, port))
            
            if 'request' in signature:
                request_data = signature['request']()
                if request_data:
                    sock.send(request_data)
            
            response = sock.recv(4096)
            sock.close()
            
            if signature['response_patterns']:
                for pattern in signature['response_patterns']:
                    if pattern in response:
                        return {
                            'service': f'{coin}-node',
                            'confidence': signature['confidence'],
                            'banner': f'{coin.upper()} Blockchain Node',
                            'details': self._analyze_blockchain_response(coin, response),
                            'response_data': response[:200]
                        }
            
            return None
                
        except Exception:
            return None
    
    def _analyze_blockchain_response(self, coin: str, response: bytes) -> str:
        return f"Обнаружен {coin} узел. Размер ответа: {len(response)} байт"
    
    def create_bitcoin_version_msg(self) -> bytes:
        try:
            version = 70015
            services = 1
            timestamp = int(time.time())
            
            payload = struct.pack('<LQQ', version, services, timestamp)
            command = b'version\x00\x00\x00\x00\x00'
            length = struct.pack('<L', len(payload))
            
            message = b'\xf9\xbe\xb4\xd9' + command + length + payload
            return message
            
        except Exception:
            return b''
    
    def create_ethereum_handshake(self) -> bytes:
        return b'\x00' * 32