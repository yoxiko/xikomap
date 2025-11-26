import socket
import struct
import time
from typing import Dict, List, Optional, Any

class ICSSCADADetector:
    """
    Industrial Control Systems (ICS) and SCADA protocol detector
    Detects industrial protocols and equipment
    """
    
    def __init__(self, timeout: float = 3.0):
        self.timeout = timeout
        
        # ICS/SCADA protocols and their signatures
        self.ics_protocols = {
            'modbus': {
                'ports': [502, 503, 504],
                'request': self._create_modbus_request,
                'response_patterns': [b'modbus', b'\x00\x01\x00\x00'],
                'description': 'Modbus TCP - Industrial automation protocol'
            },
            's7': {
                'ports': [102, 103, 104],
                'request': self._create_s7_request,
                'response_patterns': [b'SIMATIC', b'S7'],
                'description': 'Siemens S7 - PLC communication'
            },
            'bacnet': {
                'ports': [47808, 47809, 47810],
                'request': self._create_bacnet_request,
                'response_patterns': [b'\x81', b'BACnet'],
                'description': 'BACnet - Building automation'
            },
            'dnp3': {
                'ports': [20000, 20001, 19999],
                'request': self._create_dnp3_request,
                'response_patterns': [b'\x05\x64', b'DNP3'],
                'description': 'DNP3 - Electrical grid systems'
            },
            'opc_ua': {
                'ports': [4840, 4841, 4843],
                'request': self._create_opcua_request,
                'response_patterns': [b'HEL', b'OPCUA'],
                'description': 'OPC UA - Industrial data exchange'
            },
            'iec_60870': {
                'ports': [2404, 2405, 2406],
                'request': self._create_iec60870_request,
                'response_patterns': [b'\x68', b'IEC60870'],
                'description': 'IEC 60870-5-104 - Electrical telecontrol'
            },
            'ethernet_ip': {
                'ports': [44818, 44819, 2222],
                'request': self._create_ethernetip_request,
                'response_patterns': [b'EtherNet/IP', b'CIP'],
                'description': 'EtherNet/IP - Industrial Ethernet'
            },
            'profinet': {
                'ports': [34962, 34963, 34964],
                'request': self._create_profinet_request,
                'response_patterns': [b'PROFINET', b'PNIO'],
                'description': 'PROFINET - Process field network'
            },
            'fox': {
                'ports': [5555, 5556, 5557],
                'request': self._create_fox_request,
                'response_patterns': [b'FOX', b'Yokogawa'],
                'description': 'FOX - Yokogawa process control'
            },
            'hart_ip': {
                'ports': [5094, 5095, 5096],
                'request': self._create_hartip_request,
                'response_patterns': [b'HART-IP', b'HART'],
                'description': 'HART-IP - Wireless industrial protocol'
            }
        }
        
        # Common ICS device manufacturers
        self.manufacturers = {
            'siemens': ['SIMATIC', 'S7', 'Siemens'],
            'rockwell': ['Allen-Bradley', 'ControlLogix', 'CompactLogix'],
            'schneider': ['Modicon', 'Quantum', 'Schneider Electric'],
            'abb': ['ABB', 'AC800M', 'Industrial IT'],
            'emerson': ['DeltaV', 'Ovation', 'Emerson'],
            'yokogawa': ['CENTUM', 'FA-M3', 'Yokogawa'],
            'ge': ['GE', 'Mark VIe', 'General Electric'],
            'honeywell': ['Experion', 'HC900', 'Honeywell']
        }

    def detect_ics_protocols(self, target: str, port: int) -> List[Dict[str, Any]]:
        """
        Detect ICS/SCADA protocols on target port
        
        Args:
            target: Target hostname or IP
            port: Target port
            
        Returns:
            List of detected protocols with details
        """
        results = []
        
        for protocol_name, protocol_info in self.ics_protocols.items():
            if port in protocol_info['ports']:
                detection = self._check_protocol(target, port, protocol_name, protocol_info)
                if detection and detection['confidence'] > 0.3:
                    results.append(detection)
        
        return results

    def quick_ics_scan(self, target: str) -> List[Dict[str, Any]]:
        """
        Quick scan for common ICS protocols
        
        Args:
            target: Target hostname or IP
            
        Returns:
            List of detected ICS services
        """
        results = []
        common_ports = set()
        
        # Collect all common ICS ports
        for protocol_info in self.ics_protocols.values():
            common_ports.update(protocol_info['ports'][:2])  # First 2 ports per protocol
        
        for port in common_ports:
            try:
                # Quick port check first
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1.0)
                result = sock.connect_ex((target, port))
                sock.close()
                
                if result == 0:
                    # Port is open, detect protocol
                    protocols = self.detect_ics_protocols(target, port)
                    if protocols:
                        results.extend(protocols)
                    else:
                        results.append({
                            'service': 'unknown-ics',
                            'port': port,
                            'confidence': 0.5,
                            'banner': 'ICS port open but protocol not identified'
                        })
            except:
                continue
        
        return results

    def _check_protocol(self, target: str, port: int, protocol_name: str, 
                       protocol_info: Dict) -> Optional[Dict[str, Any]]:
        """
        Check specific protocol on target
        """
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((target, port))
            
            # Send protocol-specific request
            request_data = protocol_info['request']()
            if request_data:
                sock.send(request_data)
                time.sleep(0.5)  # Wait for response
            
            # Receive response
            response = sock.recv(1024)
            sock.close()
            
            # Analyze response
            confidence = 0.0
            evidence = []
            
            # Check for response patterns
            for pattern in protocol_info['response_patterns']:
                if pattern in response:
                    confidence += 0.4
                    evidence.append(f"Pattern matched: {pattern}")
            
            # Check for manufacturer signatures
            manufacturer = self._identify_manufacturer(response)
            if manufacturer:
                confidence += 0.3
                evidence.append(f"Manufacturer: {manufacturer}")
            
            # Basic response validation
            if len(response) > 0:
                confidence += 0.2
                evidence.append("Received response")
            
            if confidence > 0.3:
                return {
                    'service': f"{protocol_name}-ics",
                    'protocol': protocol_name,
                    'port': port,
                    'confidence': min(confidence, 1.0),
                    'banner': response[:200].decode('utf-8', errors='ignore'),
                    'manufacturer': manufacturer,
                    'description': protocol_info['description'],
                    'evidence': evidence
                }
        
        except Exception as e:
            pass
        
        return None

    def _identify_manufacturer(self, response: bytes) -> Optional[str]:
        """Identify device manufacturer from response"""
        response_str = response.decode('utf-8', errors='ignore')
        
        for manufacturer, signatures in self.manufacturers.items():
            for signature in signatures:
                if signature.lower() in response_str.lower():
                    return manufacturer
        
        return None

    # Protocol request creators
    def _create_modbus_request(self) -> bytes:
        """Create Modbus TCP request"""
        return struct.pack('>HHHBBHH', 
                          0x0000,  # Transaction ID
                          0x0000,  # Protocol ID
                          0x0006,  # Length
                          0x01,    # Unit ID
                          0x03,    # Function Code (Read Holding Registers)
                          0x0000,  # Starting Address
                          0x0001)  # Quantity

    def _create_s7_request(self) -> bytes:
        """Create Siemens S7 request"""
        return b'\x03\x00\x00\x16\x11\xe0\x00\x00\x00\x01\x00\xc1\x02\x01\x00\xc2\x02\x01\x02\xc0\x01\x09'

    def _create_bacnet_request(self) -> bytes:
        """Create BACnet request"""
        return b'\x81\x0a\x00\x0c\x01\x20\xff\xff\x00\xff\x10\x00'

    def _create_dnp3_request(self) -> bytes:
        """Create DNP3 request"""
        return b'\x05\x64\x05\xc0\x00\x00\x00\x00'

    def _create_opcua_request(self) -> bytes:
        """Create OPC UA request"""
        return b'HEL'

    def _create_iec60870_request(self) -> bytes:
        """Create IEC 60870-5-104 request"""
        return struct.pack('BBBB', 0x68, 0x04, 0x07, 0x00)

    def _create_ethernetip_request(self) -> bytes:
        """Create EtherNet/IP request"""
        return b'\x63\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'

    def _create_profinet_request(self) -> bytes:
        """Create PROFINET request"""
        return b'PROFINET'

    def _create_fox_request(self) -> bytes:
        """Create FOX request"""
        return b'FOX'

    def _create_hartip_request(self) -> bytes:
        """Create HART-IP request"""
        return b'HART-IP'

    def get_ics_ports(self) -> List[int]:
        """Get all ICS-related ports"""
        ports = set()
        for protocol_info in self.ics_protocols.values():
            ports.update(protocol_info['ports'])
        return sorted(ports)

    def get_protocol_info(self, protocol_name: str) -> Dict[str, Any]:
        """Get information about specific protocol"""
        protocol_info = self.ics_protocols.get(protocol_name, {})
        return {
            'name': protocol_name,
            'ports': protocol_info.get('ports', []),
            'description': protocol_info.get('description', 'Unknown protocol'),
            'manufacturers': self._get_common_manufacturers(protocol_name)
        }

    def _get_common_manufacturers(self, protocol_name: str) -> List[str]:
        """Get common manufacturers for protocol"""
        manufacturer_map = {
            's7': ['siemens'],
            'modbus': ['schneider', 'rockwell', 'abb'],
            'bacnet': ['honeywell', 'johnson controls', 'siemens'],
            'dnp3': ['ge', 'abb', 'siemens'],
            'ethernet_ip': ['rockwell', 'allen-bradley'],
            'fox': ['yokogawa'],
            'profinet': ['siemens']
        }
        return manufacturer_map.get(protocol_name, [])