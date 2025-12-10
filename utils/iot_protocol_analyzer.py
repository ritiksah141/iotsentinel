#!/usr/bin/env python3
"""
IoT Protocol Analyzer

Detects and analyzes IoT-specific protocols including:
- MQTT (Message Queuing Telemetry Transport)
- CoAP (Constrained Application Protocol)
- Zigbee/Z-Wave

Integrates with packet capture to identify IoT protocol usage and security issues.
"""

import json
import logging
import struct
from datetime import datetime
from typing import Dict, List, Optional
from scapy.all import IP, TCP, UDP, Raw

logger = logging.getLogger(__name__)


class IoTProtocolAnalyzer:
    """Analyzer for IoT-specific network protocols."""

    def __init__(self, db_manager):
        """
        Initialize IoT Protocol Analyzer.

        Args:
            db_manager: DatabaseManager instance
        """
        self.db = db_manager

        # MQTT ports
        self.mqtt_ports = {1883, 8883}  # 8883 is MQTT over TLS

        # CoAP ports
        self.coap_ports = {5683, 5684}  # 5684 is CoAP over DTLS

        # Zigbee/Z-Wave typical gateway ports
        self.zigbee_ports = {17754, 17755}  # Typical Zigbee coordinator ports
        self.zwave_ports = {4123, 8888, 9090}  # Z-Wave gateway HTTP/WebSocket ports

        # mDNS/Bonjour port
        self.mdns_port = 5353

    def analyze_packet(self, packet) -> Optional[Dict]:
        """
        Analyze a packet for IoT protocols.

        Args:
            packet: Scapy packet object

        Returns:
            Dict with protocol info if IoT protocol detected, None otherwise
        """
        if not packet.haslayer(IP):
            return None

        try:
            # Check for MQTT
            if packet.haslayer(TCP):
                tcp_layer = packet[TCP]
                if tcp_layer.dport in self.mqtt_ports or tcp_layer.sport in self.mqtt_ports:
                    return self._analyze_mqtt(packet)

                # Check for Z-Wave gateway traffic
                if tcp_layer.dport in self.zwave_ports or tcp_layer.sport in self.zwave_ports:
                    return self._analyze_zwave(packet)

            # Check for CoAP
            if packet.haslayer(UDP):
                udp_layer = packet[UDP]
                if udp_layer.dport in self.coap_ports or udp_layer.sport in self.coap_ports:
                    return self._analyze_coap(packet)

                # Check for mDNS/Bonjour
                if udp_layer.dport == self.mdns_port or udp_layer.sport == self.mdns_port:
                    return self._analyze_mdns(packet)

        except Exception as e:
            logger.error(f"Error analyzing packet: {e}")

        return None

    def _analyze_mqtt(self, packet) -> Optional[Dict]:
        """
        Analyze MQTT packet.

        MQTT packet structure:
        - Fixed header (2+ bytes)
        - Variable header
        - Payload

        Returns:
            Dict with MQTT packet details
        """
        try:
            if not packet.haslayer(Raw):
                return None

            payload = bytes(packet[Raw].load)
            if len(payload) < 2:
                return None

            # Parse MQTT fixed header
            byte1 = payload[0]
            message_type = (byte1 & 0xF0) >> 4

            mqtt_types = {
                1: 'CONNECT', 2: 'CONNACK', 3: 'PUBLISH',
                4: 'PUBACK', 5: 'PUBREC', 6: 'PUBREL',
                7: 'PUBCOMP', 8: 'SUBSCRIBE', 9: 'SUBACK',
                10: 'UNSUBSCRIBE', 11: 'UNSUBACK',
                12: 'PINGREQ', 13: 'PINGRESP', 14: 'DISCONNECT'
            }

            ip_layer = packet[IP]
            tcp_layer = packet[TCP]

            # Determine if encrypted (port 8883)
            is_encrypted = tcp_layer.dport == 8883 or tcp_layer.sport == 8883

            mqtt_info = {
                'protocol': 'MQTT',
                'timestamp': datetime.now(),
                'device_ip': ip_layer.src if tcp_layer.dport in self.mqtt_ports else ip_layer.dst,
                'broker_ip': ip_layer.dst if tcp_layer.dport in self.mqtt_ports else ip_layer.src,
                'broker_port': tcp_layer.dport if tcp_layer.dport in self.mqtt_ports else tcp_layer.sport,
                'message_type': mqtt_types.get(message_type, f'UNKNOWN_{message_type}'),
                'is_encrypted': is_encrypted,
                'payload_size': len(payload),
                'qos': (byte1 & 0x06) >> 1 if message_type == 3 else None,  # Only for PUBLISH
                'retain_flag': (byte1 & 0x01) == 1 if message_type == 3 else None
            }

            # Try to extract topic and client ID for CONNECT/PUBLISH
            if message_type in [1, 3]:  # CONNECT or PUBLISH
                try:
                    mqtt_info.update(self._parse_mqtt_payload(payload, message_type))
                except:
                    pass

            self._save_mqtt_traffic(mqtt_info)
            self._update_protocol_stats(mqtt_info['device_ip'], 'mqtt', len(payload), is_encrypted)

            return mqtt_info

        except Exception as e:
            logger.error(f"Error analyzing MQTT packet: {e}")
            return None

    def _parse_mqtt_payload(self, payload: bytes, message_type: int) -> Dict:
        """Parse MQTT payload for additional info."""
        result = {}

        try:
            if message_type == 3:  # PUBLISH
                # Skip fixed header and remaining length
                pos = 2
                # Get topic length
                topic_len = struct.unpack('!H', payload[pos:pos+2])[0]
                pos += 2
                # Get topic
                topic = payload[pos:pos+topic_len].decode('utf-8', errors='ignore')
                result['topic'] = topic

                # Get payload preview (first 200 chars)
                pos += topic_len
                if pos < len(payload):
                    preview = payload[pos:pos+200].decode('utf-8', errors='ignore')
                    result['payload_preview'] = preview

            elif message_type == 1:  # CONNECT
                # Skip fixed header, protocol name
                pos = 12  # Approximate position of client ID
                if pos < len(payload):
                    try:
                        client_id_len = struct.unpack('!H', payload[pos:pos+2])[0]
                        pos += 2
                        client_id = payload[pos:pos+client_id_len].decode('utf-8', errors='ignore')
                        result['client_id'] = client_id
                    except:
                        pass

        except Exception as e:
            logger.debug(f"Could not parse MQTT payload: {e}")

        return result

    def _save_mqtt_traffic(self, mqtt_info: Dict):
        """Save MQTT traffic to database."""
        try:
            cursor = self.db.conn.cursor()
            cursor.execute("""
                INSERT INTO mqtt_traffic (
                    device_ip, broker_ip, broker_port, client_id, topic,
                    message_type, qos, payload_size, payload_preview,
                    retain_flag, is_encrypted
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                mqtt_info['device_ip'],
                mqtt_info['broker_ip'],
                mqtt_info['broker_port'],
                mqtt_info.get('client_id'),
                mqtt_info.get('topic'),
                mqtt_info['message_type'],
                mqtt_info.get('qos'),
                mqtt_info['payload_size'],
                mqtt_info.get('payload_preview'),
                mqtt_info.get('retain_flag'),
                mqtt_info['is_encrypted']
            ))
            self.db.conn.commit()
        except Exception as e:
            logger.error(f"Failed to save MQTT traffic: {e}")

    def _analyze_coap(self, packet) -> Optional[Dict]:
        """
        Analyze CoAP packet.

        CoAP packet structure:
        - Version (2 bits)
        - Type (2 bits)
        - Token Length (4 bits)
        - Code (8 bits)
        - Message ID (16 bits)

        Returns:
            Dict with CoAP packet details
        """
        try:
            if not packet.haslayer(Raw):
                return None

            payload = bytes(packet[Raw].load)
            if len(payload) < 4:
                return None

            # Parse CoAP header
            byte1 = payload[0]
            version = (byte1 & 0xC0) >> 6
            msg_type = (byte1 & 0x30) >> 4
            token_len = byte1 & 0x0F

            code = payload[1]
            msg_id = struct.unpack('!H', payload[2:4])[0]

            coap_types = {0: 'CON', 1: 'NON', 2: 'ACK', 3: 'RST'}
            coap_methods = {
                1: 'GET', 2: 'POST', 3: 'PUT', 4: 'DELETE'
            }

            ip_layer = packet[IP]
            udp_layer = packet[UDP]

            # Determine if encrypted (DTLS on port 5684)
            is_dtls = udp_layer.dport == 5684 or udp_layer.sport == 5684

            coap_info = {
                'protocol': 'CoAP',
                'timestamp': datetime.now(),
                'device_ip': ip_layer.src if udp_layer.dport in self.coap_ports else ip_layer.dst,
                'dest_ip': ip_layer.dst if udp_layer.dport in self.coap_ports else ip_layer.src,
                'dest_port': udp_layer.dport if udp_layer.dport in self.coap_ports else udp_layer.sport,
                'method': coap_methods.get(code, f'CODE_{code}') if code < 32 else None,
                'message_type': coap_types.get(msg_type, f'TYPE_{msg_type}'),
                'response_code': code if code >= 64 else None,
                'is_dtls': is_dtls,
                'payload_size': len(payload)
            }

            self._save_coap_traffic(coap_info)
            self._update_protocol_stats(coap_info['device_ip'], 'coap', len(payload), is_dtls)

            return coap_info

        except Exception as e:
            logger.error(f"Error analyzing CoAP packet: {e}")
            return None

    def _save_coap_traffic(self, coap_info: Dict):
        """Save CoAP traffic to database."""
        try:
            cursor = self.db.conn.cursor()
            cursor.execute("""
                INSERT INTO coap_traffic (
                    device_ip, dest_ip, dest_port, method,
                    message_type, response_code, payload_size, is_dtls
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                coap_info['device_ip'],
                coap_info['dest_ip'],
                coap_info['dest_port'],
                coap_info.get('method'),
                coap_info['message_type'],
                coap_info.get('response_code'),
                coap_info['payload_size'],
                coap_info['is_dtls']
            ))
            self.db.conn.commit()
        except Exception as e:
            logger.error(f"Failed to save CoAP traffic: {e}")

    def _analyze_zwave(self, packet) -> Optional[Dict]:
        """
        Analyze Z-Wave gateway traffic.

        Z-Wave uses proprietary protocol over serial/USB, but we can detect
        gateway HTTP/WebSocket control traffic.

        Returns:
            Dict with Z-Wave gateway traffic details
        """
        try:
            ip_layer = packet[IP]
            tcp_layer = packet[TCP]

            # Determine device IP (source if initiating Z-Wave commands)
            device_ip = ip_layer.src if tcp_layer.dport in self.zwave_ports else ip_layer.dst

            payload_size = len(packet[Raw].load) if packet.haslayer(Raw) else 0

            zwave_info = {
                'protocol': 'Z-Wave',
                'timestamp': datetime.now(),
                'device_ip': device_ip,
                'gateway_ip': ip_layer.dst if tcp_layer.dport in self.zwave_ports else ip_layer.src,
                'gateway_port': tcp_layer.dport if tcp_layer.dport in self.zwave_ports else tcp_layer.sport,
                'payload_size': payload_size,
                'is_encrypted': tcp_layer.dport == 8883  # HTTPS
            }

            # Try to detect Z-Wave command types from payload
            if packet.haslayer(Raw):
                payload = bytes(packet[Raw].load)
                zwave_info['command_type'] = self._detect_zwave_command(payload)

            self._save_zwave_traffic(zwave_info)
            self._update_protocol_stats(device_ip, 'zwave', payload_size, zwave_info['is_encrypted'])

            return zwave_info

        except Exception as e:
            logger.error(f"Error analyzing Z-Wave packet: {e}")
            return None

    def _detect_zwave_command(self, payload: bytes) -> str:
        """Detect Z-Wave command type from payload patterns."""
        try:
            payload_str = payload.decode('utf-8', errors='ignore').lower()

            # Common Z-Wave API patterns
            if 'switch' in payload_str:
                return 'SWITCH_CONTROL'
            elif 'sensor' in payload_str or 'binary' in payload_str:
                return 'SENSOR_READ'
            elif 'thermostat' in payload_str or 'temperature' in payload_str:
                return 'THERMOSTAT_CONTROL'
            elif 'lock' in payload_str or 'unlock' in payload_str:
                return 'LOCK_CONTROL'
            elif 'add' in payload_str or 'include' in payload_str:
                return 'DEVICE_INCLUSION'
            elif 'remove' in payload_str or 'exclude' in payload_str:
                return 'DEVICE_EXCLUSION'
            else:
                return 'GENERIC'
        except:
            return 'UNKNOWN'

    def _save_zwave_traffic(self, zwave_info: Dict):
        """Save Z-Wave traffic to database."""
        try:
            cursor = self.db.conn.cursor()
            cursor.execute("""
                INSERT INTO zigbee_traffic (
                    device_ip, zigbee_address, device_type, command, manufacturer_code
                ) VALUES (?, ?, ?, ?, ?)
            """, (
                zwave_info['device_ip'],
                zwave_info['gateway_ip'],  # Use gateway IP as identifier
                'Z-Wave Gateway',
                zwave_info.get('command_type', 'UNKNOWN'),
                'Z-Wave'
            ))
            self.db.conn.commit()
        except Exception as e:
            logger.error(f"Failed to save Z-Wave traffic: {e}")

    def _analyze_mdns(self, packet) -> Optional[Dict]:
        """
        Analyze mDNS/Bonjour packets.

        mDNS is used for local network service discovery.
        Port 5353, multicast address 224.0.0.251

        Returns:
            Dict with mDNS packet details
        """
        try:
            if not packet.haslayer(Raw):
                return None

            ip_layer = packet[IP]
            udp_layer = packet[UDP]
            payload = bytes(packet[Raw].load)

            if len(payload) < 12:  # Minimum DNS header size
                return None

            # Parse basic DNS header
            transaction_id = struct.unpack('!H', payload[0:2])[0]
            flags = struct.unpack('!H', payload[2:4])[0]
            is_query = (flags & 0x8000) == 0
            question_count = struct.unpack('!H', payload[4:6])[0]
            answer_count = struct.unpack('!H', payload[6:8])[0]

            # Extract service names from DNS questions
            services = self._extract_mdns_services(payload[12:])

            mdns_info = {
                'protocol': 'mDNS',
                'timestamp': datetime.now(),
                'device_ip': ip_layer.src,
                'is_query': is_query,
                'services': services,
                'question_count': question_count,
                'answer_count': answer_count,
                'is_multicast': ip_layer.dst.startswith('224.0.0.')
            }

            self._save_mdns_discovery(mdns_info)
            self._update_protocol_stats(ip_layer.src, 'mdns', len(payload), False)

            return mdns_info

        except Exception as e:
            logger.error(f"Error analyzing mDNS packet: {e}")
            return None

    def _extract_mdns_services(self, dns_data: bytes) -> List[str]:
        """Extract service names from mDNS DNS data."""
        services = []
        try:
            # Look for common mDNS service patterns
            data_str = dns_data.decode('utf-8', errors='ignore')

            # Common service types
            service_patterns = [
                '_http._tcp', '_https._tcp', '_ssh._tcp',
                '_airplay._tcp', '_homekit._tcp', '_hap._tcp',
                '_googlecast._tcp', '_spotify-connect._tcp',
                '_smb._tcp', '_afpovertcp._tcp',
                '_printer._tcp', '_ipp._tcp',
                '_raop._tcp'  # AirPlay audio
            ]

            for pattern in service_patterns:
                if pattern in data_str:
                    services.append(pattern)

        except:
            pass

        return services if services else ['unknown']

    def _save_mdns_discovery(self, mdns_info: Dict):
        """Save mDNS discovery to device fingerprints."""
        try:
            cursor = self.db.conn.cursor()

            # Update device fingerprint with discovered mDNS services
            cursor.execute("""
                SELECT mdns_services FROM device_fingerprints
                WHERE device_ip = ?
            """, (mdns_info['device_ip'],))

            result = cursor.fetchone()
            existing_services = json.loads(result['mdns_services']) if result and result['mdns_services'] else []

            # Merge with new services
            all_services = list(set(existing_services + mdns_info['services']))

            cursor.execute("""
                INSERT INTO device_fingerprints (device_ip, mdns_services, last_fingerprint_update)
                VALUES (?, ?, CURRENT_TIMESTAMP)
                ON CONFLICT(device_ip) DO UPDATE SET
                    mdns_services = excluded.mdns_services,
                    last_fingerprint_update = CURRENT_TIMESTAMP
            """, (mdns_info['device_ip'], json.dumps(all_services)))

            self.db.conn.commit()
            logger.info(f"mDNS discovery saved for {mdns_info['device_ip']}: {mdns_info['services']}")

        except Exception as e:
            logger.error(f"Failed to save mDNS discovery: {e}")

    def _update_protocol_stats(self, device_ip: str, protocol: str,
                                bytes_count: int, encrypted: bool):
        """Update protocol usage statistics."""
        try:
            cursor = self.db.conn.cursor()
            cursor.execute("""
                INSERT INTO protocol_stats (
                    device_ip, protocol, first_seen, last_seen,
                    total_messages, total_bytes, encryption_used
                ) VALUES (?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP, 1, ?, ?)
                ON CONFLICT(device_ip, protocol) DO UPDATE SET
                    last_seen = CURRENT_TIMESTAMP,
                    total_messages = total_messages + 1,
                    total_bytes = total_bytes + excluded.total_bytes,
                    encryption_used = encryption_used OR excluded.encryption_used
            """, (device_ip, protocol, bytes_count, encrypted))
            self.db.conn.commit()
        except Exception as e:
            logger.error(f"Failed to update protocol stats: {e}")

    def get_protocol_summary(self, device_ip: Optional[str] = None) -> Dict:
        """
        Get summary of IoT protocol usage.

        Args:
            device_ip: Optional device IP to filter by

        Returns:
            Dict with protocol statistics
        """
        try:
            cursor = self.db.conn.cursor()

            if device_ip:
                cursor.execute("""
                    SELECT protocol, total_messages, total_bytes,
                           encryption_used, authentication_used
                    FROM protocol_stats
                    WHERE device_ip = ?
                """, (device_ip,))
            else:
                cursor.execute("""
                    SELECT protocol,
                           SUM(total_messages) as total_messages,
                           SUM(total_bytes) as total_bytes,
                           SUM(CASE WHEN encryption_used THEN 1 ELSE 0 END) as encrypted_devices,
                           COUNT(*) as total_devices
                    FROM protocol_stats
                    GROUP BY protocol
                """)

            results = {}
            for row in cursor.fetchall():
                results[row['protocol']] = dict(row)

            return results

        except Exception as e:
            logger.error(f"Error getting protocol summary: {e}")
            return {}

    def detect_insecure_protocols(self) -> List[Dict]:
        """
        Detect devices using insecure (unencrypted) IoT protocols.

        Returns:
            List of devices with insecure protocol usage
        """
        try:
            cursor = self.db.conn.cursor()
            cursor.execute("""
                SELECT d.device_ip, d.device_name, d.device_type,
                       ps.protocol, ps.encryption_used, ps.total_messages
                FROM protocol_stats ps
                JOIN devices d ON ps.device_ip = d.device_ip
                WHERE ps.encryption_used = 0
                AND ps.protocol IN ('mqtt', 'coap')
                ORDER BY ps.total_messages DESC
            """)

            insecure_devices = []
            for row in cursor.fetchall():
                insecure_devices.append({
                    'device_ip': row['device_ip'],
                    'device_name': row['device_name'],
                    'device_type': row['device_type'],
                    'protocol': row['protocol'],
                    'message_count': row['total_messages'],
                    'recommendation': f"Enable encryption for {row['protocol'].upper()}"
                })

            return insecure_devices

        except Exception as e:
            logger.error(f"Error detecting insecure protocols: {e}")
            return []


# Singleton instance
_analyzer_instance = None


def get_protocol_analyzer(db_manager) -> IoTProtocolAnalyzer:
    """Get or create IoT Protocol Analyzer singleton."""
    global _analyzer_instance
    if _analyzer_instance is None:
        _analyzer_instance = IoTProtocolAnalyzer(db_manager)
    return _analyzer_instance
