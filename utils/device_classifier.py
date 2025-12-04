"""
IoT Device Classifier
Identifies device types, manufacturers, and categories based on multiple fingerprinting techniques
"""

import re
import logging
from typing import Dict, Optional, Tuple

logger = logging.getLogger(__name__)


# MAC Address OUI to Manufacturer mapping (first 3 bytes)
# Sourced from IEEE OUI database + common IoT vendors
MAC_VENDOR_DATABASE = {
    # Smart Home Hubs & Controllers
    '00:17:88': 'Philips Hue',
    '00:0D:6F': 'Philips',
    'EC:1B:BD': 'Philips Hue',
    'B0:CE:18': 'Amazon (Echo)',
    '44:65:0D': 'Amazon (Echo)',
    'F0:D2:F1': 'Amazon (Echo)',
    'FC:A6:67': 'Amazon (Echo)',
    'F0:27:2D': 'Google (Nest)',
    '64:16:66': 'Google (Nest)',
    '54:60:09': 'Google (Nest)',
    '18:B4:30': 'Google (Nest)',

    # Security Cameras
    '18:B4:30': 'Nest',
    'B0:7F:B9': 'Ring',
    '74:C6:3B': 'Ring',
    '0C:91:92': 'Ring',
    '00:62:6E': 'Arlo',
    '88:03:4B': 'Wyze',
    'D0:3F:27': 'Wyze',
    '2C:AA:8E': 'Wyze',

    # Smart Plugs & Switches
    '50:C7:BF': 'TP-Link (Kasa)',
    '54:AF:97': 'TP-Link (Kasa)',
    '98:DA:C4': 'TP-Link (Kasa)',
    '1C:3B:F3': 'Wemo',
    '14:91:82': 'Wemo',
    'EC:FA:5C': 'Sonoff',
    '68:C6:3A': 'Sonoff',

    # Smart Thermostats
    '18:B4:30': 'Nest',
    '44:61:32': 'Ecobee',
    'D8:80:39': 'Honeywell',

    # Smart Locks
    '00:0D:6F': 'August',
    'A0:A3:07': 'Yale',
    '88:E7:12': 'Schlage',

    # Routers & Networking
    '00:23:69': 'Cisco',
    '00:1F:CA': 'Cisco',
    'E8:ED:F3': 'Ubiquiti',
    'F0:9F:C2': 'Ubiquiti',
    '74:83:C2': 'Ubiquiti',
    '88:15:44': 'TP-Link Router',
    'C8:3A:35': 'Netgear',
    'A0:63:91': 'Netgear',

    # Computers & Phones
    '00:50:56': 'VMware',
    '08:00:27': 'VirtualBox',
    '3C:22:FB': 'Apple',
    '00:1B:63': 'Apple',
    'A4:83:E7': 'Apple',
    'DC:A6:32': 'Raspberry Pi',
    'E4:5F:01': 'Raspberry Pi',
    'B8:27:EB': 'Raspberry Pi',
    '28:CD:C1': 'Raspberry Pi',

    # TVs & Streaming
    '00:E0:91': 'Samsung TV',
    'EC:F4:BB': 'Samsung TV',
    '00:26:37': 'LG TV',
    'B4:E6:2D': 'Roku',
    '08:05:81': 'Roku',
    '00:0D:4B': 'Roku',
    '28:C6:8E': 'Amazon Fire TV',
    '74:C2:46': 'Amazon Fire TV',
}


# Device type classification rules
DEVICE_TYPE_RULES = {
    'camera': {
        'manufacturers': ['Nest', 'Ring', 'Arlo', 'Wyze', 'Blink'],
        'hostnames': ['camera', 'cam', 'doorbell', 'ring', 'nest-cam'],
        'ports': [554, 8000, 8080, 8554, 10080],  # RTSP, HTTP streaming
        'icon': '📷',
        'category': 'security'
    },
    'smart_speaker': {
        'manufacturers': ['Amazon (Echo)', 'Google (Nest)', 'Apple (HomePod)'],
        'hostnames': ['echo', 'alexa', 'google-home', 'nest-audio', 'homepod'],
        'ports': [8443, 55443],
        'icon': '🔊',
        'category': 'smart_home'
    },
    'smart_bulb': {
        'manufacturers': ['Philips Hue', 'LIFX', 'TP-Link (Kasa)'],
        'hostnames': ['hue', 'lifx', 'bulb', 'light'],
        'ports': [80, 443],
        'icon': '💡',
        'category': 'smart_home'
    },
    'smart_plug': {
        'manufacturers': ['TP-Link (Kasa)', 'Wemo', 'Sonoff'],
        'hostnames': ['plug', 'switch', 'outlet', 'kasa', 'wemo'],
        'ports': [9999],  # TP-Link discovery
        'icon': '🔌',
        'category': 'smart_home'
    },
    'thermostat': {
        'manufacturers': ['Nest', 'Ecobee', 'Honeywell'],
        'hostnames': ['thermostat', 'nest', 'ecobee'],
        'ports': [],
        'icon': '🌡️',
        'category': 'smart_home'
    },
    'smart_lock': {
        'manufacturers': ['August', 'Yale', 'Schlage'],
        'hostnames': ['lock', 'august', 'yale'],
        'ports': [],
        'icon': '🔒',
        'category': 'security'
    },
    'router': {
        'manufacturers': ['Cisco', 'Ubiquiti', 'TP-Link Router', 'Netgear'],
        'hostnames': ['router', 'gateway', 'modem'],
        'ports': [80, 443, 8080, 22],
        'icon': '🌐',
        'category': 'network'
    },
    'tv': {
        'manufacturers': ['Samsung TV', 'LG TV', 'Sony TV'],
        'hostnames': ['tv', 'samsung', 'lg-tv', 'sony'],
        'ports': [8001, 8002, 3000, 9080],
        'icon': '📺',
        'category': 'entertainment'
    },
    'streaming_device': {
        'manufacturers': ['Roku', 'Amazon Fire TV', 'Apple TV', 'Chromecast'],
        'hostnames': ['roku', 'firetv', 'chromecast', 'appletv'],
        'ports': [8008, 8009],  # Chromecast
        'icon': '📱',
        'category': 'entertainment'
    },
    'phone': {
        'manufacturers': ['Apple', 'Samsung', 'Google'],
        'hostnames': ['iphone', 'android', 'pixel', 'galaxy'],
        'ports': [],
        'icon': '📱',
        'category': 'mobile'
    },
    'computer': {
        'manufacturers': ['Apple', 'Dell', 'HP', 'Lenovo'],
        'hostnames': ['macbook', 'imac', 'laptop', 'desktop', 'pc'],
        'ports': [22, 3389, 5900],  # SSH, RDP, VNC
        'icon': '💻',
        'category': 'computer'
    },
    'iot_hub': {
        'manufacturers': ['Philips Hue', 'Samsung SmartThings'],
        'hostnames': ['hub', 'bridge', 'smartthings'],
        'ports': [80, 443],
        'icon': '🏠',
        'category': 'smart_home'
    },
    'raspberry_pi': {
        'manufacturers': ['Raspberry Pi'],
        'hostnames': ['raspberrypi', 'pi'],
        'ports': [22],
        'icon': '🥧',
        'category': 'computer'
    }
}


class DeviceClassifier:
    """Classifies network devices using multiple fingerprinting techniques"""

    def __init__(self):
        self.mac_vendor_db = MAC_VENDOR_DATABASE
        self.device_rules = DEVICE_TYPE_RULES

    def get_manufacturer_from_mac(self, mac_address: str) -> Optional[str]:
        """
        Look up manufacturer from MAC address OUI (first 3 bytes)

        Args:
            mac_address: MAC address in format AA:BB:CC:DD:EE:FF

        Returns:
            Manufacturer name or None
        """
        if not mac_address:
            return None

        # Normalize MAC address
        mac = mac_address.upper().replace('-', ':')

        # Extract OUI (first 3 bytes)
        oui = ':'.join(mac.split(':')[:3])

        return self.mac_vendor_db.get(oui)

    def classify_device(
        self,
        mac_address: str,
        hostname: Optional[str] = None,
        open_ports: Optional[list] = None,
        ip_address: Optional[str] = None
    ) -> Dict[str, str]:
        """
        Classify device type using multiple fingerprinting techniques

        Args:
            mac_address: Device MAC address
            hostname: Device hostname (from DNS/mDNS)
            open_ports: List of open ports detected
            ip_address: Device IP address

        Returns:
            Dictionary with device classification:
            {
                'device_type': 'camera',
                'manufacturer': 'Nest',
                'icon': '📷',
                'category': 'security',
                'confidence': 'high'
            }
        """
        result = {
            'device_type': 'unknown',
            'manufacturer': None,
            'icon': '❓',
            'category': 'other',
            'confidence': 'low'
        }

        # Step 1: Get manufacturer from MAC
        manufacturer = self.get_manufacturer_from_mac(mac_address)
        if manufacturer:
            result['manufacturer'] = manufacturer
            result['confidence'] = 'medium'

        # Step 2: Try to match device type
        hostname_lower = hostname.lower() if hostname else ''
        open_ports = open_ports or []

        scores = {}

        for device_type, rules in self.device_rules.items():
            score = 0

            # Manufacturer match (strongest signal)
            if manufacturer and manufacturer in rules['manufacturers']:
                score += 10

            # Hostname match
            if hostname_lower:
                for pattern in rules['hostnames']:
                    if pattern in hostname_lower:
                        score += 5
                        break

            # Port match
            if open_ports:
                for port in rules['ports']:
                    if port in open_ports:
                        score += 2

            scores[device_type] = score

        # Get best match
        if scores:
            best_match = max(scores.items(), key=lambda x: x[1])
            if best_match[1] > 0:
                device_type = best_match[0]
                device_info = self.device_rules[device_type]

                result['device_type'] = device_type
                result['icon'] = device_info['icon']
                result['category'] = device_info['category']

                # Set confidence based on score
                if best_match[1] >= 10:
                    result['confidence'] = 'high'
                elif best_match[1] >= 5:
                    result['confidence'] = 'medium'
                else:
                    result['confidence'] = 'low'

        # Special cases
        if not result['manufacturer']:
            # Try to infer from hostname
            if hostname_lower:
                for vendor_name in ['nest', 'ring', 'wyze', 'philips', 'amazon', 'google']:
                    if vendor_name in hostname_lower:
                        result['manufacturer'] = vendor_name.title()
                        break

        # Check if it's a router (usually .1 or .254)
        if ip_address and (ip_address.endswith('.1') or ip_address.endswith('.254')):
            if result['device_type'] == 'unknown':
                result['device_type'] = 'router'
                result['icon'] = '🌐'
                result['category'] = 'network'
                result['confidence'] = 'medium'

        return result

    def is_iot_device(self, device_classification: Dict[str, str]) -> bool:
        """
        Determine if device is an IoT device

        Args:
            device_classification: Result from classify_device()

        Returns:
            True if device is IoT
        """
        iot_categories = ['security', 'smart_home', 'entertainment']
        iot_types = ['camera', 'smart_speaker', 'smart_bulb', 'smart_plug',
                     'thermostat', 'smart_lock', 'tv', 'streaming_device', 'iot_hub']

        if device_classification['category'] in iot_categories:
            return True

        if device_classification['device_type'] in iot_types:
            return True

        return False

    def get_device_recommendations(self, device_classification: Dict[str, str]) -> list:
        """
        Get security recommendations for device type

        Args:
            device_classification: Result from classify_device()

        Returns:
            List of recommendation strings
        """
        recommendations = []

        device_type = device_classification['device_type']

        # General IoT recommendations
        if self.is_iot_device(device_classification):
            recommendations.append("Consider isolating IoT devices on a separate VLAN")
            recommendations.append("Ensure device firmware is up to date")
            recommendations.append("Change default passwords if applicable")

        # Device-specific recommendations
        if device_type == 'camera':
            recommendations.append("Disable remote access if not needed")
            recommendations.append("Use strong passwords and enable 2FA")
            recommendations.append("Review cloud recording retention policies")

        elif device_type == 'smart_speaker':
            recommendations.append("Review voice command history regularly")
            recommendations.append("Disable microphone when not in use")
            recommendations.append("Be cautious with third-party skills/actions")

        elif device_type in ['smart_plug', 'smart_bulb']:
            recommendations.append("Monitor for unusual power usage patterns")
            recommendations.append("Disable remote access features if not needed")

        elif device_type == 'router':
            recommendations.append("Enable WPA3 encryption if available")
            recommendations.append("Disable WPS and UPnP if not needed")
            recommendations.append("Keep router firmware updated")
            recommendations.append("Use strong admin password")

        return recommendations


# Global classifier instance
classifier = DeviceClassifier()


def classify_device_simple(mac_address: str, hostname: str = None) -> Tuple[str, str, str]:
    """
    Simple wrapper for device classification

    Returns:
        Tuple of (device_type, manufacturer, icon)
    """
    result = classifier.classify_device(mac_address, hostname)
    return (
        result['device_type'],
        result['manufacturer'] or 'Unknown',
        result['icon']
    )
