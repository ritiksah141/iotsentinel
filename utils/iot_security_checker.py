"""
IoT Security Checker
Analyzes IoT devices for common vulnerabilities and security issues
"""

import logging
from typing import Dict, List, Tuple
from utils.device_classifier import classifier

logger = logging.getLogger(__name__)


class IoTSecurityChecker:
    """Check IoT devices for security vulnerabilities"""

    def __init__(self):
        self.vulnerability_checks = {
            'default_ports': self._check_default_ports,
            'firmware_outdated': self._check_firmware_version,
            'excessive_traffic': self._check_traffic_patterns,
        }

    def check_device_security(self, device: Dict) -> Dict:
        """
        Perform comprehensive security check on a device

        Args:
            device: Device dictionary from database

        Returns:
            Security assessment dictionary
        """
        result = {
            'device_ip': device['device_ip'],
            'vulnerabilities': [],
            'risk_score': 0,  # 0-100
            'recommendations': []
        }

        device_type = device.get('device_type', 'unknown')
        category = device.get('category', 'other')

        # Check if it's an IoT device
        classification = {'device_type': device_type, 'category': category}
        is_iot = classifier.is_iot_device(classification)

        if not is_iot:
            return result

        # Get device-specific recommendations
        classification_full = {
            'device_type': device_type,
            'manufacturer': device.get('manufacturer'),
            'icon': device.get('icon'),
            'category': category
        }
        recommendations = classifier.get_device_recommendations(classification_full)
        result['recommendations'] = recommendations

        # Check for common vulnerabilities
        vulnerabilities = []

        # 1. Check for devices with no firmware version (likely default/unupdated)
        if not device.get('firmware_version'):
            vulnerabilities.append({
                'type': 'unknown_firmware',
                'severity': 'medium',
                'description': 'Firmware version unknown - may be outdated'
            })
            result['risk_score'] += 20

        # 2. Check device age (if not seen recently, may be abandoned)
        # This would require checking last_seen timestamp

        # 3. IoT devices should ideally be isolated
        if is_iot:
            vulnerabilities.append({
                'type': 'network_isolation',
                'severity': 'low',
                'description': 'IoT device not on isolated network segment'
            })
            result['risk_score'] += 10

        # 4. Camera-specific checks
        if device_type == 'camera':
            vulnerabilities.append({
                'type': 'camera_exposure',
                'severity': 'high',
                'description': 'Security camera detected - ensure strong passwords and disable remote access if not needed'
            })
            result['risk_score'] += 30

        # 5. Smart lock checks
        if device_type == 'smart_lock':
            vulnerabilities.append({
                'type': 'smart_lock_security',
                'severity': 'critical',
                'description': 'Smart lock detected - critical device requiring maximum security'
            })
            result['risk_score'] += 40

        result['vulnerabilities'] = vulnerabilities

        # Cap risk score at 100
        result['risk_score'] = min(result['risk_score'], 100)

        return result

    def _check_default_ports(self, device: Dict) -> List[Dict]:
        """Check for default/insecure port usage"""
        vulnerabilities = []
        # This would require connection data
        return vulnerabilities

    def _check_firmware_version(self, device: Dict) -> List[Dict]:
        """Check if firmware is outdated"""
        vulnerabilities = []

        firmware = device.get('firmware_version')
        if not firmware:
            vulnerabilities.append({
                'type': 'firmware_unknown',
                'severity': 'medium',
                'description': 'Firmware version not detected'
            })

        return vulnerabilities

    def _check_traffic_patterns(self, device: Dict) -> List[Dict]:
        """Check for suspicious traffic patterns"""
        vulnerabilities = []
        # This would require analyzing connection history
        return vulnerabilities

    def get_network_security_score(self, devices: List[Dict]) -> Dict:
        """
        Calculate overall network security score

        Args:
            devices: List of all devices

        Returns:
            Security summary dictionary
        """
        total_devices = len(devices)
        iot_devices = []
        vulnerable_devices = []
        total_risk = 0

        for device in devices:
            device_type = device.get('device_type', 'unknown')
            category = device.get('category', 'other')

            classification = {'device_type': device_type, 'category': category}
            is_iot = classifier.is_iot_device(classification)

            if is_iot:
                iot_devices.append(device)

                # Check security
                security_check = self.check_device_security(device)
                total_risk += security_check['risk_score']

                if security_check['vulnerabilities']:
                    vulnerable_devices.append(device)

        # Calculate overall score (100 = perfect, 0 = terrible)
        if iot_devices:
            avg_risk = total_risk / len(iot_devices)
            security_score = max(0, 100 - avg_risk)
        else:
            security_score = 100

        return {
            'total_devices': total_devices,
            'iot_devices_count': len(iot_devices),
            'vulnerable_count': len(vulnerable_devices),
            'security_score': int(security_score),
            'risk_level': self._get_risk_level(security_score),
            'top_recommendations': self._get_top_recommendations(vulnerable_devices)
        }

    def _get_risk_level(self, score: int) -> str:
        """Convert security score to risk level"""
        if score >= 80:
            return 'low'
        elif score >= 60:
            return 'medium'
        elif score >= 40:
            return 'high'
        else:
            return 'critical'

    def _get_top_recommendations(self, vulnerable_devices: List[Dict]) -> List[str]:
        """Generate top security recommendations"""
        recommendations = []

        if len(vulnerable_devices) > 0:
            recommendations.append(f"Review security of {len(vulnerable_devices)} vulnerable IoT devices")

        recommendations.append("Consider isolating IoT devices on separate VLAN")
        recommendations.append("Enable automatic firmware updates where available")
        recommendations.append("Use strong, unique passwords for all IoT devices")
        recommendations.append("Disable UPnP on your router to prevent unauthorized access")

        return recommendations[:5]  # Return top 5


# Global security checker instance
security_checker = IoTSecurityChecker()
