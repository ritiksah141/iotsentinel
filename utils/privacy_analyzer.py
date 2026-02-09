#!/usr/bin/env python3
"""
Privacy Analyzer for IoTSentinel

Analyzes what data each device collects and transmits.
Provides unified view of device data collection patterns for privacy transparency.
"""

import logging
import sqlite3
from typing import Dict, Any, List, Optional
from datetime import datetime, timedelta
from collections import defaultdict

from database.db_manager import DatabaseManager

logger = logging.getLogger(__name__)


# Privacy risk categories
PRIVACY_RISK_LEVELS = {
    'critical': {'color': 'danger', 'score': 100},
    'high': {'color': 'warning', 'score': 75},
    'medium': {'color': 'info', 'score': 50},
    'low': {'color': 'success', 'score': 25},
    'minimal': {'color': 'secondary', 'score': 0}
}

# Cloud service categories and their privacy implications
CLOUD_SERVICE_PRIVACY = {
    'amazon': {'category': 'E-commerce & Cloud', 'data_types': ['usage', 'voice', 'commands']},
    'google': {'category': 'Advertising & Analytics', 'data_types': ['usage', 'voice', 'location', 'behavior']},
    'apple': {'category': 'Platform Services', 'data_types': ['usage', 'health', 'location']},
    'microsoft': {'category': 'Cloud & Productivity', 'data_types': ['usage', 'documents', 'telemetry']},
    'facebook': {'category': 'Social Media', 'data_types': ['social', 'behavior', 'contacts']},
    'tencent': {'category': 'Social & Gaming', 'data_types': ['social', 'payments', 'behavior']},
    'alibaba': {'category': 'E-commerce', 'data_types': ['shopping', 'payments', 'location']},
    'analytics': {'category': 'Analytics', 'data_types': ['usage', 'behavior', 'telemetry']},
    'advertising': {'category': 'Advertising', 'data_types': ['behavior', 'interests', 'demographics']},
    'cdn': {'category': 'Content Delivery', 'data_types': ['usage', 'location']},
    'unknown': {'category': 'Unknown', 'data_types': ['unknown']}
}

# Data types collected
DATA_TYPES = {
    'usage': {'name': 'Usage Patterns', 'sensitivity': 'medium'},
    'voice': {'name': 'Voice Recordings', 'sensitivity': 'high'},
    'commands': {'name': 'Voice Commands', 'sensitivity': 'high'},
    'location': {'name': 'Location Data', 'sensitivity': 'critical'},
    'behavior': {'name': 'Behavioral Data', 'sensitivity': 'high'},
    'health': {'name': 'Health Data', 'sensitivity': 'critical'},
    'social': {'name': 'Social Connections', 'sensitivity': 'high'},
    'contacts': {'name': 'Contact List', 'sensitivity': 'critical'},
    'documents': {'name': 'Documents', 'sensitivity': 'critical'},
    'telemetry': {'name': 'Device Telemetry', 'sensitivity': 'low'},
    'payments': {'name': 'Payment Info', 'sensitivity': 'critical'},
    'shopping': {'name': 'Shopping History', 'sensitivity': 'medium'},
    'interests': {'name': 'Interests & Preferences', 'sensitivity': 'medium'},
    'demographics': {'name': 'Demographics', 'sensitivity': 'high'},
    'unknown': {'name': 'Unknown Data', 'sensitivity': 'medium'}
}


class PrivacyAnalyzer:
    """
    Analyzes device data collection patterns for privacy transparency.

    Provides unified view of:
    - What cloud services devices connect to
    - What types of data are being transmitted
    - Privacy risk assessment
    - Data collection frequency
    """

    def __init__(self, db_manager: DatabaseManager = None):
        """
        Initialize privacy analyzer.

        Args:
            db_manager: DatabaseManager instance (uses default if None)
        """
        self.db_manager = db_manager or DatabaseManager()
        logger.info("Privacy analyzer initialized")

    def analyze_device_data_collection(self, device_ip: str, days: int = 7) -> Dict[str, Any]:
        """
        Analyze what data a specific device collects and transmits.

        Args:
            device_ip: Device IP address
            days: Number of days to analyze

        Returns:
            Dictionary with privacy analysis results
        """
        try:
            conn = self.db_manager.conn
            cursor = conn.cursor()

            # Get device info
            cursor.execute("SELECT * FROM devices WHERE device_ip = ?", (device_ip,))
            device = cursor.fetchone()

            if not device:
                return {'error': 'Device not found'}

            device_info = dict(device)

            # Get cloud connections (last N days)
            cutoff_date = (datetime.now() - timedelta(days=days)).isoformat()

            cursor.execute('''
                SELECT cloud_provider, connection_count,
                       first_seen, last_seen
                FROM cloud_connections
                WHERE device_ip = ? AND last_seen > ?
                ORDER BY connection_count DESC
            ''', (device_ip, cutoff_date))

            cloud_connections = [dict(row) for row in cursor.fetchall()]

            # Get data exfiltration events
            cursor.execute('''
                SELECT destination_ip, destination_domain, bytes_transferred,
                       protocol, timestamp
                FROM data_exfiltration_events
                WHERE device_ip = ? AND timestamp > ?
                ORDER BY timestamp DESC
                LIMIT 100
            ''', (device_ip, cutoff_date))

            exfiltration_events = [dict(row) for row in cursor.fetchall()]

            # Get protocol usage
            cursor.execute('''
                SELECT protocol, COUNT(*) as count, SUM(bytes_sent) as total_bytes
                FROM connections
                WHERE device_ip = ? AND timestamp > ?
                GROUP BY protocol
                ORDER BY count DESC
            ''', (device_ip, cutoff_date))

            protocol_usage = [dict(row) for row in cursor.fetchall()]

            # Analyze cloud services
            cloud_analysis = self._analyze_cloud_services(cloud_connections)

            # Analyze data types collected
            data_types_collected = self._infer_data_types(
                device_info, cloud_connections, exfiltration_events
            )

            # Calculate privacy risk score
            privacy_risk = self._calculate_privacy_risk(
                cloud_analysis, data_types_collected, exfiltration_events
            )

            # Calculate data transmission statistics
            transmission_stats = self._calculate_transmission_stats(
                cloud_connections, exfiltration_events, protocol_usage
            )

            result = {
                'device_ip': device_ip,
                'device_name': device_info.get('device_name') or device_info.get('manufacturer', 'Unknown'),
                'device_type': device_info.get('device_type', 'unknown'),
                'analysis_period_days': days,
                'analyzed_at': datetime.now().isoformat(),
                'cloud_services': cloud_analysis,
                'data_types_collected': data_types_collected,
                'privacy_risk': privacy_risk,
                'transmission_stats': transmission_stats,
                'raw_data': {
                    'cloud_connections': cloud_connections[:10],  # Top 10
                    'recent_exfiltration': exfiltration_events[:10]
                }
            }

            # logger.info(f"Privacy analysis complete for {device_ip}: {privacy_risk['level']} risk")

            return result

        except Exception as e:
            logger.error(f"Error analyzing device data collection: {e}")
            return {'error': str(e)}

    def _analyze_cloud_services(self, cloud_connections: List[Dict]) -> Dict[str, Any]:
        """Analyze cloud service connections and categorize them."""
        services_by_category = defaultdict(list)
        total_connections = 0
        formatted_services = []

        for conn in cloud_connections:
            provider = (conn.get('cloud_provider') or 'unknown').lower()
            count = conn.get('connection_count', 0)

            # Get privacy info for this provider
            privacy_info = CLOUD_SERVICE_PRIVACY.get(provider, CLOUD_SERVICE_PRIVACY['unknown'])

            service_info = {
                'provider': provider.capitalize(),
                'service': services,
                'connections': count,
                'category': privacy_info['category'],
                'potential_data_types': privacy_info['data_types'],
                'first_seen': conn.get('first_seen'),
                'last_seen': conn.get('last_seen')
            }

            services_by_category[privacy_info['category']].append(service_info)
            formatted_services.append(service_info)
            total_connections += count

        return {
            'total_connections': total_connections,
            'unique_services': len(cloud_connections),
            'by_category': dict(services_by_category),
            'top_services': formatted_services[:10]  # Top 10 most connected
        }

    def _infer_data_types(
        self,
        device_info: Dict,
        cloud_connections: List[Dict],
        exfiltration_events: List[Dict]
    ) -> List[Dict[str, Any]]:
        """Infer what types of data the device likely collects."""
        data_types_set = set()

        # Infer from device type
        device_type = (device_info.get('device_type') or '').lower()
        if 'camera' in device_type:
            data_types_set.update(['usage', 'behavior', 'location'])
        elif 'speaker' in device_type or 'assistant' in device_type:
            data_types_set.update(['voice', 'commands', 'usage', 'behavior'])
        elif 'thermostat' in device_type:
            data_types_set.update(['usage', 'behavior', 'location'])
        elif 'lock' in device_type:
            data_types_set.update(['usage', 'behavior', 'location'])
        elif 'watch' in device_type or 'fitness' in device_type:
            data_types_set.update(['health', 'location', 'usage', 'behavior'])
        elif 'tv' in device_type:
            data_types_set.update(['usage', 'behavior', 'interests'])
        else:
            data_types_set.add('usage')

        # Infer from cloud services
        for conn in cloud_connections:
            provider = (conn.get('cloud_provider') or 'unknown').lower()
            privacy_info = CLOUD_SERVICE_PRIVACY.get(provider, CLOUD_SERVICE_PRIVACY['unknown'])
            data_types_set.update(privacy_info['data_types'])

        # Convert to detailed list
        data_types_list = []
        for data_type in data_types_set:
            type_info = DATA_TYPES.get(data_type, DATA_TYPES['unknown'])
            data_types_list.append({
                'type': data_type,
                'name': type_info['name'],
                'sensitivity': type_info['sensitivity'],
                'inferred': True
            })

        # Sort by sensitivity
        sensitivity_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3}
        data_types_list.sort(key=lambda x: sensitivity_order.get(x['sensitivity'], 4))

        return data_types_list

    def _calculate_privacy_risk(
        self,
        cloud_analysis: Dict,
        data_types: List[Dict],
        exfiltration_events: List[Dict]
    ) -> Dict[str, Any]:
        """Calculate overall privacy risk score."""
        risk_score = 0
        risk_factors = []

        # Factor 1: Number of cloud services (more = higher risk)
        unique_services = cloud_analysis.get('unique_services', 0)
        if unique_services > 10:
            risk_score += 20
            risk_factors.append(f"Connects to {unique_services} different cloud services")
        elif unique_services > 5:
            risk_score += 10
            risk_factors.append(f"Connects to {unique_services} cloud services")

        # Factor 2: Sensitive data types collected
        critical_data = [d for d in data_types if d['sensitivity'] == 'critical']
        high_data = [d for d in data_types if d['sensitivity'] == 'high']

        if critical_data:
            risk_score += len(critical_data) * 25
            risk_factors.append(f"Collects {len(critical_data)} critical data type(s): {', '.join([d['name'] for d in critical_data])}")

        if high_data:
            risk_score += len(high_data) * 10
            risk_factors.append(f"Collects {len(high_data)} high-sensitivity data type(s)")

        # Factor 3: Data exfiltration frequency
        exfil_count = len(exfiltration_events)
        if exfil_count > 50:
            risk_score += 20
            risk_factors.append(f"High data transmission frequency ({exfil_count} events)")
        elif exfil_count > 20:
            risk_score += 10
            risk_factors.append(f"Moderate data transmission frequency ({exfil_count} events)")

        # Normalize to 0-100
        risk_score = min(risk_score, 100)

        # Determine risk level
        if risk_score >= 75:
            risk_level = 'critical'
        elif risk_score >= 50:
            risk_level = 'high'
        elif risk_score >= 25:
            risk_level = 'medium'
        elif risk_score > 0:
            risk_level = 'low'
        else:
            risk_level = 'minimal'

        return {
            'score': risk_score,
            'level': risk_level,
            'color': PRIVACY_RISK_LEVELS[risk_level]['color'],
            'factors': risk_factors,
            'recommendations': self._generate_privacy_recommendations(risk_level, risk_factors)
        }

    def _calculate_transmission_stats(
        self,
        cloud_connections: List[Dict],
        exfiltration_events: List[Dict],
        protocol_usage: List[Dict]
    ) -> Dict[str, Any]:
        """Calculate data transmission statistics."""
        total_events = len(exfiltration_events)
        total_bytes = sum(e.get('bytes_transferred', 0) for e in exfiltration_events)

        # Calculate frequency (events per day)
        if exfiltration_events:
            first_event = min(e.get('timestamp', '') for e in exfiltration_events)
            last_event = max(e.get('timestamp', '') for e in exfiltration_events)

            try:
                first_dt = datetime.fromisoformat(first_event)
                last_dt = datetime.fromisoformat(last_event)
                days_span = max((last_dt - first_dt).days, 1)
                events_per_day = total_events / days_span
            except:
                events_per_day = 0
        else:
            events_per_day = 0

        # Top protocols
        top_protocols = protocol_usage[:5] if protocol_usage else []

        return {
            'total_events': total_events,
            'total_bytes': total_bytes,
            'total_mb': round(total_bytes / 1024 / 1024, 2),
            'events_per_day': round(events_per_day, 1),
            'top_protocols': top_protocols
        }

    def _generate_privacy_recommendations(self, risk_level: str, risk_factors: List[str]) -> List[str]:
        """Generate privacy recommendations based on risk assessment."""
        recommendations = []

        if risk_level in ['critical', 'high']:
            recommendations.append("Consider reviewing device privacy settings")
            recommendations.append("Check manufacturer privacy policy for data usage details")

            if any('critical data' in f.lower() for f in risk_factors):
                recommendations.append("⚠️ Device collects highly sensitive data - review necessity")

            if any('cloud services' in f.lower() for f in risk_factors):
                recommendations.append("Consider network segmentation to isolate this device")
                recommendations.append("Monitor outbound connections for unusual activity")

        elif risk_level == 'medium':
            recommendations.append("Review device privacy settings periodically")
            recommendations.append("Monitor data transmission patterns")

        else:
            recommendations.append("Privacy risk is low - maintain current monitoring")

        return recommendations

    def get_all_devices_privacy_summary(self, days: int = 7) -> List[Dict[str, Any]]:
        """
        Get privacy summary for all devices.

        Args:
            days: Number of days to analyze

        Returns:
            List of device privacy summaries
        """
        try:
            conn = self.db_manager.conn
            cursor = conn.cursor()

            cursor.execute("SELECT device_ip FROM devices")
            devices = cursor.fetchall()

            summaries = []
            # logger.info(f"Found {len(devices)} devices for privacy analysis")
            for device_row in devices:
                device_ip = device_row[0]
                logger.debug(f"Analyzing privacy for device: {device_ip}")
                analysis = self.analyze_device_data_collection(device_ip, days)

                if 'error' not in analysis:
                    summaries.append({
                        'device_ip': device_ip,
                        'device_name': analysis.get('device_name', 'Unknown'),
                        'device_type': analysis.get('device_type', 'unknown'),
                        'privacy_risk_score': analysis.get('privacy_risk', {}).get('score', 0),
                        'privacy_risk_level': analysis.get('privacy_risk', {}).get('level', 'minimal'),
                        'unique_cloud_services': analysis.get('cloud_services', {}).get('unique_services', 0),
                        'data_types_count': len(analysis.get('data_types_collected', [])),
                        'critical_data_types': len([
                            d for d in analysis.get('data_types_collected', [])
                            if d.get('sensitivity') == 'critical'
                        ])
                    })
                    logger.debug(f"Added device {device_ip} with risk level: {analysis.get('privacy_risk', {}).get('level', 'minimal')}")
                else:
                    logger.warning(f"Skipping device {device_ip} due to error: {analysis.get('error')}")

            # logger.info(f"Privacy analysis complete: {len(summaries)} devices analyzed")

            # Sort by risk score (highest first)
            summaries.sort(key=lambda x: x['privacy_risk_score'], reverse=True)

            return summaries

        except Exception as e:
            logger.error(f"Error getting privacy summary for all devices: {e}")
            return []


# Global privacy analyzer instance
_privacy_analyzer = None


def get_privacy_analyzer(db_manager: DatabaseManager = None) -> PrivacyAnalyzer:
    """
    Get or create privacy analyzer instance.

    Args:
        db_manager: DatabaseManager instance

    Returns:
        PrivacyAnalyzer instance
    """
    global _privacy_analyzer
    if _privacy_analyzer is None:
        _privacy_analyzer = PrivacyAnalyzer(db_manager=db_manager)
    return _privacy_analyzer
