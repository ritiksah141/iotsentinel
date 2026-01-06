#!/usr/bin/env python3
"""
Trend Analysis Module for IoTSentinel

Provides time-series analysis and trend detection for security metrics.
Analyzes historical data to identify patterns, anomalies, and trends.
"""

import sqlite3
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Tuple
from collections import defaultdict
import json
import sys
from pathlib import Path

# Add database module to path
sys.path.insert(0, str(Path(__file__).parent.parent))
from database.query_optimizer import QueryOptimizer

logger = logging.getLogger(__name__)


class TrendAnalyzer:
    """
    Analyzes trends in IoT security data.

    Provides methods to:
    - Calculate alert trends over time
    - Detect device activity patterns
    - Identify network traffic anomalies
    - Generate trend statistics
    """

    def __init__(self, db_path: str):
        """
        Initialize trend analyzer with query optimization.

        Args:
            db_path: Path to SQLite database
        """
        self.db_path = db_path
        self.query_optimizer = QueryOptimizer(db_path)

    def analyze_alert_trends(
        self,
        days: int = 30,
        granularity: str = 'daily'
    ) -> Dict[str, Any]:
        """
        Analyze alert trends over time period.

        Args:
            days: Number of days to analyze
            granularity: 'hourly', 'daily', or 'weekly'

        Returns:
            Dictionary with trend data including:
            - time_series: List of (timestamp, count) tuples
            - severity_trends: Breakdown by severity over time
            - trend_direction: 'increasing', 'decreasing', or 'stable'
            - percent_change: Percentage change from start to end
            - total_alerts: Total count in period
        """
        try:
            # Use optimized query
            results = self.query_optimizer.get_aggregated_alerts(
                days=days,
                granularity=granularity
            )

            # Organize data
            time_series = defaultdict(int)
            severity_trends = defaultdict(lambda: defaultdict(int))

            for time_bucket, count, severity in results:
                time_series[time_bucket] += count
                severity_trends[time_bucket][severity] = count

            # Convert to lists
            time_points = sorted(time_series.keys())
            counts = [time_series[t] for t in time_points]

            # Calculate trend direction
            if len(counts) >= 2:
                first_half_avg = sum(counts[:len(counts)//2]) / max(1, len(counts)//2)
                second_half_avg = sum(counts[len(counts)//2:]) / max(1, len(counts) - len(counts)//2)

                if second_half_avg > first_half_avg * 1.1:
                    trend_direction = 'increasing'
                elif second_half_avg < first_half_avg * 0.9:
                    trend_direction = 'decreasing'
                else:
                    trend_direction = 'stable'

                percent_change = ((second_half_avg - first_half_avg) / max(1, first_half_avg)) * 100
            else:
                trend_direction = 'insufficient_data'
                percent_change = 0

            return {
                'time_series': list(zip(time_points, counts)),
                'severity_trends': dict(severity_trends),
                'trend_direction': trend_direction,
                'percent_change': round(percent_change, 2),
                'total_alerts': sum(counts),
                'period_days': days,
                'granularity': granularity
            }

        except Exception as e:
            logger.error(f"Error analyzing alert trends: {e}")
            return {
                'time_series': [],
                'severity_trends': {},
                'trend_direction': 'error',
                'percent_change': 0,
                'total_alerts': 0,
                'error': str(e)
            }

    def analyze_device_activity(
        self,
        days: int = 7
    ) -> Dict[str, Any]:
        """
        Analyze device activity patterns.

        Args:
            days: Number of days to analyze

        Returns:
            Dictionary with:
            - most_active_devices: List of (device_ip, connection_count)
            - activity_by_hour: Hourly activity distribution
            - new_devices: Count of new devices detected
            - inactive_devices: Count of devices with no recent activity
        """
        try:
            cutoff = datetime.now() - timedelta(days=days)
            cutoff_str = cutoff.strftime('%Y-%m-%d %H:%M:%S')

            # Most active devices - use optimized query
            most_active = self.query_optimizer.get_top_devices_by_activity(
                days=days,
                limit=10
            )

            # For remaining queries, use standard connection
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()

            # Activity by hour of day
            cursor.execute("""
                SELECT
                    CAST(strftime('%H', timestamp) AS INTEGER) as hour,
                    COUNT(*) as activity_count
                FROM connections
                WHERE timestamp >= ?
                GROUP BY hour
                ORDER BY hour
            """, (cutoff_str,))

            hourly_activity = dict(cursor.fetchall())

            # Fill missing hours with 0
            activity_by_hour = {hour: hourly_activity.get(hour, 0) for hour in range(24)}

            # New devices (first seen in this period)
            cursor.execute("""
                SELECT COUNT(DISTINCT device_ip)
                FROM devices
                WHERE first_seen >= ?
            """, (cutoff_str,))

            new_devices = cursor.fetchone()[0]

            # Inactive devices (last seen before this period)
            cursor.execute("""
                SELECT COUNT(*)
                FROM devices
                WHERE last_seen < ?
            """, (cutoff_str,))

            inactive_devices = cursor.fetchone()[0]

            conn.close()

            return {
                'most_active_devices': most_active,
                'activity_by_hour': activity_by_hour,
                'new_devices': new_devices,
                'inactive_devices': inactive_devices,
                'analysis_period_days': days
            }

        except Exception as e:
            logger.error(f"Error analyzing device activity: {e}")
            return {
                'most_active_devices': [],
                'activity_by_hour': {},
                'new_devices': 0,
                'inactive_devices': 0,
                'error': str(e)
            }

    def analyze_network_traffic(
        self,
        hours: int = 24
    ) -> Dict[str, Any]:
        """
        Analyze network traffic patterns.

        Args:
            hours: Number of hours to analyze

        Returns:
            Dictionary with:
            - total_connections: Total connection count
            - unique_sources: Number of unique source IPs
            - unique_destinations: Number of unique destination IPs
            - top_ports: Most commonly used ports
            - traffic_volume: Total bytes transferred
            - suspicious_patterns: Count of unusual patterns
        """
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()

            cutoff = datetime.now() - timedelta(hours=hours)
            cutoff_str = cutoff.strftime('%Y-%m-%d %H:%M:%S')

            # Total connections
            cursor.execute("""
                SELECT COUNT(*) FROM connections
                WHERE timestamp >= ?
            """, (cutoff_str,))
            total_connections = cursor.fetchone()[0]

            # Unique sources and destinations
            cursor.execute("""
                SELECT
                    COUNT(DISTINCT device_ip) as unique_sources,
                    COUNT(DISTINCT dest_ip) as unique_destinations
                FROM connections
                WHERE timestamp >= ?
            """, (cutoff_str,))

            unique_sources, unique_destinations = cursor.fetchone()

            # Top ports
            cursor.execute("""
                SELECT dest_port, COUNT(*) as port_count
                FROM connections
                WHERE timestamp >= ?
                GROUP BY dest_port
                ORDER BY port_count DESC
                LIMIT 10
            """, (cutoff_str,))

            top_ports = cursor.fetchall()

            # Traffic volume (if bytes_sent/bytes_received columns exist)
            try:
                cursor.execute("""
                    SELECT
                        COALESCE(SUM(bytes_sent), 0) as total_sent,
                        COALESCE(SUM(bytes_received), 0) as total_received
                    FROM connections
                    WHERE timestamp >= ?
                """, (cutoff_str,))

                total_sent, total_received = cursor.fetchone()
                traffic_volume = {
                    'sent_bytes': total_sent,
                    'received_bytes': total_received,
                    'total_bytes': total_sent + total_received
                }
            except sqlite3.OperationalError:
                traffic_volume = {'note': 'Traffic volume tracking not available'}

            # Suspicious patterns (connections to unusual ports)
            suspicious_ports = [23, 69, 135, 139, 445, 1433, 3306, 3389, 5900]
            cursor.execute(f"""
                SELECT COUNT(*) FROM connections
                WHERE timestamp >= ?
                AND dest_port IN ({','.join('?' * len(suspicious_ports))})
            """, (cutoff_str, *suspicious_ports))

            suspicious_patterns = cursor.fetchone()[0]

            conn.close()

            return {
                'total_connections': total_connections,
                'unique_sources': unique_sources,
                'unique_destinations': unique_destinations,
                'top_ports': top_ports,
                'traffic_volume': traffic_volume,
                'suspicious_patterns': suspicious_patterns,
                'analysis_period_hours': hours
            }

        except Exception as e:
            logger.error(f"Error analyzing network traffic: {e}")
            return {
                'total_connections': 0,
                'unique_sources': 0,
                'unique_destinations': 0,
                'top_ports': [],
                'traffic_volume': {},
                'suspicious_patterns': 0,
                'error': str(e)
            }

    def get_executive_summary(
        self,
        days: int = 7
    ) -> Dict[str, Any]:
        """
        Generate comprehensive executive summary.

        Args:
            days: Number of days to analyze

        Returns:
            Dictionary with high-level metrics and trends suitable
            for executive reporting
        """
        try:
            # Get all trend analyses
            alert_trends = self.analyze_alert_trends(days=days, granularity='daily')
            device_activity = self.analyze_device_activity(days=days)
            network_traffic = self.analyze_network_traffic(hours=days*24)

            # Calculate summary metrics
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()

            cutoff = datetime.now() - timedelta(days=days)
            cutoff_str = cutoff.strftime('%Y-%m-%d %H:%M:%S')

            # Critical alerts
            cursor.execute("""
                SELECT COUNT(*) FROM alerts
                WHERE timestamp >= ? AND severity = 'critical'
            """, (cutoff_str,))
            critical_alerts = cursor.fetchone()[0]

            # Total devices
            cursor.execute("""
                SELECT COUNT(*) FROM devices
            """)
            total_devices = cursor.fetchone()[0]

            # Active devices (seen in last 24 hours)
            active_cutoff = (datetime.now() - timedelta(hours=24)).strftime('%Y-%m-%d %H:%M:%S')
            cursor.execute("""
                SELECT COUNT(*) FROM devices
                WHERE last_seen >= ? OR last_activity >= ?
            """, (active_cutoff, active_cutoff))
            active_devices = cursor.fetchone()[0]

            # Blocked devices/connections
            cursor.execute("""
                SELECT COUNT(*) FROM devices
                WHERE is_blocked = 1
            """)
            blocked_connections = cursor.fetchone()[0]

            conn.close()

            return {
                'period': {
                    'days': days,
                    'start_date': cutoff.strftime('%Y-%m-%d'),
                    'end_date': datetime.now().strftime('%Y-%m-%d')
                },
                'security_posture': {
                    'alert_trend': alert_trends['trend_direction'],
                    'total_alerts': alert_trends['total_alerts'],
                    'critical_alerts': critical_alerts,
                    'percent_change': alert_trends['percent_change']
                },
                'network_activity': {
                    'total_connections': network_traffic['total_connections'],
                    'blocked_connections': blocked_connections,
                    'suspicious_patterns': network_traffic['suspicious_patterns'],
                    'unique_sources': network_traffic['unique_sources']
                },
                'device_status': {
                    'device_count': total_devices,
                    'active_devices': active_devices,
                    'new_devices': device_activity['new_devices'],
                    'inactive_devices': device_activity['inactive_devices']
                },
                'top_concerns': self._identify_top_concerns(
                    alert_trends, device_activity, network_traffic
                )
            }

        except Exception as e:
            logger.error(f"Error generating executive summary: {e}")
            return {'error': str(e)}

    def _identify_top_concerns(
        self,
        alert_trends: Dict,
        device_activity: Dict,
        network_traffic: Dict
    ) -> List[str]:
        """
        Identify top security concerns based on analysis.

        Returns:
            List of concern descriptions
        """
        concerns = []

        # Check alert trends
        if alert_trends['trend_direction'] == 'increasing':
            concerns.append(
                f"Alert volume increasing by {abs(alert_trends['percent_change']):.1f}%"
            )

        # Check suspicious network activity
        if network_traffic.get('suspicious_patterns', 0) > 10:
            concerns.append(
                f"{network_traffic['suspicious_patterns']} connections to suspicious ports detected"
            )

        # Check new devices
        if device_activity.get('new_devices', 0) > 5:
            concerns.append(
                f"{device_activity['new_devices']} new devices detected - verify authorization"
            )

        # Check inactive devices
        if device_activity.get('inactive_devices', 0) > 10:
            concerns.append(
                f"{device_activity['inactive_devices']} devices inactive - possible network issues"
            )

        if not concerns:
            concerns.append("No major concerns detected")

        return concerns[:5]  # Return top 5 concerns

    def detect_anomalies(
        self,
        metric: str = 'alerts',
        days: int = 30,
        threshold_std: float = 2.0
    ) -> Dict[str, Any]:
        """
        Detect anomalies using statistical analysis.

        Args:
            metric: 'alerts', 'connections', or 'traffic'
            days: Number of days for baseline
            threshold_std: Number of standard deviations for anomaly

        Returns:
            Dictionary with anomaly detection results
        """
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()

            cutoff = datetime.now() - timedelta(days=days)
            cutoff_str = cutoff.strftime('%Y-%m-%d %H:%M:%S')

            if metric == 'alerts':
                # Get daily alert counts
                cursor.execute("""
                    SELECT
                        strftime('%Y-%m-%d', timestamp) as day,
                        COUNT(*) as count
                    FROM alerts
                    WHERE timestamp >= ?
                    GROUP BY day
                    ORDER BY day
                """, (cutoff_str,))
            elif metric == 'connections':
                # Get daily connection counts
                cursor.execute("""
                    SELECT
                        strftime('%Y-%m-%d', timestamp) as day,
                        COUNT(*) as count
                    FROM connections
                    WHERE timestamp >= ?
                    GROUP BY day
                    ORDER BY day
                """, (cutoff_str,))
            else:
                conn.close()
                return {'error': 'Invalid metric'}

            data = cursor.fetchall()
            conn.close()

            if len(data) < 3:
                return {
                    'anomalies': [],
                    'message': 'Insufficient data for anomaly detection'
                }

            # Calculate statistics
            counts = [count for _, count in data]
            mean = sum(counts) / len(counts)
            variance = sum((x - mean) ** 2 for x in counts) / len(counts)
            std_dev = variance ** 0.5

            # Detect anomalies
            anomalies = []
            for day, count in data:
                z_score = (count - mean) / max(std_dev, 1)
                if abs(z_score) > threshold_std:
                    anomalies.append({
                        'date': day,
                        'value': count,
                        'z_score': round(z_score, 2),
                        'deviation': 'high' if z_score > 0 else 'low'
                    })

            return {
                'metric': metric,
                'baseline': {
                    'mean': round(mean, 2),
                    'std_dev': round(std_dev, 2),
                    'threshold': threshold_std
                },
                'anomalies': anomalies,
                'anomaly_count': len(anomalies)
            }

        except Exception as e:
            logger.error(f"Error detecting anomalies: {e}")
            return {'error': str(e)}
