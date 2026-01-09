#!/usr/bin/env python3
"""
Sustainability Calculator for IoTSentinel

Calculates environmental impact metrics including:
- Carbon footprint from network usage
- Energy consumption estimates
- Device efficiency scores
- Green security best practices
"""

import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional
import json

logger = logging.getLogger(__name__)


class SustainabilityCalculator:
    """Calculates environmental impact and sustainability metrics."""

    def __init__(self, db_manager):
        self.db = db_manager

        # Energy conversion factors
        self.ENERGY_PER_GB = 0.06  # kWh per GB of data transferred (industry average)
        self.CARBON_PER_KWH = 0.5  # kg CO2 per kWh (US average grid mix)

        # Device power consumption estimates (watts) - industry averages
        self.device_power_estimates = {
            'Camera': 5.0,  # IP cameras
            'Smart Speaker': 3.0,
            'Smart Lock': 1.5,
            'Smart Thermostat': 2.0,
            'Smart Bulb': 9.0,  # When on
            'Router': 10.0,
            'Smart TV': 80.0,  # Active viewing
            'Smart Plug': 0.5,
            'DVR/NVR': 15.0,
            'Computer': 100.0,  # Desktop
            'Phone': 5.0,  # Charging
            'Tablet': 10.0,  # Charging
            'Unknown': 5.0  # Conservative estimate
        }

    def calculate_network_carbon_footprint(self, hours: int = 24) -> Dict:
        """
        Calculate carbon footprint from network data transfer.

        Args:
            hours: Time period to calculate (hours)

        Returns:
            Dict with carbon footprint metrics
        """
        try:
            cursor = self.db.conn.cursor()

            cutoff_time = datetime.now() - timedelta(hours=hours)

            # Get total data transferred
            cursor.execute("""
                SELECT
                    SUM(bytes_sent) as total_sent,
                    SUM(bytes_received) as total_received
                FROM connections
                WHERE timestamp >= ?
            """, (cutoff_time.isoformat(),))

            result = cursor.fetchone()
            total_sent = result['total_sent'] or 0
            total_received = result['total_received'] or 0

            # Convert to GB
            total_gb = (total_sent + total_received) / (1024 ** 3)

            # Calculate energy consumption
            energy_kwh = total_gb * self.ENERGY_PER_GB

            # Calculate carbon footprint
            carbon_kg = energy_kwh * self.CARBON_PER_KWH

            # Extrapolate to different time periods
            daily_carbon = carbon_kg * (24 / hours) if hours != 24 else carbon_kg
            monthly_carbon = daily_carbon * 30
            yearly_carbon = daily_carbon * 365

            return {
                'period_hours': hours,
                'total_data_gb': round(total_gb, 2),
                'energy_kwh': round(energy_kwh, 3),
                'carbon_kg': round(carbon_kg, 3),
                'daily_carbon_kg': round(daily_carbon, 3),
                'monthly_carbon_kg': round(monthly_carbon, 2),
                'yearly_carbon_kg': round(yearly_carbon, 1),
                'equivalent_trees': round(yearly_carbon / 21, 1),  # Trees needed to offset (1 tree absorbs ~21kg CO2/year)
                'equivalent_miles_driven': round(yearly_carbon / 0.404, 1),  # Car miles equivalent (0.404 kg CO2/mile)
                'timestamp': datetime.now().isoformat()
            }

        except Exception as e:
            logger.error(f"Error calculating carbon footprint: {e}")
            return {'error': str(e)}

    def calculate_device_energy_consumption(self, device_ip: str, date: Optional[str] = None) -> Dict:
        """
        Estimate energy consumption for a specific device.

        Args:
            device_ip: Device IP address
            date: Date to calculate for (YYYY-MM-DD), defaults to today

        Returns:
            Dict with energy estimates
        """
        try:
            cursor = self.db.conn.cursor()

            # Get device info
            cursor.execute("""
                SELECT device_type, device_name
                FROM devices
                WHERE device_ip = ?
            """, (device_ip,))

            device = cursor.fetchone()
            if not device:
                return {'error': 'Device not found'}

            device_type = device['device_type'] or 'Unknown'
            estimated_power_watts = self.device_power_estimates.get(device_type, 5.0)

            # Get activity data for the date
            if date is None:
                date = datetime.now().date().isoformat()

            cursor.execute("""
                SELECT COUNT(*) as connection_count,
                       SUM(bytes_sent + bytes_received) as total_bytes
                FROM connections
                WHERE device_ip = ?
                AND DATE(timestamp) = ?
            """, (device_ip, date))

            activity = cursor.fetchone()
            connection_count = activity['connection_count'] or 0
            total_bytes = activity['total_bytes'] or 0

            # Estimate active hours based on connection patterns
            # Assume device is active if it has connections
            cursor.execute("""
                SELECT COUNT(DISTINCT strftime('%H', timestamp)) as active_hours
                FROM connections
                WHERE device_ip = ?
                AND DATE(timestamp) = ?
            """, (device_ip, date))

            active_hours_result = cursor.fetchone()
            active_hours = active_hours_result['active_hours'] or 0

            # If no connections, estimate based on device type
            if active_hours == 0:
                always_on_types = ['Router', 'Camera', 'DVR/NVR']
                if device_type in always_on_types:
                    active_hours = 24

            # Calculate energy
            estimated_energy_kwh = (estimated_power_watts * active_hours) / 1000
            data_gb = total_bytes / (1024 ** 3)

            # Save estimate to database
            self._save_device_energy_estimate(
                device_ip, device_type, date, estimated_power_watts,
                active_hours, estimated_energy_kwh, data_gb
            )

            return {
                'device_ip': device_ip,
                'device_name': device['device_name'],
                'device_type': device_type,
                'date': date,
                'estimated_power_watts': estimated_power_watts,
                'active_hours': active_hours,
                'estimated_energy_kwh': round(estimated_energy_kwh, 3),
                'data_transferred_gb': round(data_gb, 2),
                'carbon_kg': round(estimated_energy_kwh * self.CARBON_PER_KWH, 3)
            }

        except Exception as e:
            logger.error(f"Error calculating device energy: {e}")
            return {'error': str(e)}

    def calculate_total_energy_consumption(self, date: Optional[str] = None) -> Dict:
        """
        Calculate total energy consumption for all devices.

        Args:
            date: Date to calculate for (YYYY-MM-DD), defaults to today

        Returns:
            Dict with total energy metrics
        """
        try:
            cursor = self.db.conn.cursor()

            if date is None:
                date = datetime.now().date().isoformat()

            cursor.execute("""
                SELECT device_ip
                FROM devices
            """)

            devices = cursor.fetchall()
            total_energy = 0
            total_carbon = 0
            device_breakdown = []

            for device in devices:
                energy_data = self.calculate_device_energy_consumption(device['device_ip'], date)
                if 'error' not in energy_data:
                    total_energy += energy_data['estimated_energy_kwh']
                    total_carbon += energy_data['carbon_kg']
                    device_breakdown.append(energy_data)

            # Calculate cost (assuming $0.13/kWh average US rate)
            energy_cost = total_energy * 0.13

            return {
                'date': date,
                'total_devices': len(devices),
                'total_energy_kwh': round(total_energy, 2),
                'total_carbon_kg': round(total_carbon, 2),
                'estimated_cost_usd': round(energy_cost, 2),
                'monthly_estimate_kwh': round(total_energy * 30, 1),
                'monthly_estimate_cost': round(energy_cost * 30, 2),
                'yearly_estimate_kwh': round(total_energy * 365, 1),
                'yearly_estimate_cost': round(energy_cost * 365, 2),
                'device_breakdown': sorted(
                    device_breakdown,
                    key=lambda x: x['estimated_energy_kwh'],
                    reverse=True
                )[:10]  # Top 10 energy consumers
            }

        except Exception as e:
            logger.error(f"Error calculating total energy: {e}")
            return {'error': str(e)}

    def get_green_best_practices(self) -> List[Dict]:
        """
        Get green security best practices and recommendations.

        Returns:
            List of green practice recommendations
        """
        return [
            {
                'category': 'Energy Efficiency',
                'title': 'Schedule IoT Device Sleep Times',
                'description': 'Configure devices to enter low-power mode when not in use',
                'impact': 'Can reduce energy consumption by 30-50%',
                'difficulty': 'Easy',
                'examples': [
                    'Schedule smart cameras to sleep during work hours',
                    'Set smart lights to auto-off after 30 minutes',
                    'Enable router power-saving mode during night'
                ]
            },
            {
                'category': 'E-Waste Reduction',
                'title': 'Extend Device Lifespan with Updates',
                'description': 'Keep firmware updated to extend device support life',
                'impact': 'Can add 2-3 years of device usability',
                'difficulty': 'Easy',
                'examples': [
                    'Enable automatic firmware updates',
                    'Replace batteries in wireless devices',
                    'Clean device vents to prevent overheating'
                ]
            },
            {
                'category': 'Network Optimization',
                'title': 'Reduce Unnecessary Cloud Polling',
                'description': 'Disable unnecessary cloud features and reduce polling frequency',
                'impact': '10-20% reduction in network energy use',
                'difficulty': 'Medium',
                'examples': [
                    'Use local storage instead of cloud when possible',
                    'Reduce smart speaker status check frequency',
                    'Disable unused app notifications'
                ]
            },
            {
                'category': 'Green Purchasing',
                'title': 'Choose Energy-Efficient Devices',
                'description': 'Select devices with Energy Star or equivalent certifications',
                'impact': 'Up to 50% lower lifetime energy use',
                'difficulty': 'Easy',
                'examples': [
                    'Look for Energy Star certified smart devices',
                    'Choose PoE (Power over Ethernet) cameras',
                    'Select devices with sleep/standby modes'
                ]
            },
            {
                'category': 'Recycling',
                'title': 'Proper E-Waste Disposal',
                'description': 'Recycle old devices through certified programs',
                'impact': 'Prevents toxic materials from landfills',
                'difficulty': 'Easy',
                'examples': [
                    'Use manufacturer take-back programs',
                    'Donate working devices to schools/nonprofits',
                    'Find local e-waste recycling centers'
                ]
            },
            {
                'category': 'Security Efficiency',
                'title': 'Network Segmentation Reduces Energy',
                'description': 'Proper network segmentation can reduce broadcast traffic and energy',
                'impact': '5-10% reduction in network equipment energy use',
                'difficulty': 'Advanced',
                'examples': [
                    'Separate IoT devices on dedicated VLAN',
                    'Reduce unnecessary cross-VLAN traffic',
                    'Use multicast filtering to reduce broadcasts'
                ]
            }
        ]

    def save_sustainability_metrics(self, metrics: Dict) -> bool:
        """
        Save sustainability metrics to database.

        Args:
            metrics: Metrics dictionary

        Returns:
            True if successful
        """
        try:
            cursor = self.db.conn.cursor()

            cursor.execute("""
                INSERT INTO sustainability_metrics (
                    timestamp, period_start, period_end,
                    total_data_gb, estimated_energy_kwh,
                    carbon_footprint_kg, device_count,
                    active_device_hours
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                datetime.now().isoformat(),
                metrics.get('period_start'),
                metrics.get('period_end'),
                metrics.get('total_data_gb', 0),
                metrics.get('energy_kwh', 0),
                metrics.get('carbon_kg', 0),
                metrics.get('device_count', 0),
                metrics.get('active_device_hours', 0)
            ))

            self.db.conn.commit()
            return True

        except Exception as e:
            logger.error(f"Failed to save sustainability metrics: {e}")
            return False

    def _save_device_energy_estimate(self, device_ip: str, device_type: str,
                                      date: str, power_watts: float,
                                      active_hours: float, energy_kwh: float,
                                      data_gb: float):
        """Save device energy estimate to database."""
        try:
            cursor = self.db.conn.cursor()

            cursor.execute("""
                INSERT INTO device_energy_estimates (
                    device_ip, device_type, date,
                    estimated_power_watts, active_hours,
                    estimated_energy_kwh, data_transferred_gb
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(device_ip, date) DO UPDATE SET
                    estimated_power_watts = excluded.estimated_power_watts,
                    active_hours = excluded.active_hours,
                    estimated_energy_kwh = excluded.estimated_energy_kwh,
                    data_transferred_gb = excluded.data_transferred_gb
            """, (device_ip, device_type, date, power_watts, active_hours, energy_kwh, data_gb))

            self.db.conn.commit()

        except Exception as e:
            logger.error(f"Failed to save device energy estimate: {e}")

    def get_sustainability_history(self, days: int = 30) -> List[Dict]:
        """
        Get sustainability metrics history.

        Args:
            days: Number of days to retrieve

        Returns:
            List of historical metrics
        """
        try:
            cursor = self.db.conn.cursor()

            cutoff_date = datetime.now() - timedelta(days=days)

            cursor.execute("""
                SELECT *
                FROM sustainability_metrics
                WHERE timestamp >= ?
                ORDER BY timestamp DESC
            """, (cutoff_date.isoformat(),))

            results = cursor.fetchall()
            return [dict(row) for row in results]

        except Exception as e:
            logger.error(f"Failed to get sustainability history: {e}")
            return []


# Global instance
_sustainability_calculator = None


def get_sustainability_calculator(db_manager):
    """Get global sustainability calculator instance."""
    global _sustainability_calculator
    if _sustainability_calculator is None:
        _sustainability_calculator = SustainabilityCalculator(db_manager)
    return _sustainability_calculator
