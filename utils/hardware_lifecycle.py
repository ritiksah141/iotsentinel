#!/usr/bin/env python3
"""
Hardware Lifecycle Manager for IoTSentinel

Tracks device hardware lifecycle, end-of-life dates, and generates
alerts for devices approaching or past their support end dates.
"""

import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional
import json

logger = logging.getLogger(__name__)


class HardwareLifecycleManager:
    """Manages hardware lifecycle tracking and EOL alerts."""

    def __init__(self, db_manager):
        self.db = db_manager

        # Industry-standard hardware support periods (years)
        self.default_support_periods = {
            'Camera': 5,
            'Smart Speaker': 4,
            'Smart Lock': 6,
            'Smart Thermostat': 7,
            'Smart Bulb': 5,
            'Router': 5,
            'Smart TV': 6,
            'Smart Plug': 4,
            'DVR/NVR': 7,
            'Computer': 8,
            'Phone': 5,
            'Tablet': 5
        }

        # Recycling resources by device type
        self.recycling_resources = {
            'Camera': 'https://earth911.com/recycling-guide/how-to-recycle-security-cameras/',
            'Computer': 'https://www.epa.gov/recycle/electronics-donation-and-recycling',
            'Phone': 'https://www.epa.gov/recycle/electronics-donation-and-recycling',
            'Smart TV': 'https://earth911.com/recycling-guide/how-to-recycle-tvs/',
            'Router': 'https://earth911.com/recycling-guide/how-to-recycle-routers/',
            'default': 'https://www.epa.gov/recycle/electronics-donation-and-recycling'
        }

    def check_device_lifecycle(self, device_ip: str, generate_alerts: bool = True) -> Dict:
        """
        Check hardware lifecycle status for a device.

        Args:
            device_ip: Device IP address
            generate_alerts: Whether to generate alerts for EOL devices

        Returns:
            Dict with lifecycle status
        """
        try:
            cursor = self.db.conn.cursor()

            cursor.execute("""
                SELECT device_ip, device_type, device_name, manufacturer, model,
                       manufacturing_date, hardware_eol_date
                FROM devices
                WHERE device_ip = ?
            """, (device_ip,))

            device = cursor.fetchone()
            if not device:
                return {'error': 'Device not found'}

            device_type = device['device_type'] or 'Unknown'
            manufacturing_date = device['manufacturing_date']
            hardware_eol_date = device['hardware_eol_date']

            # If no manufacturing date, can't calculate lifecycle
            if not manufacturing_date:
                return {
                    'device_ip': device_ip,
                    'status': 'unknown',
                    'message': 'Manufacturing date not set',
                    'action_required': 'Set manufacturing date in device details'
                }

            # Parse manufacturing date
            mfg_date = datetime.fromisoformat(manufacturing_date)
            today = datetime.now()
            device_age_days = (today - mfg_date).days
            device_age_years = device_age_days / 365.25

            # Check if EOL date is set
            if hardware_eol_date:
                eol_date = datetime.fromisoformat(hardware_eol_date)
                days_until_eol = (eol_date - today).days

                if days_until_eol < 0:
                    # Device is past EOL
                    status = 'past_eol'
                    days_past_eol = abs(days_until_eol)

                    if generate_alerts:
                        self._generate_eol_alert(
                            device_ip,
                            'critical',
                            f"Device '{device['device_name']}' is {days_past_eol} days past EOL. "
                            f"No security updates available. Consider replacement.",
                            {'days_past_eol': days_past_eol, 'eol_date': hardware_eol_date}
                        )

                    return {
                        'device_ip': device_ip,
                        'device_name': device['device_name'],
                        'device_type': device_type,
                        'status': status,
                        'manufacturing_date': manufacturing_date,
                        'hardware_eol_date': hardware_eol_date,
                        'device_age_years': round(device_age_years, 1),
                        'days_past_eol': days_past_eol,
                        'message': f'Device is {days_past_eol} days past end-of-life',
                        'action_required': 'Replace device immediately - no security updates available',
                        'recycling_link': self._get_recycling_link(device_type)
                    }

                elif days_until_eol <= 180:  # Within 6 months of EOL
                    # Approaching EOL
                    status = 'approaching_eol'

                    if generate_alerts:
                        self._generate_eol_alert(
                            device_ip,
                            'high',
                            f"Device '{device['device_name']}' will reach EOL in {days_until_eol} days. "
                            f"Plan for replacement.",
                            {'days_until_eol': days_until_eol, 'eol_date': hardware_eol_date}
                        )

                    return {
                        'device_ip': device_ip,
                        'device_name': device['device_name'],
                        'device_type': device_type,
                        'status': status,
                        'manufacturing_date': manufacturing_date,
                        'hardware_eol_date': hardware_eol_date,
                        'device_age_years': round(device_age_years, 1),
                        'days_until_eol': days_until_eol,
                        'message': f'Device will reach EOL in {days_until_eol} days',
                        'action_required': 'Plan for device replacement',
                        'recycling_link': self._get_recycling_link(device_type)
                    }

                else:
                    # Device is current
                    status = 'current'
                    return {
                        'device_ip': device_ip,
                        'device_name': device['device_name'],
                        'device_type': device_type,
                        'status': status,
                        'manufacturing_date': manufacturing_date,
                        'hardware_eol_date': hardware_eol_date,
                        'device_age_years': round(device_age_years, 1),
                        'days_until_eol': days_until_eol,
                        'message': f'Device is current (EOL in {days_until_eol} days)',
                        'action_required': None
                    }

            else:
                # No EOL date set - estimate based on device type
                default_support = self.default_support_periods.get(device_type, 5)
                estimated_eol = mfg_date + timedelta(days=default_support * 365.25)
                days_until_estimated_eol = (estimated_eol - today).days

                # Check if device might be past estimated EOL
                if days_until_estimated_eol < 0:
                    status = 'possibly_past_eol'

                    if generate_alerts:
                        self._generate_eol_alert(
                            device_ip,
                            'medium',
                            f"Device '{device['device_name']}' may be past typical EOL "
                            f"(estimated {abs(days_until_estimated_eol)} days ago). "
                            f"Set exact EOL date or verify support status.",
                            {'estimated_age_years': device_age_years}
                        )

                    return {
                        'device_ip': device_ip,
                        'device_name': device['device_name'],
                        'device_type': device_type,
                        'status': status,
                        'manufacturing_date': manufacturing_date,
                        'hardware_eol_date': None,
                        'device_age_years': round(device_age_years, 1),
                        'estimated_eol_date': estimated_eol.date().isoformat(),
                        'message': f'Device may be past typical {default_support}-year support period',
                        'action_required': 'Verify support status and set EOL date',
                        'recycling_link': self._get_recycling_link(device_type)
                    }

                else:
                    status = 'eol_date_not_set'
                    return {
                        'device_ip': device_ip,
                        'device_name': device['device_name'],
                        'device_type': device_type,
                        'status': status,
                        'manufacturing_date': manufacturing_date,
                        'hardware_eol_date': None,
                        'device_age_years': round(device_age_years, 1),
                        'estimated_eol_date': estimated_eol.date().isoformat(),
                        'message': f'Set EOL date for accurate tracking (estimated: {estimated_eol.date()})',
                        'action_required': 'Set hardware EOL date in device details'
                    }

        except Exception as e:
            logger.error(f"Error checking device lifecycle: {e}")
            return {'error': str(e)}

    def check_all_devices_lifecycle(self) -> List[Dict]:
        """
        Check lifecycle status for all devices.

        Returns:
            List of lifecycle status dicts
        """
        try:
            cursor = self.db.conn.cursor()

            cursor.execute("""
                SELECT device_ip
                FROM devices
                WHERE manufacturing_date IS NOT NULL
            """)

            devices = cursor.fetchall()
            results = []

            for device in devices:
                status = self.check_device_lifecycle(device['device_ip'], generate_alerts=False)
                if 'error' not in status:
                    results.append(status)

            return results

        except Exception as e:
            logger.error(f"Error checking all devices lifecycle: {e}")
            return []

    def _generate_eol_alert(self, device_ip: str, severity: str,
                           explanation: str, indicators: Dict):
        """Generate hardware EOL alert."""
        try:
            from alerts.alert_manager import alert_manager

            alert_manager.create_alert(
                device_ip=device_ip,
                severity=severity,
                anomaly_score=0.0,
                explanation=f"[Hardware EOL] {explanation}",
                top_features=json.dumps(indicators),
                category='hardware_lifecycle'
            )
            logger.warning(f"Hardware EOL alert generated for {device_ip}: {explanation}")

        except Exception as e:
            logger.error(f"Failed to generate EOL alert: {e}")

    def _get_recycling_link(self, device_type: str) -> str:
        """Get recycling resource link for device type."""
        return self.recycling_resources.get(device_type, self.recycling_resources['default'])

    def add_manufacturer_eol_data(self, manufacturer: str, model: str,
                                   device_type: str, eol_date: str,
                                   replacement_model: Optional[str] = None,
                                   recycling_info: Optional[str] = None) -> bool:
        """
        Add or update manufacturer EOL database entry.

        Args:
            manufacturer: Device manufacturer
            model: Device model
            device_type: Type of device
            eol_date: End-of-life date (YYYY-MM-DD)
            replacement_model: Recommended replacement model
            recycling_info: Recycling instructions

        Returns:
            True if successful
        """
        try:
            cursor = self.db.conn.cursor()

            cursor.execute("""
                INSERT INTO manufacturer_eol_database (
                    manufacturer, model, device_type, eol_date,
                    replacement_model, recycling_info
                ) VALUES (?, ?, ?, ?, ?, ?)
                ON CONFLICT(manufacturer, model) DO UPDATE SET
                    eol_date = excluded.eol_date,
                    replacement_model = excluded.replacement_model,
                    recycling_info = excluded.recycling_info
            """, (manufacturer, model, device_type, eol_date, replacement_model, recycling_info))

            self.db.conn.commit()
            logger.info(f"Added EOL data for {manufacturer} {model}")
            return True

        except Exception as e:
            logger.error(f"Failed to add manufacturer EOL data: {e}")
            return False

    def get_manufacturer_eol_data(self, manufacturer: str, model: str) -> Optional[Dict]:
        """
        Get manufacturer EOL data for a specific device.

        Args:
            manufacturer: Device manufacturer
            model: Device model

        Returns:
            EOL data dict or None
        """
        try:
            cursor = self.db.conn.cursor()

            cursor.execute("""
                SELECT *
                FROM manufacturer_eol_database
                WHERE manufacturer = ? AND model = ?
            """, (manufacturer, model))

            result = cursor.fetchone()
            if result:
                return dict(result)
            return None

        except Exception as e:
            logger.error(f"Failed to get manufacturer EOL data: {e}")
            return None


# Global instance
_lifecycle_manager = None


def get_lifecycle_manager(db_manager):
    """Get global hardware lifecycle manager instance."""
    global _lifecycle_manager
    if _lifecycle_manager is None:
        _lifecycle_manager = HardwareLifecycleManager(db_manager)
    return _lifecycle_manager
