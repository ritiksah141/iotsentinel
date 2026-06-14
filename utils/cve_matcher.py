#!/usr/bin/env python3
"""
CVE Matcher for IoTSentinel

Matches CVEs from NVD to devices in the database using fuzzy matching.
Parses CPE (Common Platform Enumeration) and matches to device vendor/model/firmware.
"""

import logging
from typing import Dict, Any, Optional, List, Tuple
from fuzzywuzzy import fuzz
from datetime import datetime

logger = logging.getLogger(__name__)


class CVEMatcher:
    """
    Matches CVEs to IoT devices using fuzzy matching.

    Parses CPE strings and matches against device vendor, model, and firmware.
    """

    def __init__(
        self,
        db_path: str = 'data/iot_monitor.db',
        match_threshold: float = 0.85,
        db_manager=None,
    ):
        """
        Initialize CVE matcher.

        Args:
            db_path: Path to SQLite database (used when db_manager is not provided)
            match_threshold: Fuzzy match threshold (0.0-1.0)
            db_manager: DatabaseManager instance (preferred over db_path)
        """
        self.match_threshold = match_threshold

        if db_manager is not None:
            self.db_manager = db_manager
            self.db_path = None
        else:
            # Create a lightweight DatabaseManager from path so all methods work
            from database.db_manager import DatabaseManager
            self.db_manager = DatabaseManager(db_path=db_path)
            self.db_path = db_path

        logger.info(f"CVE matcher initialized (threshold: {match_threshold})")

    def parse_cpe(self, cpe_string: str) -> Optional[Dict[str, str]]:
        """
        Parse CPE (Common Platform Enumeration) string.

        CPE 2.3 format:
        cpe:2.3:part:vendor:product:version:update:edition:language:sw_edition:target_sw:target_hw:other

        Example:
        cpe:2.3:h:google:nest_cam:1.2.3:*:*:*:*:*:*:*

        Args:
            cpe_string: CPE string

        Returns:
            Dictionary with parsed CPE components or None
        """
        try:
            parts = cpe_string.split(':')

            if len(parts) < 5 or parts[0] != 'cpe':
                logger.warning(f"Invalid CPE format: {cpe_string}")
                return None

            # Extract components
            cpe_data = {
                'cpe_version': parts[1] if len(parts) > 1 else '',
                'part': parts[2] if len(parts) > 2 else '',  # h=hardware, o=os, a=application
                'vendor': parts[3].replace('_', ' ') if len(parts) > 3 else '',
                'product': parts[4].replace('_', ' ') if len(parts) > 4 else '',
                'version': parts[5] if len(parts) > 5 else '',
                'update': parts[6] if len(parts) > 6 else '',
            }

            # Clean wildcards
            for key in cpe_data:
                if cpe_data[key] == '*' or cpe_data[key] == '-':
                    cpe_data[key] = ''

            return cpe_data

        except Exception as e:
            logger.error(f"Error parsing CPE {cpe_string}: {e}")
            return None

    def fuzzy_match_score(
        self,
        str1: str,
        str2: str,
        partial: bool = True
    ) -> float:
        """
        Calculate fuzzy match score between two strings.

        Args:
            str1: First string
            str2: Second string
            partial: Use partial matching

        Returns:
            Match score (0.0-1.0)
        """
        if not str1 or not str2:
            return 0.0

        # Normalize strings
        str1_lower = str1.lower().strip()
        str2_lower = str2.lower().strip()

        # Exact match
        if str1_lower == str2_lower:
            return 1.0

        # Use fuzzywuzzy
        if partial:
            score = fuzz.partial_ratio(str1_lower, str2_lower)
        else:
            score = fuzz.ratio(str1_lower, str2_lower)

        return score / 100.0

    def match_cve_to_device(
        self,
        cve: Dict[str, Any],
        device: Dict[str, Any]
    ) -> Tuple[bool, float, str]:
        """
        Check if CVE matches a specific device.

        Args:
            cve: CVE dictionary with cpe_list
            device: Device dictionary with vendor, model, firmware_version

        Returns:
            Tuple of (is_match, confidence_score, matched_cpe)
        """
        device_vendor = device.get('vendor', '').lower().strip()
        device_manufacturer = device.get('manufacturer', '').lower().strip()
        device_model = device.get('model', '').lower().strip()
        device_firmware = device.get('firmware_version', '').lower().strip()

        # Combine vendor and manufacturer for better matching
        device_vendor_combined = ' '.join(filter(None, [device_vendor, device_manufacturer]))

        best_match_score = 0.0
        best_matched_cpe = ''

        # Check each CPE in the CVE
        for cpe_string in cve.get('cpe_list', []):
            cpe = self.parse_cpe(cpe_string)

            if not cpe:
                continue

            # Only match hardware (h) and OS (o) types
            if cpe['part'] not in ['h', 'o']:
                continue

            # Calculate vendor match score
            vendor_score = max(
                self.fuzzy_match_score(cpe['vendor'], device_vendor),
                self.fuzzy_match_score(cpe['vendor'], device_manufacturer),
                self.fuzzy_match_score(cpe['vendor'], device_vendor_combined)
            )

            # Calculate product match score
            product_score = self.fuzzy_match_score(cpe['product'], device_model)

            # Calculate version match score (if both have versions)
            version_score = 1.0  # Default to match if no version specified
            if cpe['version'] and device_firmware:
                version_score = self.fuzzy_match_score(cpe['version'], device_firmware, partial=False)

            # Calculate weighted overall score
            # Vendor and product are most important
            overall_score = (
                vendor_score * 0.4 +
                product_score * 0.4 +
                version_score * 0.2
            )

            # Update best match
            if overall_score > best_match_score:
                best_match_score = overall_score
                best_matched_cpe = cpe_string

        # Determine if it's a match
        is_match = best_match_score >= self.match_threshold

        return is_match, best_match_score, best_matched_cpe

    def find_vulnerable_devices(
        self,
        cve_list: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """
        Find devices vulnerable to given CVEs.

        Args:
            cve_list: List of CVE dictionaries

        Returns:
            List of matches with device and CVE information
        """
        matches = []

        try:
            # Get all devices from database
            conn = self.db_manager.conn

            cursor = conn.cursor()

            cursor.execute('''
                SELECT ip_address, hostname, vendor, manufacturer, model,
                       firmware_version, device_type
                FROM devices
            ''')

            devices = [dict(row) for row in cursor.fetchall()]

            logger.info(f"Matching {len(cve_list)} CVEs against {len(devices)} devices")

            # Match each CVE against each device
            for cve in cve_list:
                for device in devices:
                    is_match, confidence, matched_cpe = self.match_cve_to_device(cve, device)

                    if is_match:
                        match_info = {
                            'device_ip': device['ip_address'],
                            'device_hostname': device['hostname'],
                            'device_vendor': device.get('vendor', device.get('manufacturer', '')),
                            'device_model': device.get('model', ''),
                            'cve_id': cve['cve_id'],
                            'cvss_score': cve['cvss_score'],
                            'severity': cve['severity'],
                            'description': cve['description'],
                            'matched_cpe': matched_cpe,
                            'confidence': confidence,
                            'detected_at': datetime.now().isoformat()
                        }

                        matches.append(match_info)

                        logger.info(
                            f"Match found: {device['ip_address']} ({device.get('model', 'unknown')}) "
                            f"<-> {cve['cve_id']} (confidence: {confidence:.2f})"
                        )

            logger.info(f"Found {len(matches)} CVE-device matches")
            return matches

        except Exception as e:
            logger.error(f"Error finding vulnerable devices: {e}")
            return []

    def save_matches_to_db(self, matches: List[Dict[str, Any]]) -> int:
        """
        Save CVE matches to database.

        Args:
            matches: List of match dictionaries

        Returns:
            Number of matches saved
        """
        if not matches:
            return 0

        try:
            conn = self.db_manager.conn
            cursor = conn.cursor()

            saved_count = 0

            for match in matches:
                # risk_score = cvss_score * confidence (both in device_vulnerabilities_detected schema)
                risk_score = round(
                    float(match.get('cvss_score', 0.0) or 0.0) *
                    float(match.get('confidence', 0.8) or 0.8),
                    2,
                )
                # Use INSERT OR IGNORE + UPDATE so UNIQUE(device_ip, cve_id) is respected
                cursor.execute('''
                    INSERT OR IGNORE INTO device_vulnerabilities_detected
                    (device_ip, cve_id, detected_date, status, risk_score, auto_detected)
                    VALUES (?, ?, datetime('now'), 'active', ?, 1)
                ''', (match['device_ip'], match['cve_id'], risk_score))

                if cursor.rowcount == 0:
                    # Row already existed — refresh risk_score and last_checked
                    cursor.execute('''
                        UPDATE device_vulnerabilities_detected
                        SET risk_score = ?, last_checked = datetime('now')
                        WHERE device_ip = ? AND cve_id = ?
                    ''', (risk_score, match['device_ip'], match['cve_id']))

                saved_count += 1

            conn.commit()

            logger.info(f"Saved {saved_count} CVE matches to database")
            return saved_count

        except Exception as e:
            logger.error(f"Error saving matches to database: {e}")
            return 0

    def get_device_vulnerabilities(
        self,
        device_ip: str
    ) -> List[Dict[str, Any]]:
        """
        Get all vulnerabilities for a specific device.

        Args:
            device_ip: Device IP address

        Returns:
            List of vulnerability dictionaries
        """
        try:
            conn = self.db_manager.conn

            cursor = conn.cursor()

            cursor.execute('''
                SELECT dvd.device_ip, dvd.cve_id, dvd.detected_date,
                       dvd.status, dvd.risk_score, dvd.auto_detected,
                       iv.severity, iv.cvss_score, iv.description, iv.title,
                       iv.exploit_available, iv.patch_available
                FROM device_vulnerabilities_detected dvd
                JOIN iot_vulnerabilities iv ON dvd.cve_id = iv.cve_id
                WHERE dvd.device_ip = ?
                ORDER BY iv.cvss_score DESC
            ''', (device_ip,))

            vulns = [dict(row) for row in cursor.fetchall()]

            return vulns

        except Exception as e:
            logger.error(f"Error getting device vulnerabilities: {e}")
            return []

    def calculate_risk_score(
        self,
        device_ip: str,
        device_criticality: float = 1.0
    ) -> float:
        """
        Calculate aggregate risk score for a device.

        Args:
            device_ip: Device IP address
            device_criticality: Device criticality multiplier (1.0-3.0)

        Returns:
            Risk score (0.0-10.0)
        """
        vulns = self.get_device_vulnerabilities(device_ip)

        if not vulns:
            return 0.0

        # Calculate weighted average of CVSS scores
        total_score = 0.0
        total_weight = 0.0

        for vuln in vulns:
            cvss = vuln.get('cvss_score', 0.0)
            confidence = vuln.get('confidence', 1.0)

            # Weight by confidence
            weight = confidence
            total_score += cvss * weight
            total_weight += weight

        if total_weight == 0:
            return 0.0

        # Calculate average and apply criticality multiplier
        avg_score = total_score / total_weight
        risk_score = min(avg_score * device_criticality, 10.0)

        return round(risk_score, 2)


# Global CVE matcher instance
_cve_matcher = None


def get_cve_matcher(db_path: str = 'data/iot_monitor.db', db_manager=None) -> CVEMatcher:
    """
    Get global CVE matcher instance.

    Args:
        db_path: Path to database (used only when db_manager is not provided)
        db_manager: DatabaseManager instance (preferred)

    Returns:
        CVEMatcher instance
    """
    global _cve_matcher
    if _cve_matcher is None:
        _cve_matcher = CVEMatcher(db_path=db_path, db_manager=db_manager)
    return _cve_matcher
