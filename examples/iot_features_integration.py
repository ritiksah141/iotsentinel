#!/usr/bin/env python3
"""
IoT Features Integration Example

Demonstrates how to integrate all new IoT-specific features into the IoTSentinel system.
This example can be used as a template for updating your main orchestrator.
"""

import logging
from datetime import datetime
from database.db_manager import DatabaseManager

# Import all IoT feature modules
from utils.iot_device_intelligence import get_intelligence
from utils.iot_protocol_analyzer import get_protocol_analyzer
from utils.iot_threat_detector import get_threat_detector
from utils.iot_features import (
    get_smart_home_manager,
    get_privacy_monitor,
    get_network_segmentation,
    get_firmware_manager
)

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class IoTFeaturesOrchestrator:
    """Orchestrates all IoT-specific features."""

    def __init__(self, db_path: str = 'data/database/iotsentinel.db'):
        """Initialize the orchestrator."""
        self.db = DatabaseManager(db_path)

        # Initialize all IoT feature modules
        self.intelligence = get_intelligence(self.db)
        self.protocol_analyzer = get_protocol_analyzer(self.db)
        self.threat_detector = get_threat_detector(self.db)
        self.smart_home = get_smart_home_manager(self.db)
        self.privacy_monitor = get_privacy_monitor(self.db)
        self.segmentation = get_network_segmentation(self.db)
        self.firmware_manager = get_firmware_manager(self.db)

        logger.info("IoT Features Orchestrator initialized successfully")

    def process_new_device(self, device_ip: str, mac_address: str, hostname: str = None):
        """
        Complete workflow for processing a newly discovered device.

        Args:
            device_ip: Device IP address
            mac_address: Device MAC address
            hostname: Device hostname (optional)
        """
        logger.info(f"Processing new device: {device_ip}")

        # 1. Start provisioning workflow
        provision_id = self.firmware_manager.track_provisioning(device_ip, mac_address)
        logger.info(f"Started provisioning workflow: {provision_id}")

        # 2. Fingerprint the device (if we have signals)
        # This would typically come from network scanning
        fingerprint = self.intelligence.fingerprint_device(
            device_ip=device_ip,
            http_user_agent=None,  # Would be extracted from HTTP traffic
            open_ports=[],  # Would come from port scan
            services=[],  # Would come from service detection
            mdns_services=[],  # Would come from mDNS scanning
            upnp_services=[]  # Would come from UPnP scanning
        )

        # 3. Get device classification from existing system
        cursor = self.db.conn.cursor()
        cursor.execute("SELECT device_type, manufacturer, model FROM devices WHERE device_ip = ?", (device_ip,))
        device_info = cursor.fetchone()

        if device_info:
            device_type = device_info['device_type']
            manufacturer = device_info['manufacturer']

            # 4. Check for vulnerabilities
            vulnerabilities = self.intelligence.check_vulnerabilities(device_ip)
            if vulnerabilities:
                logger.warning(f"Found {len(vulnerabilities)} vulnerabilities for {device_ip}")

            # 5. Get network segmentation recommendation
            recommendation = self.segmentation.recommend_segment(device_ip, device_type)
            logger.info(f"Segmentation recommendation: {recommendation['segment']} (VLAN {recommendation['vlan_id']})")

            # 6. Detect smart home hub
            # Note: Would need actual port scan results
            hub_type = self.smart_home.detect_smart_hub(device_ip, [], [])
            if hub_type:
                logger.info(f"Detected smart home hub: {hub_type}")

            # 7. Update provisioning status
            self.firmware_manager.update_provisioning_status(device_ip, 'identified')

        return {
            'device_ip': device_ip,
            'fingerprint': fingerprint,
            'vulnerabilities': vulnerabilities if device_info else [],
            'segmentation_recommendation': recommendation if device_info else None,
            'provision_id': provision_id
        }

    def analyze_packet(self, packet):
        """
        Analyze a packet for IoT protocols.

        Args:
            packet: Scapy packet object

        Returns:
            Dict with analysis results
        """
        # Check for IoT protocols
        protocol_info = self.protocol_analyzer.analyze_packet(packet)

        if protocol_info:
            logger.info(f"Detected {protocol_info['protocol']} traffic from {protocol_info['device_ip']}")

            # Track cloud connections if destination is cloud provider
            if protocol_info.get('dest_domain'):
                self.privacy_monitor.track_cloud_connection(
                    device_ip=protocol_info['device_ip'],
                    dest_ip=protocol_info.get('dest_ip', ''),
                    dest_domain=protocol_info.get('dest_domain', ''),
                    bytes_uploaded=protocol_info.get('bytes_sent', 0),
                    bytes_downloaded=protocol_info.get('bytes_received', 0),
                    encrypted=protocol_info.get('is_encrypted', False)
                )

                # Check for ecosystem
                ecosystem = self.smart_home.detect_ecosystem(
                    protocol_info['device_ip'],
                    protocol_info['dest_domain']
                )
                if ecosystem:
                    logger.info(f"Device belongs to {ecosystem} ecosystem")

        return protocol_info

    def run_periodic_threat_scan(self):
        """
        Run periodic threat detection scans on all devices.
        Should be scheduled to run every 10-15 minutes.
        """
        logger.info("Starting periodic threat scan...")

        cursor = self.db.conn.cursor()
        cursor.execute("SELECT device_ip, device_name FROM devices")
        devices = cursor.fetchall()

        threat_count = 0

        for device in devices:
            device_ip = device['device_ip']

            # 1. Check for default credentials (critical security risk)
            default_creds = self.threat_detector.check_default_credentials(device_ip)
            if default_creds:
                logger.critical(f"DEFAULT CREDENTIALS RISK on {device['device_name']} ({device_ip})")
                threat_count += 1

            # 2. Check for Mirai infection
            mirai = self.threat_detector.detect_mirai_infection(device_ip)
            if mirai:
                logger.critical(f"MIRAI DETECTED on {device['device_name']} ({device_ip})")
                threat_count += 1

            # 3. Check for DDoS participation
            ddos = self.threat_detector.detect_ddos_participation(device_ip)
            if ddos:
                logger.critical(f"DDoS ATTACK from {device['device_name']} ({device_ip})")
                threat_count += 1

            # 4. Check for C2 communication
            c2 = self.threat_detector.detect_c2_communication(device_ip)
            if c2:
                logger.critical(f"C2 COMMUNICATION detected on {device['device_name']} ({device_ip})")
                threat_count += 1

            # 5. Check for UPnP exploitation
            upnp_exploit = self.threat_detector.detect_upnp_exploitation(device_ip)
            if upnp_exploit:
                logger.critical(
                    f"UPnP EXPLOITATION on {device['device_name']} ({device_ip}): "
                    f"CallStranger or similar exploit detected"
                )
                threat_count += 1

            # 6. Check for behavioral anomalies (if baselines exist)
            behavioral_anomaly = self.threat_detector.detect_behavioral_anomaly(device_ip)
            if behavioral_anomaly:
                logger.warning(
                    f"BEHAVIORAL ANOMALY on {device['device_name']} ({device_ip}): "
                    f"{len(behavioral_anomaly['anomalies'])} metrics deviated"
                )
                threat_count += 1

        logger.info(f"Threat scan complete. Found {threat_count} threats.")
        return threat_count

    def run_periodic_vulnerability_scan(self):
        """
        Run periodic vulnerability scans on all devices.
        Should be scheduled to run daily.
        """
        logger.info("Starting periodic vulnerability scan...")

        cursor = self.db.conn.cursor()
        cursor.execute("SELECT device_ip FROM devices")
        devices = cursor.fetchall()

        vuln_count = 0

        for device in devices:
            vulnerabilities = self.intelligence.check_vulnerabilities(device['device_ip'])
            vuln_count += len(vulnerabilities)

        logger.info(f"Vulnerability scan complete. Found {vuln_count} vulnerabilities.")
        return vuln_count

    def run_periodic_firmware_check(self):
        """
        Check for firmware updates on all devices.
        Should be scheduled to run weekly.
        """
        logger.info("Starting firmware update check...")

        cursor = self.db.conn.cursor()
        cursor.execute("""
            SELECT d.device_ip, d.firmware_version, d.manufacturer, d.model
            FROM devices d
            WHERE d.firmware_version IS NOT NULL
        """)
        devices = cursor.fetchall()

        updates_available = 0

        for device in devices:
            status = self.firmware_manager.check_firmware_status(
                device_ip=device['device_ip'],
                current_firmware=device['firmware_version'],
                vendor=device['manufacturer'],
                model=device['model']
            )

            if status.get('update_available'):
                logger.info(f"Update available for {device['device_ip']}: {status['latest']}")
                updates_available += 1

        logger.info(f"Firmware check complete. {updates_available} updates available.")
        return updates_available

    def run_baseline_learning(self, learning_period_days: int = 7, force_relearn: bool = False):
        """
        Learn behavioral baselines for all devices.
        Should be run once after 7 days of monitoring, then weekly to update.

        Args:
            learning_period_days: Days of historical data to analyze
            force_relearn: Force relearning even if baselines exist
        """
        logger.info(f"Starting baseline learning ({learning_period_days} day period)...")

        cursor = self.db.conn.cursor()
        cursor.execute("SELECT device_ip, device_name FROM devices")
        devices = cursor.fetchall()

        learned_count = 0
        insufficient_data_count = 0
        skipped_count = 0

        for device in devices:
            # Check if baselines already exist (unless force_relearn)
            if not force_relearn:
                cursor.execute("""
                    SELECT COUNT(*) as baseline_count
                    FROM device_behavior_baselines
                    WHERE device_ip = ?
                """, (device['device_ip'],))

                if cursor.fetchone()['baseline_count'] > 0:
                    logger.debug(f"Skipping {device['device_ip']} - baselines already exist")
                    skipped_count += 1
                    continue

            result = self.intelligence.learn_baseline(
                device_ip=device['device_ip'],
                learning_period_days=learning_period_days
            )

            if result.get('status') == 'success':
                logger.info(
                    f"Learned baselines for {device['device_name']} ({device['device_ip']}): "
                    f"{len(result['baselines'])} metrics"
                )
                learned_count += 1
            elif result.get('status') == 'insufficient_data':
                insufficient_data_count += 1

        logger.info(
            f"Baseline learning complete. Learned: {learned_count}, "
            f"Skipped: {skipped_count}, Insufficient data: {insufficient_data_count}"
        )
        return {
            'learned': learned_count,
            'skipped': skipped_count,
            'insufficient_data': insufficient_data_count
        }

    def get_dashboard_summary(self) -> dict:
        """
        Get comprehensive summary for dashboard display.

        Returns:
            Dict with all IoT security metrics
        """
        cursor = self.db.conn.cursor()

        # Get device counts by type
        cursor.execute("""
            SELECT device_type, COUNT(*) as count
            FROM devices
            GROUP BY device_type
        """)
        device_counts = {row['device_type']: row['count'] for row in cursor.fetchall()}

        # Get vulnerability summary
        cursor.execute("""
            SELECT severity, COUNT(*) as count
            FROM device_vulnerabilities_detected dvd
            JOIN iot_vulnerabilities iv ON dvd.cve_id = iv.cve_id
            WHERE dvd.status = 'active'
            GROUP BY severity
        """)
        vuln_summary = {row['severity']: row['count'] for row in cursor.fetchall()}

        # Get protocol usage
        protocol_summary = self.protocol_analyzer.get_protocol_summary()

        # Get threat summary
        threat_summary = self.threat_detector.get_threat_summary(hours=24)

        # Get segmentation status
        cursor.execute("""
            SELECT COUNT(DISTINCT device_ip) as segmented_devices
            FROM device_segments
            WHERE current_segment = 1
        """)
        segmented_count = cursor.fetchone()['segmented_devices']

        cursor.execute("SELECT COUNT(*) as total FROM devices")
        total_devices = cursor.fetchone()['total']

        # Get privacy concerns
        cursor.execute("""
            SELECT privacy_concern_level, COUNT(DISTINCT device_ip) as count
            FROM cloud_connections
            WHERE privacy_concern_level IN ('high', 'critical')
            GROUP BY privacy_concern_level
        """)
        privacy_concerns = {row['privacy_concern_level']: row['count'] for row in cursor.fetchall()}

        return {
            'timestamp': datetime.now().isoformat(),
            'device_counts': device_counts,
            'total_devices': total_devices,
            'vulnerabilities': vuln_summary,
            'protocols': protocol_summary,
            'threats': threat_summary,
            'segmentation': {
                'segmented_devices': segmented_count,
                'unsegmented_devices': total_devices - segmented_count,
                'percentage_segmented': (segmented_count / total_devices * 100) if total_devices > 0 else 0
            },
            'privacy_concerns': privacy_concerns
        }


def main():
    """Example usage of IoT Features Orchestrator."""

    # Initialize orchestrator
    orchestrator = IoTFeaturesOrchestrator()

    # Example 1: Process a new device
    print("\n=== Example 1: Processing New Device ===")
    result = orchestrator.process_new_device(
        device_ip='192.168.1.50',
        mac_address='AA:BB:CC:DD:EE:FF',
        hostname='ring-doorbell'
    )
    print(f"Provisioning ID: {result['provision_id']}")

    # Example 2: Run threat scan
    print("\n=== Example 2: Running Threat Scan ===")
    threat_count = orchestrator.run_periodic_threat_scan()
    print(f"Threats detected: {threat_count}")

    # Example 3: Run vulnerability scan
    print("\n=== Example 3: Running Vulnerability Scan ===")
    vuln_count = orchestrator.run_periodic_vulnerability_scan()
    print(f"Vulnerabilities found: {vuln_count}")

    # Example 4: Get dashboard summary
    print("\n=== Example 4: Dashboard Summary ===")
    summary = orchestrator.get_dashboard_summary()
    print(f"Total devices: {summary['total_devices']}")
    print(f"Segmentation: {summary['segmentation']['percentage_segmented']:.1f}% devices segmented")
    print(f"Active threats: {summary['threats']['total_threats']}")

    print("\n✅ IoT Features integration examples completed!")


if __name__ == '__main__':
    main()
