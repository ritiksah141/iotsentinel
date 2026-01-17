#!/usr/bin/env python3
"""
IoTSentinel System Orchestrator

Main entry point that coordinates all system components:
- Zeek log parsing
- ML inference engine
- ARP network scanning
- Alerting system (email notifications + scheduled reports)
- Web dashboard (to be run separately)

Designed for systemd service deployment on Raspberry Pi OS.
"""

import logging
import signal
import sys
import time
import threading
import subprocess
import psutil
from pathlib import Path
from datetime import datetime, timedelta

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent))

from config.config_manager import config
from capture.zeek_log_parser import ZeekLogParser
from ml.inference_engine import InferenceEngine
from database.db_manager import DatabaseManager
from config.init_database import init_database as init_db
from services.hardware_monitor import HardwareMonitor, IS_RPI
from utils.arp_scanner import ARPScanner, SCAPY_AVAILABLE

# Import IoT-specific feature modules
from utils.iot_device_intelligence import get_intelligence
from utils.iot_protocol_analyzer import get_protocol_analyzer
from utils.iot_threat_detector import get_threat_detector
from utils.iot_features import (
    get_smart_home_manager,
    get_privacy_monitor,
    get_network_segmentation,
    get_firmware_manager
)

# Import sustainability and lifecycle features
from utils.sustainability_calculator import get_sustainability_calculator
from utils.hardware_lifecycle import HardwareLifecycleManager

# Import innovation feature modules
from utils.auto_provisioner import get_auto_provisioner
from utils.mdns_listener import get_mdns_manager
from utils.upnp_scanner import get_upnp_scanner
from utils.active_scanner import get_active_scanner
from utils.vulnerability_sync import get_vulnerability_sync
from utils.network_security_scorer import get_security_scorer
import os
from dotenv import load_dotenv

# Configure logging
log_dir = Path(config.get('logging', 'log_dir'))
log_dir.mkdir(parents=True, exist_ok=True)

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(log_dir / 'orchestrator.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)


class IoTSentinelOrchestrator:
    """
    Main system orchestrator for IoTSentinel.

    Coordinates all system components in a multi-threaded architecture:
    - Thread 1: Zeek log monitoring and parsing
    - Thread 2: ML inference pipeline
    - Thread 3: Daily database cleanup
    - Thread 4: System health watchdog
    - Thread 5: Hardware monitor (Pi only)
    - Thread 6: ARP network scanner (if available)
    - Thread 7: IoT threat detection (every 10 minutes)
    - Thread 8: IoT vulnerability scanning (daily)
    - Thread 9: IoT firmware checking (weekly)
    - Background: Alerting system with scheduled reports

    IoT-specific features:
    - Device intelligence (fingerprinting, baseline learning, vulnerabilities)
    - Protocol analysis (MQTT, CoAP, Zigbee, Z-Wave, mDNS)
    - Threat detection (Mirai, C2, DDoS, default credentials, behavioral anomalies)
    - Smart home integration (hub detection, ecosystem identification)
    - Privacy monitoring (cloud connections tracking)
    - Network segmentation (AI-based recommendations)
    - Firmware management (update tracking, EOL detection)
    """

    def __init__(self):
        """Initialize system components."""
        self._ensure_database_initialized()

        # Core database connection
        self.db = DatabaseManager(config.get('database', 'path'))

        # Initialize alerting system
        self.alerting = self._init_alerting_system()

        # Initialize parser
        self.parser = ZeekLogParser()

        # Initialize inference engine with alerting
        self.inference_engine = InferenceEngine(alerting_system=self.alerting)

        # Initialize ARP scanner if available
        self.arp_scanner = None
        if SCAPY_AVAILABLE:
            try:
                self.arp_scanner = ARPScanner()
                logger.info("ARP scanner initialized")
            except Exception as e:
                logger.error(f"Failed to initialize ARP scanner: {e}")
                self.arp_scanner = None
        else:
            logger.warning("ARP scanner disabled (scapy not available)")
            logger.info("Install scapy for device discovery: pip install scapy")

        # Initialize IoT-specific feature modules
        try:
            self.intelligence = get_intelligence(self.db)
            self.protocol_analyzer = get_protocol_analyzer(self.db)
            self.threat_detector = get_threat_detector(self.db)
            self.smart_home = get_smart_home_manager(self.db)
            self.privacy_monitor = get_privacy_monitor(self.db)
            self.segmentation = get_network_segmentation(self.db)
            self.firmware_manager = get_firmware_manager(self.db)

            # Initialize sustainability and lifecycle features
            self.sustainability_calc = get_sustainability_calculator(self.db)
            self.lifecycle_manager = HardwareLifecycleManager(self.db)

            logger.info("IoT feature modules initialized (intelligence, protocols, threats, smart home, privacy, segmentation, firmware, sustainability, lifecycle)")
        except Exception as e:
            logger.error(f"Failed to initialize IoT feature modules: {e}")
            # Continue without IoT features
            self.intelligence = None
            self.protocol_analyzer = None
            self.threat_detector = None
            self.smart_home = None
            self.privacy_monitor = None
            self.segmentation = None
            self.firmware_manager = None
            self.sustainability_calc = None
            self.lifecycle_manager = None

        # Initialize innovation feature modules
        self.auto_provisioner = None
        self.mdns_manager = None
        self.upnp_scanner = None
        self.active_scanner = None
        self.vuln_sync = None
        self.security_scorer = None

        try:
            # Load environment variables
            load_dotenv()

            db_path = config.get('database', 'path')

            # Always initialize auto-provisioner and security scorer
            self.auto_provisioner = get_auto_provisioner(db_path=db_path)
            self.security_scorer = get_security_scorer(db_path=db_path)
            logger.info("Auto-provisioner and security scorer initialized")

            # Initialize NVD vulnerability sync if enabled
            if config.get('nvd', {}).get('enabled', True):
                # Read API key from environment variable
                nvd_api_key = os.getenv('NVD_API_KEY', config.get('nvd', {}).get('api_key', ''))
                self.vuln_sync = get_vulnerability_sync(
                    db_path=db_path,
                    nvd_api_key=nvd_api_key if nvd_api_key else None
                )
                logger.info(f"NVD vulnerability sync initialized (API key: {'provided' if nvd_api_key else 'not provided'})")

            # Initialize discovery features based on mode
            discovery_mode = config.get('discovery', {}).get('mode', 'passive')

            # Device discovered callback
            def on_device_discovered(device_info):
                if self.auto_provisioner:
                    self.auto_provisioner.provision_device(
                        device_info=device_info,
                        discovery_method=device_info.get('discovery_method', 'unknown')
                    )

            # Initialize passive discovery (mDNS/UPnP)
            if discovery_mode in ['passive', 'hybrid']:
                self.mdns_manager = get_mdns_manager(on_device_discovered=on_device_discovered)
                self.upnp_scanner = get_upnp_scanner(on_device_discovered=on_device_discovered)
                logger.info(f"Passive discovery initialized (mDNS, UPnP)")

            # Initialize active discovery (nmap) if enabled
            if discovery_mode in ['active', 'hybrid'] or config.get('discovery', {}).get('active_scan_enabled', False):
                self.active_scanner = get_active_scanner(on_device_discovered=on_device_discovered)
                logger.info("Active scanner initialized (nmap)")

            logger.info("Innovation features initialized successfully")

        except Exception as e:
            logger.error(f"Failed to initialize innovation features: {e}")
            # Continue without innovation features

        # Threading control
        self.running = False
        self.threads = []
        self.hardware_monitor = None

        logger.info("IoTSentinel orchestrator initialized")

    def _init_alerting_system(self):
        """Initialize the alerting system if available."""
        try:
            from alerts.integration import AlertingSystem

            alerting = AlertingSystem(self.db, config)

            if alerting.is_enabled:
                logger.info("Alerting system initialized")
                status = alerting.get_status()
                logger.info(f"  - Email notifications: {'enabled' if status['components']['email_handler'] else 'disabled'}")
                logger.info(f"  - Report scheduler: {'ready' if status['components']['report_scheduler'] else 'disabled'}")
                return alerting
            else:
                logger.info("Alerting system disabled in configuration")
                return None

        except ImportError:
            logger.warning("Alerting module not found. Running without notifications.")
            logger.info("To enable: ensure 'alerts/' folder is in project root")
            return None
        except Exception as e:
            logger.error(f"Failed to initialize alerting system: {e}")
            return None

    def _ensure_database_initialized(self):
        """Check if the database exists, and if not, initialize it."""
        db_path = Path(config.get('database', 'path'))
        if not db_path.exists():
            logger.info("Database not found. Initializing a new one...")
            try:
                init_db()
                logger.info("Database initialized successfully.")
            except Exception as e:
                logger.error(f"FATAL: Could not initialize database: {e}", exc_info=True)
                sys.exit(1)

    def start(self):
        """Start all system components."""
        logger.info("Starting IoTSentinel components...")

        self.running = True

        # Start alerting system (for scheduled reports)
        if self.alerting:
            self.alerting.start()
            logger.info("Alerting system started (reports scheduled)")

        # Start parser thread
        parser_thread = threading.Thread(
            target=self._parser_loop,
            name="ParserThread",
            daemon=True
        )
        parser_thread.start()
        self.threads.append(parser_thread)

        # Start inference thread
        inference_thread = threading.Thread(
            target=self._inference_loop,
            name="InferenceThread",
            daemon=True
        )
        inference_thread.start()
        self.threads.append(inference_thread)

        # Start cleanup thread
        cleanup_thread = threading.Thread(
            target=self._cleanup_loop,
            name="CleanupThread",
            daemon=True
        )
        cleanup_thread.start()
        self.threads.append(cleanup_thread)

        # Start health check thread
        health_thread = threading.Thread(
            target=self._health_check_loop,
            name="HealthCheckThread",
            daemon=True
        )
        health_thread.start()
        self.threads.append(health_thread)

        # Start ARP scanner thread (if available)
        if self.arp_scanner:
            arp_thread = threading.Thread(
                target=self._arp_scan_loop,
                name="ARPScanThread",
                daemon=True
            )
            arp_thread.start()
            self.threads.append(arp_thread)
            logger.info("ARP scanner started.")
        else:
            logger.info("ARP scanner disabled (not available).")

        # Start hardware monitor thread (only on Pi)
        if IS_RPI:
            self.hardware_monitor = HardwareMonitor()
            hardware_thread = threading.Thread(
                target=self.hardware_monitor.monitor_loop,
                name="HardwareMonitorThread",
                daemon=True
            )
            hardware_thread.start()
            self.threads.append(hardware_thread)
            logger.info("Hardware monitor started.")
        else:
            logger.info("Hardware monitor disabled (not running on Pi).")

        # Start IoT threat detection loop (if available)
        if self.threat_detector:
            threat_thread = threading.Thread(
                target=self._iot_threat_scan_loop,
                name="IoTThreatScanThread",
                daemon=True
            )
            threat_thread.start()
            self.threads.append(threat_thread)
            logger.info("IoT threat detection started (scanning every 10 minutes).")

        # Start IoT vulnerability scan loop (if available)
        if self.intelligence:
            vuln_thread = threading.Thread(
                target=self._iot_vulnerability_scan_loop,
                name="IoTVulnerabilityScanThread",
                daemon=True
            )
            vuln_thread.start()
            self.threads.append(vuln_thread)
            logger.info("IoT vulnerability scanning started (daily scans).")

        # Start IoT firmware check loop (if available)
        if self.firmware_manager:
            firmware_thread = threading.Thread(
                target=self._iot_firmware_check_loop,
                name="IoTFirmwareCheckThread",
                daemon=True
            )
            firmware_thread.start()
            self.threads.append(firmware_thread)
            logger.info("IoT firmware checking started (weekly checks).")

        # Start Kids Device Monitor Loop (every 30 minutes)
        if self.privacy_monitor:
            kids_monitor_thread = threading.Thread(
                target=self._kids_device_monitor_loop,
                name="KidsDeviceMonitorThread",
                daemon=True
            )
            kids_monitor_thread.start()
            self.threads.append(kids_monitor_thread)
            logger.info("Kids device monitoring started (every 30 minutes).")

        # Start Hardware Lifecycle Check Loop (daily)
        if self.lifecycle_manager:
            lifecycle_thread = threading.Thread(
                target=self._hardware_lifecycle_check_loop,
                name="HardwareLifecycleThread",
                daemon=True
            )
            lifecycle_thread.start()
            self.threads.append(lifecycle_thread)
            logger.info("Hardware lifecycle monitoring started (daily checks).")

        # Start Sustainability Metrics Loop (every 6 hours)
        if self.sustainability_calc:
            sustainability_thread = threading.Thread(
                target=self._sustainability_metrics_loop,
                name="SustainabilityMetricsThread",
                daemon=True
            )
            sustainability_thread.start()
            self.threads.append(sustainability_thread)
            logger.info("Sustainability metrics logging started (every 6 hours).")

        # Start NVD Vulnerability Sync Thread (daily)
        if self.vuln_sync and config.get('nvd', {}).get('enabled', True):
            nvd_sync_thread = threading.Thread(
                target=self._nvd_sync_loop,
                name="NVDSyncThread",
                daemon=True
            )
            nvd_sync_thread.start()
            self.threads.append(nvd_sync_thread)
            logger.info("NVD vulnerability sync started (daily updates).")

        # Start Security Score Logging Thread (hourly)
        if self.security_scorer:
            score_logging_thread = threading.Thread(
                target=self._security_score_logging_loop,
                name="SecurityScoreLoggingThread",
                daemon=True
            )
            score_logging_thread.start()
            self.threads.append(score_logging_thread)
            logger.info("Security score logging started (hourly).")

        # Start mDNS Discovery Thread (continuous passive listening)
        if self.mdns_manager:
            mdns_thread = threading.Thread(
                target=self._mdns_discovery_loop,
                name="MDNSDiscoveryThread",
                daemon=True
            )
            mdns_thread.start()
            self.threads.append(mdns_thread)
            logger.info("mDNS passive discovery started.")

        # Start UPnP Discovery Thread (continuous passive listening)
        if self.upnp_scanner:
            upnp_thread = threading.Thread(
                target=self._upnp_discovery_loop,
                name="UPnPDiscoveryThread",
                daemon=True
            )
            upnp_thread.start()
            self.threads.append(upnp_thread)
            logger.info("UPnP passive discovery started.")

        # Start Active Network Scan Thread (if enabled)
        if self.active_scanner and config.get('discovery', {}).get('active_scan_enabled', False):
            active_scan_thread = threading.Thread(
                target=self._active_scan_loop,
                name="ActiveScanThread",
                daemon=True
            )
            active_scan_thread.start()
            self.threads.append(active_scan_thread)
            logger.info("Active network scanning started.")

        logger.info("All components started. Orchestrator is running.")
        self._print_status()

    def _print_status(self):
        """Print system status summary."""
        logger.info("=" * 60)
        logger.info("IOTSENTINEL STATUS")
        logger.info("=" * 60)
        logger.info(f"  Threads running: {len(self.threads)}")
        logger.info(f"  Database: {config.get('database', 'path')}")

        if self.alerting:
            status = self.alerting.get_status()
            logger.info(f"  Alerting: ENABLED")
            logger.info(f"    - Email: {'✓' if status['components']['email_handler'] else '✗'}")
            logger.info(f"    - Reports: {'✓' if status['running'] else '✗'}")
        else:
            logger.info(f"  Alerting: DISABLED")

        # IoT features status
        iot_enabled = all([
            self.intelligence, self.protocol_analyzer, self.threat_detector,
            self.smart_home, self.privacy_monitor, self.segmentation, self.firmware_manager
        ])
        logger.info(f"  IoT Features: {'ENABLED' if iot_enabled else 'DISABLED'}")
        if iot_enabled:
            logger.info(f"    - Threat Detection: ✓ (every 10 min)")
            logger.info(f"    - Vulnerability Scan: ✓ (daily)")
            logger.info(f"    - Firmware Check: ✓ (weekly)")
            logger.info(f"    - Protocol Analysis: ✓")
            logger.info(f"    - Privacy Monitoring: ✓")
            logger.info(f"    - Smart Home Integration: ✓")

        logger.info("=" * 60)

    def _parser_loop(self):
        """Wrapper for the Zeek log parser's watch loop."""
        logger.info("Log parsing loop started.")
        try:
            interval = config.get('parser', 'interval', default=60)
            while self.running:
                self.parser.parse_once()

                # Sleep in 1-second intervals to allow quick shutdown
                for _ in range(interval):
                    if not self.running:
                        break
                    time.sleep(1)

        except Exception as e:
            logger.error(f"Error in parser loop: {e}", exc_info=True)
        logger.info("Log parsing loop stopped.")

    def _inference_loop(self):
        """Wrapper for the ML inference engine's continuous loop."""
        logger.info("ML inference loop started.")
        try:
            interval = config.get('ml', 'inference_interval_seconds', default=300)
            while self.running:
                self.inference_engine.process_connections()

                # Sleep in 1-second intervals to allow quick shutdown
                for _ in range(interval):
                    if not self.running:
                        break
                    time.sleep(1)

        except Exception as e:
            logger.error(f"Error in inference loop: {e}", exc_info=True)
        logger.info("ML inference loop stopped.")

    def _cleanup_loop(self):
        """Periodically cleans up old database records."""
        logger.info("Database cleanup loop started.")
        try:
            # Run once a day
            cleanup_interval = 24 * 60 * 60  # 24 hours in seconds
            retention_days = config.get('database', 'retention_days', default=30)

            while self.running:
                logger.info(f"Running daily database cleanup (retention: {retention_days} days)...")
                self.db.cleanup_old_data(days=retention_days)

                # Sleep for 24 hours, but check for shutdown every second
                for _ in range(cleanup_interval):
                    if not self.running:
                        break
                    time.sleep(1)

        except Exception as e:
            logger.error(f"Error in cleanup loop: {e}", exc_info=True)
        logger.info("Database cleanup loop stopped.")

    def _arp_scan_loop(self):
        """Periodically scan network with ARP to discover devices."""
        if not self.arp_scanner:
            logger.warning("ARP scanner not available, loop exiting")
            return

        logger.info("ARP scan loop started.")
        try:
            interval = config.get('network', 'arp_scan_interval', default=300)

            # Perform initial scan immediately
            logger.info("Performing initial ARP network scan...")
            try:
                count = self.arp_scanner.scan_and_update_database()
                logger.info(f"Initial ARP scan complete: {count} devices discovered")
            except Exception as e:
                logger.error(f"Error in initial ARP scan: {e}")

            # Continue with periodic scans
            while self.running:
                # Sleep first, then scan
                for _ in range(interval):
                    if not self.running:
                        break
                    time.sleep(1)

                if not self.running:
                    break

                try:
                    logger.info("Running periodic ARP network scan...")
                    count = self.arp_scanner.scan_and_update_database()
                    logger.info(f"ARP scan complete: {count} devices updated")
                except Exception as e:
                    logger.error(f"Error in periodic ARP scan: {e}")

        except Exception as e:
            logger.error(f"Error in ARP scan loop: {e}", exc_info=True)
        finally:
            if self.arp_scanner:
                try:
                    self.arp_scanner.close()
                except Exception as e:
                    logger.error(f"Error closing ARP scanner: {e}")

        logger.info("ARP scan loop stopped.")

    def _is_process_running(self, process_name: str) -> bool:
        """Check if a process with the given name is running."""
        try:
            for proc in psutil.process_iter(['name']):
                if process_name.lower() in proc.info['name'].lower():
                    return True
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass
        return False

    def _health_check_loop(self):
        """Periodically checks the health of critical system components."""
        logger.info("Health check loop started.")
        interval = config.get('system', 'health_check_interval_seconds', default=600)

        while self.running:
            try:
                # Check Zeek
                if not self._is_process_running("zeek"):
                    logger.critical("Zeek is not running! Attempting to restart...")
                    try:
                        subprocess.run(
                            ["sudo", "/opt/zeek/bin/zeekctl", "deploy"],
                            check=True,
                            capture_output=True,
                            text=True,
                            timeout=30
                        )
                        logger.info("Zeek restart command executed successfully.")
                    except subprocess.TimeoutExpired:
                        logger.error("Zeek restart command timed out.")
                    except (subprocess.CalledProcessError, FileNotFoundError) as e:
                        logger.error(f"Failed to restart Zeek: {e}")

            except Exception as e:
                logger.error(f"Error during health check: {e}", exc_info=True)

            # Check for shutdown signal every second
            for _ in range(interval):
                if not self.running:
                    break
                time.sleep(1)

        logger.info("Health check loop stopped.")

    def _iot_threat_scan_loop(self):
        """Periodically scan all devices for IoT-specific threats."""
        if not self.threat_detector:
            logger.warning("IoT threat detector not available, loop exiting")
            return

        logger.info("IoT threat scan loop started.")
        try:
            # Scan every 10 minutes
            interval = config.get('iot', 'threat_scan_interval', default=600)

            # Perform initial scan after 30 seconds (let system stabilize)
            time.sleep(30)
            if not self.running:
                return

            logger.info("Performing initial IoT threat scan...")
            try:
                threat_count = self._run_iot_threat_scan()
                logger.info(f"Initial IoT threat scan complete: {threat_count} threats detected")
            except Exception as e:
                logger.error(f"Error in initial IoT threat scan: {e}")

            # Continue with periodic scans
            while self.running:
                # Sleep first, then scan
                for _ in range(interval):
                    if not self.running:
                        break
                    time.sleep(1)

                if not self.running:
                    break

                try:
                    logger.info("Running periodic IoT threat scan...")
                    threat_count = self._run_iot_threat_scan()
                    if threat_count > 0:
                        logger.warning(f"IoT threat scan complete: {threat_count} threats detected")
                    else:
                        logger.info("IoT threat scan complete: No threats detected")
                except Exception as e:
                    logger.error(f"Error in periodic IoT threat scan: {e}")

        except Exception as e:
            logger.error(f"Error in IoT threat scan loop: {e}", exc_info=True)

        logger.info("IoT threat scan loop stopped.")

    def _run_iot_threat_scan(self) -> int:
        """Execute comprehensive threat scan on all devices."""
        cursor = self.db.conn.cursor()
        cursor.execute("SELECT device_ip, device_name FROM devices")
        devices = cursor.fetchall()

        threat_count = 0

        for device in devices:
            device_ip = device['device_ip']

            # 1. Check for default credentials
            if self.threat_detector.check_default_credentials(device_ip):
                logger.critical(f"DEFAULT CREDENTIALS RISK on {device['device_name']} ({device_ip})")
                threat_count += 1

            # 2. Check for Mirai infection
            if self.threat_detector.detect_mirai_infection(device_ip):
                logger.critical(f"MIRAI DETECTED on {device['device_name']} ({device_ip})")
                threat_count += 1

            # 3. Check for DDoS participation
            if self.threat_detector.detect_ddos_participation(device_ip):
                logger.critical(f"DDoS ATTACK from {device['device_name']} ({device_ip})")
                threat_count += 1

            # 4. Check for C2 communication
            if self.threat_detector.detect_c2_communication(device_ip):
                logger.critical(f"C2 COMMUNICATION detected on {device['device_name']} ({device_ip})")
                threat_count += 1

            # 5. Check for UPnP exploitation
            if self.threat_detector.detect_upnp_exploitation(device_ip):
                logger.critical(f"UPnP EXPLOITATION on {device['device_name']} ({device_ip})")
                threat_count += 1

            # 6. Check for behavioral anomalies
            behavioral_anomaly = self.threat_detector.detect_behavioral_anomaly(device_ip)
            if behavioral_anomaly:
                logger.warning(
                    f"BEHAVIORAL ANOMALY on {device['device_name']} ({device_ip}): "
                    f"{len(behavioral_anomaly['anomalies'])} metrics deviated"
                )
                threat_count += 1

        return threat_count

    def _iot_vulnerability_scan_loop(self):
        """Periodically scan all devices for known vulnerabilities."""
        if not self.intelligence:
            logger.warning("IoT intelligence module not available, loop exiting")
            return

        logger.info("IoT vulnerability scan loop started.")
        try:
            # Scan daily
            interval = config.get('iot', 'vulnerability_scan_interval', default=86400)  # 24 hours

            # Perform initial scan after 5 minutes
            time.sleep(300)
            if not self.running:
                return

            logger.info("Performing initial IoT vulnerability scan...")
            try:
                vuln_count = self._run_iot_vulnerability_scan()
                logger.info(f"Initial IoT vulnerability scan complete: {vuln_count} vulnerabilities found")
            except Exception as e:
                logger.error(f"Error in initial IoT vulnerability scan: {e}")

            # Continue with periodic scans
            while self.running:
                for _ in range(interval):
                    if not self.running:
                        break
                    time.sleep(1)

                if not self.running:
                    break

                try:
                    logger.info("Running daily IoT vulnerability scan...")
                    vuln_count = self._run_iot_vulnerability_scan()
                    if vuln_count > 0:
                        logger.warning(f"IoT vulnerability scan complete: {vuln_count} vulnerabilities found")
                    else:
                        logger.info("IoT vulnerability scan complete: No vulnerabilities found")
                except Exception as e:
                    logger.error(f"Error in daily IoT vulnerability scan: {e}")

        except Exception as e:
            logger.error(f"Error in IoT vulnerability scan loop: {e}", exc_info=True)

        logger.info("IoT vulnerability scan loop stopped.")

    def _run_iot_vulnerability_scan(self) -> int:
        """Execute vulnerability scan on all devices."""
        cursor = self.db.conn.cursor()
        cursor.execute("SELECT device_ip FROM devices")
        devices = cursor.fetchall()

        vuln_count = 0
        for device in devices:
            vulnerabilities = self.intelligence.check_vulnerabilities(device['device_ip'])
            vuln_count += len(vulnerabilities)

        return vuln_count

    def _iot_firmware_check_loop(self):
        """Periodically check for firmware updates on all devices."""
        if not self.firmware_manager:
            logger.warning("IoT firmware manager not available, loop exiting")
            return

        logger.info("IoT firmware check loop started.")
        try:
            # Check weekly
            interval = config.get('iot', 'firmware_check_interval', default=604800)  # 7 days

            # Perform initial check after 10 minutes
            time.sleep(600)
            if not self.running:
                return

            logger.info("Performing initial IoT firmware check...")
            try:
                updates_available = self._run_iot_firmware_check()
                logger.info(f"Initial IoT firmware check complete: {updates_available} updates available")
            except Exception as e:
                logger.error(f"Error in initial IoT firmware check: {e}")

            # Continue with periodic checks
            while self.running:
                for _ in range(interval):
                    if not self.running:
                        break
                    time.sleep(1)

                if not self.running:
                    break

                try:
                    logger.info("Running weekly IoT firmware check...")
                    updates_available = self._run_iot_firmware_check()
                    if updates_available > 0:
                        logger.warning(f"IoT firmware check complete: {updates_available} updates available")
                    else:
                        logger.info("IoT firmware check complete: All devices up to date")
                except Exception as e:
                    logger.error(f"Error in weekly IoT firmware check: {e}")

        except Exception as e:
            logger.error(f"Error in IoT firmware check loop: {e}", exc_info=True)

        logger.info("IoT firmware check loop stopped.")

    def _run_iot_firmware_check(self) -> int:
        """Execute firmware update check on all devices."""
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

        return updates_available

    def _kids_device_monitor_loop(self):
        """Background loop for kids' device protection monitoring (every 30 minutes)."""
        interval = 1800  # 30 minutes
        logger.info(f"Kids device monitor loop started (interval: {interval}s)")

        while self.running:
            try:
                if self.privacy_monitor:
                    logger.info("Checking kids' devices for suspicious activity...")

                    cursor = self.db.conn.cursor()
                    cursor.execute("""
                        SELECT device_ip, device_name
                        FROM devices
                        WHERE is_kids_device = 1
                    """)
                    kids_devices = cursor.fetchall()

                    for device in kids_devices:
                        device_ip = device['device_ip']
                        device_name = device['device_name'] or device_ip

                        # Check for suspicious activity
                        result = self.privacy_monitor.check_kids_device_activity(device_ip)

                        if result and result.get('risk_score', 0) > 50:
                            logger.warning(
                                f"Kids device alert for {device_name} ({device_ip}): "
                                f"Risk score {result['risk_score']}/100"
                            )

                            # Create alert through alerting system if available
                            if self.alerting:
                                explanation = f"Kids Device Protection Alert for {device_name}\n\n"
                                explanation += f"Risk Score: {result['risk_score']}/100\n\n"

                                if result.get('detections'):
                                    explanation += "Detected Issues:\n"
                                    for detection in result['detections']:
                                        explanation += f"- {detection}\n"

                                if result.get('recommendations'):
                                    explanation += "\nRecommended Actions:\n"
                                    for rec in result['recommendations']:
                                        explanation += f"- {rec}\n"

                                self.alerting.create_alert(
                                    device_ip=device_ip,
                                    severity='high' if result['risk_score'] > 70 else 'medium',
                                    explanation=explanation,
                                    anomaly_score=result['risk_score'] / 100.0
                                )

                    logger.info(f"Kids device monitoring complete: checked {len(kids_devices)} devices")

            except Exception as e:
                logger.error(f"Error in kids device monitoring: {e}")

            time.sleep(interval)

    def _hardware_lifecycle_check_loop(self):
        """Background loop for hardware EOL monitoring (daily)."""
        interval = 86400  # 24 hours
        logger.info(f"Hardware lifecycle check loop started (interval: {interval}s)")

        while self.running:
            try:
                if self.lifecycle_manager:
                    logger.info("Checking devices for hardware lifecycle alerts...")

                    cursor = self.db.conn.cursor()
                    cursor.execute("""
                        SELECT device_ip, device_name, manufacturing_date, hardware_eol_date
                        FROM devices
                        WHERE hardware_eol_date IS NOT NULL OR manufacturing_date IS NOT NULL
                    """)
                    devices_to_check = cursor.fetchall()

                    eol_count = 0
                    for device in devices_to_check:
                        device_ip = device['device_ip']

                        # Check lifecycle status
                        result = self.lifecycle_manager.check_device_lifecycle(device_ip)

                        if result and result.get('is_eol'):
                            eol_count += 1
                            device_name = device['device_name'] or device_ip

                            logger.warning(
                                f"EOL device detected: {device_name} ({device_ip}) - "
                                f"Unsupported since {result.get('eol_date', 'unknown')}"
                            )

                            # Create alert for EOL devices if alerting is available
                            if self.alerting and result.get('days_until_eol', 0) < 30:
                                explanation = f"Hardware End-of-Life Alert for {device_name}\n\n"
                                explanation += f"EOL Date: {result.get('eol_date', 'Unknown')}\n"
                                explanation += f"Security Risk: No more firmware updates or security patches\n\n"

                                if result.get('recommendations'):
                                    explanation += "Recommended Actions:\n"
                                    for rec in result['recommendations']:
                                        explanation += f"- {rec}\n"

                                self.alerting.create_alert(
                                    device_ip=device_ip,
                                    severity='medium',
                                    explanation=explanation,
                                    anomaly_score=0.5
                                )

                    logger.info(f"Hardware lifecycle check complete: {eol_count} EOL devices found out of {len(devices_to_check)}")

            except Exception as e:
                logger.error(f"Error in hardware lifecycle check: {e}")

            time.sleep(interval)

    def _sustainability_metrics_loop(self):
        """Background loop for sustainability metrics logging (every 6 hours)."""
        interval = 21600  # 6 hours
        logger.info(f"Sustainability metrics loop started (interval: {interval}s)")

        while self.running:
            try:
                if self.sustainability_calc:
                    logger.info("Calculating and logging sustainability metrics...")

                    # Calculate carbon footprint
                    carbon_data = self.sustainability_calc.calculate_network_carbon_footprint(hours=6)

                    # Save to database
                    if carbon_data:
                        metrics = {
                            'period_start': (datetime.now() - timedelta(hours=6)).isoformat(),
                            'period_end': datetime.now().isoformat(),
                            'total_data_gb': carbon_data.get('total_data_gb', 0),
                            'energy_kwh': carbon_data.get('energy_kwh', 0),
                            'carbon_kg': carbon_data.get('carbon_kg', 0),
                            'device_count': 0,  # Will be calculated
                            'active_device_hours': 0  # Will be calculated
                        }

                        # Get device count
                        cursor = self.db.conn.cursor()
                        cursor.execute("SELECT COUNT(*) as count FROM devices")
                        metrics['device_count'] = cursor.fetchone()['count']

                        # Save metrics
                        self.sustainability_calc.save_sustainability_metrics(metrics)

                        logger.info(
                            f"Sustainability metrics saved: {carbon_data.get('carbon_kg', 0):.3f} kg CO₂, "
                            f"{carbon_data.get('energy_kwh', 0):.3f} kWh"
                        )

            except Exception as e:
                logger.error(f"Error in sustainability metrics calculation: {e}")

            time.sleep(interval)

    def _nvd_sync_loop(self):
        """Background loop for NVD vulnerability synchronization (daily)."""
        interval = config.get('nvd', {}).get('sync_interval_hours', 24) * 3600  # Convert to seconds
        initial_delay = 300  # 5 minutes

        logger.info(f"NVD sync loop started (interval: {interval/3600:.1f} hours)")

        # Initial sync after short delay
        time.sleep(initial_delay)

        while self.running:
            try:
                if self.vuln_sync:
                    logger.info("Starting NVD vulnerability synchronization...")
                    stats = self.vuln_sync.sync_vulnerabilities()

                    logger.info(
                        f"NVD sync complete: {stats.get('cves_fetched', 0)} CVEs, "
                        f"{stats.get('matches_found', 0)} matches"
                    )

                    if stats.get('critical_severity_count', 0) > 0:
                        logger.warning(
                            f"Found {stats['critical_severity_count']} CRITICAL vulnerabilities!"
                        )
            except Exception as e:
                logger.error(f"Error in NVD sync: {e}")

            time.sleep(interval)

    def _security_score_logging_loop(self):
        """Background loop for security score logging (hourly)."""
        interval = 3600  # 1 hour
        logger.info("Security score logging loop started (interval: 1 hour)")

        while self.running:
            try:
                if self.security_scorer:
                    score_data = self.security_scorer.calculate_network_score()
                    self.security_scorer.save_score_to_history(score_data)

                    logger.info(
                        f"Security score: {score_data.get('overall_score', 0)}/100 "
                        f"({score_data.get('grade', 'N/A')})"
                    )
            except Exception as e:
                logger.error(f"Error in security score logging: {e}")

            time.sleep(interval)

    def _mdns_discovery_loop(self):
        """Background loop for mDNS/Zeroconf device discovery."""
        logger.info("mDNS discovery loop started")

        try:
            if self.mdns_manager:
                self.mdns_manager.start()

                # Keep thread alive while running
                while self.running:
                    time.sleep(60)  # Check every minute

                    # Periodic stats logging
                    stats = self.mdns_manager.get_stats()
                    if stats.get('total_services', 0) > 0:
                        logger.debug(f"mDNS: {stats['total_services']} services discovered")
        except Exception as e:
            logger.error(f"Error in mDNS discovery: {e}")
        finally:
            if self.mdns_manager:
                self.mdns_manager.stop()

    def _upnp_discovery_loop(self):
        """Background loop for UPnP/SSDP device discovery."""
        logger.info("UPnP discovery loop started")

        try:
            if self.upnp_scanner:
                self.upnp_scanner.start_passive_listener()

                # Keep thread alive while running
                while self.running:
                    time.sleep(60)  # Check every minute

                    # Periodic stats logging
                    stats = self.upnp_scanner.get_stats()
                    if stats.get('total_devices', 0) > 0:
                        logger.debug(f"UPnP: {stats['total_devices']} devices discovered")
        except Exception as e:
            logger.error(f"Error in UPnP discovery: {e}")
        finally:
            if self.upnp_scanner:
                self.upnp_scanner.stop_passive_listener()

    def _active_scan_loop(self):
        """Background loop for active network scanning with nmap."""
        interval = config.get('discovery', {}).get('active_scan_interval', 3600)  # Default 1 hour
        network = config.get('network', {}).get('local_networks', ['192.168.1.0/24'])[0]

        logger.info(f"Active scan loop started (interval: {interval}s, network: {network})")

        while self.running:
            try:
                if self.active_scanner:
                    capabilities = self.active_scanner.get_capabilities()

                    if not capabilities['nmap_available']:
                        logger.warning("nmap not available, active scanning disabled")
                        break

                    logger.info(f"Starting active network scan of {network}...")
                    devices = self.active_scanner.scan_network(network, scan_type='ping')

                    logger.info(f"Active scan found {len(devices)} devices")
            except Exception as e:
                logger.error(f"Error in active scan: {e}")

            time.sleep(interval)

    def stop(self):
        """Stop all system components gracefully."""
        logger.info("Stopping IoTSentinel orchestrator...")

        self.running = False

        # Stop alerting system
        if self.alerting:
            try:
                self.alerting.stop()
                logger.info("Alerting system stopped")
            except Exception as e:
                logger.error(f"Error stopping alerting system: {e}")

        # Stop hardware monitor if it exists
        if self.hardware_monitor:
            try:
                self.hardware_monitor.stop()
            except Exception as e:
                logger.error(f"Error stopping hardware monitor: {e}")

        # Stop discovery managers
        if self.mdns_manager:
            try:
                self.mdns_manager.stop()
                logger.info("mDNS discovery manager stopped")
            except Exception as e:
                logger.error(f"Error stopping mDNS manager: {e}")

        if self.upnp_scanner:
            try:
                self.upnp_scanner.stop_passive_listener()
                logger.info("UPnP scanner stopped")
            except Exception as e:
                logger.error(f"Error stopping UPnP scanner: {e}")

        # Wait for threads to finish (with timeout)
        for thread in self.threads:
            logger.debug(f"Waiting for thread {thread.name} to stop...")
            thread.join(timeout=3)
            if thread.is_alive():
                logger.warning(f"Thread {thread.name} did not stop gracefully within timeout")

        # Close database connection
        try:
            self.db.close()
        except Exception as e:
            logger.error(f"Error closing database: {e}")

        logger.info("IoTSentinel orchestrator stopped.")

    # === Public API for external access ===

    def send_test_email(self) -> bool:
        """Send a test email to verify alerting configuration."""
        if not self.alerting:
            logger.warning("Alerting system not available")
            return False
        return self.alerting.send_test_email()

    def send_report_now(self, report_type: str = 'weekly') -> bool:
        """Manually trigger a report send."""
        if not self.alerting:
            logger.warning("Alerting system not available")
            return False
        return self.alerting.send_report_now(report_type)

    def get_alert_summary(self, hours: int = 24) -> dict:
        """Get alert summary for dashboard."""
        if self.alerting:
            return self.alerting.get_alert_summary(hours=hours)
        else:
            # Fallback to direct DB query
            alerts = self.db.get_recent_alerts(hours=hours)
            return {
                'total': len(alerts),
                'by_severity': {},
                'by_device': {}
            }


# --- Main Execution ---
orchestrator = None


def signal_handler(sig, frame):
    """Handle shutdown signals for graceful exit."""
    global orchestrator
    logger.info(f"Received signal {sig}, shutting down...")
    if orchestrator:
        orchestrator.stop()
    sys.exit(0)


if __name__ == '__main__':
    # Register signal handlers
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    # Initialize and start system
    try:
        orchestrator = IoTSentinelOrchestrator()
        orchestrator.start()

        logger.info("IoTSentinel is running. Press Ctrl+C to stop.")

        # Keep the main thread alive
        while True:
            time.sleep(1)

    except KeyboardInterrupt:
        logger.info("Keyboard interrupt received.")
        if orchestrator:
            orchestrator.stop()
    except Exception as e:
        logger.error(f"Fatal error in main: {e}", exc_info=True)
        if orchestrator:
            orchestrator.stop()
        sys.exit(1)
