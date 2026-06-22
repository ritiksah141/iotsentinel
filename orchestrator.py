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
from utils.arp_scanner import ARPScanner

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
from utils.domain_blocklist_sync import get_domain_blocklist_sync
from utils.network_security_scorer import get_security_scorer

# Import API Integration Hub
from alerts.integration_system import IntegrationManager

# Import AI Agent
from agents.security_agent import SecurityAgent, AGENT_INTERVAL
from utils.ai_assistant import HybridAIAssistant
from utils.alert_explainer import rewrite_alert, persist as persist_plain
from ml.smart_recommender import SmartRecommender

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
    - Thread 5: ARP network scanner (if available)
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

        # Ensure all performance indexes exist at runtime (idempotent; safe to
        # call on every start — uses CREATE INDEX IF NOT EXISTS internally).
        try:
            self.db.create_indexes()
        except Exception as e:
            logger.warning(f"Index creation at startup failed (non-fatal): {e}")

        # Initialize alerting system
        self.alerting = self._init_alerting_system()

        # Initialize parser
        self.parser = ZeekLogParser()

        # Initialize inference engine with alerting
        self.inference_engine = InferenceEngine(alerting_system=self.alerting)

        # Initialize ARP scanner (no sudo / no scapy required)
        self.arp_scanner = None
        try:
            self.arp_scanner = ARPScanner()
            logger.info("ARP scanner initialised (privilege-free mode)")
        except Exception as e:
            logger.error(f"Failed to initialise ARP scanner: {e}")

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
        self.domain_blocklist_sync = None
        self.security_scorer = None
        self.integration_manager = None

        try:
            # Load environment variables
            load_dotenv()

            db_path = config.get('database', 'path')

            # Always initialize auto-provisioner and security scorer
            self.auto_provisioner = get_auto_provisioner(db_path=db_path)
            self.security_scorer = get_security_scorer(db_path=db_path)
            logger.info("Auto-provisioner and security scorer initialized")

            # Initialize API Integration Hub
            self.integration_manager = IntegrationManager(db_path=db_path)
            enabled_count = len([i for i in self.integration_manager.get_all_integrations() if i.get('enabled')])
            logger.info(f"API Integration Hub initialized ({enabled_count} integrations enabled)")

            # Initialize NVD vulnerability sync if enabled
            if config.get('nvd', {}).get('enabled', True):
                # Read API key from environment variable
                nvd_api_key = os.getenv('NVD_API_KEY', config.get('nvd', {}).get('api_key', ''))
                self.vuln_sync = get_vulnerability_sync(
                    db_path=db_path,
                    nvd_api_key=nvd_api_key if nvd_api_key else None
                )
                logger.info(f"NVD vulnerability sync initialized (API key: {'provided' if nvd_api_key else 'not provided'})")

            # Initialize domain blocklist sync (URLhaus, no API key required)
            try:
                self.domain_blocklist_sync = get_domain_blocklist_sync(db_manager=self.db)
                stats = self.domain_blocklist_sync.get_stats()
                logger.info(
                    "Domain blocklist sync initialized (%d domains in DB, last sync: %s)",
                    stats.get('total_domains', 0), stats.get('last_sync', 'never'),
                )
            except Exception as _dbl_err:
                logger.warning("Domain blocklist sync init failed: %s", _dbl_err)

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
        # Set on stop() so worker loops waiting in _sleep() wake immediately instead
        # of blocking out their full interval — keeps shutdown fast and graceful.
        self._shutdown_event = threading.Event()

        # Initialize AI Security Agent
        try:
            _agent_ai = HybridAIAssistant.from_config(config)
            self.security_agent = SecurityAgent(
                db=self.db,
                ai_assistant=_agent_ai,
                alerting=self.alerting,
            )
            logger.info("AI Security Agent initialized")
        except Exception as e:
            logger.warning(f"AI Security Agent unavailable: {e}")
            self.security_agent = None

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

        # Self-heal the monitored subnet. The setup wizard can only guess the LAN
        # while the Pi is still on its own 10.42.0.1 hotspot, so local_networks is
        # often left as the hotspot range or the shipped default — which makes
        # device discovery scan an empty network. Once the Pi is on home Wi-Fi we
        # can read the real subnet off the interface.
        self._autodetect_local_network()

        # In gateway mode, bring the IoT access point up FIRST so its interface
        # exists before Zeek targets it. No-op (and safe) in passive mode.
        self._ensure_ap_configured()

        # Ensure Zeek is pointed at the monitored interface and deployed before we
        # start parsing its logs — otherwise the capture pipeline has no input.
        self._ensure_zeek_configured()

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

        # Start device baseline learning loop (if available)
        if self.intelligence:
            baseline_thread = threading.Thread(
                target=self._device_baseline_learning_loop,
                name="DeviceBaselineLearningThread",
                daemon=True
            )
            baseline_thread.start()
            self.threads.append(baseline_thread)
            logger.info("Device baseline learning started (every 8 hours).")

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

        # Start Domain Blocklist Sync Thread (every 12 hours)
        if self.domain_blocklist_sync:
            domain_sync_thread = threading.Thread(
                target=self._domain_blocklist_loop,
                name="DomainBlocklistThread",
                daemon=True,
            )
            domain_sync_thread.start()
            self.threads.append(domain_sync_thread)
            logger.info("Domain blocklist sync started (URLhaus, every 12 hours).")

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

        # Start AI Security Agent loop
        if self.security_agent:
            agent_thread = threading.Thread(
                target=self._agent_loop,
                name="SecurityAgentThread",
                daemon=True
            )
            agent_thread.start()
            self.threads.append(agent_thread)
            logger.info(f"AI Security Agent started (scanning every {AGENT_INTERVAL}s).")

        # Start plain-English background rewrite worker (runs always — not gated by agent toggle)
        plain_english_thread = threading.Thread(
            target=self._plain_english_loop,
            name="PlainEnglishRewriteThread",
            daemon=True
        )
        plain_english_thread.start()
        self.threads.append(plain_english_thread)
        logger.info("Plain-English alert rewrite worker started (every 120s).")

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

        # API Integration Hub status
        if self.integration_manager:
            integrations = self.integration_manager.get_all_integrations()
            enabled = [i for i in integrations if i.get('enabled')]
            logger.info(f"  API Integration Hub: {len(enabled)}/{len(integrations)} integrations enabled")
            if enabled:
                logger.info(f"    - Active integrations: {', '.join([i['name'] for i in enabled[:5]])}")

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

    def _agent_loop(self):
        """AI Security Agent — runs every AGENT_INTERVAL seconds."""
        logger.info("AI Security Agent loop started.")

        # Clear any circuit-breaker suspension left over from the previous run.
        # A restart is implicit human acknowledgement that normal operation should resume.
        try:
            self.db.set_setting('auto_block_suspended', '0')
            logger.info("[agent] Circuit breaker cleared on startup.")
        except Exception:
            pass

        try:
            while self.running:
                # Honour the dashboard start/stop toggle (persisted in system_settings)
                agent_enabled = self.db.get_setting('agent_enabled', 'true')
                if str(agent_enabled).lower() not in ('false', '0', 'no'):
                    try:
                        self.security_agent.run_cycle()
                    except Exception as e:
                        logger.error(f"Error in agent cycle: {e}", exc_info=True)
                else:
                    logger.debug("AI Security Agent is paused (agent_enabled=false)")

                for _ in range(AGENT_INTERVAL):
                    if not self.running:
                        break
                    time.sleep(1)
        except Exception as e:
            logger.error(f"Agent loop fatal error: {e}", exc_info=True)
        logger.info("AI Security Agent loop stopped.")

    def _plain_english_loop(self):
        """Background worker — rewrites alert plain_explanation via LLM proactively.

        Picks up newly-created alerts that still have template/MITRE text
        (plain_explanation_ai = 0) and rewrites them using the HybridAIAssistant,
        so alert cards show genuine AI plain-English without the user needing to
        open each alert's modal first.

        Runs every 120 seconds. Processes at most 3 alerts per cycle to stay
        well inside Groq's free-tier quota (14,400 req/day). Skips silently when
        no real LLM provider is configured (Groq/OpenAI/Ollama), leaving the MITRE
        templates in place rather than overwriting them with rule-based canned text.
        """
        logger.info("Plain-English rewrite worker started.")

        REWRITE_INTERVAL = 120   # seconds between cycles
        BATCH_SIZE = 3           # alerts per cycle (quota-friendly)
        INTER_ITEM_SLEEP = 1.0   # seconds between LLM calls within a cycle

        # Each background thread gets its own AI assistant and recommender so
        # there is no shared-state conflict with the security agent's assistant.
        try:
            _ai = HybridAIAssistant.from_config(config)
            _recommender = SmartRecommender(self.db)
        except Exception as exc:
            logger.warning(f"Plain-English worker could not initialise: {exc}")
            return

        try:
            while self.running:
                try:
                    # Skip entirely when no real LLM provider is reachable.
                    if not _ai.has_llm_provider():
                        logger.debug("PlainEnglishRewrite: no LLM provider — skipping cycle.")
                    else:
                        # Fetch a small batch of un-rewritten alerts, newest critical/high first.
                        cursor = self.db.conn.cursor()
                        cursor.execute(
                            """
                            SELECT a.id, a.device_ip, d.device_name,
                                   a.severity, a.explanation, a.plain_explanation
                            FROM alerts a
                            LEFT JOIN devices d ON a.device_ip = d.device_ip
                            WHERE a.plain_explanation_ai = 0
                            ORDER BY
                                CASE a.severity
                                    WHEN 'critical' THEN 1
                                    WHEN 'high'     THEN 2
                                    WHEN 'medium'   THEN 3
                                    ELSE 4
                                END,
                                a.timestamp DESC
                            LIMIT ?
                            """,
                            (BATCH_SIZE,),
                        )
                        rows = cursor.fetchall()

                        for row in rows:
                            if not self.running:
                                break
                            alert_id, device_ip, device_name, severity, explanation, plain_exp = row
                            alert_row = {
                                'id': alert_id,
                                'device_ip': device_ip,
                                'device_name': device_name or device_ip,
                                'severity': severity,
                                'explanation': explanation,
                                'plain_explanation': plain_exp,
                            }

                            # Count today's alerts for this device (urgency context).
                            try:
                                c2 = self.db.conn.cursor()
                                c2.execute(
                                    "SELECT COUNT(*) FROM alerts WHERE device_ip=? "
                                    "AND timestamp >= date('now')",
                                    (device_ip,),
                                )
                                today_count = c2.fetchone()[0]
                            except Exception:
                                today_count = 1

                            # Get recommender context (read-only DB calls).
                            try:
                                recs = _recommender.recommend_for_alert(alert_id)
                            except Exception:
                                recs = []

                            sections = rewrite_alert(alert_row, today_count, recs, _ai)
                            if sections:
                                plain_text = sections.get('what_happened', '')
                                _src = sections.get('_source', '')
                                if plain_text:
                                    ok = persist_plain(self.db, alert_id, plain_text, source=_src)
                                    if ok:
                                        logger.info(
                                            f"[PlainEnglish] alert {alert_id} rewritten "
                                            f"via {_src or '?'}."
                                        )
                                        # Record activity timestamp so the live pulse badge
                                        # in the dashboard knows AI is actively working.
                                        try:
                                            import time as _t
                                            self.db.set_setting(
                                                'last_ai_activity',
                                                str(int(_t.time()))
                                            )
                                        except Exception:
                                            pass

                            self._sleep(INTER_ITEM_SLEEP)

                except Exception as exc:
                    logger.debug(f"PlainEnglishRewrite cycle error: {exc}")

                # Sleep in 1-second chunks for clean shutdown.
                for _ in range(REWRITE_INTERVAL):
                    if not self.running:
                        break
                    time.sleep(1)

        except Exception as exc:
            logger.error(f"Plain-English rewrite worker fatal error: {exc}", exc_info=True)

        logger.info("Plain-English rewrite worker stopped.")

    def _cleanup_loop(self):
        """Periodically cleans up old database records (daily) and optimises the
        database (weekly: ANALYZE + WAL checkpoint + size-guarded VACUUM)."""
        logger.info("Database cleanup loop started.")
        try:
            cleanup_interval = 24 * 60 * 60  # 24 hours in seconds
            retention_days = config.get('database', 'retention_days', default=30)
            _days_since_optimize = 0  # count daily cycles; optimize every 7th

            while self.running:
                logger.info(f"Running daily database cleanup (retention: {retention_days} days)...")
                self.db.cleanup_old_data(days=retention_days)

                _days_since_optimize += 1
                if _days_since_optimize >= 7:
                    logger.info("Running weekly database optimization (ANALYZE + WAL checkpoint)...")
                    try:
                        self.db.optimize_database()
                    except Exception as e:
                        logger.error(f"Weekly database optimization failed: {e}")
                    _days_since_optimize = 0

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
            # Let a long ping sweep abort promptly when the orchestrator is shutting down.
            self.arp_scanner.stop_event = self._shutdown_event

            # Perform initial scan immediately (skip if already shutting down)
            if self.running and not self._shutdown_event.is_set():
                logger.info("Performing initial ARP network scan...")
                try:
                    count = self.arp_scanner.scan_and_update_database()
                    logger.info(f"Initial ARP scan complete: {count} devices discovered")
                except Exception as e:
                    logger.error(f"Error in initial ARP scan: {e}")

            # Continue with periodic scans (interruptible wait — wakes instantly on stop)
            while self.running:
                if self._sleep(interval):
                    break  # shutdown signalled during the wait

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

    def _ensure_zeek_configured(self):
        """Point Zeek at the configured interface and deploy it (idempotent).

        Delegates to config/configure_zeek.sh, which writes node.cfg and runs
        `zeekctl deploy` only when the interface changes. Best-effort and never
        fatal: on a dev machine (no Zeek / no sudo) this is expected to no-op so
        the rest of the system still starts.
        """
        script = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                              'config', 'configure_zeek.sh')
        if not os.path.isfile(script):
            logger.warning("configure_zeek.sh missing — skipping Zeek deploy.")
            return
        self._ensure_zeek_configured_inner(script)

    def _ensure_ap_configured(self):
        """In gateway mode, bring up the IoT Wi-Fi access point (NetworkManager
        shared mode) before Zeek starts. Best-effort and never fatal — on a dev
        machine (no nmcli/sudo) and in passive mode this is a no-op. After bring-up
        it verifies the home uplink is still healthy and rolls back if not, so the
        AP can never strand the user's internet."""
        mode = config.get('network', 'capture_mode', default='passive')
        if mode != 'gateway':
            return
        try:
            from utils.ap_manager import AccessPointManager
            ap = AccessPointManager()
            if not ap.start():
                logger.warning("Access point did not start — staying on passive capture.")
                return
            logger.info("IoT access point started (gateway mode).")
        except Exception as e:
            logger.error("Could not start access point: %s", e)
            return
        # Immediate post-bring-up safety check: if the AP disrupted the home uplink,
        # roll it straight back rather than wait for the periodic watchdog.
        try:
            from utils.network_monitor import uplink_ok
            if not (uplink_ok() or uplink_ok()):
                logger.critical("Home uplink unreachable right after AP bring-up — "
                                "rolling the access point back.")
                self._rollback_gateway("uplink lost immediately after AP bring-up")
        except Exception as e:
            logger.error("Post-AP uplink check failed: %s", e)

    def _ensure_zeek_configured_inner(self, script):
        # In gateway mode let configure_zeek.sh resolve the interface itself
        # (monitor_interface > ap_interface). Passing the home interface as a CLI arg
        # would win over that and point Zeek at the wrong NIC.
        mode = config.get('network', 'capture_mode', default='passive')
        interface = '' if mode == 'gateway' else (config.get('network', 'interface', default='') or '')
        try:
            # Invoke the script directly (executable shebang) with -n so the sudoers
            # path rule matches and it never blocks on a password prompt.
            subprocess.run(
                ["sudo", "-n", script] + ([interface] if interface else []),
                check=False, capture_output=True, text=True, timeout=60,
            )
            logger.info("Zeek configuration applied (interface=%s).",
                        interface or "auto")
        except subprocess.TimeoutExpired:
            logger.error("configure_zeek.sh timed out.")
        except Exception as e:
            logger.error("Could not configure Zeek: %s", e)

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

                # Connectivity watchdog — only active in gateway mode (the only mode
                # where IoTSentinel alters routing and could affect the uplink).
                self._check_uplink_watchdog()

            except Exception as e:
                logger.error(f"Error during health check: {e}", exc_info=True)

            # Check for shutdown signal every second
            for _ in range(interval):
                if not self.running:
                    break
                time.sleep(1)

        logger.info("Health check loop stopped.")

    def _check_uplink_watchdog(self):
        """Gateway-mode safety net: if the home-Wi-Fi uplink goes down (e.g. bringing
        up the IoT access point disrupted it), roll the gateway back so the user never
        loses internet. No-op in passive mode."""
        mode = config.get('network', 'capture_mode', default='passive')
        if mode != 'gateway':
            self._uplink_fail_count = 0
            return
        try:
            from utils.network_monitor import uplink_ok
        except Exception:
            return
        # Confirm a real outage with quick retries so a transient blip never triggers
        # a rollback.
        down = True
        for _ in range(3):
            if uplink_ok():
                down = False
                break
            self._sleep(3)
        if not down:
            self._uplink_fail_count = 0
            return
        self._uplink_fail_count = getattr(self, '_uplink_fail_count', 0) + 1
        logger.critical(
            "Connectivity watchdog: internet uplink DOWN in gateway mode "
            "(consecutive=%d) — rolling back the IoT access point.",
            self._uplink_fail_count,
        )
        self._rollback_gateway("uplink lost in gateway mode")

    def _rollback_gateway(self, reason: str):
        """Tear down the IoT AP and restore the plain home-Wi-Fi uplink. Best-effort,
        never fatal. The real AP teardown lands with ap_manager (Phase 2); until then
        this logs and records the event so the failure is always visible."""
        rolled_back = False
        try:
            from utils.ap_manager import AccessPointManager
            AccessPointManager().stop()
            rolled_back = True
            logger.warning("Gateway rolled back to passive (AP stopped): %s", reason)
        except ImportError:
            logger.error("Gateway rollback requested (%s) but ap_manager is not "
                         "available yet — manual check needed.", reason)
        except Exception as e:
            logger.error("Gateway rollback failed (%s): %s", reason, e)
        # Best-effort user-facing alert (never crash the watchdog).
        try:
            if getattr(self, 'alerting', None):
                self.alerting.create_alert(
                    device_ip='SYSTEM', severity='critical', anomaly_score=1.0,
                    explanation=("Connectivity watchdog: internet uplink lost in gateway "
                                 "mode. "
                                 + ("Access point rolled back to passive."
                                    if rolled_back else "Manual check needed.")
                                 + f" Reason: {reason}"),
                    send_notification=False,
                    plain_explanation=("Your IoTSentinel hub lost internet while running "
                                       "in access-point mode and switched back to safe "
                                       "monitoring so your devices keep working."),
                )
        except Exception:
            pass

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
            self._sleep(30)
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
            self._sleep(300)
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

    def _device_baseline_learning_loop(self):
        """
        Periodically learn behavioral baselines for every known device.

        Runs every 8 hours.  Uses the IoTDeviceIntelligence singleton that is
        already initialized as self.intelligence.  Each call to learn_baseline()
        self-guards: devices with fewer than 100 connections are skipped and
        return {'status': 'insufficient_data'} — nothing is stored, so fresh
        installs degrade gracefully to the "No baseline data yet" UI state.
        """
        if not self.intelligence:
            logger.warning("IoT intelligence module not available, baseline learning loop exiting")
            return

        logger.info("Device baseline learning loop started.")
        interval = 8 * 3600  # 8 hours

        # First pass after a short delay to let other threads settle.
        self._sleep(120)
        if not self.running:
            return

        try:
            while self.running:
                try:
                    cursor = self.db.conn.cursor()
                    cursor.execute("SELECT device_ip FROM devices")
                    devices = cursor.fetchall()

                    learned = 0
                    for device in devices:
                        if not self.running:
                            break
                        result = self.intelligence.learn_baseline(device['device_ip'])
                        if result.get('status') == 'success':
                            learned += 1

                    if learned:
                        logger.info(f"Device baseline learning complete: updated baselines for {learned} device(s).")
                    else:
                        logger.debug("Device baseline learning: no devices had sufficient data yet.")

                except Exception as e:
                    logger.error(f"Error during device baseline learning pass: {e}")

                # Wait for next cycle, checking running flag each second.
                for _ in range(interval):
                    if not self.running:
                        break
                    time.sleep(1)

        except Exception as e:
            logger.error(f"Error in device baseline learning loop: {e}", exc_info=True)

        logger.info("Device baseline learning loop stopped.")

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
            self._sleep(600)
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

            self._sleep(interval)

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

            self._sleep(interval)

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

            self._sleep(interval)

    def _nvd_sync_loop(self):
        """Background loop for NVD vulnerability synchronization (daily)."""
        interval = config.get('nvd', {}).get('sync_interval_hours', 24) * 3600  # Convert to seconds
        initial_delay = 300  # 5 minutes

        logger.info(f"NVD sync loop started (interval: {interval/3600:.1f} hours)")

        # Initial sync after short delay
        self._sleep(initial_delay)

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

            self._sleep(interval)

    def _domain_blocklist_loop(self):
        """Background loop for domain blocklist sync (every 12 hours)."""
        interval = 12 * 3600  # 12 hours
        initial_delay = 120   # 2 minutes — let the system finish startup first

        logger.info("Domain blocklist sync loop started (interval: 12h)")
        self._sleep(initial_delay)

        while self.running:
            try:
                if self.domain_blocklist_sync:
                    logger.info("Starting domain blocklist sync (URLhaus)...")
                    stats = self.domain_blocklist_sync.sync_blocklist()
                    logger.info(
                        "Domain blocklist sync complete: +%d domains added, %d total",
                        stats.get('added', 0), stats.get('total', 0),
                    )
            except Exception as e:
                logger.error("Error in domain blocklist sync: %s", e)

            self._sleep(interval)

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

            self._sleep(interval)

    def _mdns_discovery_loop(self):
        """Background loop for mDNS/Zeroconf device discovery."""
        logger.info("mDNS discovery loop started")

        try:
            if self.mdns_manager:
                self.mdns_manager.start()

                # Keep thread alive while running
                while self.running:
                    self._sleep(60)  # Check every minute

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
                    self._sleep(60)  # Check every minute

                    # Periodic stats logging
                    stats = self.upnp_scanner.get_stats()
                    if stats.get('total_devices', 0) > 0:
                        logger.debug(f"UPnP: {stats['total_devices']} devices discovered")
        except Exception as e:
            logger.error(f"Error in UPnP discovery: {e}")
        finally:
            if self.upnp_scanner:
                self.upnp_scanner.stop_passive_listener()

    def _autodetect_local_network(self):
        """Update network.local_networks to the subnet the Pi is actually on.

        Only runs in passive mode and only overwrites a placeholder value (the
        shipped default or the hotspot range), so a subnet the user set on
        purpose is never clobbered. Best-effort — never fatal to startup.
        """
        try:
            mode = config.get('network', 'capture_mode', default='passive')
            if mode == 'gateway':
                return  # gateway mode monitors the AP subnet, not the home LAN
            from utils.net_detect import detect_active_cidr, PLACEHOLDER_CIDRS
            current = config.get('network', {}).get('local_networks', ['192.168.1.0/24'])
            current_first = current[0] if current else None
            if current_first and current_first not in PLACEHOLDER_CIDRS:
                return  # user/previous run already set a real subnet
            iface = config.get('network', 'interface', default='wlan0') or 'wlan0'
            detected = detect_active_cidr(iface)
            if detected and detected != current_first:
                config.update('network', 'local_networks', [detected])
                logger.info(f"Auto-detected home subnet {detected} on {iface} "
                            f"(was {current_first}) — updated network.local_networks")
                # The ARP scanner cached its range at construction (before this
                # ran), so refresh it now or it would keep scanning the old subnet.
                if self.arp_scanner is not None:
                    try:
                        self.arp_scanner.network_range = detected
                    except Exception:
                        pass
        except Exception as e:
            logger.warning(f"Local-network auto-detection failed: {e}")

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

            self._sleep(interval)

    def _sleep(self, seconds: float) -> bool:
        """Interruptible sleep for worker loops. Returns immediately once stop() has
        been called (the shutdown event is set), so threads never block out a long
        interval during shutdown. Returns True if a shutdown was signalled."""
        ev = getattr(self, '_shutdown_event', None)
        if ev is not None:
            return ev.wait(seconds)
        time.sleep(seconds)  # defensive fallback if called before __init__ ran
        return False

    def stop(self):
        """Stop all system components gracefully."""
        logger.info("Stopping IoTSentinel orchestrator...")

        self.running = False
        # Wake every worker thread parked in _sleep() so the joins below return fast.
        self._shutdown_event.set()

        # Stop alerting system
        if self.alerting:
            try:
                self.alerting.stop()
                logger.info("Alerting system stopped")
            except Exception as e:
                logger.error(f"Error stopping alerting system: {e}")

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
