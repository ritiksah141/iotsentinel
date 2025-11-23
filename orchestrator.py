#!/usr/bin/env python3
"""
IoTSentinel System Orchestrator

Main entry point that coordinates all system components:
- Zeek log parsing
- ML inference engine
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

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent))

from config.config_manager import config
from capture.zeek_log_parser import ZeekLogParser
from ml.inference_engine import InferenceEngine
from database.db_manager import DatabaseManager
from config.init_database import init_database as init_db
from services.hardware_monitor import HardwareMonitor, IS_RPI

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

    Coordinates the log parser and ML inference engine in a multi-threaded architecture.
    - Thread 1: Zeek log monitoring and parsing.
    - Thread 2: ML inference pipeline.
    - Thread 3: Daily database cleanup.
    - Thread 4: System health watchdog.
    - Thread 5: Hardware monitor (Pi only).
    """

    def __init__(self):
        """Initialize system components."""
        self._ensure_database_initialized()
        self.parser = ZeekLogParser()
        self.inference_engine = InferenceEngine()
        self.db = DatabaseManager(config.get('database', 'path'))

        # Threading control
        self.running = False
        self.threads = []

        logger.info("IoTSentinel orchestrator initialized")

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

        # Start hardware monitor thread (only on Pi)
        if IS_RPI:
            hardware_monitor = HardwareMonitor()
            hardware_thread = threading.Thread(
                target=hardware_monitor.monitor_loop,
                name="HardwareMonitorThread",
                daemon=True
            )
            hardware_thread.start()
            self.threads.append(hardware_thread)
            logger.info("Hardware monitor started.")

        logger.info("All components started. Orchestrator is running.")

    def _parser_loop(self):
        """Wrapper for the Zeek log parser's watch loop."""
        logger.info("Log parsing loop started.")
        try:
            # We can't use the watch_and_parse directly because it has a while True loop
            # that we can't break out of gracefully from here.
            # Instead, we'll call the parsing logic periodically.
            interval = config.get('parser', 'interval', default=60)
            while self.running:
                self.parser.parse_once()
                time.sleep(interval)
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
                time.sleep(interval)
        except Exception as e:
            logger.error(f"Error in inference loop: {e}", exc_info=True)
        logger.info("ML inference loop stopped.")

    def _cleanup_loop(self):
        """Periodically cleans up old database records."""
        logger.info("Database cleanup loop started.")
        try:
            # Run once a day
            cleanup_interval = 24 * 60 * 60  # 24 hours
            retention_days = config.get('database', 'retention_days', default=30)

            while self.running:
                logger.info(f"Running daily database cleanup (retention: {retention_days} days)...")
                self.db.cleanup_old_data(days=retention_days)

                # Sleep for 24 hours, but check for shutdown every minute
                for _ in range(24 * 60):
                    if not self.running:
                        break
                    time.sleep(60)

        except Exception as e:
            logger.error(f"Error in cleanup loop: {e}", exc_info=True)
        logger.info("Database cleanup loop stopped.")

    def _is_process_running(self, process_name: str) -> bool:
        """Check if a process with the given name is running."""
        for proc in psutil.process_iter(['name']):
            if process_name.lower() in proc.info['name'].lower():
                return True
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
                        # This assumes zeekctl is in the PATH and sudo is configured
                        subprocess.run(["sudo", "/opt/zeek/bin/zeekctl", "deploy"], check=True, capture_output=True, text=True)
                        logger.info("Zeek restart command executed successfully.")
                    except (subprocess.CalledProcessError, FileNotFoundError) as e:
                        logger.error(f"Failed to restart Zeek: {e}")

            except Exception as e:
                logger.error(f"Error during health check: {e}", exc_info=True)

            time.sleep(interval)
        logger.info("Health check loop stopped.")

    def stop(self):
        """Stop all system components gracefully."""
        logger.info("Stopping IoTSentinel orchestrator...")

        self.running = False

        # Wait for threads to finish
        for thread in self.threads:
            thread.join(timeout=10)

        self.db.close()
        logger.info("IoTSentinel orchestrator stopped.")

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
    orchestrator = IoTSentinelOrchestrator()
    orchestrator.start()

    logger.info("IoTSentinel is running. Press Ctrl+C to stop.")

    # Keep the main thread alive
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        if orchestrator:
            orchestrator.stop()
