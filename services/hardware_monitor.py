#!/usr/bin/env python3
"""
Hardware Monitor for IoTSentinel

- Lights a RED LED if a critical alert is active.
- Listens for a button press to pause/resume monitoring.

This service is designed to run only on a Raspberry Pi.
"""

import time
import sys
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from config.config_manager import config
from database.db_manager import DatabaseManager

# GPIO pins
LED_PIN = 18  # Red LED
BUTTON_PIN = 23 # Physical button

# --- Mock GPIO for non-Pi environments ---
try:
    import RPi.GPIO as GPIO
    IS_RPI = True
except (ImportError, RuntimeError):
    print("WARNING: RPi.GPIO not found. Using mock GPIO library.")
    IS_RPI = False

    class MockGPIO:
        BCM = "BCM"
        OUT = "OUT"
        IN = "IN"
        PUD_UP = "PUD_UP"
        HIGH = 1
        LOW = 0

        def setmode(self, mode):
            print(f"MockGPIO: Set mode to {mode}")

        def setup(self, pin, mode, pull_up_down=None):
            print(f"MockGPIO: Setup pin {pin} to mode {mode}")

        def output(self, pin, value):
            print(f"MockGPIO: Set pin {pin} to {'HIGH' if value else 'LOW'}")

        def input(self, pin):
            # To test button presses, you could simulate this
            return self.HIGH

        def cleanup(self):
            print("MockGPIO: Cleanup")

    GPIO = MockGPIO()
# --- End Mock GPIO ---


class HardwareMonitor:
    """Monitors hardware status and user input."""

    def __init__(self):
        self.db = DatabaseManager(config.get('database', 'path'))
        self.status_file_path = Path(config.get('system', 'status_file_path', default='config/monitoring_status.json'))
        self._setup_gpio()

    def _setup_gpio(self):
        """Configure GPIO pins."""
        if not IS_RPI:
            return
        GPIO.setmode(GPIO.BCM)
        GPIO.setup(LED_PIN, GPIO.OUT)
        GPIO.setup(BUTTON_PIN, GPIO.IN, pull_up_down=GPIO.PUD_UP)
        GPIO.output(LED_PIN, GPIO.LOW) # Turn off LED on start

    def _is_monitoring_paused(self):
        """Check if monitoring is paused."""
        try:
            with open(self.status_file_path, 'r') as f:
                return json.load(f).get('status') == 'paused'
        except (FileNotFoundError, json.JSONDecodeError):
            return False

    def _toggle_pause(self):
        """Toggle the monitoring pause state."""
        new_status = 'paused' if not self._is_monitoring_paused() else 'running'
        try:
            with open(self.status_file_path, 'w') as f:
                json.dump({'status': new_status}, f)
            print(f"Monitoring status set to: {new_status}")
        except IOError as e:
            print(f"Error writing status file: {e}")

    def monitor_loop(self):
        """Main monitoring loop."""
        print("Hardware monitor started.")
        try:
            while True:
                # Check for critical alerts
                alerts = self.db.get_recent_alerts(hours=1)
                critical_active = any(
                    a['severity'] == 'critical' and not a['acknowledged']
                    for a in alerts
                )
                GPIO.output(LED_PIN, GPIO.HIGH if critical_active else GPIO.LOW)

                # Check for button press
                if GPIO.input(BUTTON_PIN) == GPIO.LOW:
                    print("Button pressed!")
                    self._toggle_pause()
                    time.sleep(1) # Debounce

                time.sleep(2)
        except KeyboardInterrupt:
            print("Stopping hardware monitor...")
        finally:
            if IS_RPI:
                GPIO.cleanup()
            self.db.close()
            print("Hardware monitor stopped.")


if __name__ == '__main__':
    monitor = HardwareMonitor()
    monitor.monitor_loop()
