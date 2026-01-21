#!/usr/bin/env python3
"""
Hardware Monitor for IoTSentinel

- Lights a RED LED if a critical alert is active.
- Listens for a button press to pause/resume monitoring.

This service is designed to run only on a Raspberry Pi.
"""

import time
import sys
import json
import logging
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from config.config_manager import config
from database.db_manager import DatabaseManager

# Configure logging
logger = logging.getLogger('hardware')  # Use dedicated hardware logger

# GPIO pins
LED_PIN = 18  # Red LED (BCM numbering)
BUTTON_PIN = 23 # Physical button (BCM numbering)

# --- Mock GPIO for non-Pi environments ---
class MockGPIO:
    """Mock GPIO class for testing on non-Pi systems."""
    BCM = "BCM"
    OUT = "OUT"
    IN = "IN"
    PUD_UP = "PUD_UP"
    HIGH = 1
    LOW = 0

    def setmode(self, mode):
        pass

    def setup(self, pin, mode, pull_up_down=None):
        pass

    def output(self, pin, value):
        pass

    def input(self, pin):
        return self.HIGH

    def cleanup(self):
        pass


# Try to import real GPIO libraries
_IS_REAL_RPI_GPIO_AVAILABLE = False
_GPIO_LIBRARY = None
GPIO = None

if sys.platform.startswith('linux'):
    # Try RPi.GPIO first (works on Pi 1-4)
    try:
        import RPi.GPIO as GPIO
        _IS_REAL_RPI_GPIO_AVAILABLE = True
        _GPIO_LIBRARY = "RPi.GPIO"
        logger.info("Using RPi.GPIO library")
    except (ImportError, RuntimeError) as e:
        logger.debug(f"RPi.GPIO not available: {e}")

        # Try lgpio/gpiod for Pi 5
        try:
            import gpiod
            _GPIO_LIBRARY = "gpiod"
            logger.info("Using gpiod library (Pi 5 compatible)")
            # Note: gpiod has a different API, we'll handle this in the class
        except ImportError:
            logger.debug("gpiod not available either")

if _GPIO_LIBRARY is None:
    GPIO = MockGPIO()
    logger.info("Using mock GPIO for hardware monitoring.")
    _IS_REAL_RPI_GPIO_AVAILABLE = False

# Export IS_RPI flag for use by other modules
IS_RPI = _IS_REAL_RPI_GPIO_AVAILABLE
# --- End Mock GPIO ---


class HardwareMonitor:
    """Monitors hardware status and user input."""

    def __init__(self):
        self.db = DatabaseManager(config.get('database', 'path'))
        self.status_file_path = Path(config.get('system', 'status_file_path', default='config/monitoring_status.json'))
        self.is_mock_gpio = not _IS_REAL_RPI_GPIO_AVAILABLE
        self.gpio_library = _GPIO_LIBRARY
        self.gpio_initialized = False
        self.running = False

        # For gpiod
        self.chip = None
        self.led_line = None
        self.button_line = None

        self._setup_gpio()

    def _setup_gpio(self):
        """Configure GPIO pins."""
        if self.is_mock_gpio:
            logger.info("Hardware monitor initialized with mock GPIO (no physical hardware)")
            logger.info("🔧 HARDWARE: Mock GPIO mode - no physical LED/button control")
            self.gpio_initialized = True
            return

        # Setup based on library type
        if self.gpio_library == "RPi.GPIO":
            try:
                GPIO.setmode(GPIO.BCM)
                GPIO.setup(LED_PIN, GPIO.OUT)
                GPIO.setup(BUTTON_PIN, GPIO.IN, pull_up_down=GPIO.PUD_UP)
                GPIO.output(LED_PIN, GPIO.LOW)
                self.gpio_initialized = True
                logger.info("GPIO pins configured successfully with RPi.GPIO")
                logger.info(f"🔧 HARDWARE: RPi.GPIO initialized - LED:GPIO{LED_PIN}, Button:GPIO{BUTTON_PIN}")
            except Exception as e:
                logger.error(f"Failed to configure GPIO with RPi.GPIO: {e}")
                logger.error(f"🔧 HARDWARE: GPIO initialization failed - {str(e)}")
                self._fallback_to_mock()

        elif self.gpio_library == "gpiod":
            try:
                import gpiod
                # Pi 5 uses gpiochip4
                self.chip = gpiod.Chip('gpiochip4')

                # Setup LED (output)
                self.led_line = self.chip.get_line(LED_PIN)
                self.led_line.request(consumer="IoTSentinel", type=gpiod.LINE_REQ_DIR_OUT)
                self.led_line.set_value(0)  # Turn off LED

                # Setup button (input with pull-up)
                self.button_line = self.chip.get_line(BUTTON_PIN)
                self.button_line.request(
                    consumer="IoTSentinel",
                    type=gpiod.LINE_REQ_DIR_IN,
                    flags=gpiod.LINE_REQ_FLAG_BIAS_PULL_UP
                )

                self.gpio_initialized = True
                logger.info("GPIO pins configured successfully with gpiod (Pi 5)")
                logger.info(f"🔧 HARDWARE: gpiod initialized (Pi 5) - LED:GPIO{LED_PIN}, Button:GPIO{BUTTON_PIN}")
            except Exception as e:
                logger.error(f"Failed to configure GPIO with gpiod: {e}")
                logger.error(f"🔧 HARDWARE: gpiod initialization failed (Pi 5) - {str(e)}")
                self._fallback_to_mock()

    def _fallback_to_mock(self):
        """Fall back to mock GPIO mode."""
        logger.warning("Falling back to mock GPIO mode")
        logger.warning("🔧 HARDWARE: Switched to mock GPIO - physical controls disabled")
        self.is_mock_gpio = True
        self.gpio_initialized = True
        global GPIO
        GPIO = MockGPIO()

    def _is_monitoring_paused(self):
        """Check if monitoring is paused."""
        try:
            if not self.status_file_path.exists():
                return False
            with open(self.status_file_path, 'r') as f:
                return json.load(f).get('status') == 'paused'
        except (FileNotFoundError, json.JSONDecodeError) as e:
            logger.debug(f"Could not read status file: {e}")
            return False

    def _toggle_pause(self):
        """Toggle the monitoring pause state."""
        new_status = 'paused' if not self._is_monitoring_paused() else 'running'
        try:
            self.status_file_path.parent.mkdir(parents=True, exist_ok=True)
            with open(self.status_file_path, 'w') as f:
                json.dump({'status': new_status}, f)
            logger.info(f"Monitoring status set to: {new_status}")
            logger.info(f"🔧 HARDWARE: Monitoring status changed to {new_status.upper()}")
        except IOError as e:
            logger.error(f"Error writing status file: {e}")
            logger.error(f"🔧 HARDWARE: Failed to update status file - {str(e)}")

    def _set_led(self, state: bool):
        """Set LED state (on/off)."""
        if self.is_mock_gpio:
            return

        try:
            if self.gpio_library == "RPi.GPIO":
                GPIO.output(LED_PIN, GPIO.HIGH if state else GPIO.LOW)
            elif self.gpio_library == "gpiod":
                self.led_line.set_value(1 if state else 0)
            logger.debug(f"🔧 HARDWARE: LED {'ON' if state else 'OFF'} (GPIO{LED_PIN})")
        except Exception as e:
            logger.debug(f"Error setting LED: {e}")
            logger.error(f"🔧 HARDWARE: LED control error - {str(e)}")

    def _read_button(self) -> bool:
        """Read button state (True if pressed)."""
        if self.is_mock_gpio:
            return False

        try:
            if self.gpio_library == "RPi.GPIO":
                result = GPIO.input(BUTTON_PIN) == GPIO.LOW
            elif self.gpio_library == "gpiod":
                result = self.button_line.get_value() == 0  # Active low

            if result:  # Only log when button is actually pressed
                logger.debug(f"🔧 HARDWARE: Button pressed (GPIO{BUTTON_PIN})")
            return result
        except Exception as e:
            logger.debug(f"Error reading button: {e}")
            logger.error(f"🔧 HARDWARE: Button read error - {str(e)}")
            return False

    def stop(self):
        """Signal the monitor loop to stop."""
        logger.info("Hardware monitor stop requested.")
        self.running = False

    def monitor_loop(self):
        """Main monitoring loop."""
        if not self.gpio_initialized:
            logger.error("GPIO not initialized. Hardware monitor cannot start.")
            logger.error("🔧 HARDWARE: Monitor cannot start - GPIO initialization failed")
            return

        logger.info("Hardware monitor started.")
        logger.info("🔧 HARDWARE: Monitor loop started - watching for critical alerts")
        self.running = True

        try:
            while self.running:
                if self.is_mock_gpio:
                    time.sleep(2)
                    continue

                # Check for critical alerts
                try:
                    alerts = self.db.get_recent_alerts(hours=1)
                    critical_active = any(
                        a['severity'] == 'critical' and not a['acknowledged']
                        for a in alerts
                    )
                    if critical_active:
                        logger.info("🔧 HARDWARE: Critical alert active - LED indicator enabled")
                    self._set_led(critical_active)
                except Exception as e:
                    logger.debug(f"Error checking alerts: {e}")

                # Check for button press
                if self._read_button():
                    logger.info("Button pressed!")
                    self._toggle_pause()
                    time.sleep(1)  # Debounce

                time.sleep(2)

        except KeyboardInterrupt:
            logger.info("Hardware monitor interrupted by user.")
        except Exception as e:
            logger.error(f"Unexpected error in hardware monitor: {e}", exc_info=True)
        finally:
            # Cleanup
            if not self.is_mock_gpio and self.gpio_initialized:
                try:
                    if self.gpio_library == "RPi.GPIO":
                        GPIO.cleanup()
                    elif self.gpio_library == "gpiod":
                        if self.led_line:
                            self.led_line.release()
                        if self.button_line:
                            self.button_line.release()
                        if self.chip:
                            self.chip.close()
                    logger.info("GPIO cleanup complete.")
                except Exception as e:
                    logger.error(f"Error during GPIO cleanup: {e}")

            self.db.close()
            logger.info("Hardware monitor stopped.")


if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO)
    monitor = HardwareMonitor()
    monitor.monitor_loop()
