#!/usr/bin/env python3
"""AccessPointManager — bring the IoTSentinel Wi-Fi access point up and down.

Thin, defensive wrapper over config/configure_ap.sh (NetworkManager shared mode).
Used by the orchestrator at startup (gateway mode) and by the connectivity watchdog
to roll the AP back if the home-Wi-Fi uplink drops. Every operation is best-effort
and never raises — on a dev machine (no nmcli / no passwordless sudo) it simply
no-ops, so importing and calling this is always safe.

The companion script only ever manages its own "iotsentinel-ap" connection profile
on the AP interface; it never touches the home-Wi-Fi uplink connection.
"""

import logging
import os
import subprocess

from config.config_manager import config

logger = logging.getLogger(__name__)

_SCRIPT = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "config", "configure_ap.sh",
)
_CON_NAME = "iotsentinel-ap"


class AccessPointManager:
    """Manage the IoT access point via config/configure_ap.sh."""

    def __init__(self):
        self.script = _SCRIPT
        self.con_name = _CON_NAME

    def is_enabled(self) -> bool:
        """True when capture_mode is 'gateway'."""
        return (config.get("network", "capture_mode", default="passive") or "passive") == "gateway"

    def _run(self, *args, timeout: int = 60) -> bool:
        if not os.path.isfile(self.script):
            logger.warning("configure_ap.sh missing — cannot manage access point.")
            return False
        try:
            # Invoke the script directly (it is executable with a bash shebang) so the
            # sudoers rule can match an exact path rather than a fragile "bash <script>".
            r = subprocess.run(
                ["sudo", "-n", self.script, *args],
                check=False, capture_output=True, text=True, timeout=timeout,
            )
            if r.returncode != 0:
                logger.warning("configure_ap.sh %s exited %d: %s",
                               " ".join(args), r.returncode,
                               (r.stderr or "").strip()[:200])
            return r.returncode == 0
        except subprocess.TimeoutExpired:
            logger.error("configure_ap.sh %s timed out.", " ".join(args))
            return False
        except Exception as e:
            logger.error("Access point command failed: %s", e)
            return False

    def start(self) -> bool:
        """Bring the AP up (gateway mode only). Returns True on success."""
        if not self.is_enabled():
            logger.info("Capture mode is not 'gateway' — access point not started.")
            return False
        logger.info("Bringing up IoTSentinel access point …")
        return self._run()

    def stop(self) -> bool:
        """Tear the AP down (rollback / safe-mode). Returns True on success."""
        logger.info("Bringing down IoTSentinel access point …")
        return self._run("--down")

    def status(self) -> dict:
        """Report whether the AP profile is currently active."""
        active = False
        try:
            r = subprocess.run(
                ["nmcli", "-t", "-f", "NAME", "connection", "show", "--active"],
                capture_output=True, text=True, timeout=5,
            )
            active = any(line.strip() == self.con_name for line in r.stdout.splitlines())
        except Exception:
            pass
        return {"enabled": self.is_enabled(), "active": active, "connection": self.con_name}
