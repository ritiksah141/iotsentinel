#!/usr/bin/env python3
"""
FirewallEnforcer — real network-level device blocking for IoTSentinel.

Two backends (auto-selected at init):
  • local   — local iptables/nftables on the Pi. Enforces for all traffic
               routed THROUGH the Pi (hotspot / NAT gateway deployments).
  • router  — SSH to an OpenWrt router via scripts/firewall_manager.py.
               Enforces LAN-wide even when the Pi is a passive monitor.

Auto-select: router backend if config firewall.enabled=true AND router_ip is
set; otherwise local iptables.

All changes are audit-logged to data/logs/audit.log.
"""

import json
import logging
import os
import subprocess
from datetime import datetime
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)


def _priv(cmd: list) -> list:
    """Prefix a privileged command with `sudo -n` unless already running as root.

    The backend runs as an unprivileged service user (User=sentinel), so nft and
    iptables need elevation. setup_pi.sh grants NOPASSWD sudo for exactly these two
    binaries, so this never prompts. Already-root deployments skip sudo.
    """
    try:
        if os.geteuid() == 0:
            return cmd
    except AttributeError:
        pass  # non-POSIX (dev only) — sudo path is harmless there
    return ["sudo", "-n"] + cmd


CHAIN = "IOTSENTINEL"
_AUDIT_LOG = Path("data/logs/audit.log")
_BACKUP_PATH = Path("data/firewall_backup.nft")

# Ports that must never be blocked, regardless of user rules
_FAILSAFE_PORTS = [22, 8050]


def _capture_mode() -> str:
    """Current capture mode ('passive' | 'gateway')."""
    try:
        from config.config_manager import config as _cfg
        return _cfg.get('network', 'capture_mode', 'passive') or 'passive'
    except Exception:
        return 'passive'


def _ap_gateway_ip() -> Optional[str]:
    """The Pi's AP gateway address — the first host of the configured AP subnet
    (e.g. 10.42.0.1 for 10.42.0.0/24). This is the Pi itself on the IoT segment."""
    try:
        import ipaddress
        from config.config_manager import config as _cfg
        subnet = _cfg.get('network', 'ap_subnet', '10.42.0.0/24') or '10.42.0.0/24'
        return str(ipaddress.ip_network(subnet, strict=False).network_address + 1)
    except Exception:
        return None


def _failsafe_accept_nets() -> list:
    """Source networks the FORWARD chain always accepts so management can never be
    locked out.

    In gateway mode the IoT devices live on the AP subnet (inside 10.0.0.0/8) and we
    MUST be able to block them, so we deliberately do NOT blanket-accept 10.0.0.0/8
    there — only the AP gateway (the Pi) itself. Otherwise an `ip saddr 10.0.0.0/8
    accept` rule would match before any device drop rule and silently defeat
    enforcement. Passive/router deployments keep the original broad whitelist.
    """
    nets = ["192.168.0.0/16", "172.16.0.0/12"]
    if _capture_mode() == 'gateway':
        gw = _ap_gateway_ip()
        if gw:
            nets.append(f"{gw}/32")
    else:
        nets.append("10.0.0.0/8")
    return nets


# ---------------------------------------------------------------------------
# Self-lockout guard — never auto-block the admin's own device or the router
# ---------------------------------------------------------------------------
# A callable that returns the current protected admin IP.  Injected from
# dashboard/shared.py after db_manager is ready; avoids a circular import.
_protected_ip_provider = None


def set_protected_ip_provider(fn):
    """
    Register a callable that returns the admin's current IP address.

    Called from dashboard/shared.py so the firewall can refuse to block the
    IP the admin is using to access the dashboard.

    Example::
        set_protected_ip_provider(lambda: db_manager.get_setting('protected_admin_ip'))
    """
    global _protected_ip_provider
    _protected_ip_provider = fn


def _is_protected_ip(ip: str) -> bool:
    """
    Return True if the IP must never be auto-blocked.

    Covers three cases:
    1. The logged-in admin's current browser IP (from system_settings).
    2. The configured router/gateway IP from config.firewall.router_ip.
    3. The runtime-detected default gateway (Pi's upstream router).
    """
    if not ip:
        return False

    # 1. Admin's current browser IP (persisted on each login)
    if _protected_ip_provider is not None:
        try:
            protected = _protected_ip_provider()
            if protected and ip == protected:
                return True
        except Exception:
            pass

    # 2. Static router IP from config
    try:
        from config.config_manager import config as _cfg
        router_ip = _cfg.get('firewall', 'router_ip', '') or ''
        if router_ip and ip == router_ip:
            return True
    except Exception:
        pass

    # 3. Runtime-detected default gateway
    try:
        from utils.network_monitor import get_default_gateway
        gw = get_default_gateway()
        if gw and ip == gw:
            return True
    except Exception:
        pass

    # 4. The Pi's own AP gateway (gateway mode) — never firewall the access point
    #    that the IoT devices depend on for DHCP/DNS/NAT.
    try:
        ap_gw = _ap_gateway_ip()
        if ap_gw and ip == ap_gw:
            return True
    except Exception:
        pass

    return False


def _audit(action: str, target: str, success: bool, detail: str = "", dry_run: bool = False):
    """Append a structured line to the audit log."""
    try:
        _AUDIT_LOG.parent.mkdir(parents=True, exist_ok=True)
        line = json.dumps({
            "ts": datetime.utcnow().isoformat(),
            "subsystem": "firewall",
            "action": action,
            "target": target,
            "success": success,
            "dry_run": dry_run,
            "detail": detail,
        })
        with open(_AUDIT_LOG, "a") as f:
            f.write(line + "\n")
    except Exception as e:
        logger.warning(f"Audit log write failed: {e}")


class _LocalBackend:
    """
    Enforce rules on the Pi itself.

    Auto-detects at init: uses native nftables if `nft` is available (Pi OS
    Bookworm default), otherwise falls back to iptables.

    Safety guarantees (nftables path only):
    - Failsafe whitelist (RFC-1918 + SSH + dashboard) is installed before any
      user rules, so the Pi can never block itself out.
    - Full ruleset backup is written to data/firewall_backup.nft before every
      destructive change; restore with: nft -f data/firewall_backup.nft
    """

    _NF_TABLE = "iotsentinel"
    _NF_CHAIN = "forward"

    def __init__(self):
        self._use_nft = self._detect_nft()
        self._nft_chain_ready = False  # track whether we've run ensure-chain this session
        logger.info("LocalBackend: %s", "nftables" if self._use_nft else "iptables")

    # ------------------------------------------------------------------
    # Detection
    # ------------------------------------------------------------------

    @staticmethod
    def _detect_nft() -> bool:
        try:
            r = subprocess.run(["nft", "--version"], capture_output=True, text=True)
            return r.returncode == 0
        except FileNotFoundError:
            return False

    # ------------------------------------------------------------------
    # nftables helpers
    # ------------------------------------------------------------------

    def _nft(self, *args, dry_run: bool = False) -> tuple[bool, str]:
        cmd = _priv(["nft"] + list(args))
        if dry_run:
            logger.info("[dry-run] %s", " ".join(cmd))
            return True, ""
        try:
            r = subprocess.run(cmd, capture_output=True, text=True)
            if r.returncode != 0 and r.stderr:
                err = r.stderr.strip()
                if "already exists" in err or "No such" in err:
                    return True, err
                return False, err
            return True, r.stdout.strip()
        except FileNotFoundError:
            return False, "nft not found"
        except Exception as e:
            return False, str(e)

    def _nft_backup(self):
        """Snapshot the full ruleset before any change."""
        try:
            _BACKUP_PATH.parent.mkdir(parents=True, exist_ok=True)
            r = subprocess.run(_priv(["nft", "list", "ruleset"]), capture_output=True, text=True)
            if r.returncode == 0:
                _BACKUP_PATH.write_text(r.stdout)
        except Exception as e:
            logger.warning("Firewall backup failed: %s", e)

    def _nft_ensure_chain(self, dry_run: bool = False):
        """Idempotent setup: table → chain → failsafe whitelist rules."""
        if self._nft_chain_ready and not dry_run:
            return

        # 'add table' and 'add chain' are idempotent in nftables
        self._nft("add", "table", "inet", self._NF_TABLE, dry_run=dry_run)

        # Check if chain already exists (has its hook); only set type/hook on creation
        chain_check = subprocess.run(
            _priv(["nft", "list", "chain", "inet", self._NF_TABLE, self._NF_CHAIN]),
            capture_output=True, text=True
        )
        if chain_check.returncode != 0:
            # Create chain with hook and failsafe rules atomically
            script = (
                f"add chain inet {self._NF_TABLE} {self._NF_CHAIN} "
                f"{{ type filter hook forward priority -10; policy accept; }}\n"
                + "\n".join(
                    f"add rule inet {self._NF_TABLE} {self._NF_CHAIN} ip saddr {net} accept"
                    for net in _failsafe_accept_nets()
                ) + "\n"
                + "\n".join(
                    f"add rule inet {self._NF_TABLE} {self._NF_CHAIN} tcp dport {p} accept"
                    for p in _FAILSAFE_PORTS
                )
            )
            if dry_run:
                logger.info("[dry-run] nft chain setup:\n%s", script)
            else:
                try:
                    subprocess.run(_priv(["nft", "-f", "-"]), input=script,
                                   capture_output=True, text=True, check=False)
                except Exception as e:
                    logger.error("nft chain setup failed: %s", e)

        if not dry_run:
            self._nft_chain_ready = True

    def _nft_handles_for(self, pattern: str) -> list[str]:
        """Return rule handles whose text contains `pattern`."""
        r = subprocess.run(
            _priv(["nft", "-a", "list", "chain", "inet", self._NF_TABLE, self._NF_CHAIN]),
            capture_output=True, text=True
        )
        handles = []
        for line in r.stdout.splitlines():
            if pattern in line and "# handle" in line:
                h = line.split("# handle")[-1].strip()
                handles.append(h)
        return handles

    def _nft_delete_rules(self, pattern: str, dry_run: bool = False) -> bool:
        handles = self._nft_handles_for(pattern)
        ok = True
        for h in handles:
            success, err = self._nft(
                "delete", "rule", "inet", self._NF_TABLE, self._NF_CHAIN, "handle", h,
                dry_run=dry_run
            )
            if not success:
                ok = False
                logger.error("nft delete handle %s failed: %s", h, err)
        return ok  # True even if no handles found (already unblocked)

    # ------------------------------------------------------------------
    # iptables helpers (fallback)
    # ------------------------------------------------------------------

    def _ipt(self, *args, dry_run: bool = False) -> tuple[bool, str]:
        cmd = _priv(["iptables"] + list(args))
        if dry_run:
            logger.info("[dry-run] %s", " ".join(cmd))
            return True, ""
        try:
            r = subprocess.run(cmd, capture_output=True, text=True)
            if r.returncode != 0 and r.stderr:
                err = r.stderr.strip()
                if "already exists" in err or "does not exist" in err or "No chain" in err:
                    return True, err
                return False, err
            return True, r.stdout.strip()
        except FileNotFoundError:
            return False, "iptables not found"
        except Exception as e:
            return False, str(e)

    def _ipt_ensure_chain(self, dry_run: bool = False):
        self._ipt("-N", CHAIN, dry_run=dry_run)
        self._ipt("-C", "FORWARD", "-j", CHAIN, dry_run=dry_run)
        self._ipt("-I", "FORWARD", "1", "-j", CHAIN, dry_run=dry_run)

    # ------------------------------------------------------------------
    # Public interface — dispatches to nft or ipt path
    # ------------------------------------------------------------------

    def block_ip(self, ip: str, dry_run: bool = False) -> bool:
        if self._use_nft:
            self._nft_backup()
            self._nft_ensure_chain(dry_run=dry_run)
            ok1, e1 = self._nft("add", "rule", "inet", self._NF_TABLE, self._NF_CHAIN,
                                "ip", "saddr", ip, "drop", dry_run=dry_run)
            ok2, e2 = self._nft("add", "rule", "inet", self._NF_TABLE, self._NF_CHAIN,
                                "ip", "daddr", ip, "drop", dry_run=dry_run)
            ok, err = ok1 and ok2, f"{e1} {e2}".strip()
        else:
            self._ipt_ensure_chain(dry_run=dry_run)
            ok, err = self._ipt("-A", CHAIN, "-s", ip, "-j", "DROP", dry_run=dry_run)
            if ok:
                self._ipt("-A", CHAIN, "-d", ip, "-j", "DROP", dry_run=dry_run)
        _audit("block_ip", ip, ok, err, dry_run=dry_run)
        if not ok:
            logger.error("[local] block_ip(%s) failed: %s", ip, err)
        return ok

    def unblock_ip(self, ip: str, dry_run: bool = False) -> bool:
        if self._use_nft:
            self._nft_backup()
            ok = self._nft_delete_rules(f"saddr {ip} drop", dry_run) and \
                 self._nft_delete_rules(f"daddr {ip} drop", dry_run)
            err = ""
        else:
            ok1, e1 = self._ipt("-D", CHAIN, "-s", ip, "-j", "DROP", dry_run=dry_run)
            ok2, e2 = self._ipt("-D", CHAIN, "-d", ip, "-j", "DROP", dry_run=dry_run)
            ok, err = ok1 and ok2, f"{e1} {e2}".strip()
        _audit("unblock_ip", ip, ok, err, dry_run=dry_run)
        return ok

    def block_mac(self, mac: str, dry_run: bool = False) -> bool:
        if self._use_nft:
            self._nft_backup()
            self._nft_ensure_chain(dry_run=dry_run)
            ok, err = self._nft("add", "rule", "inet", self._NF_TABLE, self._NF_CHAIN,
                                "ether", "saddr", mac, "drop", dry_run=dry_run)
        else:
            self._ipt_ensure_chain(dry_run=dry_run)
            ok, err = self._ipt("-A", CHAIN, "-m", "mac", "--mac-source", mac,
                                "-j", "DROP", dry_run=dry_run)
        _audit("block_mac", mac, ok, err, dry_run=dry_run)
        return ok

    def unblock_mac(self, mac: str, dry_run: bool = False) -> bool:
        if self._use_nft:
            self._nft_backup()
            ok = self._nft_delete_rules(f"ether saddr {mac} drop", dry_run)
            err = ""
        else:
            ok, err = self._ipt("-D", CHAIN, "-m", "mac", "--mac-source", mac,
                                "-j", "DROP", dry_run=dry_run)
        _audit("unblock_mac", mac, ok, err, dry_run=dry_run)
        return ok

    def is_blocked_ip(self, ip: str) -> bool:
        if self._use_nft:
            return bool(self._nft_handles_for(f"saddr {ip} drop"))
        ok, _ = self._ipt("-C", CHAIN, "-s", ip, "-j", "DROP")
        return ok

    def list_rules(self) -> list:
        if self._use_nft:
            ok, out = self._nft("list", "chain", "inet", self._NF_TABLE, self._NF_CHAIN)
            # The chain is only created on the first block, so on a fresh system it
            # doesn't exist yet. _nft maps that "No such file or directory" to ok=True
            # with the error TEXT as output — never surface that as an "active rule".
            # No chain == nothing blocked == no active rules.
            if not ok or "No such" in out or out.lstrip().lower().startswith("error"):
                return []
        else:
            ok, out = self._ipt("-L", CHAIN, "-n", "--line-numbers")
            if not ok:
                return []
        return [ln.strip() for ln in out.splitlines() if ln.strip()]

    def name(self) -> str:
        return "local_nftables" if self._use_nft else "local_iptables"


class _RouterBackend:
    """Enforce rules via SSH to an OpenWrt router (wraps scripts/firewall_manager.py)."""

    def __init__(self):
        # Import lazily so missing paramiko doesn't break the whole module
        from scripts import firewall_manager as _fm
        self._fm = _fm

    def block_ip(self, ip: str, dry_run: bool = False) -> bool:
        # firewall_manager works on MAC addresses; we need the device MAC.
        # We accept IP and log a warning that router backend needs MAC.
        # Callers should prefer block_mac for the router backend.
        logger.warning(
            f"Router backend: block_ip({ip}) — router backend requires MAC address. "
            "Use block_mac() for reliable enforcement via the router."
        )
        _audit("block_ip_router_warn", ip, False,
               "router backend needs MAC address", dry_run=dry_run)
        return False

    def unblock_ip(self, ip: str, dry_run: bool = False) -> bool:
        logger.warning(f"Router backend: unblock_ip({ip}) — needs MAC. Use unblock_mac().")
        return False

    def block_mac(self, mac: str, dry_run: bool = False) -> bool:
        if dry_run:
            logger.info(f"[dry-run] router.block_device({mac})")
            _audit("block_mac", mac, True, "dry_run", dry_run=True)
            return True
        ok = self._fm.block_device(mac)
        _audit("block_mac", mac, ok, "router SSH", dry_run=False)
        return ok

    def unblock_mac(self, mac: str, dry_run: bool = False) -> bool:
        if dry_run:
            logger.info(f"[dry-run] router.unblock_device({mac})")
            _audit("unblock_mac", mac, True, "dry_run", dry_run=True)
            return True
        ok = self._fm.unblock_device(mac)
        _audit("unblock_mac", mac, ok, "router SSH", dry_run=False)
        return ok

    def is_blocked_ip(self, ip: str) -> bool:
        return False  # router has no cheap check-by-IP

    def list_rules(self) -> list:
        return ["(router backend — view rules on the router directly)"]

    def name(self) -> str:
        return "router_ssh"


class FirewallEnforcer:
    """
    Public interface for firewall operations.

    Usage::
        from utils.firewall_enforcer import firewall_enforcer  # shared singleton

        firewall_enforcer.block_ip("192.168.1.42")
        firewall_enforcer.block_ip("192.168.1.42", dry_run=True)  # preview only
        firewall_enforcer.unblock_ip("192.168.1.42")
        firewall_enforcer.list_rules()
    """

    def __init__(self):
        from config.config_manager import config as _config
        router_enabled = str(_config.get('firewall', 'enabled', 'false')).lower() == 'true'
        router_ip = _config.get('firewall', 'router_ip', '')

        if router_enabled and router_ip:
            try:
                self._backend = _RouterBackend()
                logger.info("FirewallEnforcer: using router_ssh backend")
            except Exception as e:
                logger.warning(f"Router backend unavailable ({e}), falling back to local iptables")
                self._backend = _LocalBackend()
        else:
            self._backend = _LocalBackend()
            logger.info("FirewallEnforcer: using %s backend", self._backend.name())

    @property
    def backend_name(self) -> str:
        return self._backend.name()

    def block_ip(self, ip: str, dry_run: bool = False) -> bool:
        if _is_protected_ip(ip):
            logger.warning(
                "[firewall] Refused to block protected IP %s (admin/router/gateway)", ip
            )
            _audit("block_ip_refused", ip, False, "protected IP — admin/router/gateway")
            return False
        return self._backend.block_ip(ip, dry_run=dry_run)

    def unblock_ip(self, ip: str, dry_run: bool = False) -> bool:
        return self._backend.unblock_ip(ip, dry_run=dry_run)

    def block_mac(self, mac: str, dry_run: bool = False) -> bool:
        return self._backend.block_mac(mac, dry_run=dry_run)

    def unblock_mac(self, mac: str, dry_run: bool = False) -> bool:
        return self._backend.unblock_mac(mac, dry_run=dry_run)

    def block_device(self, ip: str, mac: Optional[str] = None, dry_run: bool = False) -> bool:
        """Block by IP (and MAC if provided for router backend)."""
        if _is_protected_ip(ip):
            logger.warning(
                "[firewall] Refused to block protected device %s (admin/router/gateway)", ip
            )
            _audit("block_device_refused", ip, False, "protected IP — admin/router/gateway")
            return False
        if mac and isinstance(self._backend, _RouterBackend):
            return self.block_mac(mac, dry_run=dry_run)
        return self.block_ip(ip, dry_run=dry_run)

    def unblock_device(self, ip: str, mac: Optional[str] = None, dry_run: bool = False) -> bool:
        if mac and isinstance(self._backend, _RouterBackend):
            return self.unblock_mac(mac, dry_run=dry_run)
        return self.unblock_ip(ip, dry_run=dry_run)

    def is_blocked(self, ip: str) -> bool:
        return self._backend.is_blocked_ip(ip)

    def list_rules(self) -> list:
        return self._backend.list_rules()

    def rollback(self) -> bool:
        """Restore the last pre-change backup (nftables only)."""
        if not _BACKUP_PATH.exists():
            logger.warning("No firewall backup found at %s", _BACKUP_PATH)
            return False
        try:
            r = subprocess.run(_priv(["nft", "-f", str(_BACKUP_PATH)]), capture_output=True, text=True)
            ok = r.returncode == 0
            _audit("rollback", str(_BACKUP_PATH), ok, r.stderr.strip() if not ok else "")
            return ok
        except Exception as e:
            logger.error("Firewall rollback failed: %s", e)
            return False

    @property
    def backup_path(self) -> Optional[Path]:
        return _BACKUP_PATH if _BACKUP_PATH.exists() else None


# Module-level singleton — import this in callbacks / orchestrator
try:
    firewall_enforcer = FirewallEnforcer()
except Exception as _e:
    logger.error(f"FirewallEnforcer init failed: {_e}")

    class _NoopEnforcer:
        backend_name = "noop"
        backup_path = None
        def block_ip(self, *a, **kw): return False
        def unblock_ip(self, *a, **kw): return False
        def block_mac(self, *a, **kw): return False
        def unblock_mac(self, *a, **kw): return False
        def block_device(self, *a, **kw): return False
        def unblock_device(self, *a, **kw): return False
        def is_blocked(self, *a, **kw): return False
        def list_rules(self): return []
        def rollback(self): return False

    firewall_enforcer = _NoopEnforcer()
