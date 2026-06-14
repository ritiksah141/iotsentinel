#!/usr/bin/env python3
"""
SecurityAgent — active IDS: detect -> classify -> decide -> enforce -> report.

The agent polls for new, unacknowledged high/critical alerts, decides on a
remediation action, and enforces it autonomously (no human gate required).

Autonomy model:
  LOW-RISK  (auto-execute): mark device suspicious in DB, send a notification,
            acknowledge low-severity alerts.
  HIGH-RISK (auto-enforce): firewall block via FirewallEnforcer.block_device()
            when agent.auto_block.enabled is true (default).
            Falls back to queue-for-approval when auto_block is disabled.

Investigation includes live AbuseIPDB lookups for external destination IPs so
high-confidence malicious destinations are also blocked at the network level.

CVE matching runs on every new-device join and persists results to the
device_vulnerabilities_detected table for the dashboard to surface.

Self-lockout guard: the FirewallEnforcer.block_ip/block_device methods refuse
to block the admin's current IP, the configured router, or the default gateway.

Plain-English incident reports are generated via HybridAIAssistant and stored
in the agent_actions table.
"""

import json
import logging
from datetime import datetime, timedelta
from typing import Optional, List, Tuple

logger = logging.getLogger(__name__)

# How often the agent scans for new alerts (seconds)
AGENT_INTERVAL = 60

# Only act on alerts newer than this window on each scan
ALERT_WINDOW_MINUTES = 5

# Policy: maps (severity, attack_type) → (action_type, risk_level)
# '*' is a wildcard for attack_type.
_POLICY: list[tuple] = [
    # (severity, attack_type_contains,   action_type,      risk_level)
    ('critical', 'COMPROMISED',          'firewall_block', 'high'),
    ('critical', 'COMMAND_AND_CONTROL',  'firewall_block', 'high'),
    ('critical', 'DATA_BREACH',          'firewall_block', 'high'),
    ('critical', 'DDOS',                 'firewall_block', 'high'),
    ('critical', '*',                    'firewall_block', 'high'),  # auto-enforced
    ('high',     'COMPROMISED',          'mark_suspicious','low'),
    ('high',     'BRUTE_FORCE',          'mark_suspicious','low'),
    ('high',     'PORT_SCAN',            'notify',         'low'),
    ('high',     '*',                    'mark_suspicious','low'),
    ('medium',   '*',                    'notify',         'low'),
    ('low',      '*',                    'acknowledge',    'low'),
]

_SOURCE_BADGE = {
    'openai': '[OpenAI]',
    'groq':   '[Groq]',
    'ollama': '[Ollama]',
    'rules':  '[Rules]',
}


def _match_policy(severity: str, attack_type: str) -> tuple[str, str]:
    """Return (action_type, risk_level) for a given severity + attack_type."""
    severity = (severity or 'low').lower()
    attack_type = (attack_type or '').upper()
    for sev, atk_pattern, action, risk in _POLICY:
        if sev != severity:
            continue
        if atk_pattern == '*' or atk_pattern in attack_type:
            return action, risk
    return 'notify', 'low'


class SecurityAgent:
    """
    Autonomous security agent that processes new alerts and takes action.

    Args:
        db: DatabaseManager instance (shared with orchestrator).
        ai_assistant: HybridAIAssistant for generating plain-English reports.
        alerting: Optional AlertingSystem for sending notifications.
    """

    def __init__(self, db, ai_assistant=None, alerting=None):
        self.db = db
        self.ai = ai_assistant
        self.alerting = alerting
        self._last_scan_time: Optional[datetime] = None

        # Lazy-initialize threat intelligence client (resolves API key from env/Integration Hub)
        self._threat_intel = None
        try:
            from utils.threat_intel import ThreatIntelligence
            self._threat_intel = ThreatIntelligence(db_manager=db)
            if self._threat_intel.enabled:
                logger.info("[agent] Threat intelligence (AbuseIPDB) enabled")
            else:
                logger.info("[agent] Threat intelligence disabled — no AbuseIPDB key")
        except Exception as _ti_err:
            logger.warning(f"[agent] ThreatIntelligence init failed: {_ti_err}")

        # Lazy-initialize CVE matcher for on-join vulnerability scanning
        self._cve_matcher = None
        try:
            from utils.cve_matcher import CVEMatcher
            self._cve_matcher = CVEMatcher(db_manager=db)
            logger.info("[agent] CVE matcher initialized")
        except Exception as _cve_err:
            logger.warning(f"[agent] CVEMatcher init failed: {_cve_err}")

    # ------------------------------------------------------------------
    # Main cycle — called periodically from the orchestrator loop
    # ------------------------------------------------------------------

    def run_cycle(self):
        """Process new alerts and triage new devices. Called every AGENT_INTERVAL seconds."""
        # Reset per-cycle threat-intel call counter so we never exhaust the daily
        # API quota (AbuseIPDB: 1000/day) on a single busy cycle.
        self._ti_calls_this_cycle = 0

        window_start = datetime.utcnow() - timedelta(minutes=ALERT_WINDOW_MINUTES)

        # --- Alert processing ---
        try:
            alerts = self._get_new_alerts(window_start)
        except Exception as e:
            logger.error(f"[agent] Failed to fetch alerts: {e}")
            alerts = []

        if alerts:
            logger.info(f"[agent] Processing {len(alerts)} new alert(s)")
            for alert in alerts:
                try:
                    self._process_alert(alert)
                except Exception as e:
                    logger.error(f"[agent] Error processing alert {alert.get('id')}: {e}")

        # --- New-device triage ---
        try:
            self._scan_new_devices()
        except Exception as e:
            logger.error(f"[agent] New-device scan failed: {e}")

    def _get_new_alerts(self, since: datetime) -> list:
        """Return unacknowledged high/critical alerts since `since`."""
        try:
            cursor = self.db.conn.cursor()
            cursor.execute('''
                SELECT a.*, d.device_name, d.mac_address
                FROM alerts a
                LEFT JOIN devices d ON a.device_ip = d.device_ip
                WHERE a.acknowledged = 0
                  AND a.severity IN ('critical', 'high', 'medium')
                  AND a.timestamp > ?
                ORDER BY a.timestamp DESC
                LIMIT 20
            ''', (since.strftime('%Y-%m-%d %H:%M:%S'),))
            return [dict(row) for row in cursor.fetchall()]
        except Exception as e:
            logger.error(f"[agent] DB query failed: {e}")
            return []

    def _process_alert(self, alert: dict):
        alert_id = alert.get('id')
        device_ip = alert.get('device_ip', '')
        severity = (alert.get('severity') or 'low').lower()
        attack_type = alert.get('anomaly_type') or alert.get('explanation') or ''
        mac_address = alert.get('mac_address') or ''

        # Skip if we already queued/executed an action for this device+action combo
        action_type, risk_level = _match_policy(severity, attack_type)

        if self.db.action_already_queued(device_ip, action_type, hours=24):
            logger.debug(f"[agent] Skipping duplicate action {action_type} for {device_ip}")
            return

        rationale = (
            f"Alert severity={severity}, pattern={attack_type or 'anomaly'} "
            f"on device {alert.get('device_name') or device_ip}."
        )

        steps, threat_meta = self._investigate(alert)
        investigation_json = json.dumps(steps)
        plain_report, report_source = self._generate_report(alert, action_type, risk_level)

        if risk_level == 'low':
            # Escalation: repeated high alerts from the same device in 10 min → auto-block
            if self._check_alert_escalation(device_ip):
                auto_cfg = self._get_auto_block_config()
                if auto_cfg.get('enabled', True):
                    logger.warning(
                        "[agent] ESCALATION: repeated high-severity alerts from %s — "
                        "escalating to firewall_block",
                        device_ip,
                    )
                    self._execute_auto_block(
                        alert_id, device_ip, mac_address, 'firewall_block',
                        f"[Escalated: repeated alerts] {rationale}",
                        plain_report, investigation_json, threat_meta,
                        auto_cfg.get('confidence_threshold', 85),
                        ai_source=report_source,
                    )
                    return
            self._execute_low_risk(alert_id, device_ip, action_type,
                                   rationale, plain_report, alert, investigation_json,
                                   ai_source=report_source)
        else:
            # HIGH-RISK: enforce autonomously if auto_block is enabled
            auto_cfg = self._get_auto_block_config()
            if auto_cfg.get('enabled', True):
                self._execute_auto_block(
                    alert_id, device_ip, mac_address, action_type,
                    rationale, plain_report, investigation_json, threat_meta,
                    auto_cfg.get('confidence_threshold', 85),
                    ai_source=report_source,
                )
            else:
                # Legacy mode: queue for human approval
                params = json.dumps({'ip': device_ip, 'mac': mac_address})
                action_db_id = self.db.create_agent_action(
                    device_ip=device_ip,
                    action_type=action_type,
                    risk_level='high',
                    rationale=rationale,
                    plain_report=plain_report,
                    status='pending',
                    alert_id=alert_id,
                    params=params,
                    investigation=investigation_json,
                    ai_source=report_source,
                )
                if action_db_id:
                    logger.info(
                        f"[agent] Queued HIGH-RISK action '{action_type}' for {device_ip} "
                        f"(action_id={action_db_id}) — auto_block disabled, awaiting approval."
                    )

    def _execute_low_risk(self, alert_id: Optional[int], device_ip: str,
                          action_type: str, rationale: str,
                          plain_report: str, alert: dict,
                          investigation_json: Optional[str] = None,
                          ai_source: Optional[str] = None):
        """Execute a reversible low-risk action immediately."""
        params = json.dumps({'ip': device_ip})

        if action_type == 'mark_suspicious':
            self.db.set_device_blocked(device_ip, True)
            logger.info(f"[agent] AUTO: marked {device_ip} as suspicious (DB flag)")

        elif action_type in ('notify', 'acknowledge'):
            pass  # notification handled below

        # Acknowledge the alert
        if action_type == 'acknowledge' or alert.get('severity') == 'low':
            try:
                cursor = self.db.conn.cursor()
                cursor.execute(
                    "UPDATE alerts SET acknowledged = 1 WHERE id = ?",
                    (alert_id,)
                )
                self.db.conn.commit()
            except Exception as e:
                logger.warning(f"[agent] Acknowledge failed: {e}")

        # Record the action
        self.db.create_agent_action(
            device_ip=device_ip,
            action_type=action_type,
            risk_level='low',
            rationale=rationale,
            plain_report=plain_report,
            status='auto',
            alert_id=alert_id,
            params=params,
            investigation=investigation_json,
            ai_source=ai_source,
        )
        logger.info(f"[agent] AUTO: executed '{action_type}' for {device_ip}")

        # Send a notification if alerting is wired up
        if self.alerting and action_type != 'acknowledge':
            try:
                self.alerting.create_alert(
                    device_ip=device_ip,
                    severity='medium',
                    anomaly_score=0.0,
                    explanation=f"AI Agent auto-action: {action_type} - {rationale}",
                    top_features='{}',
                    plain_explanation=plain_report,
                )
            except Exception as e:
                logger.warning(f"[agent] Notification send failed: {e}")

    # ------------------------------------------------------------------
    # Auto-block helpers
    # ------------------------------------------------------------------

    def _get_auto_block_config(self) -> dict:
        """Read agent.auto_block config; returns safe defaults on failure."""
        try:
            from config.config_manager import config as _cfg
            # ConfigManager.get is (section, key, default) — read the nested
            # auto_block dict directly so the wizard's consent choice is honoured.
            auto_block = _cfg.get('agent', 'auto_block',
                                  {'enabled': True, 'confidence_threshold': 85})
            if isinstance(auto_block, dict):
                return auto_block
        except Exception:
            pass
        return {'enabled': True, 'confidence_threshold': 85}

    def _execute_auto_block(
        self,
        alert_id: Optional[int],
        device_ip: str,
        mac_address: str,
        action_type: str,
        rationale: str,
        plain_report: str,
        investigation_json: str,
        threat_meta: dict,
        confidence_threshold: int = 85,
        ai_source: Optional[str] = None,
    ):
        """
        Autonomously enforce a firewall block for a high-risk alert.

        Blocks the source device and any confirmed-malicious destination IPs
        found during investigation.  The FirewallEnforcer's self-lockout guard
        prevents the admin's own IP from ever being blocked.
        """
        # Circuit breaker: if the system has auto-blocked too many devices recently,
        # suspend autonomous enforcement and queue for human review instead.
        if self._check_circuit_breaker():
            logger.warning(
                "[agent] AUTO-BLOCK skipped for %s — circuit breaker active, queuing for approval",
                device_ip,
            )
            self.db.create_agent_action(
                device_ip=device_ip,
                action_type=action_type,
                risk_level='high',
                rationale=f"[Circuit breaker active] {rationale}",
                plain_report=plain_report,
                status='pending',
                alert_id=alert_id,
                params=json.dumps({'ip': device_ip, 'mac': mac_address}),
                investigation=investigation_json,
                ai_source=ai_source,
            )
            return

        from utils.firewall_enforcer import firewall_enforcer as _fw

        params = json.dumps({'ip': device_ip, 'mac': mac_address})

        # Block the source device (guard in enforcer protects admin/router)
        try:
            blocked = _fw.block_device(device_ip, mac_address or None)
            if blocked:
                self.db.set_device_blocked(device_ip, True)
                logger.warning("[agent] AUTO-BLOCK: blocked device %s (critical alert)", device_ip)
            else:
                logger.info(
                    "[agent] AUTO-BLOCK: block_device(%s) refused or noop (protected/noop enforcer)",
                    device_ip,
                )
        except Exception as e:
            logger.error("[agent] AUTO-BLOCK: firewall call failed for %s: %s", device_ip, e)

        # Block confirmed-malicious external destination IPs
        for dest_ip, conf in threat_meta.get('malicious_dests', []):
            if conf >= confidence_threshold:
                try:
                    dest_blocked = _fw.block_ip(dest_ip)
                    if dest_blocked:
                        logger.warning(
                            "[agent] AUTO-BLOCK: blocked malicious dest %s (AbuseIPDB conf=%d)",
                            dest_ip, conf,
                        )
                except Exception as e:
                    logger.error("[agent] AUTO-BLOCK: failed to block dest %s: %s", dest_ip, e)

        # Record the action (status='auto' — no human approval needed)
        self.db.create_agent_action(
            device_ip=device_ip,
            action_type=action_type,
            risk_level='high',
            rationale=rationale,
            plain_report=plain_report,
            status='auto',
            alert_id=alert_id,
            params=params,
            investigation=investigation_json,
            ai_source=ai_source,
        )
        logger.info("[agent] AUTO: executed '%s' for %s", action_type, device_ip)

        # Send critical notification
        if self.alerting:
            try:
                self.alerting.create_alert(
                    device_ip=device_ip,
                    severity='critical',
                    anomaly_score=1.0,
                    explanation=f"AI Agent AUTO-BLOCKED: {action_type} - {rationale}",
                    top_features='{}',
                    plain_explanation=plain_report,
                )
            except Exception as e:
                logger.warning("[agent] Notification send failed: %s", e)

    # ------------------------------------------------------------------
    # Investigation timeline (Feature 1: visible reasoning)
    # ------------------------------------------------------------------

    def _investigate(self, alert: dict) -> Tuple[list, dict]:
        """
        Build a step-by-step investigation timeline for an alert.

        Each step is {"label": str, "detail": str, "verdict": "ok"|"warn"|"bad"}.
        Step 3 also performs a live AbuseIPDB lookup for external destination IPs
        (cached 24h).

        Returns:
            (steps, threat_meta) where threat_meta = {
                'max_confidence': int,          # highest AbuseIPDB score seen
                'malicious_dests': [(ip, conf)] # confirmed-malicious dest IPs
            }
        """
        steps = []
        threat_meta: dict = {'max_confidence': 0, 'malicious_dests': []}
        device_ip = alert.get('device_ip', '')
        severity = alert.get('severity', 'unknown')
        external_dest_ips: List[str] = []  # collected in Step 2, used in Step 3

        # Step 1: device history
        try:
            cursor = self.db.conn.cursor()
            cursor.execute(
                "SELECT COUNT(*) FROM connections WHERE device_ip = ?", (device_ip,)
            )
            total_conns = cursor.fetchone()[0]
            cursor.execute(
                "SELECT COUNT(*) FROM alerts WHERE device_ip = ? AND timestamp >= datetime('now', '-7 days')",
                (device_ip,)
            )
            week_alerts = cursor.fetchone()[0]
            verdict = 'bad' if week_alerts > 5 else 'warn' if week_alerts > 1 else 'ok'
            steps.append({
                'label': 'Device history',
                'detail': f"{total_conns} total connections recorded; {week_alerts} alert(s) in the last 7 days.",
                'verdict': verdict,
            })
        except Exception:
            pass

        # Step 2: top external destinations in last hour
        try:
            cursor = self.db.conn.cursor()
            cursor.execute(
                """SELECT dest_ip, COUNT(*) AS n FROM connections
                   WHERE device_ip = ?
                     AND dest_ip NOT LIKE '192.168.%'
                     AND dest_ip NOT LIKE '10.%'
                     AND dest_ip NOT LIKE '172.1%.%'
                     AND dest_ip NOT LIKE '172.2%.%'
                     AND dest_ip NOT LIKE '172.3%.%'
                     AND timestamp >= datetime('now', '-1 hour')
                   GROUP BY dest_ip ORDER BY n DESC LIMIT 5""",
                (device_ip,)
            )
            rows = cursor.fetchall()
            if rows:
                external_dest_ips = [r[0] for r in rows]
                dest_list = ', '.join(f"{r[0]} ({r[1]}x)" for r in rows[:3])
                steps.append({
                    'label': 'External destinations (last hour)',
                    'detail': dest_list,
                    'verdict': 'warn',
                })
        except Exception:
            pass

        # Step 3: threat intelligence — local DB first, then live AbuseIPDB
        try:
            cursor = self.db.conn.cursor()
            cursor.execute(
                """SELECT c.dest_ip, m.source FROM connections c
                   JOIN malicious_ips m ON c.dest_ip = m.ip
                   WHERE c.device_ip = ?
                     AND c.timestamp >= datetime('now', '-1 hour')
                   LIMIT 3""",
                (device_ip,)
            )
            local_hits = cursor.fetchall()
        except Exception:
            local_hits = []

        # Live AbuseIPDB lookup for external dest IPs (cached 24h per-IP).
        # Hard cap: at most 3 live API calls per cycle total across all alerts to
        # stay within the AbuseIPDB 1000/day free tier (24 cycles/h × 3 = 72/h max).
        _MAX_TI_CALLS_PER_CYCLE = 3
        if not hasattr(self, '_ti_calls_this_cycle'):
            self._ti_calls_this_cycle = 0

        live_flagged: List[Tuple[str, int, str]] = []  # (ip, confidence, level)
        if self._threat_intel and self._threat_intel.enabled and external_dest_ips:
            for dest_ip in external_dest_ips[:3]:
                if self._ti_calls_this_cycle >= _MAX_TI_CALLS_PER_CYCLE:
                    logger.debug("[agent] TI call cap reached for this cycle — skipping %s", dest_ip)
                    break
                try:
                    rep = self._threat_intel.get_ip_reputation(dest_ip)
                    self._ti_calls_this_cycle += 1
                    score = rep.get('abuse_confidence_score', 0)
                    level = rep.get('reputation_level', 'safe')
                    if score > 0:
                        live_flagged.append((dest_ip, score, level))
                        if score > threat_meta['max_confidence']:
                            threat_meta['max_confidence'] = score
                        if level in ('suspicious', 'malicious'):
                            threat_meta['malicious_dests'].append((dest_ip, score))
                except Exception as e:
                    logger.debug("[agent] TI lookup failed for %s: %s", dest_ip, e)

        # Build TI step summary
        ti_parts = []
        for r in local_hits:
            ti_parts.append(f"{r[0]} [local:{r[1]}]")
        for ip, score, level in live_flagged:
            if not any(r[0] == ip for r in local_hits):
                ti_parts.append(f"{ip} [AbuseIPDB:{score}% {level}]")

        if ti_parts:
            steps.append({
                'label': 'Threat intelligence',
                'detail': f"Flagged IP(s) contacted: {', '.join(ti_parts)}",
                'verdict': 'bad',
            })
        else:
            steps.append({
                'label': 'Threat intelligence',
                'detail': 'No known malicious IPs contacted in the last hour.',
                'verdict': 'ok',
            })

        # Step 4: baseline comparison
        try:
            cursor = self.db.conn.cursor()
            cursor.execute(
                "SELECT bytes_out_avg FROM device_behavior_baselines WHERE device_ip = ?",
                (device_ip,)
            )
            row = cursor.fetchone()
            if row and row[0]:
                cursor.execute(
                    "SELECT COALESCE(SUM(bytes_sent), 0) FROM connections WHERE device_ip = ? AND timestamp >= datetime('now', '-1 hour')",
                    (device_ip,)
                )
                current = cursor.fetchone()[0] or 0
                ratio = current / row[0] if row[0] > 0 else 0
                verdict = 'bad' if ratio > 3 else 'warn' if ratio > 1.5 else 'ok'
                steps.append({
                    'label': 'Traffic vs baseline',
                    'detail': f"Outbound traffic is {ratio:.1f}x its normal average.",
                    'verdict': verdict,
                })
        except Exception:
            pass

        # Step 5: policy decision
        attack_type = alert.get('anomaly_type') or alert.get('explanation') or ''
        action_type, risk_level = _match_policy(severity, attack_type)
        steps.append({
            'label': 'Agent decision',
            'detail': f"Policy matched: {action_type.replace('_', ' ')} (risk: {risk_level}). {alert.get('plain_explanation') or ''}",
            'verdict': 'bad' if risk_level == 'high' else 'warn',
        })

        return steps, threat_meta

    # ------------------------------------------------------------------
    # New-device triage (Feature 2)
    # ------------------------------------------------------------------

    def _device_has_critical_alert(self, device_ip: str, within_hours: int = 1) -> bool:
        """Return True if the device triggered a critical alert in the last N hours."""
        try:
            cursor = self.db.conn.cursor()
            cursor.execute(
                """SELECT COUNT(*) FROM alerts
                   WHERE device_ip = ?
                     AND severity = 'critical'
                     AND timestamp >= datetime('now', ?)""",
                (device_ip, f'-{within_hours} hours'),
            )
            return cursor.fetchone()[0] > 0
        except Exception:
            return False

    def _check_alert_escalation(self, device_ip: str) -> bool:
        """
        Return True if this device has 3+ unacknowledged high/critical alerts in the
        last 10 minutes — triggers escalation from low-risk to auto-block response.
        """
        try:
            cursor = self.db.conn.cursor()
            cursor.execute(
                """SELECT COUNT(*) FROM alerts
                   WHERE device_ip = ?
                     AND severity IN ('high', 'critical')
                     AND acknowledged = 0
                     AND timestamp >= datetime('now', '-10 minutes')""",
                (device_ip,),
            )
            return cursor.fetchone()[0] >= 3
        except Exception:
            return False

    def _check_circuit_breaker(self) -> bool:
        """
        Trip the auto-block circuit breaker if 3+ distinct devices were auto-blocked
        in the last 10 minutes. Suspends autonomous blocking to prevent a
        false-positive storm from locking out the entire network.

        Returns True when the breaker is tripped (caller must skip enforcement).
        Fails open on DB error so a broken breaker never prevents legitimate blocks.
        """
        try:
            if self.db.get_setting('auto_block_suspended') == '1':
                logger.warning("[agent] Auto-block is suspended (circuit breaker). "
                               "Clear via Admin > Agent to resume.")
                return True

            cursor = self.db.conn.cursor()
            cursor.execute(
                """SELECT COUNT(DISTINCT device_ip) FROM agent_actions
                   WHERE action_type = 'firewall_block'
                     AND status = 'auto'
                     AND created_at >= datetime('now', '-10 minutes')""",
            )
            count = cursor.fetchone()[0]

            if count >= 3:
                self.db.set_setting('auto_block_suspended', '1')
                logger.critical(
                    "[agent] CIRCUIT BREAKER TRIPPED: %d devices auto-blocked in 10 min. "
                    "Autonomous blocking suspended. Clear via Admin > Agent.",
                    count,
                )
                if self.alerting:
                    try:
                        self.alerting.create_alert(
                            device_ip='system',
                            severity='critical',
                            anomaly_score=1.0,
                            explanation=(
                                f"AUTO-BLOCK CIRCUIT BREAKER: {count} devices blocked in 10 "
                                "minutes. Autonomous blocking suspended — admin review required."
                            ),
                            top_features='{}',
                            plain_explanation=(
                                f"The automatic blocking system paused because {count} devices "
                                "were blocked in the last 10 minutes, which may indicate a "
                                "false-positive storm. No further devices will be auto-blocked "
                                "until an admin clears the suspension in Admin > Agent."
                            ),
                        )
                    except Exception:
                        pass
                return True

            return False
        except Exception as e:
            logger.debug("[agent] Circuit breaker check failed (failing open): %s", e)
            return False  # fail open — never prevent legitimate blocks on DB error

    def _scan_new_devices(self):
        """
        Detect devices first seen in the last AGENT_INTERVAL window.

        For each new device:
        1. Run CVE matching against already-synced vulnerability data.
        2. If the device already has a critical alert in its first hour,
           auto-quarantine it via the firewall (guard protects admin IP).
        3. Otherwise queue a Trust/Block triage card for the human.

        Idempotent: skips IPs already triaged in the last 30 days.
        """
        window_minutes = max(AGENT_INTERVAL // 60, 2)
        new_devices = self.db.get_new_devices(since_minutes=window_minutes)
        for device in new_devices:
            device_ip = device.get('device_ip', '')
            if not device_ip:
                continue
            if self.db.action_already_queued(device_ip, 'device_triage', hours=720):
                continue

            # CVE scan on join: match against synced iot_vulnerabilities data
            self._run_cve_scan_for_device(device)

            # Auto-quarantine if the device already fired a critical alert
            if self._device_has_critical_alert(device_ip, within_hours=1):
                auto_cfg = self._get_auto_block_config()
                if auto_cfg.get('enabled', True):
                    self._auto_quarantine_new_device(device)
                    continue  # skip normal triage card

            # Normal triage: queue Trust/Block card for the human
            report = self._generate_triage_report(device)
            params = json.dumps({
                'ip': device_ip,
                'mac': device.get('mac_address', ''),
                'device_type': device.get('device_type', ''),
                'manufacturer': device.get('manufacturer', ''),
            })
            self.db.create_agent_action(
                device_ip=device_ip,
                action_type='device_triage',
                risk_level='low',
                rationale=(
                    f"New device detected: {device.get('manufacturer') or 'unknown'} "
                    f"{device.get('device_type') or 'device'} at {device_ip}"
                ),
                plain_report=report,
                status='pending',
                params=params,
            )
            logger.info(f"[agent] Triage queued for new device {device_ip}")

    def _run_cve_scan_for_device(self, device: dict):
        """
        Match a new device against synced CVE data in iot_vulnerabilities.

        Uses direct LIKE matching on affected_vendors/affected_models columns rather
        than CPE parsing — the iot_vulnerabilities table stores vendor/model as
        comma-separated text extracted from CPE during the daily NVD sync, not the
        raw CPE list itself.

        Writes matches to device_vulnerabilities_detected using the actual schema:
        (device_ip, cve_id, detected_date, status, risk_score, auto_detected).
        """
        device_ip = device.get('device_ip', '')
        manufacturer = (device.get('manufacturer') or '').strip().lower()
        model = (device.get('model') or '').strip().lower()
        device_type = (device.get('device_type') or '').strip().lower()

        # Need at least one identifier to match against
        if not device_ip or not (manufacturer or model or device_type):
            return

        try:
            cursor = self.db.conn.cursor()

            # Build OR conditions for each non-empty identifier
            conditions = []
            params: list = []
            for term in filter(None, [manufacturer, model, device_type]):
                conditions.append("(LOWER(COALESCE(affected_vendors,'')) LIKE ? OR LOWER(COALESCE(affected_models,'')) LIKE ?)")
                params.extend([f'%{term}%', f'%{term}%'])

            if not conditions:
                return

            where_clause = ' OR '.join(conditions)
            query = f"""
                SELECT cve_id, cvss_score
                FROM iot_vulnerabilities
                WHERE ({where_clause})
                  AND cve_id NOT IN (
                      SELECT cve_id FROM device_vulnerabilities_detected WHERE device_ip = ?
                  )
            """
            params.append(device_ip)
            cursor.execute(query, params)
            rows = cursor.fetchall()

            if not rows:
                return

            for row in rows:
                cvss = float(row['cvss_score'] or 0.0)
                risk_score = round(cvss * 0.8, 2)  # 80% confidence for text match
                cursor.execute(
                    """INSERT OR IGNORE INTO device_vulnerabilities_detected
                       (device_ip, cve_id, detected_date, status, risk_score, auto_detected)
                       VALUES (?, ?, datetime('now'), 'active', ?, 1)""",
                    (device_ip, row['cve_id'], risk_score),
                )

            self.db.conn.commit()
            logger.info(
                "[agent] CVE scan: %d match(es) found for new device %s",
                len(rows), device_ip,
            )
        except Exception as e:
            logger.warning("[agent] CVE scan failed for %s: %s", device_ip, e)

    def _auto_quarantine_new_device(self, device: dict):
        """Auto-block a new device that immediately triggered a critical alert."""
        from utils.firewall_enforcer import firewall_enforcer as _fw
        device_ip = device.get('device_ip', '')
        mac = device.get('mac_address', '')
        manufacturer = device.get('manufacturer') or 'unknown'
        device_type = (device.get('device_type') or 'device').replace('_', ' ')

        try:
            blocked = _fw.block_device(device_ip, mac or None)
            if blocked:
                self.db.set_device_blocked(device_ip, True)
                logger.warning(
                    "[agent] AUTO-QUARANTINE: new device %s (%s %s) blocked — critical alert on join",
                    device_ip, manufacturer, device_type,
                )
        except Exception as e:
            logger.error("[agent] AUTO-QUARANTINE: firewall call failed for %s: %s", device_ip, e)

        rationale = (
            f"New device {manufacturer} {device_type} at {device_ip} triggered a critical alert "
            "within its first hour on the network."
        )
        plain_report = (
            f"A new {manufacturer} device appeared at {device_ip} and immediately triggered a "
            "critical security alert. It has been automatically isolated from the network as a "
            "precaution. Review the alert history to decide whether to trust or remove this device."
        )
        params = json.dumps({'ip': device_ip, 'mac': mac, 'auto_quarantine': True})
        self.db.create_agent_action(
            device_ip=device_ip,
            action_type='device_triage',
            risk_level='high',
            rationale=rationale,
            plain_report=plain_report,
            status='auto',
            params=params,
        )
        logger.info("[agent] AUTO-QUARANTINE action recorded for %s", device_ip)

    def _generate_triage_report(self, device: dict) -> str:
        """Generate a plain-English triage summary for a newly seen device."""
        ip = device.get('device_ip', 'unknown IP')
        manufacturer = device.get('manufacturer') or 'Unknown manufacturer'
        device_type = (device.get('device_type') or 'device').replace('_', ' ')
        confidence = device.get('confidence')
        conf_text = f" ({int(confidence * 100)}% confident)" if confidence else ""

        if self.ai is None:
            return (
                f"A new device appeared on your network: {manufacturer} {device_type}{conf_text} "
                f"at {ip}. Choose Trust to add it to your trusted devices, or Block to prevent "
                f"it from accessing the internet."
            )

        prompt = (
            f"A new device just joined a home network. Write 2 plain English sentences "
            f"explaining what this device likely is and whether it looks safe.\n"
            f"Device info: manufacturer={manufacturer}, type={device_type}{conf_text}, ip={ip}\n"
            f"No em dashes. No jargon. End with: 'Choose Trust to allow it or Block to isolate it.'"
        )
        try:
            report, _ = self.ai.get_response(prompt=prompt, max_tokens=80, temperature=0.4)
            if report:
                report = report.replace('—', '-').replace('–', '-').replace('**', '')
            return report or (
                f"New {manufacturer} {device_type} detected at {ip}{conf_text}. "
                "Choose Trust to allow it or Block to isolate it."
            )
        except Exception:
            return (
                f"New {manufacturer} {device_type} detected at {ip}{conf_text}. "
                "Choose Trust to allow it or Block to isolate it."
            )

    def _generate_report(self, alert: dict, action_type: str, risk_level: str):
        """Generate a plain-English incident report via HybridAI.

        Returns (report: str, source: str) so callers can persist which provider
        was used alongside the report text.
        """
        device = alert.get('device_name') or alert.get('device_ip', 'unknown device')
        severity = alert.get('severity', 'unknown')
        explanation = alert.get('plain_explanation') or alert.get('explanation', '')

        if self.ai is None:
            return (
                f"The AI agent detected a {severity} security event on {device}. "
                f"Recommended action: {action_type.replace('_', ' ')}. "
                f"Details: {explanation}",
                'rules',
            )

        prompt = (
            f"Write a 2-sentence plain-English incident report for a home network security event:\n"
            f"Device: {device}\n"
            f"Severity: {severity}\n"
            f"What happened: {explanation}\n"
            f"Recommended action: {action_type.replace('_', ' ')}\n"
            f"Risk level: {risk_level}\n\n"
            "Keep it simple, avoid jargon, and explain what the user should know."
        )
        context = (
            "You are IoTSentinel's autonomous security agent. Generate a concise, "
            "non-technical incident report. Be reassuring but clear about the risk."
        )

        try:
            report, source = self.ai.get_response(
                prompt=prompt,
                context=context,
                max_tokens=150,
                temperature=0.4,
            )
            report = (report or '').replace('—', '-').replace('–', '-').replace('**', '')
            return report.strip(), source
        except Exception as e:
            logger.warning(f"[agent] AI report generation failed: {e}")
            return (
                f"A {severity} security event was detected on {device}. "
                f"The agent is recommending: {action_type.replace('_', ' ')}.",
                'rules',
            )
