"""
Firewall Control callbacks — real rule management via FirewallEnforcer.

Populates:
  • Blocked Devices tab  — DB devices with is_blocked=1, Release buttons
  • Active Rules tab     — live firewall rules from FirewallEnforcer.list_rules()
  • Add Rule tab         — IP/port/action form with dry-run preview
  • Audit Log tab        — last 100 lines of data/logs/audit.log
"""

import json
import re
from datetime import datetime
from pathlib import Path

import dash
import dash_bootstrap_components as dbc
from dash import html, Input, Output, State, ALL, callback_context, no_update

from flask_login import current_user

from dashboard.shared import db_manager, logger, firewall_enforcer, audit_logger, ToastManager

_AUDIT_LOG = Path("data/logs/audit.log")
_IP_RE = re.compile(
    r'^((25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(25[0-5]|2[0-4]\d|[01]?\d\d?)$'
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _toast(message: str, kind: str = "success", header: str = None):
    """Delegate to the app-wide ToastManager so styling matches everywhere."""
    header = header or kind.capitalize()
    fn = {'success': ToastManager.success, 'error': ToastManager.error,
          'warning': ToastManager.warning}.get(kind, ToastManager.success)
    return fn(message, header=header, category="security")


def _blocked_device_card(device: dict) -> dbc.Card:
    ip = device.get('device_ip', 'Unknown')
    mac = device.get('mac_address', '')
    name = device.get('device_name') or device.get('hostname') or ip
    return dbc.Card([
        dbc.CardBody([
            dbc.Row([
                dbc.Col([
                    html.I(className="fa fa-ban fa-lg text-danger me-2"),
                ], width="auto", className="d-flex align-items-center pe-0"),
                dbc.Col([
                    html.Strong(name, className="d-block"),
                    html.Small(f"{ip}  {('  MAC: ' + mac) if mac else ''}",
                               className="text-muted"),
                ]),
                dbc.Col([
                    dbc.Button(
                        [html.I(className="fa fa-lock-open me-1"), "Release"],
                        id={'type': 'fw-release-btn', 'ip': ip, 'mac': mac or ''},
                        color="outline-success", size="sm",
                        n_clicks=0,
                    )
                ], width="auto", className="d-flex align-items-center"),
            ], align="center", className="g-2"),
        ]),
    ], className="mb-2 border-0 shadow-sm firewall-blocked-card")


def _rule_row(line: str, idx: int) -> html.Tr:
    """Single row for iptables-format rules."""
    cols = line.split()
    if cols and cols[0].isdigit():
        num, rest = cols[0], " ".join(cols[1:])
    else:
        num, rest = str(idx + 1), line
    return html.Tr([
        html.Td(num, className="text-center text-muted u-col-w-sm"),
        html.Td(html.Code(rest, className="u-text-xs")),
    ])


def _is_nft_structural(line: str) -> bool:
    s = line.strip()
    return (not s or s in ('{', '}') or
            s.startswith('table ') or
            s.startswith('chain ') or
            s.startswith('type filter'))


_FAILSAFE_PATTERNS = (
    '192.168.0.0/16', '10.0.0.0/8', '172.16.0.0/12',
    'tcp dport 22 accept', 'tcp dport 8050 accept',
)


def _render_rules(rules: list, backend: str) -> list:
    """Render firewall rules for both nftables and iptables backends."""
    use_nft = 'nft' in backend

    if use_nft:
        failsafe_rows, user_rows = [], []
        for ln in rules:
            s = ln.strip()
            if _is_nft_structural(s):
                continue
            is_failsafe = any(p in s for p in _FAILSAFE_PATTERNS)
            handle = s.split('# handle')[-1].strip() if '# handle ' in s else ''
            rule_text = s.split('# handle')[0].strip() if handle else s
            if is_failsafe:
                badge = dbc.Badge("failsafe", color="success", className="ms-2")
                row = html.Tr([html.Td([html.Code(rule_text, className="u-text-xs"), badge])])
                failsafe_rows.append(row)
            else:
                badge = (dbc.Badge(f"#{handle}", color="secondary", pill=True, className="ms-2 font-monospace")
                         if handle else None)
                cells = [html.Code(rule_text, className="u-text-xs")]
                if badge:
                    cells.append(badge)
                user_rows.append(html.Tr([html.Td(cells)]))

        if not failsafe_rows and not user_rows:
            return [
                html.P("No rules in iotsentinel chain.", className="text-muted text-center py-3"),
                dbc.Alert([html.I(className="fa fa-info-circle me-2"),
                           "Rules appear here when you block a device or use Add Rule."],
                          color="info", className="mt-2"),
            ]
        return [
            dbc.Table(
                [html.Thead(html.Tr([html.Th("nftables Rule")])),
                 html.Tbody(failsafe_rows + user_rows)],
                bordered=False, hover=True, size="sm", responsive=True,
                className="firewall-rules-table",
            )
        ]
    else:
        # iptables format — filter out header lines
        rule_lines = [
            ln for ln in rules
            if not (ln.startswith("Chain") or ln.startswith("target") or ln.startswith("num"))
        ]
        if not rule_lines:
            return [
                html.P("No rules in IOTSENTINEL chain.", className="text-muted text-center py-3"),
                dbc.Alert([html.I(className="fa fa-info-circle me-2"),
                           "Rules appear here when you block a device or use Add Rule."],
                          color="info", className="mt-2"),
            ]
        return [
            dbc.Table(
                [html.Thead(html.Tr([html.Th("#", className="u-col-w-sm"), html.Th("iptables Rule")])),
                 html.Tbody([_rule_row(ln, i) for i, ln in enumerate(rule_lines)])],
                bordered=False, hover=True, size="sm", responsive=True,
                className="firewall-rules-table",
            )
        ]


def _read_audit_entries(limit: int = 100) -> list:
    if not _AUDIT_LOG.exists():
        return []
    try:
        lines = _AUDIT_LOG.read_text(errors='replace').splitlines()
        entries = []
        for ln in reversed(lines[-limit:]):
            ln = ln.strip()
            if not ln:
                continue
            try:
                entries.append(json.loads(ln))
            except Exception:
                entries.append({'ts': '', 'action': ln, 'target': '', 'success': None,
                                'dry_run': False, 'detail': ''})
        return entries
    except Exception:
        return []


def _audit_table(entries: list) -> dbc.Table:
    rows = []
    for e in entries:
        ts = e.get('ts', '')[:19].replace('T', ' ')
        action = e.get('action', '')
        target = e.get('target', '')
        success = e.get('success')
        dry = e.get('dry_run', False)
        detail = e.get('detail', '')

        icon = ('fa-check-circle text-success' if success
                else ('fa-info-circle text-info' if success is None
                      else 'fa-times-circle text-danger'))
        tags = [dbc.Badge("dry-run", color="info", className="me-1")] if dry else []
        rows.append(html.Tr([
            html.Td(html.Small(ts, className="text-muted u-nowrap")),
            html.Td([html.I(className=f"fa {icon} me-1"), action]),
            html.Td(html.Code(target, className="u-text-xs")),
            html.Td([*tags, html.Small(detail[:60], className="text-muted")]),
        ]))

    return dbc.Table(
        [html.Thead(html.Tr([html.Th("Time"), html.Th("Action"), html.Th("Target"), html.Th("Detail")])),
         html.Tbody(rows)],
        bordered=False, hover=True, size="sm", responsive=True,
        className="firewall-rules-table",
    )


def _check_admin() -> bool:
    return current_user.is_authenticated and hasattr(current_user, 'is_admin') and current_user.is_admin()


def _nft_rule_count(rules: list) -> int:
    return sum(1 for ln in rules if ln.strip() and not _is_nft_structural(ln))


# ---------------------------------------------------------------------------
# Register
# ---------------------------------------------------------------------------

def register(app):

    # ------------------------------------------------------------------
    # Blocked Devices — refresh on tab activate, button, interval, or signal
    # ------------------------------------------------------------------
    @app.callback(
        [Output('firewall-blocked-devices', 'children'),
         Output('toast-container', 'children', allow_duplicate=True)],
        [Input('firewall-tabs', 'active_tab'),
         Input('fw-refresh-blocked-btn', 'n_clicks'),
         Input('firewall-refresh-interval', 'n_intervals'),
         Input('fw-release-signal', 'data')],
        prevent_initial_call='initial_duplicate',
    )
    def refresh_blocked_devices(active_tab, btn_clicks, _n, _signal):
        triggered = callback_context.triggered_id
        show_toast = triggered == 'fw-refresh-blocked-btn' and btn_clicks

        try:
            devices = db_manager.get_blocked_devices()
        except Exception as e:
            return [dbc.Alert(f"DB error: {e}", color="danger")], no_update

        if not devices:
            content = [html.Div([
                html.I(className="fa fa-check-circle fa-2x text-success mb-2 d-block"),
                html.P("No blocked devices.", className="text-muted text-center"),
            ], className="py-4 text-center")]
        else:
            content = [_blocked_device_card(d) for d in devices]

        n = len(devices)
        toast = (_toast(f"{n} blocked device{'s' if n != 1 else ''}", header="Refreshed")
                 if show_toast else no_update)
        return content, toast

    # ------------------------------------------------------------------
    # Active Rules — refresh on tab activate, button, or signal
    # ------------------------------------------------------------------
    @app.callback(
        [Output('firewall-rules-list', 'children'),
         Output('fw-backend-badge', 'children'),
         Output('toast-container', 'children', allow_duplicate=True)],
        [Input('firewall-tabs', 'active_tab'),
         Input('fw-refresh-rules-btn', 'n_clicks'),
         Input('fw-release-signal', 'data')],
        prevent_initial_call='initial_duplicate',
    )
    def refresh_rules_list(active_tab, btn_clicks, _signal):
        triggered = callback_context.triggered_id
        show_toast = triggered == 'fw-refresh-rules-btn' and btn_clicks

        backend = getattr(firewall_enforcer, 'backend_name', 'noop')
        badge_color = "primary" if 'nft' in backend else ("secondary" if 'ipt' in backend else "danger")
        badge = [
            dbc.Badge(backend, color=badge_color, className="me-2"),
            html.Small("active backend", className="text-muted"),
        ]

        try:
            rules = firewall_enforcer.list_rules() if firewall_enforcer else []
        except Exception as e:
            return [dbc.Alert(f"Error reading rules: {e}", color="danger")], badge, no_update

        content = _render_rules(rules, backend)
        rule_count = _nft_rule_count(rules) if 'nft' in backend else len(rules)
        toast = (_toast(f"{rule_count} rule{'s' if rule_count != 1 else ''}", header="Refreshed")
                 if show_toast else no_update)
        return content, badge, toast

    # ------------------------------------------------------------------
    # Audit Log — refresh on tab activate, button, or signal
    # ------------------------------------------------------------------
    @app.callback(
        [Output('firewall-audit-log', 'children'),
         Output('toast-container', 'children', allow_duplicate=True)],
        [Input('firewall-tabs', 'active_tab'),
         Input('fw-refresh-audit-btn', 'n_clicks'),
         Input('fw-release-signal', 'data')],
        prevent_initial_call='initial_duplicate',
    )
    def refresh_audit_log(active_tab, btn_clicks, _signal):
        triggered = callback_context.triggered_id
        show_toast = triggered == 'fw-refresh-audit-btn' and btn_clicks

        entries = _read_audit_entries(100)
        if not entries:
            content = [html.P("No audit entries yet. Firewall actions will appear here.",
                              className="text-muted text-center py-4")]
        else:
            content = [_audit_table(entries)]

        n = len(entries)
        toast = (_toast(f"{n} audit entr{'ies' if n != 1 else 'y'}", header="Refreshed")
                 if show_toast else no_update)
        return content, toast

    # ------------------------------------------------------------------
    # Release a blocked device
    # ------------------------------------------------------------------
    @app.callback(
        [Output('toast-container', 'children', allow_duplicate=True),
         Output('fw-release-signal', 'data', allow_duplicate=True)],
        Input({'type': 'fw-release-btn', 'ip': ALL, 'mac': ALL}, 'n_clicks'),
        prevent_initial_call=True,
    )
    def release_device(n_clicks_list):
        ctx = callback_context
        if not ctx.triggered or not any(n_clicks_list):
            raise dash.exceptions.PreventUpdate

        # triggered_id is already a parsed dict for pattern-matched IDs —
        # avoids the split('.')[0] bug when the IP contains dots.
        btn_id = ctx.triggered_id
        if not isinstance(btn_id, dict):
            raise dash.exceptions.PreventUpdate

        ip = btn_id.get('ip', '')
        mac = btn_id.get('mac') or None
        if not ip:
            raise dash.exceptions.PreventUpdate

        if not _check_admin():
            return _toast("Admin access required to release devices.", "error",
                          header="Permission denied"), no_update

        try:
            ok = firewall_enforcer.unblock_device(ip, mac) if firewall_enforcer else False
            db_manager.set_device_blocked(ip, False)
            try:
                audit_logger.log_action(
                    "fw_release_device",
                    f"Released blocked device {ip}",
                    target_resource=ip,
                    success=ok,
                )
            except Exception:
                pass
            backend = getattr(firewall_enforcer, 'backend_name', 'noop')
            if ok:
                return (_toast(f"Device {ip} released (backend: {backend})", "success",
                               header="Device Released"),
                        datetime.now().timestamp())
            else:
                return (_toast(f"DB updated — no firewall rule removed (backend: {backend})",
                               "warning", header="Partial Release"),
                        datetime.now().timestamp())
        except Exception as e:
            logger.error(f"fw release_device {ip}: {e}")
            return _toast(f"Error releasing {ip}: {e}", "error", header="Release Failed"), no_update

    # ------------------------------------------------------------------
    # Rollback last firewall change
    # ------------------------------------------------------------------
    @app.callback(
        [Output('toast-container', 'children', allow_duplicate=True),
         Output('fw-release-signal', 'data', allow_duplicate=True)],
        Input('fw-rollback-btn', 'n_clicks'),
        prevent_initial_call=True,
    )
    def rollback_firewall(n_clicks):
        if not n_clicks:
            raise dash.exceptions.PreventUpdate
        if not _check_admin():
            return _toast("Admin access required.", "error", header="Permission denied"), no_update
        if not firewall_enforcer:
            return _toast("Firewall enforcer unavailable.", "error"), no_update

        backup_path = getattr(firewall_enforcer, 'backup_path', None)
        if backup_path is None:
            return _toast("No backup found — apply a rule first.", "warning",
                          header="No Backup"), no_update

        ok = firewall_enforcer.rollback()
        try:
            audit_logger.log_action("fw_rollback", "Rolled back firewall rules to last backup",
                                    success=ok)
        except Exception:
            pass

        if ok:
            return (_toast("Rules restored from last backup.", "success", header="Rolled Back"),
                    datetime.now().timestamp())
        return _toast("Rollback failed — check server logs.", "error", header="Rollback Failed"), no_update

    # ------------------------------------------------------------------
    # Dry-run preview for Add Rule form
    # ------------------------------------------------------------------
    @app.callback(
        Output('fw-rule-preview', 'children'),
        Input('fw-preview-btn', 'n_clicks'),
        [State('fw-target-ip', 'value'),
         State('fw-target-port', 'value'),
         State('fw-action-select', 'value'),
         State('fw-direction-select', 'value'),
         State('fw-dry-run-toggle', 'value')],
        prevent_initial_call=True,
    )
    def preview_rule(n_clicks, target_ip, target_port, action, direction, dry_run_toggle):
        if not n_clicks:
            raise dash.exceptions.PreventUpdate

        errors = _validate_rule_inputs(target_ip, target_port)
        if errors:
            return dbc.Alert(errors, color="danger")

        backend = getattr(firewall_enforcer, 'backend_name', 'noop')
        cmds = _build_rule_commands(target_ip.strip(), target_port, action, direction, backend)
        code_block = html.Pre("\n".join(cmds), className="code-terminal")
        is_dry = "dry_run" in (dry_run_toggle or [])
        note = ("Preview only — no changes applied." if is_dry
                else "Apply Rule will execute these commands immediately.")
        return html.Div([
            html.Small(note, className=f"text-{'info' if is_dry else 'warning'} d-block mb-1"),
            code_block,
        ])

    # ------------------------------------------------------------------
    # Apply Add Rule
    # ------------------------------------------------------------------
    @app.callback(
        [Output('toast-container', 'children', allow_duplicate=True),
         Output('fw-release-signal', 'data', allow_duplicate=True)],
        Input('fw-apply-rule-btn', 'n_clicks'),
        [State('fw-target-ip', 'value'),
         State('fw-target-port', 'value'),
         State('fw-action-select', 'value'),
         State('fw-direction-select', 'value'),
         State('fw-dry-run-toggle', 'value')],
        prevent_initial_call=True,
    )
    def apply_rule(n_clicks, target_ip, target_port, action, direction, dry_run_toggle):
        if not n_clicks:
            raise dash.exceptions.PreventUpdate

        if not _check_admin():
            return (_toast("Admin access required to add firewall rules.", "error",
                           header="Permission denied"), no_update)

        errors = _validate_rule_inputs(target_ip, target_port)
        if errors:
            return _toast(errors, "error", header="Invalid Input"), no_update

        dry_run = "dry_run" in (dry_run_toggle or [])
        ip = target_ip.strip()

        try:
            if not dry_run:
                ok = (firewall_enforcer.block_ip(ip) if action == "block"
                      else firewall_enforcer.unblock_ip(ip))
            else:
                ok = True
                _audit_dry_run(action, ip, target_port, direction)

            try:
                audit_logger.log_action(
                    f"fw_add_rule_{action}",
                    f"{'[DRY RUN] ' if dry_run else ''}Firewall rule: {action} {ip}",
                    target_resource=ip,
                    success=ok,
                )
            except Exception:
                pass

            backend = getattr(firewall_enforcer, 'backend_name', 'noop')
            port_str = f" port {target_port}" if target_port else ""
            if dry_run:
                return (_toast(f"Dry run: {action.upper()} {ip}{port_str} ({backend})",
                               "success", header="Preview Only"), no_update)
            elif ok:
                return (_toast(f"{action.upper()} {ip}{port_str} applied ({backend})",
                               "success", header="Rule Applied"),
                        datetime.now().timestamp())
            else:
                return (_toast(f"Rule may not have applied — check logs ({backend})",
                               "warning", header="Partial Apply"),
                        datetime.now().timestamp())

        except Exception as e:
            logger.error(f"fw apply_rule error: {e}")
            return _toast(f"Error applying rule: {e}", "error", header="Apply Failed"), no_update


# ---------------------------------------------------------------------------
# Private helpers
# ---------------------------------------------------------------------------

def _validate_rule_inputs(target_ip, target_port) -> str:
    if not target_ip or not target_ip.strip():
        return "Target IP address is required."
    if not _IP_RE.match(target_ip.strip()):
        return f"'{target_ip.strip()}' is not a valid IPv4 address."
    if target_port:
        for part in target_port.replace(' ', '').split(','):
            rng = part.split('-')
            if not all(r.isdigit() and 0 < int(r) <= 65535 for r in rng):
                return f"Invalid port '{part}'. Use 80, 22-443, or comma-separated values."
    return ""


def _build_rule_commands(ip: str, port: str, action: str, direction: str, backend: str) -> list:
    """Build preview commands for the correct backend."""
    if 'nft' in backend:
        jump = "drop" if action == "block" else "accept"
        port_clause = f" tcp dport {port}" if port else ""
        table = "inet iotsentinel forward"
        cmds = []
        if direction in ("both", "in"):
            cmds.append(f"nft add rule {table} ip saddr {ip}{port_clause} {jump}")
        if direction in ("both", "out"):
            cmds.append(f"nft add rule {table} ip daddr {ip}{port_clause} {jump}")
        return cmds
    else:
        jump = "DROP" if action == "block" else "ACCEPT"
        port_args = ["-p", "tcp", "--dport", port] if port else []
        base = ["iptables", "-A", "IOTSENTINEL"]
        cmds = []
        if direction in ("both", "in"):
            cmds.append(" ".join(base + ["-s", ip] + port_args + ["-j", jump]))
        if direction in ("both", "out"):
            cmds.append(" ".join(base + ["-d", ip] + port_args + ["-j", jump]))
        return cmds


def _audit_dry_run(action: str, ip: str, port: str, direction: str):
    from utils.firewall_enforcer import _audit
    _audit(f"{action}_dry_run", ip, True,
           f"port={port or 'any'} dir={direction}", dry_run=True)
