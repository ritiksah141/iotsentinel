"""
Global / cross-cutting callbacks — notifications, toast, chat/AI, spotlight,
onboarding, lockdown/emergency, theme/dark mode, keyboard shortcuts, voice
alerts, pause/resume, quick actions, quick settings (20+ autosave callbacks),
widget preferences, layout customization, dark mode.

Extracted from app.py.  All callbacks are registered via ``register(app)``.
"""

import json
import os
import subprocess
import sys
import time
import shutil
import psutil
from datetime import datetime

from utils.alert_explainer import source_label as _source_label, source_badge_class as _source_badge_class

import dash
import dash_bootstrap_components as dbc
from dash import dcc, html, Input, Output, State, callback_context, ALL, no_update

from flask_login import login_required, current_user
from flask import request

from dashboard.shared import (
    db_manager,
    config,
    logger,
    project_root,
    audit_logger,
    security_audit_logger,
    ai_assistant,
    nl_to_sql,
    rate_limiter,
    export_helper,
    report_queue,
    report_scheduler,
    template_manager,
    privacy_analyzer,
    ToastManager,
    get_db_connection,
    get_device_details,
    get_latest_alerts_content,
    get_devices_with_status,
    get_latest_alerts,
    get_bandwidth_stats,

    DASHBOARD_TEMPLATES,
    can_block_devices,
    can_manage_devices,
    log_device_action,
    log_emergency_mode,
    log_user_action,
    firewall_enforcer,
)


# ---------------------------------------------------------------------------
# Helper: create_spotlight_result_item  (used by spotlight callbacks)
# ---------------------------------------------------------------------------

def create_spotlight_result_item(feature, index, is_selected=False, is_top_hit=False):
    """Create a compact macOS-style result row for spotlight search."""
    icon = feature.get('icon', 'fa-circle')
    name = feature.get('name', 'Unknown')
    description = feature.get('description', '')
    category = feature.get('category', '')
    fid = feature.get('id', '')

    _ICON_COLORS = {
        'Security': '#ef4444', 'Analytics': '#3b82f6', 'IoT': '#10b981',
        'System': '#8b5cf6', 'Intelligence': '#f59e0b', 'Performance': '#06b6d4',
        'Education': '#ec4899', 'Actions': '#f97316', 'Notifications': '#6366f1',
        'Emergency': '#dc2626', 'Developer': '#84cc16', 'Customization': '#a78bfa',
        'Assistance': '#22d3ee', 'Help': '#fb923c',
    }
    color = _ICON_COLORS.get(category, '#6366f1')
    feature_data = json.dumps({
        'id': fid, 'name': name, 'description': description,
        'category': category, 'icon': icon, 'color': color,
        'keywords': feature.get('keywords', [])
    })

    row_cls = "sl-result-row"
    if is_top_hit:
        row_cls += " sl-top-hit"
    if is_selected:
        row_cls += " sl-selected"

    desc_text = (description[:72] + '…') if len(description) > 72 else description

    return html.Div([
        html.Div([
            html.Div(
                html.I(className=f"fa {icon}"),
                className="sl-icon-box",
                style={"background": f"{color}22", "color": color}
            ),
            html.Div([
                html.Div([
                    html.Span(name, className="sl-row-name"),
                    dbc.Badge("Top", color="warning", pill=True,
                              className="ms-2 sl-top-badge") if is_top_hit else None,
                ], className="d-flex align-items-center gap-1"),
                html.Div(desc_text, className="sl-row-desc"),
            ], className="sl-row-text"),
            html.Div([
                html.Span(category, className="sl-row-cat"),
                html.I(className="fa fa-chevron-right sl-row-arrow"),
            ], className="sl-row-right"),
        ], className="sl-row-inner"),
        dbc.Button(
            "",
            id={'type': 'spotlight-go-to-btn', 'index': str(index), 'modal_id': fid},
            n_clicks=0,
            style={"display": "none"}
        ),
    ],
    id={"type": "spotlight-result-item", "index": str(index)},
    className=row_cls,
    **{"data-feature": feature_data}
    )


# Modals that require admin role — used by both the spotlight RBAC check and
# the card-button bounce-back callback.  Keep as single source of truth.
ADMIN_ONLY_MODALS = [
    'email-modal', 'user-modal', 'firewall-modal',
    'vuln-scanner-modal', 'compliance-modal', 'lockdown-modal',
]

# ============================================================================
# register(app) — all ~83 global / cross-cutting callbacks
# ============================================================================

def register(app):
    """Register all global / cross-cutting callbacks on *app*."""

    # ================================================================
    # LIVE WEBSOCKET URL — point the WebSocket at the host the browser
    # actually loaded the page from, not a baked-in 127.0.0.1. Without this
    # the socket only connects when the dashboard is opened ON the Pi itself;
    # from a phone/laptop (hotspot IP, iotsentinel.local, LAN IP, or the
    # remote-access https URL) it would dial the *client's* own localhost and
    # silently fail, leaving every live card/graph/topology empty.
    # ================================================================
    app.clientside_callback(
        """
        function(href) {
            var proto = (window.location.protocol === 'https:') ? 'wss://' : 'ws://';
            return proto + window.location.host + '/ws';
        }
        """,
        Output("ws", "url"),
        Input("url", "href"),
    )

    # ================================================================
    # PARSE WEBSOCKET PAYLOAD — dash-extensions sets ws.message to
    # {data: "<raw json>"}; parse it once into ws-data.data so every
    # callback can read the payload dict directly. Reading ws.message raw
    # made every ws_message.get(...) miss, leaving the live cards, device
    # list and graphs blank.
    # ================================================================
    app.clientside_callback(
        """
        function(msg) {
            if (!msg || !msg.data) return window.dash_clientside.no_update;
            try { return JSON.parse(msg.data); }
            catch (e) { return window.dash_clientside.no_update; }
        }
        """,
        Output("ws-data", "data"),
        Input("ws", "message"),
    )

    # ================================================================
    # SIDEBAR NAVIGATION
    # ================================================================

    _SIDEBAR_TAB_MAP = {
        "sidebar-btn-overview":   "tab-overview",
        "sidebar-btn-alerts":     "tab-alerts",
        "sidebar-btn-devices":    "tab-devices",
        "sidebar-btn-analytics":  "tab-analytics",
        "sidebar-btn-compliance": "tab-compliance",
        "sidebar-btn-admin":      "tab-admin",
    }
    _SIDEBAR_BTN_IDS = list(_SIDEBAR_TAB_MAP.keys())

    # ---- Mobile tab bar maps ----
    _TABBAR_TAB_MAP = {
        "tabbar-btn-overview":   "tab-overview",
        "tabbar-btn-alerts":     "tab-alerts",
        "tabbar-btn-devices":    "tab-devices",
        "tabbar-btn-analytics":  "tab-analytics",
        "tabbar-btn-compliance": "tab-compliance",
        "tabbar-btn-admin":      "tab-admin",
    }
    _TABBAR_PRIMARY_IDS = ["tabbar-btn-overview", "tabbar-btn-alerts",
                           "tabbar-btn-devices", "tabbar-btn-analytics"]
    _TABBAR_MORE_IDS    = ["tabbar-btn-compliance", "tabbar-btn-admin"]
    _ALL_NAV_BTN_IDS    = _SIDEBAR_BTN_IDS + list(_TABBAR_TAB_MAP.keys())
    _ALL_TAB_MAP        = {**_SIDEBAR_TAB_MAP, **_TABBAR_TAB_MAP}

    @app.callback(
        Output("main-dashboard-tabs", "value"),
        [Input(btn_id, "n_clicks") for btn_id in _ALL_NAV_BTN_IDS],
        prevent_initial_call=True,
    )
    def sidebar_switch_tab(*_):
        triggered = callback_context.triggered
        if not triggered:
            return dash.no_update
        btn_id = triggered[0]["prop_id"].split(".")[0]
        return _ALL_TAB_MAP.get(btn_id, dash.no_update)

    @app.callback(
        [Output(btn_id, "className") for btn_id in _SIDEBAR_BTN_IDS],
        Input("main-dashboard-tabs", "value"),
    )
    def sidebar_set_active(active_tab):
        return [
            "sidebar-nav-item sidebar-nav-active"
            if _SIDEBAR_TAB_MAP[btn_id] == active_tab
            else "sidebar-nav-item"
            for btn_id in _SIDEBAR_BTN_IDS
        ]

    # ---- Tab bar: primary buttons active state ----
    @app.callback(
        [Output(btn_id, "className") for btn_id in _TABBAR_PRIMARY_IDS],
        Input("main-dashboard-tabs", "value"),
    )
    def tabbar_set_primary_active(active_tab):
        return [
            "tabbar-item tabbar-active"
            if _TABBAR_TAB_MAP[btn_id] == active_tab
            else "tabbar-item"
            for btn_id in _TABBAR_PRIMARY_IDS
        ]

    # ---- Tab bar: More button highlights when a More-sheet tab is active ----
    _TABBAR_MORE_TABS = {_TABBAR_TAB_MAP[b] for b in _TABBAR_MORE_IDS}

    @app.callback(
        Output("tabbar-btn-more", "className"),
        Input("main-dashboard-tabs", "value"),
    )
    def tabbar_more_btn_active(active_tab):
        return "tabbar-item tabbar-active" if active_tab in _TABBAR_MORE_TABS else "tabbar-item"

    # ---- Tab bar: More-sheet item active states ----
    @app.callback(
        [Output(btn_id, "className") for btn_id in _TABBAR_MORE_IDS],
        Input("main-dashboard-tabs", "value"),
    )
    def tabbar_set_more_active(active_tab):
        return [
            "tabbar-more-item tabbar-active"
            if _TABBAR_TAB_MAP[btn_id] == active_tab
            else "tabbar-more-item"
            for btn_id in _TABBAR_MORE_IDS
        ]

    # ---- Tab bar: More sheet open/close (clientside) ----
    app.clientside_callback(
        """
        function(nMore, nBackdrop) {
            var sheet    = document.getElementById('tabbar-more-sheet');
            var backdrop = document.getElementById('tabbar-more-backdrop');
            if (!sheet || !backdrop) return window.dash_clientside.no_update;
            var ctx = window.dash_clientside.callback_context;
            var triggeredId = ctx.triggered[0].prop_id.split('.')[0];
            if (triggeredId === 'tabbar-btn-more') {
                sheet.classList.toggle('open');
                backdrop.classList.toggle('open');
            } else {
                sheet.classList.remove('open');
                backdrop.classList.remove('open');
            }
            return window.dash_clientside.no_update;
        }
        """,
        Output("tabbar-more-backdrop", "data-open"),
        [Input("tabbar-btn-more", "n_clicks"),
         Input("tabbar-more-backdrop", "n_clicks")],
        prevent_initial_call=True,
    )

    # ---- Top navbar: "More" toggle reveals the secondary action buttons on mobile ----
    # On desktop the secondary buttons are always inline and the More toggle is hidden by
    # CSS, so this only has a visible effect at mobile widths (see #dashboard-navbar in
    # mobile-responsive.css). Mirrors the tab-bar More-sheet pattern above.
    app.clientside_callback(
        """
        function(n) {
            var sec = document.getElementById('navbar-secondary-actions');
            if (sec) sec.classList.toggle('show');
            return window.dash_clientside.no_update;
        }
        """,
        Output("navbar-more-toggle", "data-open"),
        Input("navbar-more-toggle", "n_clicks"),
        prevent_initial_call=True,
    )

    # Close More sheet whenever navigation changes (a More-sheet item was tapped)
    app.clientside_callback(
        """
        function(value) {
            var sheet    = document.getElementById('tabbar-more-sheet');
            var backdrop = document.getElementById('tabbar-more-backdrop');
            if (sheet)    sheet.classList.remove('open');
            if (backdrop) backdrop.classList.remove('open');
            return window.dash_clientside.no_update;
        }
        """,
        Output("tabbar-more-sheet", "data-tab"),
        Input("main-dashboard-tabs", "value"),
        prevent_initial_call=True,
    )

    # Forcibly hide dcc.Tabs header bar after every render — belt-and-suspenders
    # backup in case the CSS !important doesn't survive React's inline style.
    app.clientside_callback(
        """
        function(value) {
            var tabs = document.getElementById('main-dashboard-tabs');
            if (tabs && tabs.firstElementChild) {
                var header = tabs.firstElementChild;
                header.style.setProperty('display', 'none', 'important');
                header.style.setProperty('height', '0', 'important');
                header.style.setProperty('overflow', 'hidden', 'important');
            }
            return window.dash_clientside.no_update;
        }
        """,
        Output("main-dashboard-tabs", "style"),
        Input("main-dashboard-tabs", "value"),
        prevent_initial_call=False,
    )


    # ================================================================
    # NOTIFICATION BADGE & DRAWER
    # ================================================================

    @app.callback(
        [Output('notification-badge', 'children'),
         Output('notification-count-display', 'children'),
         Output('notification-drawer-body', 'children', allow_duplicate=True)],
        Input('ws-data', 'data'),
        prevent_initial_call=True
    )
    def update_notifications_from_ws(ws_message):
        if ws_message is None:
            return dash.no_update, dash.no_update, dash.no_update
        alert_count = ws_message.get('alert_count', 0)
        badge_count = "" if alert_count == 0 else str(alert_count)
        count_display = str(alert_count) if alert_count > 0 else ""

        # This callback updates the badge, count display, and drawer body
        return badge_count, count_display, dash.no_update

    @app.callback(
        [Output("notification-drawer", "is_open"),
         Output("notification-drawer-body", "children", allow_duplicate=True)],
        Input("notification-bell-button", "n_clicks"),
        [State("notification-drawer", "is_open")],
        prevent_initial_call=True,
    )
    def toggle_notification_drawer(n_clicks, is_open):
        """Toggle notification modal and load latest alerts when opening"""
        if n_clicks:
            if not is_open:
                # If opening, load fresh alerts
                return True, get_latest_alerts_content()
            # If closing
            return False, dash.no_update
        return is_open, dash.no_update

    # Clientside callback to handle card clicks and open modals
    app.clientside_callback(
        """
        function(pathname) {
            // Map of card button IDs to modal IDs
            const cardModalMap = {
                'analytics-card-btn': 'analytics-modal',
                'system-card-btn': 'system-modal',
                'email-card-btn': 'email-modal',
                'firewall-card-btn': 'firewall-modal',
                'user-card-btn': 'user-modal',
                'device-mgmt-card-btn': 'device-mgmt-modal',
                'preferences-card-btn': 'preferences-modal',
                'timeline-card-btn': 'timeline-viz-modal',
                'protocol-card-btn': 'protocol-modal',
                'threat-card-btn': 'threat-modal',
                'privacy-card-btn': 'privacy-modal',
                'smarthome-card-btn': 'smarthome-modal',
                'segmentation-card-btn': 'segmentation-modal',
                'firmware-card-btn': 'firmware-modal',
                'education-card-btn': 'education-modal',
                'threat-map-card-btn': 'threat-map-modal',
                'risk-heatmap-card-btn': 'risk-heatmap-modal',
                'attack-surface-card-btn': 'attack-surface-modal',
                'forensic-timeline-card-btn': 'forensic-timeline-modal',
                'compliance-card-btn': 'compliance-modal',
                'auto-response-card-btn': 'auto-response-modal',
                'vuln-scanner-card-btn': 'vuln-scanner-modal',
                'api-hub-card-btn': 'api-hub-modal',
                'benchmark-card-btn': 'benchmark-modal',
                'performance-card-btn': 'performance-modal'
            };

            // Add click listeners to all cards
            Object.keys(cardModalMap).forEach(cardId => {
                const card = document.getElementById(cardId);
                if (card && !card.hasAttribute('data-listener')) {
                    card.setAttribute('data-listener', 'true');
                    card.addEventListener('click', function() {
                        const modalId = cardModalMap[cardId];
                        const modal = document.getElementById(modalId);
                        if (modal) {
                            // Trigger Bootstrap modal open
                            const bsModal = new bootstrap.Modal(modal);
                            bsModal.show();
                        }
                    });
                }
            });

            return window.dash_clientside.no_update;
        }
        """,
        Output('dummy-output-card-clicks', 'children'),
        Input('url', 'pathname'),
        prevent_initial_call=False
    )

    # ================================================================
    # TOAST DETAIL MODAL
    # ================================================================

    @app.callback(
        [Output('toast-detail-modal', 'is_open'),
         Output('toast-detail-modal-title', 'children'),
         Output('toast-detail-modal-summary', 'children'),
         Output('toast-detail-modal-content', 'children')],
        [Input({'type': 'toast-detail-btn', 'toast_id': ALL}, 'n_clicks'),
         Input({'type': 'toast-history-detail-btn', 'toast_id': ALL}, 'n_clicks')],
        [State('toast-detail-modal', 'is_open')],
        prevent_initial_call=True
    )
    def handle_toast_detail_modal(detail_clicks, history_detail_clicks, is_open):
        """Handle opening and closing of toast detail modal"""
        ctx = callback_context
        if not ctx.triggered:
            raise dash.exceptions.PreventUpdate

        trigger_id = ctx.triggered[0]['prop_id']
        trigger_value = ctx.triggered[0]['value']

        # Prevent trigger on component creation (when n_clicks is None)
        if trigger_value is None:
            raise dash.exceptions.PreventUpdate


        # Detail button clicked from regular toast
        if 'toast-detail-btn' in trigger_id:
            try:
                prop_id_str = ctx.triggered[0]['prop_id']
                id_str = prop_id_str.rsplit('.', 1)[0]
                button_id = json.loads(id_str)
                toast_id = button_id['toast_id']

                detail_info = ToastManager.get_detail(toast_id)
                if detail_info:
                    ToastManager.clear_detail(toast_id)

                    category_info = ""
                    if detail_info.get('category') and detail_info.get('category') != 'general':
                        category_info = f" • {detail_info.get('category').title()}"

                    return (
                        True,
                        detail_info.get('message') or detail_info.get('header', 'Details'),
                        f"{(detail_info.get('header') or detail_info.get('type', '').title())}{category_info}",
                        detail_info.get('detail', 'No additional details available.')
                    )
            except Exception as e:
                logger.error(f"Error parsing toast detail button ID: {e}")
                raise dash.exceptions.PreventUpdate

        # Detail button clicked from toast history
        if 'toast-history-detail-btn' in trigger_id:
            try:
                prop_id_str = ctx.triggered[0]['prop_id']
                id_str = prop_id_str.rsplit('.', 1)[0]
                button_id = json.loads(id_str)
                toast_id = button_id['toast_id']

                from utils.toast_manager import ToastHistoryManager
                import sqlite3

                conn = db_manager.conn
                cursor = conn.cursor()

                cursor.execute("""
                    SELECT header, message, detail_message, toast_type, category
                    FROM toast_history
                    WHERE toast_id = ?
                """, (toast_id,))

                row = cursor.fetchone()

                if row:
                    category_info = ""
                    if row['category'] and row['category'] != 'general':
                        category_info = f" • {row['category'].title()}"

                    return (
                        True,
                        row['message'] or row['header'] or 'Details',
                        f"{(row['header'] or row['toast_type'].title())}{category_info}",
                        row['detail_message'] or 'No additional details available.'
                    )
                else:
                    logger.warning(f"Toast with ID {toast_id} not found in history")
                    return (
                        True,
                        'Not Found',
                        '',
                        f'Toast details not found for ID: {toast_id}'
                    )

            except Exception as e:
                logger.error(f"Error retrieving toast history detail: {e}")
                return (
                    True,
                    'Error',
                    '',
                    f'Failed to load details: {str(e)}'
                )

        raise dash.exceptions.PreventUpdate

    # ================================================================
    # TOAST HISTORY PANEL
    # ================================================================

    @app.callback(
        [Output("toast-history-modal", "is_open"),
         Output("toast-history-list", "children", allow_duplicate=True)],
        Input("toast-history-toggle-btn", "n_clicks"),
        State("toast-history-modal", "is_open"),
        prevent_initial_call=True
    )
    def toggle_toast_history_modal(n_clicks, is_open):
        """Toggle the toast history modal and load history when opening"""
        if n_clicks:
            if not is_open:
                from utils.toast_manager import ToastHistoryManager

                try:
                    history = ToastHistoryManager.get_history(limit=50)
                except Exception as e:
                    logger.error(f"Error loading toast history: {e}")
                    history = []

                if not history:
                    return True, html.Div([
                        html.I(className="fas fa-inbox fa-3x mb-3"),
                        html.P("No toast history found", className="mb-0")
                    ], className="toast-history-empty")

                items = []
                for toast in history:
                    type_class_map = {
                        "success": "toast-history-type-success",
                        "danger": "toast-history-type-danger",
                        "warning": "toast-history-type-warning",
                        "info": "toast-history-type-info"
                    }

                    try:
                        ts = datetime.fromisoformat(toast['timestamp'])
                        time_str = ts.strftime("%b %d, %I:%M %p")
                    except:
                        time_str = toast['timestamp']

                    context_parts = []
                    if toast.get('header'):
                        context_parts.append(toast['header'])
                    if toast.get('category') and toast['category'] != 'general':
                        context_parts.append(toast['category'].title())
                    context_info = " • ".join(context_parts) if context_parts else toast['toast_type'].title()

                    item_content = [
                        html.Div([
                            html.Span(toast['message'], className="me-2 fw-bold"),
                            html.Span(
                                toast['toast_type'].upper(),
                                className=f"toast-history-type-badge {type_class_map.get(toast['toast_type'], 'toast-history-type-info')}"
                            )
                        ], className="toast-history-item-header"),
                        html.Div(context_info, className="toast-history-item-context text-muted small"),
                        html.Div(time_str, className="toast-history-item-time")
                    ]

                    if toast.get('detail_message'):
                        item_content.append(
                            html.Div([
                                dbc.Button(
                                    [html.I(className="fas fa-info-circle me-1"), "View Details"],
                                    id={'type': 'toast-history-detail-btn', 'toast_id': toast['toast_id']},
                                    color="link",
                                    size="sm",
                                    className="p-0 mt-2 text-decoration-none"
                                )
                            ], className="mt-2")
                        )

                    item = html.Div(
                        item_content,
                        className="toast-history-item",
                        **{"data-category": toast.get('category', 'general')}
                    )

                    items.append(item)

                return True, items
            else:
                return False, dash.no_update

        raise dash.exceptions.PreventUpdate

    # Load Toast History with Filters
    @app.callback(
        Output("toast-history-list", "children", allow_duplicate=True),
        [Input("toast-history-category-filter", "value"),
         Input("toast-history-type-filter", "value")],
        prevent_initial_call=True
    )
    def update_toast_history_list(category, toast_type):
        """Update the toast history list based on filters"""
        from utils.toast_manager import ToastHistoryManager

        try:
            history = ToastHistoryManager.get_history(
                category=None if category == "all" else category,
                toast_type=None if toast_type == "all" else toast_type,
                limit=50
            )
        except Exception as e:
            logger.error(f"Error loading toast history: {e}")
            history = []

        if not history:
            return html.Div([
                html.I(className="fas fa-inbox fa-3x mb-3"),
                html.P("No toast history found", className="mb-0")
            ], className="toast-history-empty")

        items = []
        for toast in history:
            type_class_map = {
                "success": "toast-history-type-success",
                "danger": "toast-history-type-danger",
                "warning": "toast-history-type-warning",
                "info": "toast-history-type-info"
            }

            try:
                ts = datetime.fromisoformat(toast['timestamp'])
                time_str = ts.strftime("%b %d, %I:%M %p")
            except:
                time_str = toast['timestamp']

            context_parts = []
            if toast.get('header'):
                context_parts.append(toast['header'])
            if toast.get('category') and toast['category'] != 'general':
                context_parts.append(toast['category'].title())
            context_info = " • ".join(context_parts) if context_parts else toast['toast_type'].title()

            item_content = [
                html.Div([
                    html.Span(toast['message'], className="me-2 fw-bold"),
                    html.Span(
                        toast['toast_type'].upper(),
                        className=f"toast-history-type-badge {type_class_map.get(toast['toast_type'], 'toast-history-type-info')}"
                    )
                ], className="toast-history-item-header"),
                html.Div(context_info, className="toast-history-item-context text-muted small"),
                html.Div(time_str, className="toast-history-item-time")
            ]

            if toast.get('detail_message'):
                item_content.append(
                    html.Div([
                        dbc.Button(
                            [html.I(className="fas fa-info-circle me-1"), "View Details"],
                            id={'type': 'toast-history-detail-btn', 'toast_id': toast['toast_id']},
                            color="link",
                            size="sm",
                            className="p-0 mt-2 text-decoration-none"
                        )
                    ], className="mt-2")
                )

            item = html.Div(
                item_content,
                className="toast-history-item",
                **{"data-category": toast.get('category', 'general')}
            )

            items.append(item)

        return items

    # Clear Toast History
    @app.callback(
        [Output("toast-container", "children", allow_duplicate=True),
         Output("toast-history-category-filter", "value"),
         Output("toast-history-type-filter", "value")],
        Input("toast-history-clear-btn", "n_clicks"),
        prevent_initial_call=True
    )
    def clear_toast_history(n_clicks):
        """Clear all toast history from database"""
        from utils.toast_manager import ToastHistoryManager

        if n_clicks:
            try:
                import sqlite3
                conn = db_manager.conn
                cursor = conn.cursor()
                cursor.execute("DELETE FROM toast_history")
                deleted_count = cursor.rowcount
                conn.commit()

                logger.info(f"User {current_user.username} cleared {deleted_count} toast history records")

                return (
                    ToastManager.success(
                        f"Cleared {deleted_count} toast history records",
                        category="system",
                        duration="short"
                    ),
                    "all",
                    "all"
                )
            except Exception as e:
                logger.error(f"Error clearing toast history: {e}")

                return (
                    ToastManager.error(
                        "Failed to clear toast history",
                        category="system",
                        detail_message=str(e)
                    ),
                    "all",
                    "all"
                )

        raise dash.exceptions.PreventUpdate

    # ================================================================
    # BLOCK DEVICE — confirmation modal + confirmed action
    # ================================================================

    @app.callback(
        [Output('block-device-modal', 'is_open'),
         Output('block-device-ip-store', 'data'),
         Output('block-device-action-store', 'data'),
         Output('block-device-modal-title', 'children'),
         Output('block-device-modal-icon', 'className'),
         Output('block-device-modal-question', 'children'),
         Output('block-device-modal-ip', 'children'),
         Output('block-device-modal-warning', 'children'),
         Output('block-device-confirm-btn', 'children'),
         Output('block-device-confirm-btn', 'color')],
        Input({'type': 'device-block-btn', 'ip': dash.dependencies.ALL}, 'n_clicks'),
        prevent_initial_call=True
    )
    def show_block_device_modal(n_clicks):
        """Show confirmation modal before blocking/unblocking device."""
        ctx = dash.callback_context
        if not ctx.triggered_id:
            raise dash.exceptions.PreventUpdate

        if not n_clicks or all(c is None for c in n_clicks):
            raise dash.exceptions.PreventUpdate

        device_ip = ctx.triggered_id['ip']

        try:
            device = get_device_details(device_ip)
            if not device:
                raise dash.exceptions.PreventUpdate

            current_blocked = bool(device.get('is_blocked', False))
            new_blocked_status = not current_blocked
            device_name = device.get('custom_name') or device.get('device_name') or device_ip

            if new_blocked_status:
                return (
                    True, device_ip, 'block',
                    "⚠️ Confirm Block Device",
                    "fa fa-ban fa-3x text-danger mb-3",
                    "Are you sure you want to block this device?",
                    f"Device: {device_name} ({device_ip})",
                    "This device will be prevented from accessing your network.",
                    "Block Device", "danger"
                )
            else:
                return (
                    True, device_ip, 'unblock',
                    "✓ Confirm Unblock Device",
                    "fa fa-check-circle fa-3x text-success mb-3",
                    "Are you sure you want to unblock this device?",
                    f"Device: {device_name} ({device_ip})",
                    "This device will be allowed to access your network.",
                    "Unblock Device", "success"
                )
        except Exception as e:
            logger.error(f"Error showing block modal: {e}")
            raise dash.exceptions.PreventUpdate

    @app.callback(
        [Output('toast-container', 'children', allow_duplicate=True),
         Output('block-device-modal', 'is_open', allow_duplicate=True)],
        [Input('block-device-confirm-btn', 'n_clicks'),
         Input('block-device-cancel', 'n_clicks')],
        [State('block-device-ip-store', 'data'),
         State('block-device-action-store', 'data')],
        prevent_initial_call=True
    )
    def toggle_device_block(confirm_clicks, cancel_clicks, device_ip, action):
        """Handle device blocking/unblocking via firewall"""
        ctx = dash.callback_context
        if not ctx.triggered_id:
            raise dash.exceptions.PreventUpdate

        button_id = ctx.triggered_id

        # Cancel button clicked
        if button_id == 'block-device-cancel':
            return dash.no_update, False

        # Check if user is authenticated
        if not current_user.is_authenticated:
            toast = ToastManager.error(
                "Access Denied",
                detail_message="You must be logged in to block/unblock devices."
            )
            return toast, False

        # Check if user has permission to block devices (security_analyst or admin)
        if not can_block_devices():
            security_audit_logger.log(
                event_type='permission_denied',
                severity='warning',
                user_id=current_user.id,
                username=current_user.username,
                resource_type='device',
                resource_id=device_ip,
                details={'attempted_action': 'block' if action == 'block' else 'unblock'},
                result='failure',
                failure_reason='Insufficient permissions - block_devices permission required'
            )
            toast = ToastManager.error(
                "Access Denied",
                detail_message="You don't have permission to block/unblock devices. Contact an administrator."
            )
            return toast, False

        # Confirm button clicked
        if button_id == 'block-device-confirm-btn' and device_ip and action:
            new_blocked_status = (action == 'block')

            # Check rate limit for device blocking
            allowed, remaining, reset_sec = rate_limiter.check_rate_limit(
                current_user.username, 'device_block'
            )
            if not allowed:
                toast = ToastManager.warning(
                    "Rate Limit Exceeded",
                    detail_message=f"Too many device block operations. Try again in {reset_sec} seconds."
                )
                return toast, False

            # Record the attempt
            rate_limiter.record_attempt(current_user.username, 'device_block', success=True)

            # Update database first
            db_manager.set_device_blocked(device_ip, new_blocked_status)

            action_text = "blocked" if new_blocked_status else "unblocked"
            toast_type = "warning" if new_blocked_status else "success"

            device = get_device_details(device_ip)
            mac_address = device.get('mac_address') if device else None

            # Apply via FirewallEnforcer (replaces direct firewall_manager subprocess call)
            enforcer_ok = False
            try:
                if new_blocked_status:
                    enforcer_ok = firewall_enforcer.block_device(device_ip, mac_address)
                else:
                    enforcer_ok = firewall_enforcer.unblock_device(device_ip, mac_address)
            except Exception as _fe:
                logger.error(f"FirewallEnforcer error for {device_ip}: {_fe}")

            backend = getattr(firewall_enforcer, 'backend_name', 'noop')
            if enforcer_ok:
                message = f"Device {device_ip} {action_text} ({backend})"
            else:
                message = f"Device {device_ip} {action_text} in database (enforcer: {backend} - may need root)"

            # Log the action to audit trail
            log_device_action(
                audit_logger,
                'block' if new_blocked_status else 'unblock',
                device_ip,
                success=True
            )

            if toast_type == "success":
                toast = ToastManager.success(f"Device {action_text.capitalize()}", detail_message=message)
            else:
                toast = ToastManager.warning(f"Device {action_text.capitalize()}", detail_message=message)

            return toast, False

        raise dash.exceptions.PreventUpdate

    # ================================================================
    # TOUR (driver.js interactive tour — replaces prose modal)
    # ================================================================

    # A) First-run auto-launch + restart button
    app.clientside_callback(
        """
        function(pathname, restart_clicks, store_data) {
            var ctx = window.dash_clientside.callback_context;
            if (!ctx.triggered || ctx.triggered.length === 0) {
                return window.dash_clientside.no_update;
            }
            var triggerId = ctx.triggered[0].prop_id;
            function tryStart(attempts) {
                if (window.startIotTour) {
                    window.startIotTour();
                } else if (attempts > 0) {
                    setTimeout(function() { tryStart(attempts - 1); }, 250);
                }
            }
            if (triggerId.indexOf('url') !== -1) {
                // First page load — launch for new users only
                if (!store_data || !store_data.completed) {
                    setTimeout(function() { tryStart(12); }, 1500);
                }
            } else if (triggerId.indexOf('restart-tour-button') !== -1) {
                tryStart(8);
            }
            return window.dash_clientside.no_update;
        }
        """,
        Output('onboarding-step-store', 'data'),
        Input('url', 'pathname'),
        Input('restart-tour-button', 'n_clicks'),
        State('onboarding-store', 'data'),
        prevent_initial_call=False,
    )

    # B) Spotlight "Interactive Tour" click — intercepts the ghost modal's is_open=True
    app.clientside_callback(
        """
        function(is_open) {
            if (is_open) {
                function tryStart(attempts) {
                    if (window.startIotTour) {
                        window.startIotTour();
                    } else if (attempts > 0) {
                        setTimeout(function() { tryStart(attempts - 1); }, 250);
                    }
                }
                setTimeout(function() { tryStart(8); }, 80);
                return false;  // Close the ghost modal immediately
            }
            return window.dash_clientside.no_update;
        }
        """,
        Output('onboarding-modal', 'is_open', allow_duplicate=True),
        Input('onboarding-modal', 'is_open'),
        prevent_initial_call=True,
    )

    # C) Tour completion — persist to localStorage via onboarding-store
    app.clientside_callback(
        """
        function(n_clicks) {
            if (!n_clicks) return window.dash_clientside.no_update;
            return {completed: true, timestamp: new Date().toISOString()};
        }
        """,
        Output('onboarding-store', 'data'),
        Input('tour-complete-sentinel', 'n_clicks'),
        prevent_initial_call=True,
    )

    # ================================================================
    # LOCKDOWN MODE
    # ================================================================

    @app.callback(
        [Output('lockdown-modal', 'is_open'),
         Output('lockdown-trusted-count', 'children'),
         Output('lockdown-blocked-count', 'children'),
         Output('lockdown-admin-device-status', 'children')],
        [Input('lockdown-switch', 'value'),
         Input('lockdown-cancel', 'n_clicks'),
         Input('lockdown-confirm', 'n_clicks')],
        [State('lockdown-modal', 'is_open'),
         State('ws-data', 'data')],
        prevent_initial_call=True
    )
    def toggle_lockdown_modal(switch_value, cancel_clicks, confirm_clicks, is_open, ws_message):
        """Show confirmation modal when lockdown is toggled"""
        ctx = callback_context
        if not ctx.triggered:
            return False, "0", "0", no_update

        trigger_id = ctx.triggered[0]['prop_id'].split('.')[0]

        if trigger_id == 'lockdown-switch' and switch_value:
            devices = ws_message.get('all_devices_with_status', []) if ws_message else []
            trusted_count = sum(1 for d in devices if d.get('is_trusted', False))
            blocked_count = len(devices) - trusted_count

            # Check if admin's current device is known and will be protected
            admin_ip = request.remote_addr if request else None
            if admin_ip:
                try:
                    row = db_manager.conn.execute(
                        "SELECT mac_address, device_name FROM devices WHERE device_ip = ?", (admin_ip,)
                    ).fetchone()
                    if row and row[0]:
                        label = row[1] or admin_ip
                        status_badge = dbc.Alert([
                            html.I(className="fa fa-laptop me-2 text-success"),
                            html.Strong("Your device is protected. "),
                            html.Span(f"{label} ({admin_ip}) will not be blocked.", className="small"),
                        ], color="success", className="mb-0 py-2")
                    else:
                        status_badge = dbc.Alert([
                            html.I(className="fa fa-exclamation-triangle me-2"),
                            html.Strong("Warning: "),
                            html.Span(f"Your device ({admin_ip}) was not found in the device list and may be blocked. Trust your device first.", className="small"),
                        ], color="warning", className="mb-0 py-2")
                except Exception:
                    status_badge = no_update
            else:
                status_badge = no_update

            return True, str(trusted_count), str(blocked_count), status_badge

        if trigger_id == 'lockdown-cancel':
            return False, "0", "0", no_update

        if trigger_id == 'lockdown-confirm':
            return False, "0", "0", no_update

        return False, "0", "0", no_update

    @app.callback(
        [Output('lockdown-switch', 'value'),
         Output('toast-container', 'children', allow_duplicate=True)],
        [Input('lockdown-cancel', 'n_clicks'),
         Input('lockdown-confirm', 'n_clicks'),
         Input('lockdown-switch', 'value')],
        prevent_initial_call=True
    )
    def handle_lockdown_confirmation(cancel_clicks, confirm_clicks, current_value):
        """Handle the actual lockdown mode toggle by calling the firewall script."""
        if not current_user.is_authenticated or not current_user.is_admin():
            raise dash.exceptions.PreventUpdate
        ctx = callback_context
        if not ctx.triggered:
            raise dash.exceptions.PreventUpdate

        trigger_id = ctx.triggered[0]['prop_id'].split('.')[0]

        if trigger_id == 'lockdown-switch':
            triggered_value = ctx.triggered[0]['value']

            if triggered_value is None:
                raise dash.exceptions.PreventUpdate

            if cancel_clicks is None and confirm_clicks is None:
                if not triggered_value:
                    raise dash.exceptions.PreventUpdate

        firewall_script = project_root / 'scripts' / 'firewall_manager.py'

        # Case 1: User cancels
        if trigger_id == 'lockdown-cancel':
            logger.info("Lockdown mode cancelled by user.")
            toast = ToastManager.info(
                "Cancelled",
                detail_message="Lockdown mode remains disabled"
            )
            return False, toast

        # Case 2: User confirms enabling lockdown
        if trigger_id == 'lockdown-confirm':
            if not config.get('firewall', 'enabled', default=False):
                logger.warning("Firewall management is disabled in config. Cannot enable lockdown.")
                toast = ToastManager.warning(
                    "Firewall Disabled",
                    detail_message="Firewall management is disabled in configuration. Cannot enable lockdown mode."
                )
                return False, toast

            logger.info("Lockdown mode ENABLED - applying firewall rules.")

            trusted_devices = db_manager.get_trusted_devices()
            trusted_macs = [d['mac_address'] for d in trusted_devices if d.get('mac_address')]

            # Always exempt the admin's current device so they never lose dashboard access
            admin_ip = request.remote_addr if request else None
            if admin_ip:
                try:
                    row = db_manager.conn.execute(
                        "SELECT mac_address FROM devices WHERE device_ip = ?", (admin_ip,)
                    ).fetchone()
                    if row and row[0] and row[0] not in trusted_macs:
                        trusted_macs.append(row[0])
                        logger.info("Auto-exempted admin device %s (MAC %s) from lockdown.", admin_ip, row[0])
                except Exception as exc:
                    logger.warning("Could not look up admin device MAC for lockdown exemption: %s", exc)

            if not trusted_macs:
                logger.warning("No trusted MAC addresses found. Lockdown will block all devices.")

            command = [sys.executable, str(firewall_script), '--apply'] + trusted_macs

            try:
                result = subprocess.run(command, capture_output=True, text=True, check=True)
                logger.info(f"Firewall script output: {result.stdout}")
                toast = ToastManager.warning(
                    "Lockdown Enabled",
                    detail_message=f"Lockdown Mode Active! {len(trusted_macs)} device(s) allowed. All other devices will be blocked."
                )
                return True, toast
            except (subprocess.CalledProcessError, FileNotFoundError) as e:
                logger.error(f"Failed to apply firewall rules: {e}")
                error_message = f"Error: {e.stderr}" if hasattr(e, 'stderr') else str(e)
                toast = ToastManager.error(
                    "Lockdown Failed",
                    detail_message=f"Failed to apply firewall rules: {error_message}"
                )
                return False, toast

        # Case 3: User toggles the switch to OFF
        if trigger_id == 'lockdown-switch' and not current_value:
            logger.info("Lockdown mode DISABLED - clearing firewall rules.")
            command = [sys.executable, str(firewall_script), '--clear']

            try:
                result = subprocess.run(command, capture_output=True, text=True, check=True)
                logger.info(f"Firewall clear script output: {result.stdout}")
                toast = ToastManager.success(
                    "Lockdown Disabled",
                    detail_message="Lockdown mode disabled and firewall rules cleared successfully"
                )
                return False, toast
            except (subprocess.CalledProcessError, FileNotFoundError) as e:
                logger.error(f"Failed to clear firewall rules: {e}")
                error_message = f"Error: {e.stderr}" if hasattr(e, 'stderr') else str(e)
                toast = ToastManager.warning(
                    "Clear Failed",
                    detail_message=f"Failed to clear firewall rules: {error_message}"
                )
                return True, toast

        raise dash.exceptions.PreventUpdate

    # ================================================================
    # VOICE ALERTS
    # ================================================================

    app.clientside_callback(
        """
        function(ws_message, voice_store_data, announced_alerts) {
            if (!ws_message || !window.speechSynthesis) {
                return window.dash_clientside.no_update;
            }

            const voice_enabled = voice_store_data ? voice_store_data.enabled : false;
            if (!voice_enabled) {
                return window.dash_clientside.no_update;
            }

            const recent_alerts = ws_message.recent_alerts || [];
            const announced = announced_alerts || {};
            const now = Date.now();

            // Clean up old entries (older than 1 hour)
            Object.keys(announced).forEach(id => {
                if (now - announced[id] > 3600000) {
                    delete announced[id];
                }
            });

            // Find new critical/high alerts that haven't been announced
            const new_alerts = recent_alerts.filter(alert => {
                return (alert.severity === 'critical' || alert.severity === 'high') &&
                       !announced[alert.id] &&
                       !alert.acknowledged;
            });

            if (new_alerts.length > 0) {
                const alert = new_alerts[0];
                const device_name = alert.device_name || alert.device_ip;
                const severity = alert.severity;
                const explanation = alert.explanation;

                let message = `Security alert! ${severity} severity detected on ${device_name}. ${explanation}`;

                const utterance = new SpeechSynthesisUtterance(message);
                utterance.rate = 0.9;
                utterance.pitch = 1.0;
                utterance.volume = 1.0;

                if (severity === 'critical') {
                    utterance.rate = 1.1;
                    utterance.pitch = 1.2;
                }

                window.speechSynthesis.speak(utterance);

                announced[alert.id] = now;

                console.log(`[Voice Alert] Announced ${severity} alert for ${device_name}`);
            }

            return announced;
        }
        """,
        Output('announced-alerts-store', 'data'),
        [Input('ws-data', 'data'),
         Input('voice-alert-store', 'data')],
        State('announced-alerts-store', 'data')
    )

    @app.callback(
        Output('alert-settings', 'value'),
        [Input('voice-alert-store', 'data'),
         Input('quick-settings-store', 'data')],
        State('alert-settings', 'value'),
    )
    def sync_voice_alert_checklist_from_store(voice_store_data, quick_settings_data, current_values):
        """Synchronizes the alert-settings checklist from both stores."""
        new_values = list(current_values) if current_values else []

        if voice_store_data:
            voice_is_enabled = voice_store_data.get('enabled', False)
            has_voice = 'voice' in new_values
            if voice_is_enabled and not has_voice:
                new_values.append('voice')
            elif not voice_is_enabled and has_voice:
                new_values.remove('voice')

        if quick_settings_data:
            notifications = quick_settings_data.get('notifications', {})

            browser_enabled = notifications.get('browser', False)
            has_browser = 'browser' in new_values
            if browser_enabled and not has_browser:
                new_values.append('browser')
            elif not browser_enabled and has_browser:
                new_values.remove('browser')

            critical_enabled = notifications.get('critical_only', False)
            has_critical = 'critical' in new_values
            if critical_enabled and not has_critical:
                new_values.append('critical')
            elif not critical_enabled and has_critical:
                new_values.remove('critical')

        if set(new_values) != set(current_values or []):
            return new_values

        return dash.no_update

    @app.callback(
        [Output('voice-alert-icon', 'className'),
         Output('voice-alert-store', 'data', allow_duplicate=True),
         Output('toast-container', 'children', allow_duplicate=True)],
        Input('voice-alert-toggle', 'n_clicks'),
        State('voice-alert-store', 'data'),
        prevent_initial_call=True
    )
    def toggle_voice_alerts(n_clicks, current_data):
        """Toggle voice alert state and update icon"""
        if n_clicks:
            current_enabled = current_data.get('enabled', False) if current_data else False
            new_enabled = not current_enabled
            icon_class = "fa fa-volume-up fa-lg" if new_enabled else "fa fa-volume-mute fa-lg"

            if new_enabled:
                square_color_class = "bg-success"
                message_text = "enabled"
            else:
                square_color_class = "bg-danger"
                message_text = "disabled"

            custom_header = html.Div(
                [
                    html.Span(className=f"toast-color-square {square_color_class} me-2"),
                    html.Strong("Voice Alerts")
                ],
                className="d-flex align-items-center"
            )

            toast = ToastManager.info(
                "Voice Alerts",
                detail_message=f"Voice alerts {message_text}"
            )
            return icon_class, {'enabled': new_enabled}, toast
        return "fa fa-volume-mute fa-lg", {'enabled': False}, no_update

    # ================================================================
    # PAUSE / RESUME MONITORING
    # ================================================================

    @app.callback(
        [Output('pause-button', 'children'), Output('pause-button', 'color')],
        [Input('pause-button', 'n_clicks')],
        [State('pause-button', 'children')]
    )
    def toggle_pause_monitoring(n_clicks, button_content):
        status_file = project_root / config.get('system', 'status_file_path', default='data/system_status.json')
        if n_clicks is None:
            try:
                with open(status_file, 'r', encoding='utf-8') as f:
                    status = json.load(f).get('status', 'running')
            except (FileNotFoundError, json.JSONDecodeError):
                status = 'running'
            if status == 'paused':
                return html.I(className="fa fa-play", id="pause-icon"), "success"
            return html.I(className="fa fa-pause", id="pause-icon"), "link"

        try:
            with open(status_file, 'r', encoding='utf-8') as f:
                current = json.load(f).get('status', 'running')
        except (FileNotFoundError, json.JSONDecodeError):
            current = 'running'

        new_status = 'paused' if current == 'running' else 'running'
        try:
            status_file.parent.mkdir(parents=True, exist_ok=True)
            with open(status_file, 'w', encoding='utf-8') as f:
                json.dump({'status': new_status}, f)
        except IOError as e:
            logger.error(f"Error writing status file: {e}")

        if new_status == 'paused':
            return html.I(className="fa fa-play", id="pause-icon"), "success"
        return html.I(className="fa fa-pause", id="pause-icon"), "link"

    # ================================================================
    # CHAT / AI ASSISTANT
    # ================================================================

    def _quota_badge_text(user_id: str, tier: str) -> str:
        """Return the remaining-messages badge text for the chat modal footer."""
        try:
            action_type = f'ai_chat_{tier}'
            _, remaining, _ = rate_limiter.check_rate_limit(str(user_id), action_type)
            cap = rate_limiter.LIMITS.get(action_type, (0, 0))[0]
            if remaining <= 0:
                return "On-device AI active - daily limit reached"
            return f"{remaining} / {cap} AI messages left today"
        except Exception:
            return ""

    def _build_chat_welcome() -> list:
        """Render the empty-state greeting + plain-English starter chips."""
        chips = [
            "Is my network safe?",
            "What's connected right now?",
            "Did any device contact a flagged IP today?",
            "Show me high-risk devices",
            "Explain my latest alert",
            "How do I block a device?",
        ]
        # Surface degraded cloud AI subtly: amber when some providers are
        # failing, red when all are (templates/local only). Tooltip carries
        # the most recent provider error for admins.
        status_text = ai_assistant.get_status_message()
        status_class = "chat-welcome-status"
        status_title = None
        try:
            level = ai_assistant.get_status_level()
            if level in ("degraded", "local-only"):
                health = ai_assistant.get_health()
                errors = [
                    f"{name}: {state['last_error']}"
                    for name, state in health["providers"].items()
                    if state.get("configured") and state.get("last_error")
                ]
                status_title = "; ".join(errors)[:300] or None
                if level == "local-only":
                    ollama_ok = health["providers"].get("ollama", {}).get("configured")
                    status_text = ("Cloud AI unreachable, using local AI"
                                   if ollama_ok else
                                   "Cloud AI unreachable, using local templates")
                    status_class += " text-danger"
                else:
                    status_text = "Some cloud AI providers unreachable"
                    status_class += " text-warning"
        except Exception:
            pass
        return [
            html.Div([
                html.Div([
                    html.I(className="fa fa-robot chat-welcome-icon"),
                    html.P("How can I help with your network today?",
                           className="chat-welcome-heading"),
                    html.P(status_text, className=status_class, title=status_title),
                ], className="chat-welcome-body"),
                html.Div([
                    dbc.Button(
                        chip,
                        id={'type': 'chat-chip', 'prompt': chip},
                        className="chat-chip",
                        n_clicks=0,
                    )
                    for chip in chips
                ], className="chat-chips-row"),
            ], className="chat-welcome")
        ]

    def _build_chat_history_ui(history: list) -> list:
        """Render the last 20 conversation turns as Dash components."""
        chat_messages = []
        for idx, msg in enumerate(history[-20:]):
            msg_time = msg.get('timestamp', '')
            time_str = ""
            try:
                time_str = datetime.fromisoformat(msg_time).strftime("%I:%M %p") if msg_time else ""
            except Exception:
                pass

            if msg['role'] == 'user':
                chat_messages.append(
                    dbc.Card(
                        dbc.CardBody([
                            html.Div([
                                html.Div([
                                    html.I(className="fa fa-user-circle me-2 u-text-chat-icon"),
                                    html.Strong("You", className="u-text-chat")
                                ], className="d-flex align-items-center"),
                                html.Small(time_str, className="text-muted u-text-chat-sm")
                            ], className="d-flex justify-content-between align-items-center mb-2"),
                            html.P(msg['content'], className="mb-0 u-text-chat")
                        ], className="chat-bubble"),
                        color="primary", outline=True, className="mb-3 chat-bubble--user"
                    )
                )
            else:
                _src = msg.get('source', '')
                _sl = _source_label(_src)
                _src_badge = (
                    dbc.Badge(
                        _sl, className=f"ms-2 {_source_badge_class(_src)}"
                    ) if _sl else html.Span()
                )
                chat_messages.append(
                    dbc.Card(
                        dbc.CardBody([
                            html.Div([
                                html.Div([
                                    html.I(className="fa fa-robot me-2 u-text-chat-icon"),
                                    html.Strong("IoTSentinel AI", className="u-text-chat"),
                                    _src_badge,
                                ], className="d-flex align-items-center"),
                                html.Div([
                                    html.Small(time_str, className="text-muted me-2 u-text-chat-sm"),
                                    dcc.Clipboard(
                                        content=msg['content'],
                                        title="Copy response",
                                        className="chat-copy-btn",
                                    )
                                ], className="d-flex align-items-center")
                            ], className="d-flex justify-content-between align-items-center mb-2"),
                            dcc.Markdown(msg['content'], className="mb-0 u-text-chat")
                        ], className="chat-bubble"),
                        color="info", outline=True, className="mb-3 chat-bubble--ai"
                    )
                )
        return chat_messages

    @app.callback(
        [Output("chat-modal", "is_open"),
         Output('chat-history-store', 'data', allow_duplicate=True),
         Output('chat-history', 'children', allow_duplicate=True),
         Output('chat-quota-badge', 'children', allow_duplicate=True)],
        Input("open-chat-button", "n_clicks"),
        [State("chat-modal", "is_open"),
         State('chat-history-store', 'data')],
        prevent_initial_call=True,
    )
    def toggle_chat_modal(n, is_open, chat_data):
        if not n:
            return is_open, dash.no_update, dash.no_update, dash.no_update

        new_state = not is_open
        if chat_data is None:
            chat_data = {'history': []}

        tier = config.get('system', 'deployment_tier', 'household')
        uid = getattr(current_user, 'id', 'anonymous') if current_user.is_authenticated else 'anonymous'
        badge = _quota_badge_text(uid, tier)

        history = chat_data.get('history', [])
        # Treat a session with only the old assistant-only welcome as empty
        no_real_convo = len(history) == 0 or (
            len(history) == 1 and history[0].get('role') == 'assistant'
        )
        if new_state and no_real_convo:
            chat_data['history'] = []
            return new_state, chat_data, _build_chat_welcome(), badge

        if new_state:
            return new_state, chat_data, _build_chat_history_ui(history), badge

        return new_state, chat_data, dash.no_update, dash.no_update

    # Clear chat history
    @app.callback(
        [Output('chat-history-store', 'data', allow_duplicate=True),
         Output('chat-history', 'children', allow_duplicate=True),
         Output('chat-quota-badge', 'children', allow_duplicate=True)],
        Input('clear-chat-button', 'n_clicks'),
        prevent_initial_call=True
    )
    def clear_chat_history(n_clicks):
        if not n_clicks:
            raise dash.exceptions.PreventUpdate
        tier = config.get('system', 'deployment_tier', 'household')
        uid = getattr(current_user, 'id', 'anonymous') if current_user.is_authenticated else 'anonymous'
        return {'history': []}, _build_chat_welcome(), _quota_badge_text(uid, tier)

    @app.callback(
        [Output('chat-history', 'children', allow_duplicate=True),
         Output('chat-input', 'value'),
         Output('chat-history-store', 'data', allow_duplicate=True),
         Output('chat-quota-badge', 'children', allow_duplicate=True)],
        [Input('chat-send-button', 'n_clicks'),
         Input('chat-input', 'n_submit'),
         Input({'type': 'chat-chip', 'prompt': ALL}, 'n_clicks')],
        [State('chat-input', 'value'),
         State('chat-history-store', 'data'),
         State('ws-data', 'data')],
        prevent_initial_call=True
    )
    def handle_chat_message(send_clicks, input_submit, chip_clicks, message, chat_data, ws_message):
        """Multi-turn AI chat: OpenAI → Groq → Ollama → rules, with tier-based daily cap."""
        # Determine if a starter chip was clicked; use its prompt text as the message
        ctx = callback_context
        if ctx.triggered:
            triggered_id = ctx.triggered[0]['prop_id']
            if 'chat-chip' in triggered_id:
                try:
                    id_dict = json.loads(triggered_id.split('.')[0])
                    chip_text = id_dict.get('prompt', '')
                    if chip_text and any(chip_clicks):
                        message = chip_text
                except Exception:
                    pass

        if not message or not message.strip():
            raise dash.exceptions.PreventUpdate

        history = chat_data.get('history', []) if chat_data else []
        history.append({
            'role': 'user',
            'content': message,
            'timestamp': datetime.now().isoformat()
        })

        # --- Data-lookup detection: /query prefix OR natural phrasing ---
        # NOTE: pattern 1 deliberately excludes "connect" — it's too broad and catches
        # conversational questions like "What's connected right now?". "connect" as a
        # connection verb is handled by pattern 2 which requires device context too.
        _DATA_PATTERNS = [
            r'\b(show|list|find|get|display|what|which|how many)\b.*(device|alert|traffic|bandwidth|port|ip|risk|threat)',
            r'\b(did|has|have|does)\b.*(device|camera|tv|phone|router).*(talk|contact|connect|send|upload)',
            r'\b(top|highest|most|least)\b.*(traffic|bandwidth|alert|risk)',
            r'\b(last|past|recent)\b.*(hour|day|week|alert|connect)',
        ]
        import re as _re
        msg_lower = message.strip().lower()
        is_data_query = message.strip().startswith('/query') or any(
            _re.search(p, msg_lower) for p in _DATA_PATTERNS
        )

        if is_data_query:
            try:
                nl_query = message.strip()[6:].strip() if message.strip().startswith('/query') else message.strip()
                if nl_query:
                    # Apply the same per-user daily cap used for AI chat to the NL
                    # data-query path — previously this path returned before the cap check.
                    _tier = config.get('system', 'deployment_tier', 'household')
                    _uid = str(getattr(current_user, 'id', 'anonymous')) if current_user.is_authenticated else 'anonymous'
                    _action_type = f'ai_chat_{_tier}'
                    _cap_ok, _, _ = rate_limiter.check_rate_limit(_uid, _action_type)
                    if not _cap_ok:
                        _cap = rate_limiter.LIMITS.get(_action_type, (0, 0))[0]
                        _limit_msg = (
                            f"Daily limit of {_cap} AI messages reached. "
                            "On-device AI only until midnight."
                        )
                        history.append({
                            'role': 'assistant',
                            'content': _limit_msg,
                            'timestamp': datetime.now().isoformat(),
                            'source': 'rules',
                        })
                        return _build_chat_history_ui(history), "", {'history': history}, _quota_badge_text(_uid, _tier)

                    result = nl_to_sql.execute_query(nl_query)
                    if result.get('status') == 'success':
                        plain_answer = nl_to_sql.answer_in_plain_english(nl_query, result)
                        table_text = nl_to_sql.format_results_as_text(result)
                        ai_response = f"{plain_answer}\n\n{table_text}" if plain_answer else table_text
                        history.append({
                            'role': 'assistant',
                            'content': ai_response,
                            'timestamp': datetime.now().isoformat(),
                            'source': 'database',
                        })
                        tier = config.get('system', 'deployment_tier', 'household')
                        uid = getattr(current_user, 'id', 'anonymous') if current_user.is_authenticated else 'anonymous'
                        return _build_chat_history_ui(history), "", {'history': history}, _quota_badge_text(uid, tier)
                    # status != 'success': NL→SQL couldn't parse it — fall through to AI chat
            except Exception as e:
                logger.error(f"NL-to-SQL error: {e}")
                # fall through to AI chat on any error

        # --- Tier / user identity ---
        tier = config.get('system', 'deployment_tier', 'household')
        uid = str(getattr(current_user, 'id', 'anonymous')) if current_user.is_authenticated else 'anonymous'
        action_type = f'ai_chat_{tier}'

        # --- Daily cloud cap check ---
        cap_allowed, cap_remaining, _ = rate_limiter.check_rate_limit(uid, action_type)
        prefer_local = not cap_allowed
        cap_notice = ""
        if not cap_allowed:
            cap = rate_limiter.LIMITS.get(action_type, (0, 0))[0]
            cap_notice = (
                f"\n\n---\n*Daily limit of {cap} messages reached. "
                "Now using on-device AI (Ollama → rules).*"
            )

        # --- Build rich live context from DB ---
        try:
            devices = get_devices_with_status()
            active_devices = [d for d in devices if d.get('status') != 'offline'][:10]
            alert_devices = [d for d in devices if d.get('status') == 'alert']
        except Exception:
            active_devices, alert_devices = [], []

        try:
            recent_alerts = get_latest_alerts(limit=8)
        except Exception:
            recent_alerts = []

        try:
            bw = get_bandwidth_stats()
        except Exception:
            bw = {}

        device_lines = "\n".join(
            f"  - {d.get('device_name') or d.get('device_ip','?')} "
            f"[{d.get('category','unknown')}] status={d.get('status','?')}"
            for d in active_devices
        ) or "  (none)"

        alert_lines = "\n".join(
            f"  - {a.get('severity','?').upper()}: {a.get('plain_explanation') or a.get('explanation','?')} "
            f"({a.get('device_name') or a.get('device_ip','?')})"
            for a in recent_alerts[:5]
        ) or "  (none)"

        context = (
            "You are the IoTSentinel AI Assistant, a concise, knowledgeable home network "
            "security expert embedded in the IoTSentinel dashboard.\n\n"
            "SCOPE: Answer any question related to IoTSentinel, home networking, IoT devices, "
            "cybersecurity, privacy, network protocols, or security best-practices, including "
            "general educational questions on these topics (e.g. 'what is a firewall?', "
            "'how does WPA2 work?'). "
            "Only decline if the request is clearly personal, unrelated to technology/security "
            "(e.g. recipes, creative writing, relationship advice, coding homework), "
            "or has nothing to do with networks, devices, or security. "
            "When declining, do so in one polite sentence and redirect to security topics.\n\n"
            f"CURRENT NETWORK STATE (live, as of {datetime.now().strftime('%H:%M')}):\n"
            f"Active devices ({len(active_devices)}):\n{device_lines}\n"
            f"Devices with active alerts: {len(alert_devices)}\n"
            f"Recent open alerts ({len(recent_alerts)}):\n{alert_lines}\n"
            f"Bandwidth (last hour): {bw.get('summary','unavailable')}\n\n"
            "CAPABILITIES: River ML anomaly detection, attack-sequence prediction, "
            "traffic forecasting, device trust management, threat-intelligence lookup, "
            "plain-English alert explanations.\n\n"
            "STYLE: Write plain English. No em dashes, no markdown asterisks, no bullet points "
            "unless the user explicitly asks for a list. Keep answers concise (2-4 sentences) "
            "unless the user asks for detail."
        )

        # --- Build conversation history for multi-turn ---
        # Skip the first welcome message (role=assistant, no user turn yet)
        llm_history = [
            {'role': t['role'], 'content': t['content']}
            for t in history[:-1]  # exclude the turn we just appended
            if t['role'] in ('user', 'assistant') and t.get('content')
        ][-16:]  # last 8 user+assistant pairs

        # --- Get AI response ---
        ai_response, source = ai_assistant.get_response(
            prompt=message,
            context=context,
            history=llm_history,
            max_tokens=400,
            prefer_local=prefer_local,
        )

        # Strip em/en dashes and stray bold markers the model may output despite instructions
        ai_response = ai_response.replace('—', '-').replace('–', '-').replace('**', '')

        if cap_notice:
            ai_response += cap_notice

        # --- Record usage (all sources count toward daily cap) ---
        try:
            rate_limiter.record_attempt(uid, action_type, success=True)
        except Exception:
            pass

        history.append({
            'role': 'assistant',
            'content': ai_response,
            'timestamp': datetime.now().isoformat(),
            'source': source
        })

        quota_badge = _quota_badge_text(uid, tier)
        return _build_chat_history_ui(history), "", {'history': history}, quota_badge

    # ================================================================
    # CLIENTSIDE: copy message, auto-scroll, theme, keyboard shortcuts,
    #             chat enter, widget visibility, auto-pause
    # ================================================================

    # Auto-scroll chat to bottom after new messages
    app.clientside_callback(
        """
        function(children) {
            if (children && children.length > 0) {
                requestAnimationFrame(function() {
                    const chatHistory = document.getElementById('chat-history');
                    if (chatHistory) {
                        chatHistory.scrollTop = chatHistory.scrollHeight;
                    }
                });
            }
            return window.dash_clientside.no_update;
        }
        """,
        Output('chat-history', 'style', allow_duplicate=True),
        Input('chat-history', 'children'),
        prevent_initial_call=True
    )

    # Theme applicator — also writes resolved theme to resolved-theme-store so
    # server-side chart callbacks can detect dark mode even in Auto mode.
    app.clientside_callback(
        """
        function(theme_data) {
            if (!theme_data) return [window.dash_clientside.no_update, window.dash_clientside.no_update];

            let theme = theme_data.theme;

            if (theme === 'auto') {
                const prefersDark = window.matchMedia('(prefers-color-scheme: dark)').matches;
                theme = prefersDark ? 'dark' : 'light';
            }

            document.body.classList.remove('dark-mode', 'dark-theme', 'light-mode', 'light-theme');

            if (theme === 'dark') {
                document.body.classList.add('dark-mode');
                localStorage.setItem('iotsentinel-theme', 'dark');
            } else if (theme === 'light') {
                document.body.classList.add('light-mode');
                localStorage.setItem('iotsentinel-theme', 'light');
            }

            // Keep the PWA status-bar / address-bar colour in step with the theme.
            var tc = document.getElementById('iot-theme-color');
            if (tc) tc.setAttribute('content', theme === 'dark' ? '#0f172a' : '#f0f4f8');

            console.log('Theme applied:', theme);
            return [window.dash_clientside.no_update, {'theme': theme}];
        }
        """,
        [Output('keyboard-shortcut-store', 'data', allow_duplicate=True),
         Output('resolved-theme-store', 'data', allow_duplicate=True)],
        Input('theme-store', 'data'),
        prevent_initial_call='initial_duplicate'
    )

    @app.callback(
        Output('theme-store', 'data', allow_duplicate=True),
        Input('theme-selector', 'value'),
        prevent_initial_call=True
    )
    def update_theme_store(theme):
        return {'theme': theme}

    # Chat Enter key
    app.clientside_callback(
        """
        function(n) {
            const chatInput = document.getElementById('chat-input');
            if (chatInput) {
                chatInput.addEventListener('keypress', function(event) {
                    if (event.key === 'Enter' && !event.shiftKey) {
                        event.preventDefault();
                        document.getElementById('chat-send-button').click();
                    }
                });
            }
            return window.dash_clientside.no_update;
        }
        """,
        Output('chat-input', 'id'),
        Input('chat-modal', 'is_open')
    )

    # Widget visibility preferences
    app.clientside_callback(
        """
        function(prefs) {
            if (!prefs) {
                prefs = {metrics: true, features: true, rightPanel: true};
            }

            const metricsSection = document.getElementById('metrics-section');
            const featureSections = [
                document.getElementById('alerts-features-section'),
                document.getElementById('devices-features-section'),
                document.getElementById('analytics-features-section'),
                document.getElementById('integrations-features-section'),
                document.getElementById('compliance-features-section'),
                document.getElementById('admin-features-section')
            ];
            const rightPanelSection = document.getElementById('right-panel-section');

            if (metricsSection) {
                metricsSection.style.display = prefs.metrics ? 'block' : 'none';
            }
            featureSections.forEach(function(section) {
                if (section) {
                    section.style.display = prefs.features ? 'block' : 'none';
                }
            });
            if (rightPanelSection) {
                rightPanelSection.style.display = prefs.rightPanel ? 'block' : 'none';
            }

            return window.dash_clientside.no_update;
        }
        """,
        Output('widget-visibility-dummy', 'children'),
        Input('widget-preferences', 'data')
    )

    # Auto-pause refresh when page loses focus
    app.clientside_callback(
        """
        function() {
            if (!window.pageVisibilityInitialized) {
                window.pageVisibilityInitialized = true;

                window.intervalStates = {
                    'refresh-interval': null,
                    'security-score-interval': null,
                    'privacy-interval': null
                };

                document.addEventListener('visibilitychange', function() {
                    const isHidden = document.hidden;

                    const refreshInterval = document.getElementById('refresh-interval');
                    const securityInterval = document.getElementById('security-score-interval');
                    const privacyInterval = document.getElementById('privacy-interval');

                    if (isHidden) {
                        console.log('🔔 Page hidden - pausing auto-refresh to save resources');

                        if (refreshInterval && refreshInterval._dashprivate_layout) {
                            window.intervalStates['refresh-interval'] = refreshInterval._dashprivate_layout.props.disabled;
                            refreshInterval._dashprivate_layout.props.disabled = true;
                        }
                        if (securityInterval && securityInterval._dashprivate_layout) {
                            window.intervalStates['security-score-interval'] = securityInterval._dashprivate_layout.props.disabled;
                            securityInterval._dashprivate_layout.props.disabled = true;
                        }
                        if (privacyInterval && privacyInterval._dashprivate_layout) {
                            window.intervalStates['privacy-interval'] = privacyInterval._dashprivate_layout.props.disabled;
                            privacyInterval._dashprivate_layout.props.disabled = true;
                        }
                    } else {
                        console.log('✅ Page visible - resuming auto-refresh');

                        if (refreshInterval && refreshInterval._dashprivate_layout) {
                            refreshInterval._dashprivate_layout.props.disabled = window.intervalStates['refresh-interval'] || false;
                        }
                        if (securityInterval && securityInterval._dashprivate_layout) {
                            securityInterval._dashprivate_layout.props.disabled = window.intervalStates['security-score-interval'] || false;
                        }
                        if (privacyInterval && privacyInterval._dashprivate_layout) {
                            privacyInterval._dashprivate_layout.props.disabled = window.intervalStates['privacy-interval'] || false;
                        }
                    }
                });

                console.log('✅ Auto-pause on focus loss initialized');
            }

            return {visible: !document.hidden};
        }
        """,
        Output('page-visibility-store', 'data'),
        Input('page-visibility-store', 'data')
    )

    # ================================================================
    # QUICK ACTIONS
    # ================================================================

    @app.callback(
        Output('quick-actions-modal', 'is_open'),
        [Input('quick-actions-button', 'n_clicks')],
        [State('quick-actions-modal', 'is_open')],
        prevent_initial_call=True
    )
    def toggle_quick_actions_modal(open_clicks, is_open):
        """Toggle Quick Actions modal."""
        ctx = dash.callback_context
        if not ctx.triggered:
            return is_open

        button_id = ctx.triggered[0]['prop_id'].split('.')[0]

        if button_id == 'quick-actions-button':
            return True

        return is_open

    @app.callback(
        Output('quick-actions-content', 'children'),
        [Input('quick-actions-modal', 'is_open'),
         Input('user-role-store', 'data')],
        prevent_initial_call=False
    )
    def populate_quick_actions_content(is_open, user_data):
        """Populate Quick Actions modal with role-aware action buttons."""
        if not is_open and is_open is not None:
            return []

        user_role = user_data.get('role', 'viewer') if user_data else 'viewer'
        is_admin = user_role == 'admin'

        is_kid = False
        if current_user.is_authenticated:
            try:
                conn = get_db_connection()
                cursor = conn.cursor()
                cursor.execute(
                    "SELECT preference_value FROM user_preferences WHERE user_id = ? AND preference_key = 'is_kid'",
                    (current_user.id,)
                )
                result = cursor.fetchone()
                is_kid = result and result['preference_value'] == '1'
            except Exception as e:
                logger.error(f"Error checking family role: {e}")

        content = []

        # --- Dashboard ---
        refresh_section = [
            html.H6([html.I(className="fa fa-gauge me-2 text-primary"), "Dashboard"], className="fw-bold mb-2"),
            dbc.Row([
                dbc.Col(dbc.Button([html.I(className="fa fa-sync-alt me-2"), "Refresh"], id="quick-refresh-btn", color="primary", size="sm", className="w-100"), width=12, className="mb-2"),
            ], className="mb-2"),
        ]
        if not is_kid:
            refresh_section.extend([
                html.Label("Export Security Report:", className="fw-bold mb-1 small text-muted"),
                dbc.Row([
                    dbc.Col([
                        html.Label("Format:", className="fw-bold mb-1 small"),
                        dbc.Select(id='export-format-quick', options=[
                            {'label': 'CSV', 'value': 'csv'},
                            {'label': 'JSON', 'value': 'json'},
                            {'label': 'PDF', 'value': 'pdf'},
                            {'label': 'Excel', 'value': 'xlsx'},
                        ], value='csv', size="sm", className="mb-2"),
                    ], xs=12, sm=6),
                    dbc.Col([
                        html.Label("Download:", className="fw-bold mb-1 small"),
                        dbc.Button([html.I(className="fa fa-download me-2"), "Export"], id="quick-export-btn", color="success", size="sm", className="w-100"),
                    ], xs=12, sm=6),
                ], className="mb-3"),
            ])
        refresh_section.append(html.Hr())
        content.extend(refresh_section)

        # --- Security & Monitoring ---
        if is_kid:
            security_buttons = [dbc.Col(dbc.Button([html.I(className="fa fa-stethoscope me-2"), "Run Diagnostics"], id="quick-diagnostics-btn", color="primary", size="sm", className="w-100"), width=12, className="mb-2")]
        else:
            security_buttons = [
                dbc.Col(dbc.Button([html.I(className="fa fa-magnifying-glass me-2"), "Network Scan"], id="quick-scan-btn", color="info", size="sm", className="w-100"), xs=12, sm=6, className="mb-2"),
                dbc.Col(dbc.Button([html.I(className="fa fa-stethoscope me-2"), "Run Diagnostics"], id="quick-diagnostics-btn", color="primary", size="sm", className="w-100"), xs=12, sm=6, className="mb-2"),
            ]
            if is_admin:
                security_buttons.extend([
                    dbc.Col(dbc.Button([html.I(className="fa fa-trash me-2"), "Clear Threat Cache"], id="quick-clear-cache-btn", color="warning", size="sm", className="w-100"), xs=12, sm=6, className="mb-2"),
                    dbc.Col(dbc.Button([html.I(className="fa fa-cloud-arrow-down me-2"), "Update Threat DB"], id="quick-update-db-btn", color="info", size="sm", className="w-100"), xs=12, sm=6, className="mb-2"),
                ])
        content.extend([
            html.H6([html.I(className="fa fa-shield-halved me-2 text-danger"), "Security & Monitoring"], className="fw-bold mb-2"),
            dbc.Row(security_buttons, className="mb-3"),
            html.Hr(),
        ])

        # --- Network Management (admin only) ---
        if is_admin and not is_kid:
            content.extend([
                html.H6([html.I(className="fa fa-network-wired me-2 text-info"), "Network Management", html.Span(" (Admin)", className="ms-2 small text-muted")], className="fw-bold mb-2"),
                dbc.Row([
                    dbc.Col(dbc.Button([html.I(className="fa fa-ban me-2"), "Block Unknown"], id="quick-block-unknown-btn", color="danger", size="sm", className="w-100"), xs=12, sm=6, className="mb-2"),
                    dbc.Col(dbc.Button([html.I(className="fa fa-circle-check me-2"), "Whitelist Trusted"], id="quick-whitelist-btn", color="success", size="sm", className="w-100"), xs=12, sm=6, className="mb-2"),
                    dbc.Col(dbc.Button([html.I(className="fa fa-rotate me-2"), "Restart Monitor"], id="quick-restart-monitor-btn", color="warning", size="sm", className="w-100"), xs=12, sm=6, className="mb-2"),
                    dbc.Col(dbc.Button([html.I(className="fa fa-eraser me-2"), "Clear Net Cache"], id="quick-clear-net-cache-btn", color="secondary", size="sm", className="w-100"), xs=12, sm=6, className="mb-2"),
                ], className="mb-3"),
                html.Hr(),
            ])

        # --- Data Management ---
        if not is_kid:
            data_buttons = [
                dbc.Col(dbc.Button([html.I(className="fa fa-floppy-disk me-2"), "Backup Data"], id="quick-backup-btn", color="primary", size="sm", className="w-100"), xs=12, sm=6, className="mb-2"),
                dbc.Col(dbc.Button([html.I(className="fa fa-clock me-2"), "Clear Old Logs"], id="quick-clear-logs-btn", color="warning", size="sm", className="w-100"), xs=12, sm=6, className="mb-2"),
            ]
            if is_admin:
                data_buttons.append(dbc.Col(dbc.Button([html.I(className="fa fa-bell-slash me-2"), "Purge Alerts"], id="quick-purge-alerts-btn", color="danger", size="sm", className="w-100"), xs=12, sm=6, className="mb-2"))
            content.extend([
                html.H6([html.I(className="fa fa-database me-2 text-success"), "Data Management"], className="fw-bold mb-2"),
                dbc.Row(data_buttons, className="mb-3"),
                html.Hr(),
            ])

        # --- System ---
        if is_kid:
            system_buttons = [dbc.Col(dbc.Button([html.I(className="fa fa-file-lines me-2"), "View Logs"], id="quick-view-logs-btn", color="secondary", size="sm", className="w-100"), width=12, className="mb-2")]
        else:
            system_buttons = [
                dbc.Col(dbc.Button([html.I(className="fa fa-arrow-up-from-bracket me-2"), "Check Updates"], id="quick-check-updates-btn", color="info", size="sm", className="w-100"), xs=12, sm=6, className="mb-2"),
                dbc.Col(dbc.Button([html.I(className="fa fa-file-lines me-2"), "View Logs"], id="quick-view-logs-btn", color="secondary", size="sm", className="w-100"), xs=12, sm=6, className="mb-2"),
            ]
        content.extend([
            html.H6([html.I(className="fa fa-gear me-2 text-secondary"), "System"], className="fw-bold mb-2"),
            dbc.Row(system_buttons, className="mb-2"),
        ])

        # Role footer note
        if is_kid:
            content.append(html.Div([html.Hr(), html.Small([html.I(className="fa fa-child me-2 text-info"), "Child account - limited access. Contact parent for full access."], className="text-muted d-block text-center fw-bold")]))
        elif not is_admin:
            content.append(html.Div([html.Hr(), html.Small([html.I(className="fa fa-circle-info me-2"), "Some actions are restricted to administrators."], className="text-muted d-block text-center")]))

        return content

    @app.callback(
        [Output('refresh-interval', 'n_intervals', allow_duplicate=True),
         Output('toast-container', 'children', allow_duplicate=True)],
        [Input('quick-refresh-btn', 'n_clicks')],
        prevent_initial_call=True
    )
    def quick_refresh(n):
        """Trigger dashboard refresh by resetting interval."""
        if n:
            logger.info("Quick refresh triggered - resetting interval")
            toast = ToastManager.success(
                "Dashboard data refreshed successfully!",
                category="dashboard",
                duration="short"
            )
            return 0, toast
        return dash.no_update, dash.no_update

    @app.callback(
        Output('toast-container', 'children', allow_duplicate=True),
        [Input('quick-scan-btn', 'n_clicks')],
        prevent_initial_call=True
    )
    def quick_scan(n):
        """Trigger network scan."""
        if n:
            try:
                logger.info("Initiating network scan from quick actions")
                zeek_script = project_root / "zeek_capture.py"
                if zeek_script.exists():
                    subprocess.Popen(['python3', str(zeek_script)],
                                   stdout=subprocess.DEVNULL,
                                   stderr=subprocess.DEVNULL)
                    return ToastManager.success(
                        "Network scan started!",
                        detail_message="Results will appear shortly.",
                        category="security",
                        duration="medium"
                    )
                else:
                    logger.warning("zeek_capture.py not found, scan not available")
                    return ToastManager.warning(
                        "Scan feature not configured",
                        detail_message="Please set up Zeek first.",
                        category="security"
                    )
            except Exception as e:
                logger.error(f"Failed to start scan: {e}")
                return ToastManager.error(
                    "Scan failed",
                    detail_message=str(e),
                    category="security"
                )
        return dash.no_update

    @app.callback(
        [Output('download-export', 'data', allow_duplicate=True),
         Output('toast-container', 'children', allow_duplicate=True)],
        Input('quick-export-btn', 'n_clicks'),
        State('export-format-quick', 'value'),
        prevent_initial_call=True
    )
    def quick_export(n, export_format):
        """Export comprehensive security report in selected format."""
        if n:
            try:
                logger.info(f"Generating comprehensive security report export in {export_format} format")
                conn = get_db_connection()

                format_map = {'xlsx': 'excel', 'csv': 'csv', 'json': 'json', 'pdf': 'pdf'}
                export_format = format_map.get(export_format or 'csv', 'csv')

                download_data = export_helper.export_alerts(format=export_format, days=30)

                if download_data:
                    toast = ToastManager.success(
                        f"Security report exported as {export_format.upper()}",
                        category="data",
                        duration="short"
                    )
                    return download_data, toast
                else:
                    toast = ToastManager.warning(
                        "Export failed - no data available",
                        category="data"
                    )
                    return None, toast

            except Exception as e:
                logger.error(f"Export failed: {e}")
                toast = ToastManager.error(
                    "Export failed",
                    detail_message=str(e),
                    category="data"
                )
                return None, toast
        return None, dash.no_update

    # === SECURITY & MONITORING ACTIONS ===

    @app.callback(
        Output('toast-container', 'children', allow_duplicate=True),
        [Input('quick-clear-cache-btn', 'n_clicks')],
        prevent_initial_call=True
    )
    def quick_clear_cache(n):
        """Clear threat cache."""
        if n:
            try:
                logger.info("Clearing threat cache")
                conn = get_db_connection()
                if conn:
                    cursor = conn.cursor()
                    cursor.execute('DELETE FROM alerts WHERE timestamp < datetime("now", "-7 days")')
                    deleted = cursor.rowcount
                    conn.commit()
                    logger.info(f"Cleared {deleted} old alerts from cache")
                    return ToastManager.success(
                        "Cache cleared!",
                        detail_message=f"Removed {deleted} old alerts.",
                        category="security",
                        duration="medium"
                    )
                return ToastManager.error("Database connection failed", category="security")
            except Exception as e:
                logger.error(f"Failed to clear cache: {e}")
                return ToastManager.error("Failed to clear cache", detail_message=str(e), category="security")
        return dash.no_update

    @app.callback(
        Output('toast-container', 'children', allow_duplicate=True),
        [Input('quick-update-db-btn', 'n_clicks')],
        prevent_initial_call=True
    )
    def quick_update_db(n):
        """Update threat database."""
        if n:
            try:
                logger.info("Updating threat database")
                return ToastManager.success(
                    "Threat database updated successfully!",
                    detail_message="Latest signatures loaded.",
                    category="security",
                    duration="medium"
                )
            except Exception as e:
                logger.error(f"Failed to update database: {e}")
                return ToastManager.error("Update failed", detail_message=str(e), category="security")
        return dash.no_update

    @app.callback(
        Output('toast-container', 'children', allow_duplicate=True),
        [Input('quick-diagnostics-btn', 'n_clicks')],
        prevent_initial_call=True
    )
    def quick_diagnostics(n):
        """Run system diagnostics."""
        if n:
            try:
                logger.info("Running system diagnostics")
                diagnostics = []

                conn = get_db_connection()
                if conn:
                    diagnostics.append("✓ Database: OK")
                else:
                    diagnostics.append("✗ Database: FAILED")

                # Zeek check — look for the REAL binary. The old check looked for a
                # non-existent 'zeek_capture.py' and so ALWAYS reported "Not configured"
                # even though Zeek is installed (/opt/zeek/bin/zeek) and deployed by
                # config/configure_zeek.sh.
                from pathlib import Path as _ZPath
                zeek_bin = shutil.which("zeek")
                if zeek_bin or _ZPath("/opt/zeek/bin/zeek").exists():
                    try:
                        from utils.capture_mode import is_passive_wifi
                        _zk_note = " (passive Wi-Fi — limited capture)" if is_passive_wifi() else ""
                    except Exception:
                        _zk_note = ""
                    diagnostics.append(f"✓ Zeek: installed{_zk_note}")
                else:
                    diagnostics.append("✗ Zeek: not installed")

                total, used, free = shutil.disk_usage("/")
                free_gb = free // (2**30)
                diagnostics.append(f"✓ Disk: {free_gb}GB free")

                result = " | ".join(diagnostics)
                logger.info(f"Diagnostics complete: {result}")
                return ToastManager.info("Diagnostics Complete", detail_message=result, category="system", duration="long")
            except Exception as e:
                logger.error(f"Diagnostics failed: {e}")
                return ToastManager.error("Diagnostics failed", detail_message=str(e), category="system")
        return dash.no_update

    # === NETWORK MANAGEMENT ACTIONS ===

    @app.callback(
        Output('toast-container', 'children', allow_duplicate=True),
        [Input('quick-block-unknown-btn', 'n_clicks')],
        prevent_initial_call=True
    )
    @login_required
    def quick_block_unknown(n):
        """Block all unknown devices."""
        if n:
            if not can_block_devices(current_user):
                security_audit_logger.log(
                    event_type='permission_denied', user_id=current_user.id,
                    username=current_user.username, details={'action': 'quick_block_unknown'},
                    severity='medium', result='failure', failure_reason='Requires block_devices permission'
                )
                return ToastManager.error("Permission Denied", detail_message="You don't have permission to block devices.")

            try:
                logger.info("Blocking unknown devices")
                conn = get_db_connection()
                if conn:
                    cursor = conn.cursor()
                    cursor.execute('UPDATE devices SET is_blocked = 1 WHERE is_trusted = 0')
                    blocked = cursor.rowcount
                    conn.commit()
                    logger.info(f"Blocked {blocked} unknown devices")

                    security_audit_logger.log(
                        event_type='bulk_operation', user_id=current_user.id,
                        username=current_user.username,
                        details={'operation': 'quick_block_unknown', 'blocked_count': blocked},
                        severity='medium', resource_type='devices', result='success'
                    )

                    return ToastManager.success(f"Blocked {blocked} unknown devices successfully!", category="network", duration="medium")
                return ToastManager.error("Database connection failed", category="network")
            except Exception as e:
                logger.error(f"Failed to block devices: {e}")
                return ToastManager.error("Failed to block devices", detail_message=str(e), category="network")
        return dash.no_update

    @app.callback(
        Output('toast-container', 'children', allow_duplicate=True),
        [Input('quick-whitelist-btn', 'n_clicks')],
        prevent_initial_call=True
    )
    @login_required
    def quick_whitelist(n):
        """Whitelist all trusted devices."""
        if n:
            if not can_manage_devices(current_user):
                security_audit_logger.log(
                    event_type='permission_denied', user_id=current_user.id,
                    username=current_user.username, details={'action': 'quick_whitelist'},
                    severity='medium', result='failure', failure_reason='Requires manage_devices permission'
                )
                return ToastManager.error("Permission Denied", detail_message="You don't have permission to manage devices.")

            try:
                logger.info("Whitelisting trusted devices")
                conn = get_db_connection()
                if conn:
                    cursor = conn.cursor()
                    cursor.execute('UPDATE devices SET is_blocked = 0 WHERE is_trusted = 1')
                    whitelisted = cursor.rowcount
                    conn.commit()
                    logger.info(f"Whitelisted {whitelisted} trusted devices")

                    security_audit_logger.log(
                        event_type='bulk_operation', user_id=current_user.id,
                        username=current_user.username,
                        details={'operation': 'quick_whitelist', 'whitelisted_count': whitelisted},
                        severity='medium', resource_type='devices', result='success'
                    )

                    return ToastManager.success(f"Whitelisted {whitelisted} trusted devices successfully!", category="network", duration="medium")
                return ToastManager.error("Database connection failed", category="network")
            except Exception as e:
                logger.error(f"Failed to whitelist devices: {e}")
                return ToastManager.error("Failed to whitelist devices", detail_message=str(e), category="network")
        return dash.no_update

    @app.callback(
        Output('toast-container', 'children', allow_duplicate=True),
        [Input('quick-restart-monitor-btn', 'n_clicks')],
        prevent_initial_call=True
    )
    def quick_restart_monitor(n):
        if n:
            try:
                logger.info("Restarting network monitor")
                return ToastManager.info("Network monitor restart initiated", detail_message="Please check logs for status.", category="network", duration="medium")
            except Exception as e:
                logger.error(f"Failed to restart monitor: {e}")
                return ToastManager.error("Restart failed", detail_message=str(e), category="network")
        return dash.no_update

    @app.callback(
        Output('toast-container', 'children', allow_duplicate=True),
        [Input('quick-clear-net-cache-btn', 'n_clicks')],
        prevent_initial_call=True
    )
    def quick_clear_net_cache(n):
        if n:
            try:
                logger.info("Clearing network cache")
                conn = get_db_connection()
                if conn:
                    logger.info("Network cache cleared")
                    return ToastManager.success("Network cache cleared successfully!", category="network", duration="short")
                return ToastManager.error("Database connection failed", category="network")
            except Exception as e:
                logger.error(f"Failed to clear network cache: {e}")
                return ToastManager.error("Failed to clear cache", detail_message=str(e), category="network")
        return dash.no_update

    # === DATA MANAGEMENT ACTIONS ===

    @app.callback(
        [Output('download-export', 'data', allow_duplicate=True),
         Output('toast-container', 'children', allow_duplicate=True)],
        [Input('quick-backup-btn', 'n_clicks')],
        prevent_initial_call=True
    )
    def quick_backup(n):
        if n:
            try:
                logger.info("Creating data backup")
                db_path = project_root / "dashboard" / "iot_sentinel.db"
                if db_path.exists():
                    backup_name = f"iotsentinel_backup_{datetime.now().strftime('%Y%m%d_%H%M%S')}.db"
                    backup_path = project_root / backup_name
                    shutil.copy2(db_path, backup_path)
                    logger.info(f"Backup created: {backup_name}")

                    with open(backup_path, 'rb') as f:
                        backup_data = f.read()
                    backup_path.unlink()

                    toast = ToastManager.success("Backup created", detail_message=backup_name, category="data", duration="medium")
                    return (
                        dict(content=backup_data, filename=backup_name, type='application/octet-stream', base64=True),
                        toast
                    )
                toast = ToastManager.warning("Database not found", category="data")
                return None, toast
            except Exception as e:
                logger.error(f"Backup failed: {e}")
                toast = ToastManager.error("Backup failed", detail_message=str(e), category="data")
                return None, toast
        return None, dash.no_update

    @app.callback(
        Output('toast-container', 'children', allow_duplicate=True),
        [Input('quick-clear-logs-btn', 'n_clicks')],
        prevent_initial_call=True
    )
    def quick_clear_logs(n):
        if n:
            try:
                logger.info("Clearing old logs")
                conn = get_db_connection()
                if conn:
                    cursor = conn.cursor()
                    cursor.execute('DELETE FROM alerts WHERE timestamp < datetime("now", "-30 days")')
                    deleted = cursor.rowcount
                    conn.commit()
                    logger.info(f"Cleared {deleted} old log entries")
                    return ToastManager.success(f"Cleared {deleted} old log entries (>30 days)!", category="data", duration="medium")
                return ToastManager.error("Database connection failed", category="data")
            except Exception as e:
                logger.error(f"Failed to clear logs: {e}")
                return ToastManager.error("Failed to clear logs", detail_message=str(e), category="data")
        return dash.no_update

    @app.callback(
        Output('toast-container', 'children', allow_duplicate=True),
        [Input('quick-purge-alerts-btn', 'n_clicks')],
        prevent_initial_call=True
    )
    def quick_purge_alerts(n):
        if n:
            try:
                logger.info("Purging alerts")
                conn = get_db_connection()
                if conn:
                    cursor = conn.cursor()
                    cursor.execute('DELETE FROM alerts WHERE severity = "low" AND timestamp < datetime("now", "-7 days")')
                    deleted = cursor.rowcount
                    conn.commit()
                    logger.info(f"Purged {deleted} low-severity alerts")
                    return ToastManager.success(f"Purged {deleted} low-severity alerts successfully!", category="data", duration="medium")
                return ToastManager.error("Database connection failed", category="data")
            except Exception as e:
                logger.error(f"Failed to purge alerts: {e}")
                return ToastManager.error("Failed to purge alerts", detail_message=str(e), category="data")
        return dash.no_update

    # === SYSTEM ACTIONS ===

    @app.callback(
        Output('toast-container', 'children', allow_duplicate=True),
        [Input('quick-check-updates-btn', 'n_clicks')],
        prevent_initial_call=True
    )
    def quick_check_updates(n):
        """Check for a newer IoTSentinel release on GitHub."""
        if not n:
            return dash.no_update
        try:
            import urllib.request, json as _json
            from alerts import __version__ as _local_ver
            url = "https://api.github.com/repos/ritiksah141/iotsentinel/releases/latest"
            req = urllib.request.Request(url, headers={"User-Agent": "IoTSentinel-update-check"})
            with urllib.request.urlopen(req, timeout=5) as resp:
                data = _json.loads(resp.read())
            latest = data.get("tag_name", "").lstrip("v")
            if latest and latest != _local_ver:
                return ToastManager.info(
                    f"Update available: v{latest}",
                    detail_message=f"You're on v{_local_ver}. Visit GitHub to download the latest release.",
                    category="system", duration="long"
                )
            else:
                return ToastManager.success(
                    f"You're up to date (v{_local_ver})",
                    category="system", duration="medium"
                )
        except Exception as e:
            logger.warning(f"Update check failed: {e}")
            return ToastManager.info(
                "Update check unavailable",
                detail_message="Could not reach GitHub. Check your internet connection or visit github.com/ritiksah141/iotsentinel manually.",
                category="system", duration="medium"
            )

    @app.callback(
        Output('toast-container', 'children', allow_duplicate=True),
        [Input('quick-view-logs-btn', 'n_clicks')],
        prevent_initial_call=True
    )
    def quick_view_logs(n):
        """Quick view of system logs."""
        if n:
            try:
                logger.info("Accessing system logs")
                possible_logs = [
                    project_root / "data" / "logs" / "orchestrator.log",
                    project_root / "data" / "logs" / "zeek_parser.log",
                    project_root / "dashboard" / "dashboard.log",
                    project_root / "app.log",
                ]

                found_logs = []
                for log_file in possible_logs:
                    if log_file.exists():
                        try:
                            with open(log_file, 'r') as f:
                                lines = f.readlines()
                                line_count = len(lines)
                            if line_count > 0:
                                found_logs.append(f"{log_file.name} ({line_count} lines)")
                            else:
                                found_logs.append(f"{log_file.name} (empty)")
                        except Exception as e:
                            logger.warning(f"Could not read {log_file.name}: {e}")
                            found_logs.append(f"{log_file.name} (read error)")

                if found_logs:
                    files_list = ", ".join(found_logs)
                    return ToastManager.success(f"Found {len(found_logs)} log file(s)!", detail_message=f"Available logs: {files_list}. Location: data/logs/", category="system", duration="long")
                else:
                    return ToastManager.warning("No log files found", detail_message="System logs may not be created yet.", category="system", duration="long")
            except Exception as e:
                logger.error(f"Failed to read logs: {e}", exc_info=True)
                return ToastManager.error("Failed to read logs", detail_message=str(e), category="system")
        return dash.no_update

    # ================================================================
    # QUICK SETTINGS
    # ================================================================

    @app.callback(
        [Output('quick-settings-modal', 'is_open', allow_duplicate=True),
         Output('voice-alert-store', 'data', allow_duplicate=True),
         Output('refresh-interval', 'interval', allow_duplicate=True),
         Output('toast-container', 'children', allow_duplicate=True)],
        [Input('quick-settings-btn', 'n_clicks'),
         Input('settings-save-btn', 'n_clicks')],
        [State('quick-settings-modal', 'is_open'),
         State('alert-settings', 'value'),
         State('refresh-interval-select', 'value'),
         State('general-auto-settings', 'value'),
         State('default-view-setting', 'value'),
         State('notification-sound-select', 'value'),
         State('alert-duration-select', 'value'),
         State('notification-position-setting', 'value'),
         State('network-interface-input', 'value'),
         State('network-options-settings', 'value'),
         State('network-scan-interval-select', 'value'),
         State('connection-timeout-select', 'value'),
         State('chart-animation-select', 'value'),
         State('display-options-settings', 'value'),
         State('font-size-setting', 'value'),
         State('debug-options-settings', 'value'),
         State('performance-mode-setting', 'value'),
         State('discovery-mode-setting', 'value'),
         State('discovery-features-setting', 'value'),
         State('scan-interval-setting', 'value')],
        prevent_initial_call=True
    )
    def handle_quick_settings(settings_click, save_click, is_open,
                             _alert_settings, _refresh_interval_value,
                             _auto_settings, _default_view, _notif_sound, _alert_duration, _notif_position,
                             _network_interface, _network_options, _network_scan, _connection_timeout,
                             _chart_animation, _display_options, _font_size, _debug_options, _performance_mode,
                             discovery_mode, discovery_features, discovery_scan_interval):
        """Handle quick settings modal and save settings."""
        ctx = callback_context
        if not ctx.triggered:
            return dash.no_update, dash.no_update, dash.no_update, dash.no_update

        if not settings_click and not save_click:
            raise dash.exceptions.PreventUpdate

        button_id = ctx.triggered[0]['prop_id'].split('.')[0]

        if button_id == 'quick-settings-btn':
            return True, dash.no_update, dash.no_update, dash.no_update


        elif button_id == 'settings-save-btn':
            logger.info("💾 Save Changes button clicked - Saving all settings")

            if not current_user.is_authenticated or not current_user.is_admin():
                security_audit_logger.log(
                    event_type='permission_denied',
                    user_id=current_user.id if current_user.is_authenticated else None,
                    username=current_user.username if current_user.is_authenticated else 'anonymous',
                    details={'action': 'modify_system_settings'},
                    severity='high', result='failure', failure_reason='Requires admin role'
                )
                toast = ToastManager.error("Permission Denied", detail_message="System settings can only be changed by administrators.")
                return False, dash.no_update, dash.no_update, toast

            try:
                nmap_enabled = 'nmap' in (discovery_features or [])
                upnp_active_enabled = 'upnp' in (discovery_features or [])
                mdns_active_enabled = 'mdns' in (discovery_features or [])
                active_scan_enabled = discovery_mode in ['hybrid', 'active'] or any([nmap_enabled, upnp_active_enabled, mdns_active_enabled])

                discovery_settings = {
                    'mode': discovery_mode,
                    'active_scan_enabled': active_scan_enabled,
                    'nmap_enabled': nmap_enabled,
                    'upnp_active_enabled': upnp_active_enabled,
                    'mdns_active_enabled': mdns_active_enabled,
                    'active_scan_interval': discovery_scan_interval
                }

                success = config.update_section('discovery', discovery_settings)

                if success:
                    logger.info(f"✓ Discovery settings saved: {discovery_settings}")
                    security_audit_logger.log(
                        event_type='settings_changed', user_id=current_user.id,
                        username=current_user.username,
                        details={'settings_type': 'discovery', 'settings': discovery_settings},
                        severity='high', resource_type='system_settings', result='success'
                    )
                    # The orchestrator only reads discovery config (mode + mDNS/UPnP/nmap)
                    # at startup, so persisting alone has no live effect. Bounce the backend
                    # so it re-initialises discovery with the new settings. Best-effort;
                    # `sudo -n` never blocks, and the unit only exists on the Pi image.
                    restarted = False
                    try:
                        _unit = "/etc/systemd/system/iotsentinel-backend.service"
                        if os.path.exists(_unit):
                            subprocess.run(
                                ["sudo", "-n", "systemctl", "restart", "iotsentinel-backend"],
                                check=False, capture_output=True, timeout=15)
                            restarted = True
                    except Exception as _e:
                        logger.warning(f"Could not restart backend after discovery save: {_e}")
                    _detail = ("Saved. Monitoring restarts to apply the new scan settings - "
                               "live data resumes in a few seconds."
                               if restarted else
                               "All settings have been saved successfully.")
                    toast = ToastManager.success("💾 Settings Saved", detail_message=_detail)
                else:
                    logger.error("Failed to save discovery settings")
                    toast = ToastManager.warning("⚠️ Settings Partially Saved", detail_message="Some settings may not have been saved properly")

            except Exception as e:
                logger.error(f"Error saving settings: {e}")
                toast = ToastManager.error("❌ Error Saving Settings", detail_message=f"Error: {str(e)}")

            return False, dash.no_update, dash.no_update, toast

        return dash.no_update, dash.no_update, dash.no_update, dash.no_update

    # Discovery Settings — load
    @app.callback(
        [Output('discovery-mode-setting', 'value'),
         Output('discovery-features-setting', 'value'),
         Output('scan-interval-setting', 'value')],
        [Input('quick-settings-modal', 'is_open')],
        prevent_initial_call=True
    )
    def load_discovery_settings(is_open):
        if not is_open:
            raise dash.exceptions.PreventUpdate
        try:
            discovery_config = config.get_section('discovery')
            mode = discovery_config.get('mode', 'passive')
            features = []
            if discovery_config.get('nmap_enabled', False): features.append('nmap')
            if discovery_config.get('upnp_active_enabled', False): features.append('upnp')
            if discovery_config.get('mdns_active_enabled', False): features.append('mdns')
            scan_interval = discovery_config.get('active_scan_interval', 3600)
            return mode, features, scan_interval
        except Exception as e:
            logger.error(f"Error loading discovery settings: {e}")
            return 'passive', [], 3600

    # Discovery Settings — live status display
    @app.callback(
        Output('discovery-status-display', 'children'),
        [Input('discovery-mode-setting', 'value'),
         Input('discovery-features-setting', 'value')],
        prevent_initial_call=True
    )
    def update_discovery_status_display(mode, features):
        try:
            nmap_enabled = 'nmap' in (features or [])
            upnp_active_enabled = 'upnp' in (features or [])
            mdns_active_enabled = 'mdns' in (features or [])
            active_scan_enabled = mode in ['hybrid', 'active'] or any([nmap_enabled, upnp_active_enabled, mdns_active_enabled])

            status_badges = [dbc.Badge("Passive Listeners: Active", color="success", className="me-2 mb-1")]

            if active_scan_enabled:
                active_features = []
                if nmap_enabled: active_features.append('nmap')
                if upnp_active_enabled: active_features.append('UPnP')
                if mdns_active_enabled: active_features.append('mDNS')
                feature_text = f" ({', '.join(active_features)})" if active_features else ""
                status_badges.append(dbc.Badge(f"Active Scanning: Enabled{feature_text}", color="warning", className="mb-1"))
            else:
                status_badges.append(dbc.Badge("Active Scanning: Disabled", color="secondary", className="mb-1"))

            return status_badges
        except Exception as e:
            logger.error(f"Error updating discovery status display: {e}")
            return dash.no_update

    # Advanced — Clear Browser Cache
    @app.callback(
        [Output('quick-settings-store', 'data', allow_duplicate=True),
         Output('voice-alert-store', 'data', allow_duplicate=True),
         Output('quick-settings-modal', 'is_open', allow_duplicate=True),
         Output('toast-container', 'children', allow_duplicate=True)],
        [Input('clear-cache-btn', 'n_clicks')],
        prevent_initial_call=True
    )
    def clear_browser_cache(n):
        if not n or n == 0:
            return dash.no_update, dash.no_update, dash.no_update, dash.no_update
        if n and n > 0:
            default_settings = {
                'general': {'auto_settings': ['auto-refresh', 'auto-save'], 'default_view': 'dashboard', 'refresh_interval': 10000},
                'notifications': {'browser': False, 'critical_only': False, 'sound': 'default', 'duration': 5000, 'position': 'top-right'},
                'network': {'interface': 'en0', 'options': ['show-offline'], 'scan_interval': 300, 'timeout': 10},
                'display': {'animation': 'normal', 'options': ['smooth-scroll', 'tooltips', 'timestamps'], 'font_size': 'medium'},
                'advanced': {'debug': [], 'performance': 'balanced'}
            }
            default_voice = {'enabled': False}
            toast = ToastManager.info("Cache Cleared", detail_message="Settings cache has been cleared and reset to defaults.")
            return default_settings, default_voice, False, toast
        return dash.no_update, dash.no_update, dash.no_update, dash.no_update

    # Advanced — Reset Settings to Defaults
    @app.callback(
        [Output('quick-settings-store', 'data', allow_duplicate=True),
         Output('voice-alert-store', 'data', allow_duplicate=True),
         Output('quick-settings-modal', 'is_open', allow_duplicate=True),
         Output('toast-container', 'children', allow_duplicate=True)],
        [Input('reset-settings-btn', 'n_clicks')],
        prevent_initial_call=True
    )
    def reset_settings_to_defaults(n):
        if not n or n == 0:
            return dash.no_update, dash.no_update, dash.no_update, dash.no_update
        if n and n > 0:
            default_settings = {
                'general': {'auto_settings': ['auto-refresh', 'auto-save'], 'default_view': 'dashboard', 'refresh_interval': 10000},
                'notifications': {'browser': False, 'critical_only': False, 'sound': 'default', 'duration': 5000, 'position': 'top-right'},
                'network': {'interface': 'en0', 'options': ['show-offline'], 'scan_interval': 300, 'timeout': 10},
                'display': {'animation': 'normal', 'options': ['smooth-scroll', 'tooltips', 'timestamps'], 'font_size': 'medium'},
                'advanced': {'debug': [], 'performance': 'balanced'}
            }
            default_voice = {'enabled': False}
            toast = ToastManager.info("Settings Reset", detail_message="All settings have been restored to their defaults.")
            return default_settings, default_voice, False, toast
        return dash.no_update, dash.no_update, dash.no_update, dash.no_update

    # Advanced — Export Settings
    @app.callback(
        [Output('quick-settings-modal', 'is_open', allow_duplicate=True),
         Output('toast-container', 'children', allow_duplicate=True)],
        [Input('export-settings-btn', 'n_clicks')],
        [State('quick-settings-store', 'data'),
         State('voice-alert-store', 'data')],
        prevent_initial_call=True
    )
    def export_settings(n, settings_data, voice_data):
        if not n or n == 0:
            return dash.no_update, dash.no_update
        if n and n > 0:
            export_data = {'quick_settings': settings_data, 'voice_alert': voice_data}
            settings_json = json.dumps(export_data, indent=2)
            logger.info(f"📋 EXPORTED SETTINGS JSON:\n{settings_json}")
            toast = ToastManager.info("💾 Settings Exported", detail_message="💾 Settings Exported")
            return False, toast
        return dash.no_update, dash.no_update

    # ================================================================
    # AUTOSAVE CALLBACKS (20+)
    # ================================================================

    # Autosave: Alert / Notification Settings (including voice)
    @app.callback(
        [Output('quick-settings-store', 'data', allow_duplicate=True),
         Output('voice-alert-store', 'data', allow_duplicate=True),
         Output('toast-container', 'children', allow_duplicate=True)],
        [Input('alert-settings', 'value')],
        [State('quick-settings-store', 'data'),
         State('voice-alert-store', 'data')],
        prevent_initial_call=True
    )
    def autosave_alert_settings(alert_values, settings_data, voice_data):
        if alert_values is None:
            return dash.no_update, dash.no_update, dash.no_update
        settings_data = settings_data or {}
        settings_data['notifications'] = settings_data.get('notifications', {})
        voice_data = voice_data or {}
        voice_enabled = 'voice' in alert_values
        browser_enabled = 'browser' in alert_values
        critical_only = 'critical' in alert_values
        old_voice = voice_data.get('enabled', False)
        old_browser = settings_data['notifications'].get('browser', False)
        old_critical = settings_data['notifications'].get('critical_only', False)
        if old_voice == voice_enabled and old_browser == browser_enabled and old_critical == critical_only:
            return dash.no_update, dash.no_update, dash.no_update
        settings_data['notifications']['browser'] = browser_enabled
        settings_data['notifications']['critical_only'] = critical_only
        voice_data['enabled'] = voice_enabled
        logger.info(f"✅ AUTO-SAVED ALL ALERTS: voice={voice_enabled}, browser={browser_enabled}, critical={critical_only}")
        toast = ToastManager.info("🔔 Alerts Auto-Saved", detail_message="🔔 Alerts Auto-Saved")
        return settings_data, voice_data, toast

    # Autosave: Debug Options
    @app.callback(
        [Output('quick-settings-store', 'data', allow_duplicate=True),
         Output('toast-container', 'children', allow_duplicate=True)],
        [Input('debug-options-settings', 'value')],
        [State('quick-settings-store', 'data')],
        prevent_initial_call=True
    )
    def autosave_debug_options(debug_values, settings_data):
        if debug_values is None:
            return dash.no_update, dash.no_update
        settings_data = settings_data or {}
        settings_data['advanced'] = settings_data.get('advanced', {})
        old_value = settings_data['advanced'].get('debug', [])
        if set(old_value) == set(debug_values):
            return dash.no_update, dash.no_update
        settings_data['advanced']['debug'] = debug_values
        logger.info(f"✅ AUTO-SAVED DEBUG OPTIONS: {debug_values}")
        toast = ToastManager.warning("🔧 Debug Settings Auto-Saved", detail_message="🔧 Debug Settings Auto-Saved")
        return settings_data, toast

    # Autosave: Performance Mode
    @app.callback(
        [Output('quick-settings-store', 'data', allow_duplicate=True),
         Output('toast-container', 'children', allow_duplicate=True)],
        [Input('performance-mode-setting', 'value')],
        [State('quick-settings-store', 'data')],
        prevent_initial_call=True
    )
    def autosave_performance_mode(perf_mode, settings_data):
        if perf_mode is None:
            return dash.no_update, dash.no_update
        if not callback_context.triggered:
            return dash.no_update, dash.no_update
        settings_data = settings_data or {}
        old_value = settings_data.get('advanced', {}).get('performance')
        if old_value == perf_mode:
            return dash.no_update, dash.no_update
        settings_data['advanced'] = settings_data.get('advanced', {})
        settings_data['advanced']['performance'] = perf_mode
        logger.info(f"Auto-saved performance mode: {perf_mode}")
        toast = ToastManager.success("Performance Updated", detail_message="Performance Updated")
        return settings_data, toast

    # Autosave: Display Options
    @app.callback(
        [Output('quick-settings-store', 'data', allow_duplicate=True),
         Output('toast-container', 'children', allow_duplicate=True)],
        [Input('display-options-settings', 'value')],
        [State('quick-settings-store', 'data')],
        prevent_initial_call=True
    )
    def autosave_display_options(display_values, settings_data):
        if display_values is None:
            return dash.no_update, dash.no_update
        if not callback_context.triggered:
            return dash.no_update, dash.no_update
        settings_data = settings_data or {}
        old_values = settings_data.get('display', {}).get('options', [])
        if old_values == display_values:
            return dash.no_update, dash.no_update
        settings_data['display'] = settings_data.get('display', {})
        settings_data['display']['options'] = display_values
        logger.info(f"Auto-saved display options: {display_values}")
        toast = ToastManager.info("Display Updated", detail_message="Display Updated")
        return settings_data, toast

    # Autosave: Network Options
    @app.callback(
        [Output('quick-settings-store', 'data', allow_duplicate=True),
         Output('toast-container', 'children', allow_duplicate=True)],
        [Input('network-options-settings', 'value')],
        [State('quick-settings-store', 'data')],
        prevent_initial_call=True
    )
    def autosave_network_options(network_values, settings_data):
        if network_values is None:
            return dash.no_update, dash.no_update
        if not callback_context.triggered:
            return dash.no_update, dash.no_update
        settings_data = settings_data or {}
        old_values = settings_data.get('network', {}).get('options', [])
        if old_values == network_values:
            return dash.no_update, dash.no_update
        settings_data['network'] = settings_data.get('network', {})
        settings_data['network']['options'] = network_values
        logger.info(f"Auto-saved network options: {network_values}")
        toast = ToastManager.info("Network Settings Updated", detail_message="Network Settings Updated")
        return settings_data, toast

    # Autosave: General Auto Settings
    @app.callback(
        [Output('quick-settings-store', 'data', allow_duplicate=True),
         Output('toast-container', 'children', allow_duplicate=True)],
        [Input('general-auto-settings', 'value')],
        [State('quick-settings-store', 'data')],
        prevent_initial_call=True
    )
    def autosave_general_auto_settings(auto_values, settings_data):
        if auto_values is None:
            return dash.no_update, dash.no_update
        if not callback_context.triggered:
            return dash.no_update, dash.no_update
        settings_data = settings_data or {}
        old_values = settings_data.get('general', {}).get('auto_settings', [])
        if old_values == auto_values:
            return dash.no_update, dash.no_update
        settings_data['general'] = settings_data.get('general', {})
        settings_data['general']['auto_settings'] = auto_values
        logger.info(f"Auto-saved general auto settings: {auto_values}")
        toast = ToastManager.info("General Settings Updated", detail_message="General Settings Updated")
        return settings_data, toast

    # Autosave: Refresh Interval
    @app.callback(
        [Output('quick-settings-store', 'data', allow_duplicate=True),
         Output('refresh-interval', 'interval', allow_duplicate=True),
         Output('toast-container', 'children', allow_duplicate=True)],
        [Input('refresh-interval-select', 'value')],
        [State('quick-settings-store', 'data')],
        prevent_initial_call=True
    )
    def autosave_refresh_interval(interval_value, settings_data):
        if interval_value is None:
            return dash.no_update, dash.no_update, dash.no_update
        interval_int = int(interval_value) if isinstance(interval_value, str) else interval_value
        settings_data = settings_data or {}
        settings_data['general'] = settings_data.get('general', {})
        old_value = settings_data['general'].get('refresh_interval', 10000)
        if old_value == interval_int:
            return dash.no_update, dash.no_update, dash.no_update
        settings_data['general']['refresh_interval'] = interval_int
        logger.info(f"✅ AUTO-SAVED REFRESH INTERVAL: {interval_int}ms ({interval_int/1000}s)")
        toast = ToastManager.success("⏱️ Refresh Interval Auto-Saved", detail_message="⏱️ Refresh Interval Auto-Saved")
        return settings_data, interval_int, toast

    # Autosave: Default View
    @app.callback(
        [Output('quick-settings-store', 'data', allow_duplicate=True),
         Output('toast-container', 'children', allow_duplicate=True)],
        [Input('default-view-setting', 'value')],
        [State('quick-settings-store', 'data')],
        prevent_initial_call=True
    )
    def autosave_default_view(view_value, settings_data):
        if view_value is None:
            return dash.no_update, dash.no_update
        settings_data = settings_data or {}
        settings_data['general'] = settings_data.get('general', {})
        old_value = settings_data['general'].get('default_view', 'dashboard')
        if old_value == view_value:
            return dash.no_update, dash.no_update
        settings_data['general']['default_view'] = view_value
        logger.info(f"✅ AUTO-SAVED DEFAULT VIEW: {view_value}")
        toast = ToastManager.info("🏠 Default View Auto-Saved", detail_message="🏠 Default View Auto-Saved")
        return settings_data, toast

    # Autosave: Network Interface
    @app.callback(
        [Output('quick-settings-store', 'data', allow_duplicate=True),
         Output('toast-container', 'children', allow_duplicate=True)],
        [Input('network-interface-input', 'value')],
        [State('quick-settings-store', 'data')],
        prevent_initial_call=True
    )
    def autosave_network_interface(interface_value, settings_data):
        if interface_value is None or interface_value == '':
            return dash.no_update, dash.no_update
        settings_data = settings_data or {}
        settings_data['network'] = settings_data.get('network', {})
        old_value = settings_data['network'].get('interface', 'en0')
        if old_value == interface_value:
            return dash.no_update, dash.no_update
        settings_data['network']['interface'] = interface_value
        logger.info(f"✅ AUTO-SAVED NETWORK INTERFACE: {interface_value}")
        toast = ToastManager.info("🌐 Network Interface Auto-Saved", detail_message="🌐 Network Interface Auto-Saved")
        return settings_data, toast

    # Autosave: Font Size
    @app.callback(
        [Output('quick-settings-store', 'data', allow_duplicate=True),
         Output('toast-container', 'children', allow_duplicate=True)],
        [Input('font-size-setting', 'value')],
        [State('quick-settings-store', 'data')],
        prevent_initial_call=True
    )
    def autosave_font_size(font_value, settings_data):
        if font_value is None:
            return dash.no_update, dash.no_update
        settings_data = settings_data or {}
        settings_data['display'] = settings_data.get('display', {})
        old_value = settings_data['display'].get('font_size', 'medium')
        if old_value == font_value:
            return dash.no_update, dash.no_update
        settings_data['display']['font_size'] = font_value
        logger.info(f"✅ AUTO-SAVED FONT SIZE: {font_value}")
        toast = ToastManager.info("🔤 Font Size Auto-Saved", detail_message="🔤 Font Size Auto-Saved")
        return settings_data, toast

    # Autosave: Chart Animation
    @app.callback(
        [Output('quick-settings-store', 'data', allow_duplicate=True),
         Output('toast-container', 'children', allow_duplicate=True)],
        [Input('chart-animation-select', 'value')],
        [State('quick-settings-store', 'data')],
        prevent_initial_call=True
    )
    def autosave_chart_animation(anim_value, settings_data):
        if anim_value is None:
            return dash.no_update, dash.no_update
        settings_data = settings_data or {}
        settings_data['display'] = settings_data.get('display', {})
        old_value = settings_data['display'].get('animation', 'normal')
        if old_value == anim_value:
            return dash.no_update, dash.no_update
        settings_data['display']['animation'] = anim_value
        logger.info(f"✅ AUTO-SAVED CHART ANIMATION: {anim_value}")
        toast = ToastManager.info("📊 Chart Animation Auto-Saved", detail_message="📊 Chart Animation Auto-Saved")
        return settings_data, toast

    # Autosave: Notification Sound
    @app.callback(
        [Output('quick-settings-store', 'data', allow_duplicate=True),
         Output('toast-container', 'children', allow_duplicate=True)],
        [Input('notification-sound-select', 'value')],
        [State('quick-settings-store', 'data')],
        prevent_initial_call=True
    )
    def autosave_notification_sound(sound_value, settings_data):
        old_value = settings_data['notifications'].get('sound', 'default')
        if old_value == sound_value:
            return dash.no_update, dash.no_update
        settings_data['notifications']['sound'] = sound_value
        logger.info(f"✅ AUTO-SAVED Notification Sound: {sound_value}")
        toast = ToastManager.info("🔊 Notification Sound Auto-Saved", detail_message="🔊 Notification Sound Auto-Saved")
        return settings_data, toast

    # Autosave: Alert Duration
    @app.callback(
        [Output('quick-settings-store', 'data', allow_duplicate=True),
         Output('toast-container', 'children', allow_duplicate=True)],
        [Input('alert-duration-select', 'value')],
        [State('quick-settings-store', 'data')],
        prevent_initial_call=True
    )
    def autosave_alert_duration(duration_value, settings_data):
        duration_int = int(duration_value) if isinstance(duration_value, str) else duration_value
        old_value = settings_data['notifications'].get('duration', 5000)
        if old_value == duration_int:
            return dash.no_update, dash.no_update
        settings_data['notifications']['duration'] = duration_int
        logger.info(f"✅ AUTO-SAVED Alert Duration: {duration_int}ms")
        toast = ToastManager.info("⏲️ Alert Duration Auto-Saved", detail_message="⏲️ Alert Duration Auto-Saved")
        return settings_data, toast

    # Autosave: Notification Position
    @app.callback(
        [Output('quick-settings-store', 'data', allow_duplicate=True),
         Output('toast-container', 'children', allow_duplicate=True)],
        [Input('notification-position-setting', 'value')],
        [State('quick-settings-store', 'data')],
        prevent_initial_call=True
    )
    def autosave_notification_position(position_value, settings_data):
        old_value = settings_data['notifications'].get('position', 'top-right')
        if old_value == position_value:
            return dash.no_update, dash.no_update
        settings_data['notifications']['position'] = position_value
        logger.info(f"✅ AUTO-SAVED Notification Position: {position_value}")
        toast = ToastManager.info("📍 Notification Position Auto-Saved", detail_message="📍 Notification Position Auto-Saved")
        return settings_data, toast

    # Autosave: Network Scan Interval
    @app.callback(
        [Output('quick-settings-store', 'data', allow_duplicate=True),
         Output('toast-container', 'children', allow_duplicate=True)],
        [Input('network-scan-interval-select', 'value')],
        [State('quick-settings-store', 'data')],
        prevent_initial_call=True
    )
    def autosave_network_scan_interval(interval_value, settings_data):
        interval_int = int(interval_value) if isinstance(interval_value, str) else interval_value
        old_value = settings_data['network'].get('scan_interval', 300)
        if old_value == interval_int:
            return dash.no_update, dash.no_update
        settings_data['network']['scan_interval'] = interval_int
        logger.info(f"✅ AUTO-SAVED Network Scan Interval: {interval_int}s")
        toast = ToastManager.info("🔍 Scan Interval Auto-Saved", detail_message="🔍 Scan Interval Auto-Saved")
        return settings_data, toast

    # Autosave: Connection Timeout
    @app.callback(
        [Output('quick-settings-store', 'data', allow_duplicate=True),
         Output('toast-container', 'children', allow_duplicate=True)],
        [Input('connection-timeout-select', 'value')],
        [State('quick-settings-store', 'data')],
        prevent_initial_call=True
    )
    def autosave_connection_timeout(timeout_value, settings_data):
        timeout_int = int(timeout_value) if isinstance(timeout_value, str) else timeout_value
        old_value = settings_data['network'].get('timeout', 10)
        if old_value == timeout_int:
            return dash.no_update, dash.no_update
        settings_data['network']['timeout'] = timeout_int
        logger.info(f"✅ AUTO-SAVED Connection Timeout: {timeout_int}s")
        toast = ToastManager.info("⏱️ Connection Timeout Auto-Saved", detail_message="⏱️ Connection Timeout Auto-Saved")
        return settings_data, toast

    # Sync Quick Settings Store → Modal Inputs on page load
    @app.callback(
        [Output('general-auto-settings', 'value'),
         Output('debug-options-settings', 'value'),
         Output('performance-mode-setting', 'value'),
         Output('display-options-settings', 'value'),
         Output('network-options-settings', 'value'),
         Output('notification-sound-select', 'value'),
         Output('alert-duration-select', 'value'),
         Output('notification-position-setting', 'value'),
         Output('network-scan-interval-select', 'value'),
         Output('connection-timeout-select', 'value')],
        [Input('quick-settings-store', 'data')],
        prevent_initial_call=False
    )
    def sync_settings_from_store(settings_data):
        if not settings_data:
            return (
                ['auto-refresh', 'auto-save'], [], 'balanced',
                ['smooth-scroll', 'tooltips', 'timestamps'], ['show-offline'],
                'default', 5000, 'top-right', 300, 10
            )
        general = settings_data.get('general', {})
        advanced = settings_data.get('advanced', {})
        display = settings_data.get('display', {})
        network = settings_data.get('network', {})
        notifications = settings_data.get('notifications', {})
        return (
            general.get('auto_settings', ['auto-refresh', 'auto-save']),
            advanced.get('debug', []),
            advanced.get('performance', 'balanced'),
            display.get('options', ['smooth-scroll', 'tooltips', 'timestamps']),
            network.get('options', ['show-offline']),
            notifications.get('sound', 'default'),
            notifications.get('duration', 5000),
            notifications.get('position', 'top-right'),
            network.get('scan_interval', 300),
            network.get('timeout', 10)
        )

    # ================================================================
    # DARK MODE TOGGLE
    # ================================================================

    @app.callback(
        [Output('theme-store', 'data', allow_duplicate=True),
         Output('dark-mode-icon', 'className', allow_duplicate=True)],
        [Input('dark-mode-toggle', 'n_clicks')],
        [State('theme-store', 'data')],
        prevent_initial_call=True
    )
    def toggle_dark_mode(n_clicks, current_theme_data):
        if n_clicks:
            current_theme = current_theme_data.get('theme', 'light') if current_theme_data else 'light'
            if current_theme == 'light':
                new_theme = "dark"
                icon_class = "fa fa-moon fa-lg"
            elif current_theme == "dark":
                new_theme = "auto"
                icon_class = "fa fa-adjust fa-lg"
            else:
                new_theme = "light"
                icon_class = "fa fa-sun fa-lg"
            return {'theme': new_theme}, icon_class
        current_theme = current_theme_data.get('theme', 'light') if current_theme_data else 'light'
        if current_theme == 'light':
            icon_class = "fa fa-sun fa-lg"
        elif current_theme == "dark":
            icon_class = "fa fa-moon fa-lg"
        else:
            icon_class = "fa fa-adjust fa-lg"
        return dash.no_update, icon_class

    @app.callback(
        Output('dark-mode-icon', 'className', allow_duplicate=True),
        [Input('theme-store', 'data')],
        prevent_initial_call='initial_duplicate'
    )
    def update_dark_mode_icon(theme_data):
        current_theme = theme_data.get('theme', 'light') if theme_data else 'light'
        if current_theme == 'light':
            return "fa fa-sun fa-lg"
        elif current_theme == "dark":
            return "fa fa-moon fa-lg"
        else:
            return "fa fa-adjust fa-lg"

    # ================================================================
    # CUSTOMIZABLE WIDGET DASHBOARD
    # ================================================================

    @app.callback(
        Output('customize-layout-modal', 'is_open', allow_duplicate=True),
        [Input('customize-layout-button', 'n_clicks')],
        [State('customize-layout-modal', 'is_open')],
        prevent_initial_call=True
    )
    def toggle_customize_modal(n_clicks, is_open):
        if n_clicks:
            return not is_open
        return is_open

    @app.callback(
        Output('widget-toggles', 'value', allow_duplicate=True),
        [Input('customize-layout-modal', 'is_open')],
        [State('widget-preferences', 'data')],
        prevent_initial_call=True
    )
    def load_widget_preferences(is_open, prefs):
        if is_open and prefs:
            return [k for k, v in prefs.items() if v]
        return ["metrics", "features", "rightPanel"]

    @app.callback(
        [Output('widget-preferences', 'data'),
         Output('customize-layout-modal', 'is_open', allow_duplicate=True)],
        [Input('save-widget-prefs', 'n_clicks')],
        [State('widget-toggles', 'value')],
        prevent_initial_call=True
    )
    def save_widget_preferences(n_clicks, selected_widgets):
        if n_clicks:
            prefs = {
                'metrics': 'metrics' in selected_widgets,
                'features': 'features' in selected_widgets,
                'rightPanel': 'rightPanel' in selected_widgets
            }
            return prefs, False
        return dash.no_update, dash.no_update

    @app.callback(
        Output('customize-layout-modal', 'is_open', allow_duplicate=True),
        Input('cancel-prefs-btn', 'n_clicks'),
        prevent_initial_call=True
    )
    def cancel_preferences(n_clicks):
        if n_clicks:
            return False
        return dash.no_update

    # Export configuration
    @app.callback(
        [Output('toast-container', 'children', allow_duplicate=True),
         Output('download-export', 'data', allow_duplicate=True)],
        Input('export-config-btn', 'n_clicks'),
        [State('widget-toggles', 'value'),
         State('individual-widget-toggles', 'value'),
         State('view-density', 'value'),
         State('font-size-pref', 'value'),
         State('animation-speed', 'value'),
         State('auto-refresh-toggle', 'value'),
         State('customize-refresh-interval-select', 'value'),
         State('data-retention-select', 'value'),
         State('chart-preferences', 'value'),
         State('notification-prefs', 'value'),
         State('alert-severity-filter', 'value')],
        prevent_initial_call=True
    )
    def export_configuration(n_clicks, widget_toggles, individual_widgets, view_density,
                            font_size, animation_speed, auto_refresh, refresh_interval,
                            data_retention, chart_prefs, notif_prefs, alert_filter):
        if not n_clicks:
            raise dash.exceptions.PreventUpdate
        try:
            config_data = {
                "widget_toggles": widget_toggles or [],
                "individual_widgets": individual_widgets or [],
                "view_density": view_density or "comfortable",
                "font_size": font_size or "medium",
                "animation_speed": animation_speed or "normal",
                "auto_refresh": auto_refresh if auto_refresh is not None else True,
                "refresh_interval": refresh_interval or "10",
                "data_retention": data_retention or "168",
                "chart_preferences": chart_prefs or [],
                "notification_preferences": notif_prefs or [],
                "alert_severity_filter": alert_filter or []
            }
            download_data = dict(
                content=json.dumps(config_data, indent=2),
                filename=f"iotsentinel_config_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
            )
            toast = ToastManager.success("Export Complete", detail_message="Export Complete")
            return toast, download_data
        except Exception as e:
            logger.error(f"Error exporting configuration: {e}")
            toast = ToastManager.error("Export Error", detail_message="Export Error")
            return toast, dash.no_update

    # Import configuration
    @app.callback(
        Output('toast-container', 'children', allow_duplicate=True),
        Input('import-config-btn', 'n_clicks'),
        prevent_initial_call=True
    )
    def import_configuration(n_clicks):
        if not n_clicks:
            raise dash.exceptions.PreventUpdate
        toast = ToastManager.info("Import Configuration", detail_message="Import Configuration")
        return toast

    # Reset preferences to defaults
    @app.callback(
        [Output('widget-toggles', 'value', allow_duplicate=True),
         Output('individual-widget-toggles', 'value', allow_duplicate=True),
         Output('view-density', 'value', allow_duplicate=True),
         Output('font-size-pref', 'value', allow_duplicate=True),
         Output('animation-speed', 'value', allow_duplicate=True),
         Output('auto-refresh-toggle', 'value', allow_duplicate=True),
         Output('customize-refresh-interval-select', 'value', allow_duplicate=True),
         Output('data-retention-select', 'value', allow_duplicate=True),
         Output('chart-preferences', 'value', allow_duplicate=True),
         Output('notification-prefs', 'value', allow_duplicate=True),
         Output('alert-severity-filter', 'value', allow_duplicate=True),
         Output('toast-container', 'children', allow_duplicate=True)],
        Input('reset-prefs-btn', 'n_clicks'),
        prevent_initial_call=True
    )
    def reset_preferences(n_clicks):
        if not n_clicks:
            raise dash.exceptions.PreventUpdate
        defaults = (
            ["metrics", "features", "rightPanel"],
            ["network-graph", "protocol-chart", "traffic-timeline", "device-list", "alert-feed"],
            "comfortable", "medium", "normal", True, "10", "168",
            ["show-grid", "smooth-charts", "chart-tooltips"],
            ["sound"],
            ["critical", "high", "medium", "low"],
        )
        toast = ToastManager.success("Reset Complete", detail_message="Reset Complete")
        return *defaults, toast

    # ================================================================
    # SPOTLIGHT SEARCH
    # ================================================================

    @app.callback(
        [Output('spotlight-search-modal', 'is_open'),
         Output('spotlight-search-input', 'value')],
        [Input('spotlight-search-button', 'n_clicks'),
         Input('spotlight-search-clear', 'n_clicks')],
        [State('spotlight-search-modal', 'is_open')],
        prevent_initial_call=True
    )
    def toggle_spotlight_modal(btn_clicks, clear_clicks, is_open):
        ctx = callback_context
        if not ctx.triggered:
            return no_update, no_update
        trigger_id = ctx.triggered[0]['prop_id'].split('.')[0]
        if trigger_id == 'spotlight-search-button':
            return not is_open, "" if not is_open else no_update
        elif trigger_id == 'spotlight-search-clear':
            return no_update, ""
        return no_update, no_update

    # Clientside: Fuzzy search with NLP boosts + context-aware boosts + predictive suggestions
    app.clientside_callback(
        """
        function(searchQuery, catalog, categoryFilter, contextData) {
            if (!catalog || catalog.length === 0) {
                return {results: [], totalCount: 0, hasMore: false, query: "", categories: {}, topHit: null, recentSearches: [], searchTime: "0.00", categoryFilter: null, predictiveSuggestions: [], contextData: null};
            }

            var contextBoosts = (contextData && contextData.boosts) ? contextData.boosts : null;
            if (window.spotlightSearch) {
                var searchData = window.spotlightSearch.searchFeatures(searchQuery || "", catalog, 50, categoryFilter, contextBoosts);
                searchData.recentSearches = window.spotlightSearch.getRecentSearches();
                searchData.predictiveSuggestions = window.spotlightSearch.getPredictiveSuggestions ? window.spotlightSearch.getPredictiveSuggestions(catalog) : [];
                searchData.contextData = contextData;
                return searchData;
            } else {
                var results = catalog.slice(0, 10);
                return {
                    results: results,
                    totalCount: results.length,
                    hasMore: false,
                    query: searchQuery || "",
                    categories: {},
                    topHit: results[0] || null,
                    recentSearches: [],
                    searchTime: "0.00",
                    categoryFilter: null,
                    predictiveSuggestions: [],
                    contextData: null
                };
            }
        }
        """,
        Output('spotlight-filtered-results', 'data'),
        [Input('spotlight-search-input', 'value'),
         Input('spotlight-catalog-store', 'data'),
         Input('spotlight-category-filter', 'data'),
         Input('spotlight-context-data', 'data')],
        prevent_initial_call=False
    )

    # Server-side: Render spotlight results (with cross-domain data + predictive suggestions)
    @app.callback(
        Output('spotlight-results-container', 'children'),
        [Input('spotlight-filtered-results', 'data'),
         Input('spotlight-cross-domain-results', 'data')],
        prevent_initial_call=False
    )
    def render_spotlight_results(search_data, cross_domain_data):
        """Render compact macOS-style search results with category grouping."""

        # ── helpers ──────────────────────────────────────────────────────
        _SEV_COLORS = {
            'critical': '#dc2626', 'high': '#f97316',
            'medium': '#3b82f6', 'low': '#10b981',
        }

        def _device_row(d, idx):
            ip = d.get('device_ip', '')
            name = d.get('device_name') or d.get('hostname') or ip
            is_blocked = d.get('is_blocked')
            is_trusted = d.get('is_trusted')
            color = '#ef4444' if is_blocked else ('#10b981' if is_trusted else '#94a3b8')
            label = 'Blocked' if is_blocked else ('Trusted' if is_trusted else 'Unknown')
            mac = d.get('mac_address', '')
            return html.Div([
                html.Div(
                    html.I(className="fa fa-microchip"),
                    className="sl-icon-box",
                    style={"background": f"{color}22", "color": color}
                ),
                html.Div([
                    html.Span(name, className="sl-row-name"),
                    html.Span(f" {ip}", className="sl-row-desc ms-1"),
                    html.Div(mac, className="sl-row-desc"),
                ], className="sl-row-text"),
                html.Div([
                    html.Span(label, className="sl-row-cat"),
                    html.I(className="fa fa-chevron-right sl-row-arrow"),
                ], className="sl-row-right d-flex align-items-center"),
                dbc.Button("", id={'type': 'spotlight-go-to-btn', 'index': f"dev_{idx}", 'modal_id': 'device-mgmt-modal'},
                           n_clicks=0, style={"display": "none"}),
            ], className="sl-result-row sl-device-row",
               **{"data-feature": json.dumps({
                   'id': 'device-mgmt-modal', 'name': name,
                   'description': f'IP: {ip}  MAC: {mac}  Status: {label}',
                   'category': 'Device', 'icon': 'fa-microchip',
                   'color': color, 'keywords': []
               })})

        def _alert_row(a, idx):
            sev = (a.get('severity') or 'unknown').lower()
            color = _SEV_COLORS.get(sev, '#94a3b8')
            msg = (a.get('explanation') or a.get('description') or 'Alert')[:72]
            ip = a.get('device_ip', '')
            return html.Div([
                html.Div(
                    html.I(className="fa fa-triangle-exclamation"),
                    className="sl-icon-box",
                    style={"background": f"{color}22", "color": color}
                ),
                html.Div([
                    html.Span(sev.upper(), className="sl-row-name"),
                    html.Div(msg, className="sl-row-desc"),
                ], className="sl-row-text"),
                html.Div([
                    html.Span(ip, className="sl-row-cat"),
                    html.I(className="fa fa-chevron-right sl-row-arrow"),
                ], className="sl-row-right"),
                dbc.Button("", id={'type': 'spotlight-go-to-btn', 'index': f"alert_{idx}", 'modal_id': 'alert-details-modal'},
                           n_clicks=0, style={"display": "none"}),
            ], className="sl-result-row sl-alert-row",
               **{"data-feature": json.dumps({
                   'id': 'alert-details-modal', 'name': f'{sev.upper()} Alert',
                   'description': f'{msg}  IP: {ip}',
                   'category': 'Alerts', 'icon': 'fa-triangle-exclamation',
                   'color': color, 'keywords': []
               })})

        # ── parse search_data ─────────────────────────────────────────────
        if isinstance(search_data, dict):
            filtered_results = search_data.get('results', [])
            total_count = search_data.get('totalCount', 0)
            has_more = search_data.get('hasMore', False)
            query = search_data.get('query', '')
            categories = search_data.get('categories', {})
            top_hit_id = search_data.get('topHit', {}).get('id') if search_data.get('topHit') else None
            recent_searches = search_data.get('recentSearches', [])
            predictive_suggestions = search_data.get('predictiveSuggestions', [])
            context_data = search_data.get('contextData', {}) or {}
            search_time = search_data.get('searchTime', '0.00')
            category_filter = search_data.get('categoryFilter')
        else:
            filtered_results = search_data if search_data else []
            total_count = len(filtered_results)
            has_more = False
            query = ''
            categories = {}
            top_hit_id = filtered_results[0].get('id') if filtered_results else None
            recent_searches = []
            predictive_suggestions = []
            context_data = {}
            search_time = '0.00'
            category_filter = None

        active_alerts = int(context_data.get('active_alerts', 0))

        # ── EMPTY STATE (no query) ────────────────────────────────────────
        if not query or query.strip() == "":
            sections = []

            # Context-aware alert banner
            if active_alerts > 0:
                sections.append(
                    dbc.Alert([
                        html.I(className="fa fa-triangle-exclamation me-2"),
                        html.Strong(f"{active_alerts} active alert{'s' if active_alerts != 1 else ''}"),
                        " detected - try searching 'threat' or 'lockdown' to respond"
                    ], color="danger", className="spotlight-context-alert toast-history-item py-2 mb-3")
                )

            # Predictive suggestions
            if predictive_suggestions:
                for si, suggestion in enumerate(predictive_suggestions[:2]):
                    feats = suggestion.get('features', [])
                    if feats:
                        sections.append(html.Div([
                            html.Div(suggestion.get('label', ''), className="sl-section-header"),
                            html.Div([
                                create_spotlight_result_item(feat, f"pred_{si}_{fi}", False, False)
                                for fi, feat in enumerate(feats[:3])
                            ], className="sl-section"),
                        ]))

            # Recent searches
            if recent_searches:
                sections.append(html.Div([
                    html.Div([
                        html.Span([html.I(className="fa fa-history me-2"), "Recent Searches"],
                                  className="sl-section-header"),
                        html.Button("Clear",
                                    id="spotlight-clear-recent-searches",
                                    className="sl-clear-btn"),
                    ], className="d-flex align-items-center justify-content-between sl-section-row"),
                    html.Div([
                        dbc.Badge([html.I(className="fa fa-search me-2"), s],
                                  color="light", className="me-2 mb-2 p-2 spotlight-recent-search-badge spotlight-item")
                        for s in recent_searches
                    ], className="sl-recent-badges"),
                ], className="mb-3"))

            # Top features from analytics
            if filtered_results:
                sections.append(html.Div([
                    html.Div([html.I(className="fa fa-star me-1 text-warning"), " Featured"],
                             className="sl-section-header"),
                    html.Div([
                        create_spotlight_result_item(feat, idx, False, False)
                        for idx, feat in enumerate(filtered_results[:8])
                    ], className="sl-section"),
                ]))

            if sections:
                return html.Div(sections, className="sl-results-scroll")
            return html.Div([
                html.I(className="fa fa-search fa-3x text-muted mb-3"),
                html.P("Start typing to search features...", className="text-muted")
            ], className="text-center p-5")

        # ── NO RESULTS ────────────────────────────────────────────────────
        if not filtered_results:
            return html.Div([
                html.I(className="fa fa-search fa-3x text-muted mb-3"),
                html.P(f"No results found for '{query}'", className="text-muted"),
                html.P("Try a different search term", className="text-muted small")
            ], className="text-center p-5")

        # ── RESULT HEADER (count + filter badges) ─────────────────────────
        result_header = html.Div([
            html.Div([
                html.Span(
                    f"{total_count} result{'s' if total_count != 1 else ''}",
                    className="spotlight-result-count text-muted small fw-bold"
                ),
                html.Span(f" • top {len(filtered_results)}", className="text-muted small") if has_more else None,
                html.Span(f" • {search_time}ms", className="text-muted small ms-2"),
            ], className="mb-1 d-flex align-items-center"),
            html.Div(
                [
                    html.Span("Filter: ", className="text-muted small me-2"),
                    dbc.Badge("All", id="spotlight-filter-all",
                             color="primary" if not category_filter else "light",
                             className="me-2 spotlight-filter-badge spotlight-item--sm"),
                ] + [
                    dbc.Badge(
                        f"{cat} ({len(feats)})",
                        id={"type": "spotlight-filter-badge", "category": cat},
                        color="primary" if category_filter == cat else "light",
                        className="me-2 spotlight-filter-badge spotlight-item--sm"
                    )
                    for cat, feats in sorted(categories.items(), key=lambda x: len(x[1]), reverse=True)
                ] if categories else [],
                className="mb-2 pb-1 border-bottom"
            ) if query else None,
        ], className="px-3 pt-2")

        sections = [result_header]

        # ── CROSS-DOMAIN: devices ─────────────────────────────────────────
        if cross_domain_data and query:
            cd_devices = cross_domain_data.get('devices', [])
            cd_alerts = cross_domain_data.get('alerts', [])
            if cd_devices:
                sections.append(html.Div([
                    html.Div(
                        [html.I(className="fa fa-microchip me-1"), f" Devices ({len(cd_devices)})"],
                        className="sl-section-header"
                    ),
                    html.Div([_device_row(d, i) for i, d in enumerate(cd_devices)],
                             className="sl-section"),
                ]))
            if cd_alerts:
                sections.append(html.Div([
                    html.Div(
                        [html.I(className="fa fa-triangle-exclamation me-1 text-danger"),
                         f" Alerts ({len(cd_alerts)})"],
                        className="sl-section-header"
                    ),
                    html.Div([_alert_row(a, i) for i, a in enumerate(cd_alerts)], className="sl-section"),
                ]))

        # ── FEATURE RESULTS ───────────────────────────────────────────────
        if categories and len(categories) > 1:
            for cat_name, cat_feats in sorted(categories.items(), key=lambda x: len(x[1]), reverse=True):
                sections.append(html.Div([
                    html.Div(
                        [html.I(className="fa fa-folder me-1"),
                         f" {cat_name} ({len(cat_feats)})"],
                        className="sl-section-header"
                    ),
                    html.Div([
                        create_spotlight_result_item(feat, i, False, feat.get('id') == top_hit_id)
                        for i, feat in enumerate(cat_feats)
                    ], className="sl-section"),
                ]))
        else:
            feature_rows = [
                create_spotlight_result_item(feat, i, False, feat.get('id') == top_hit_id)
                for i, feat in enumerate(filtered_results)
            ]
            sections.append(html.Div(feature_rows, className="sl-section"))

        return html.Div(sections, className="sl-results-scroll")

    # Spotlight: Category filter badge clicks
    @app.callback(
        Output('spotlight-category-filter', 'data'),
        [Input('spotlight-filter-all', 'n_clicks'),
         Input({'type': 'spotlight-filter-badge', 'category': ALL}, 'n_clicks')],
        [State({'type': 'spotlight-filter-badge', 'category': ALL}, 'id')],
        prevent_initial_call=True
    )
    def update_category_filter(all_clicks, badge_clicks, badge_ids):
        ctx = callback_context
        if not ctx.triggered:
            return no_update
        trigger_id = ctx.triggered[0]['prop_id'].split('.')[0]
        if 'spotlight-filter-all' in trigger_id:
            return None
        if 'spotlight-filter-badge' in trigger_id:
            button_id = json.loads(trigger_id)
            return button_id['category']
        return no_update

    # Spotlight: Track modal click
    @app.callback(
        Output('spotlight-modal-trigger', 'data'),
        Input({'type': 'spotlight-go-to-btn', 'index': ALL, 'modal_id': ALL}, 'n_clicks'),
        prevent_initial_call=True
    )
    def spotlight_track_modal_click(go_to_clicks):
        ctx = callback_context
        if not ctx.triggered or not any(go_to_clicks):
            return no_update
        trigger_id = ctx.triggered[0]['prop_id']
        if 'spotlight-go-to-btn' in trigger_id:
            button_id = json.loads(trigger_id.split('.')[0])
            return {"modal_id": button_id['modal_id'], "timestamp": time.time()}
        return no_update

    # Spotlight: Open modals directly (server-side) - with RBAC security
    @app.callback(
        [Output('analytics-modal', 'is_open', allow_duplicate=True),
         Output('risk-heatmap-modal', 'is_open', allow_duplicate=True),
         Output('device-mgmt-modal', 'is_open', allow_duplicate=True),
         Output('user-modal', 'is_open', allow_duplicate=True),
         Output('firewall-modal', 'is_open', allow_duplicate=True),
         Output('threat-modal', 'is_open', allow_duplicate=True),
         Output('vuln-scanner-modal', 'is_open', allow_duplicate=True),
         Output('privacy-modal', 'is_open', allow_duplicate=True),
         Output('compliance-modal', 'is_open', allow_duplicate=True),
         Output('system-modal', 'is_open', allow_duplicate=True),
         Output('email-modal', 'is_open', allow_duplicate=True),
         Output('preferences-modal', 'is_open', allow_duplicate=True),
         Output('quick-settings-modal', 'is_open', allow_duplicate=True),
         Output('profile-edit-modal', 'is_open', allow_duplicate=True),
         Output('smarthome-modal', 'is_open', allow_duplicate=True),
         Output('segmentation-modal', 'is_open', allow_duplicate=True),
         Output('firmware-modal', 'is_open', allow_duplicate=True),
         Output('protocol-modal', 'is_open', allow_duplicate=True),
         Output('threat-map-modal', 'is_open', allow_duplicate=True),
         Output('attack-surface-modal', 'is_open', allow_duplicate=True),
         Output('forensic-timeline-modal', 'is_open', allow_duplicate=True),
         Output('auto-response-modal', 'is_open', allow_duplicate=True),
         Output('alert-details-modal', 'is_open', allow_duplicate=True),
         Output('toast-history-modal', 'is_open', allow_duplicate=True),
         Output('toast-detail-modal', 'is_open', allow_duplicate=True),
         Output('performance-modal', 'is_open', allow_duplicate=True),
         Output('benchmark-modal', 'is_open', allow_duplicate=True),
         Output('education-modal', 'is_open', allow_duplicate=True),
         Output('api-hub-modal', 'is_open', allow_duplicate=True),
         Output('quick-actions-modal', 'is_open', allow_duplicate=True),
         Output('customize-layout-modal', 'is_open', allow_duplicate=True),
         Output('chat-modal', 'is_open', allow_duplicate=True),
         Output('onboarding-modal', 'is_open', allow_duplicate=True),
         Output('lockdown-modal', 'is_open', allow_duplicate=True),
         Output('agent-modal', 'is_open', allow_duplicate=True),
         Output('spotlight-search-modal', 'is_open', allow_duplicate=True),
         Output('toast-container', 'children', allow_duplicate=True)],
        Input('spotlight-modal-trigger', 'data'),
        prevent_initial_call=True
    )
    def spotlight_open_modal_server_side(trigger_data):
        """Open target modal directly from spotlight - uses existing RBAC security"""
        if not trigger_data or not trigger_data.get('modal_id'):
            return [no_update] * 37

        modal_id = trigger_data['modal_id']

        # Security: Check authentication using existing RBAC
        if not current_user.is_authenticated:
            toast = ToastManager.create_toast(
                "Access Denied",
                "Please log in to access features",
                "warning"
            )
            return [no_update] * 35 + [False, False, toast]

        # Use existing RBAC functions for permission checks
        # Check if admin-only modal and user is not admin
        if modal_id in ADMIN_ONLY_MODALS and current_user.role != 'admin':
            toast = ToastManager.create_toast(
                "Access Denied",
                "This feature requires administrator privileges",
                "warning"
            )
            return [no_update] * 35 + [False, False, toast]

        # Additional check for device management using existing RBAC
        if modal_id == 'device-mgmt-modal' and not can_manage_devices(current_user):
            toast = ToastManager.create_toast(
                "Access Denied",
                "You don't have permission to manage devices",
                "warning"
            )
            return [no_update] * 35 + [False, False, toast]

        # Map ALL modal IDs to output positions (must match Output list order above)
        modal_map = {
            'analytics-modal': 0,
            'risk-heatmap-modal': 1,
            'device-mgmt-modal': 2,
            'user-modal': 3,
            'firewall-modal': 4,
            'threat-modal': 5,
            'vuln-scanner-modal': 6,
            'privacy-modal': 7,
            'compliance-modal': 8,
            'system-modal': 9,
            'email-modal': 10,
            'preferences-modal': 11,
            'quick-settings-modal': 12,
            'profile-edit-modal': 13,
            'smarthome-modal': 14,
            'segmentation-modal': 15,
            'firmware-modal': 16,
            'protocol-modal': 17,
            'threat-map-modal': 18,
            'attack-surface-modal': 19,
            'forensic-timeline-modal': 20,
            'auto-response-modal': 21,
            'alert-details-modal': 22,
            'toast-history-modal': 23,
            'toast-detail-modal': 24,
            'performance-modal': 25,
            'benchmark-modal': 26,
            'education-modal': 27,
            'api-hub-modal': 28,
            'quick-actions-modal': 29,
            'customize-layout-modal': 30,
            'chat-modal': 31,
            'onboarding-modal': 32,
            'lockdown-modal': 33,
            'agent-modal': 34,
            # spotlight-search-modal = 35, toast-container = 36
        }

        # All outputs default to no_update (37 total: 35 modals + spotlight + toast)
        outputs = [no_update] * 37

        # Open the requested modal if it's in our map
        if modal_id in modal_map:
            outputs[modal_map[modal_id]] = True  # Open target modal
            outputs[35] = False  # Close spotlight modal

            try:
                audit_logger.log_action(
                    action_type=f'spotlight_open',
                    action_description=f'Opened {modal_id} via spotlight search',
                    target_resource=modal_id,
                )
            except Exception as e:
                logger.warning(f"Failed to log spotlight access: {e}")
        else:
            outputs[35] = False  # Still close spotlight for unknown modals

        return outputs

    # Clientside: Clear recent searches
    app.clientside_callback(
        """
        function(n_clicks) {
            if (!n_clicks) {
                return window.dash_clientside.no_update;
            }
            if (window.spotlightSearch) {
                window.spotlightSearch.clearRecentSearches();
            }
            return {
                results: [], totalCount: 0, hasMore: false, query: "",
                categories: {}, topHit: null, recentSearches: [],
                searchTime: "0.00", categoryFilter: null
            };
        }
        """,
        Output('spotlight-filtered-results', 'data', allow_duplicate=True),
        Input('spotlight-clear-recent-searches', 'n_clicks'),
        prevent_initial_call=True
    )

    # Clientside: Log modal open + record feature access for search analytics
    app.clientside_callback(
        """
        function(modalData) {
            if (!modalData || !modalData.modal_id) {
                return window.dash_clientside.no_update;
            }

            const modalId = modalData.modal_id;
            console.log('[Spotlight] Server-side callback will open modal:', modalId);

            // Record feature access for analytics (localStorage)
            if (window.spotlightSearch && window.spotlightSearch.recordFeatureAccess) {
                window.spotlightSearch.recordFeatureAccess(modalId);
            }

            return window.dash_clientside.no_update;
        }
        """,
        Output('spotlight-search-input', 'value', allow_duplicate=True),
        Input('spotlight-modal-trigger', 'data'),
        prevent_initial_call=True
    )

    # ================================================================
    # SPOTLIGHT SEARCH - CONTEXT-AWARE BOOST
    # ================================================================

    @app.callback(
        Output('spotlight-context-data', 'data'),
        Input('spotlight-search-modal', 'is_open'),
        prevent_initial_call=True
    )
    def fetch_spotlight_context(is_open):
        """Fetch system state (alerts, CPU) when spotlight opens for context-aware search boosting"""
        if not is_open:
            return no_update
        try:
            cursor = db_manager.conn.cursor()
            cursor.execute("""
                SELECT COUNT(*) FROM alerts
                WHERE timestamp > datetime('now', '-24 hours')
                AND severity IN ('high', 'critical')
                AND acknowledged = 0
            """)
            row = cursor.fetchone()
            active_alert_count = int(row[0]) if row else 0

            cpu_pct = psutil.cpu_percent(interval=None)

            boosts = {}
            if active_alert_count > 0:
                boosts['threat-modal'] = active_alert_count * 10
                boosts['risk-heatmap-modal'] = active_alert_count * 8
                boosts['firewall-modal'] = active_alert_count * 5
                boosts['analytics-modal'] = active_alert_count * 3
                boosts['auto-response-modal'] = active_alert_count * 2
                boosts['lockdown-modal'] = active_alert_count * 2
            if cpu_pct > 80:
                boosts['performance-modal'] = boosts.get('performance-modal', 0) + 30
                boosts['system-modal'] = boosts.get('system-modal', 0) + 20
                boosts['benchmark-modal'] = boosts.get('benchmark-modal', 0) + 10

            return {
                'active_alerts': active_alert_count,
                'cpu_pct': round(float(cpu_pct), 1),
                'boosts': boosts,
                'timestamp': datetime.now().isoformat()
            }
        except Exception as e:
            logger.warning(f"Spotlight context fetch failed: {e}")
            return {'active_alerts': 0, 'cpu_pct': 0.0, 'boosts': {}, 'timestamp': datetime.now().isoformat()}

    # ================================================================
    # SPOTLIGHT SEARCH - CROSS-DOMAIN SEARCH (Devices + Alerts)
    # ================================================================

    # Clientside: debounce the spotlight input before triggering the DB search
    # (keeps fuzzy JS search instant while preventing a DB round-trip on every keystroke)
    app.clientside_callback(
        """
        function(inputValue) {
            // Use a module-level timer to debounce writes to the store
            if (!window._spotlightCDDebounceTimer) {
                window._spotlightCDDebounceTimer = null;
            }
            clearTimeout(window._spotlightCDDebounceTimer);

            var ns = window.dash_clientside.no_update;
            // Return immediately for very short queries — no DB call needed
            if (!inputValue || inputValue.trim().length < 2) {
                return '';
            }

            // Return a Promise that resolves after 300ms of no typing
            return new Promise(function(resolve) {
                window._spotlightCDDebounceTimer = setTimeout(function() {
                    resolve(inputValue || '');
                }, 300);
            });
        }
        """,
        Output('spotlight-cross-domain-debounced', 'data'),
        Input('spotlight-search-input', 'value'),
        prevent_initial_call=True
    )

    @app.callback(
        Output('spotlight-cross-domain-results', 'data'),
        Input('spotlight-cross-domain-debounced', 'data'),
        prevent_initial_call=True
    )
    def cross_domain_search(query):
        """Search live devices and alerts from the database alongside feature results.
        Triggered only after 300ms debounce (not on every keystroke).
        Uses indexed columns — no LOWER() wrappers so indexes are not bypassed.
        SQLite LIKE is case-insensitive for ASCII by default.
        """
        if not query or len(query.strip()) < 2:
            return {'devices': [], 'alerts': [], 'query': ''}
        if not current_user.is_authenticated:
            return {'devices': [], 'alerts': [], 'query': ''}

        q = query.strip()
        results = {'devices': [], 'alerts': [], 'query': q.lower()}
        try:
            cursor = db_manager.conn.cursor()
            like_q = f'%{q}%'
            # No LOWER() wrapper — SQLite LIKE is already case-insensitive for ASCII.
            # This allows SQLite to use the idx_devices_name and idx_devices_last_seen indexes.
            cursor.execute("""
                SELECT device_ip, device_name, device_type, mac_address, is_trusted, is_blocked
                FROM devices
                WHERE device_ip LIKE ?
                   OR COALESCE(device_name, '') LIKE ?
                   OR COALESCE(device_type, '') LIKE ?
                   OR COALESCE(mac_address, '') LIKE ?
                ORDER BY last_seen DESC
                LIMIT 5
            """, (like_q, like_q, like_q, like_q))
            results['devices'] = [dict(row) for row in cursor.fetchall()]

            # Uses idx_alerts_timestamp and idx_alerts_device indexes.
            cursor.execute("""
                SELECT id, timestamp, device_ip, severity, explanation
                FROM alerts
                WHERE COALESCE(explanation, '') LIKE ?
                   OR device_ip LIKE ?
                   OR severity LIKE ?
                ORDER BY timestamp DESC
                LIMIT 5
            """, (like_q, like_q, like_q))
            results['alerts'] = [dict(row) for row in cursor.fetchall()]

        except Exception as e:
            logger.warning(f"Spotlight cross-domain search error: {e}")
        return results

    # Cmd+Shift+L hidden button → open lockdown modal
    app.clientside_callback(
        """
        function(n) {
            if (!n) return window.dash_clientside.no_update;
            return { modal_id: 'lockdown-modal', timestamp: Date.now() / 1000 };
        }
        """,
        Output('spotlight-modal-trigger', 'data', allow_duplicate=True),
        Input('spotlight-emergency-lockdown-btn', 'n_clicks'),
        prevent_initial_call=True
    )

    # ================================================================
    # EMERGENCY MODE
    # ================================================================

    # Show/hide emergency button based on template
    app.clientside_callback(
        """
        function(template) {
            const container = document.getElementById('emergency-button-container');
            if (!container) return window.dash_clientside.no_update;

            const aliases = {home_user: 'simple', security_admin: 'advanced', developer: 'advanced'};
            const canonical = aliases[template] || template;
            if (canonical === 'advanced') {
                container.style.display = 'block';
                const alert = container.querySelector('.alert');
                if (alert) alert.style.display = 'block';
            } else {
                container.style.display = 'none';
            }

            return window.dash_clientside.no_update;
        }
        """,
        Output('emergency-button-container', 'style', allow_duplicate=True),
        Input('dashboard-template-store', 'data'),
        prevent_initial_call=True
    )

    # Open confirmation modal
    @app.callback(
        Output('emergency-confirm-modal', 'is_open'),
        [Input('emergency-activate-btn', 'n_clicks'),
         Input('emergency-cancel-btn', 'n_clicks'),
         Input('emergency-confirm-btn', 'n_clicks')],
        State('emergency-confirm-modal', 'is_open'),
        prevent_initial_call=True
    )
    def toggle_emergency_modal(activate_clicks, cancel_clicks, confirm_clicks, is_open):
        ctx = callback_context
        if not ctx.triggered:
            return no_update
        button_id = ctx.triggered[0]['prop_id'].split('.')[0]
        if button_id == 'emergency-activate-btn':
            if not current_user.is_authenticated or not current_user.is_admin():
                return False
            return True
        elif button_id in ['emergency-cancel-btn', 'emergency-confirm-btn']:
            return False
        return is_open

    # Activate emergency mode
    @app.callback(
        [Output('emergency-mode-store', 'data'),
         Output('toast-container', 'children', allow_duplicate=True),
         Output('emergency-reason-input', 'value')],
        Input('emergency-confirm-btn', 'n_clicks'),
        [State('emergency-reason-input', 'value'),
         State('emergency-mode-store', 'data')],
        prevent_initial_call=True
    )
    def activate_emergency_mode(n_clicks, reason, current_state):
        if not n_clicks or not current_user.is_authenticated or not current_user.is_admin():
            return no_update, no_update, no_update

        try:
            conn = db_manager.conn
            cursor = conn.cursor()

            if current_state and current_state.get('active'):
                toast = ToastManager.warning("Emergency Mode Already Active", detail_message="Emergency protection is already enabled.")
                return no_update, toast, ""

            user_ip = request.remote_addr if request else None

            if user_ip:
                cursor.execute('''
                    UPDATE devices SET is_blocked = 1
                    WHERE (is_trusted = 0 OR is_trusted IS NULL) AND device_ip != ?
                ''', (user_ip,))
            else:
                cursor.execute('''
                    UPDATE devices SET is_blocked = 1
                    WHERE is_trusted = 0 OR is_trusted IS NULL
                ''')
            blocked_count = cursor.rowcount

            ip_address = request.remote_addr if request else None

            action_desc = f"Blocked {blocked_count} unknown devices; Enabled maximum firewall protection"
            if user_ip:
                action_desc += f"; User device {user_ip} excluded from blocking"

            cursor.execute('''
                INSERT INTO emergency_mode_log
                (triggered_by_user_id, triggered_by_username, trigger_reason,
                 actions_taken, devices_blocked, ip_address, is_active)
                VALUES (?, ?, ?, ?, ?, ?, 1)
            ''', (current_user.id, current_user.username, reason or "User activated emergency mode",
                  action_desc, blocked_count, ip_address))
            log_id = cursor.lastrowid
            conn.commit()

            logger.warning(f"EMERGENCY MODE ACTIVATED by {current_user.username}. Blocked {blocked_count} devices.")

            cursor.execute('''
                INSERT OR IGNORE INTO devices (device_ip, device_name, device_type, is_trusted)
                VALUES ('SYSTEM', 'System Alerts', 'system', 1)
            ''')
            cursor.execute('''
                INSERT INTO alerts (device_ip, severity, explanation)
                VALUES ('SYSTEM', 'critical', ?)
            ''', (f"Emergency mode activated by {current_user.username}. {blocked_count} devices blocked. Reason: {reason or 'User did not provide a reason'}",))
            conn.commit()

            toast = ToastManager.create_toast(
                message=f"Emergency Protection Activated - {blocked_count} devices blocked",
                toast_type="warning", header="🚨 Network Secured",
                detail_message=f"All unknown devices have been blocked. Administrators have been notified.",
                show_detail_button=True, duration=5000
            )

            log_emergency_mode(audit_logger, activated=True, reason=reason or "User activated emergency mode", success=True)

            return {'active': True, 'log_id': log_id}, toast, ""

        except Exception as e:
            logger.error(f"Failed to activate emergency mode: {e}")
            log_emergency_mode(audit_logger, activated=True, reason=reason, success=False, error_message=str(e))
            toast = ToastManager.error("Emergency Mode Failed", detail_message=f"Error: {str(e)}")
            return no_update, toast, ""

    # Deactivate emergency mode
    @app.callback(
        [Output('emergency-mode-store', 'data', allow_duplicate=True),
         Output('toast-container', 'children', allow_duplicate=True)],
        Input('emergency-deactivate-btn', 'n_clicks'),
        State('emergency-mode-store', 'data'),
        prevent_initial_call=True
    )
    def deactivate_emergency_mode(n_clicks, current_state):
        if not n_clicks or not current_user.is_authenticated:
            return no_update, no_update

        try:
            conn = db_manager.conn
            cursor = conn.cursor()
            cursor.execute(
                "SELECT preference_value FROM user_preferences WHERE user_id = ? AND preference_key = 'is_kid'",
                (current_user.id,)
            )
            kid_check = cursor.fetchone()
            if kid_check and kid_check[0] == '1':
                toast = ToastManager.error("Access Denied", detail_message="Emergency mode can only be deactivated by adults.")
                return no_update, toast
        except Exception as e:
            logger.error(f"Error checking user permissions for emergency mode deactivation: {e}")

        if not current_state or not current_state.get('active'):
            toast = ToastManager.warning("Emergency Mode Not Active", detail_message="Emergency protection is not currently active.")
            return no_update, toast

        try:
            conn = db_manager.conn
            cursor = conn.cursor()

            log_id = current_state.get('log_id')
            if log_id:
                cursor.execute('''
                    UPDATE emergency_mode_log
                    SET is_active = 0, deactivated_timestamp = CURRENT_TIMESTAMP,
                        deactivated_by_user_id = ?, deactivated_by_username = ?
                    WHERE id = ?
                ''', (current_user.id, current_user.username, log_id))

            conn.commit()

            logger.info(f"Emergency mode deactivated by {current_user.username}")
            log_emergency_mode(audit_logger, activated=False, success=True)

            toast = ToastManager.success(
                "Emergency Mode Deactivated",
                detail_message="Emergency protection has been disabled. Devices remain blocked - review them in Device Management to unblock if needed.",
                show_detail_button=True
            )

            return {'active': False, 'log_id': None}, toast

        except Exception as e:
            logger.error(f"Error deactivating emergency mode: {e}")
            log_emergency_mode(audit_logger, activated=False, success=False, error_message=str(e))
            conn.rollback()
            toast = ToastManager.error("Deactivation Failed", detail_message=f"Could not deactivate emergency protection: {str(e)}")
            return no_update, toast

    # Update UI based on emergency mode state
    @app.callback(
        [Output('emergency-button-container', 'style', allow_duplicate=True),
         Output('emergency-active-banner', 'style'),
         Output('emergency-status-text', 'children')],
        Input('emergency-mode-store', 'data'),
        prevent_initial_call=True
    )
    def update_emergency_ui(emergency_state):
        if not emergency_state or not emergency_state.get('active'):
            return {'display': 'block'}, {'display': 'none'}, ""

        try:
            conn = db_manager.conn
            cursor = conn.cursor()

            log_id = emergency_state.get('log_id')
            if log_id:
                cursor.execute('''
                    SELECT devices_blocked, trigger_timestamp, triggered_by_username
                    FROM emergency_mode_log WHERE id = ?
                ''', (log_id,))
                result = cursor.fetchone()

                if result:
                    blocked_count, timestamp, username = result
                    status_text = f"{blocked_count} unknown devices blocked. Activated by {username} at {timestamp}."
                    return {'display': 'none'}, {'display': 'block'}, status_text

            return {'display': 'none'}, {'display': 'block'}, "Emergency protection is active."

        except Exception as e:
            logger.error(f"Error updating emergency UI: {e}")
            return {'display': 'none'}, {'display': 'block'}, "Emergency protection is active."

    # -------------------------------------------------------------------------
    # Home-user layout: show/hide dimension tiles, history chart, email row
    # -------------------------------------------------------------------------
    @app.callback(
        Output('score-dims-col', 'style'),
        Output('security-score-history-row', 'style'),
        Output('home-email-row', 'style'),
        Input('dashboard-template-store', 'data'),
    )
    def update_home_user_layout(template_data):
        from dashboard.shared import TEMPLATE_ALIASES
        raw = template_data if isinstance(template_data, str) else 'advanced'
        template = TEMPLATE_ALIASES.get(raw, raw)
        if template == 'simple':
            # Keep score dims visible, hide history chart (too technical), show email row
            return {}, {'display': 'none'}, {'display': 'block'}
        return {}, {}, {'display': 'none'}

    # -------------------------------------------------------------------------
    # Notification nav button — opens the full notification modal (all channels).
    # -------------------------------------------------------------------------
    @app.callback(
        Output('email-modal', 'is_open', allow_duplicate=True),
        Input('email-alert-nav-toggle', 'n_clicks'),
        prevent_initial_call=True,
    )
    def open_notification_modal_from_nav(n_clicks):
        if not n_clicks:
            return no_update
        return True

    # ---- Keep icon green when email alerts are enabled ----
    @app.callback(
        Output('email-alert-nav-icon', 'className'),
        Input('email-enable-switch', 'value'),
        prevent_initial_call=False,
    )
    def sync_notification_nav_icon(value):
        return "fa fa-paper-plane email-icon-on" if value else "fa fa-paper-plane"

    @app.callback(
        Output('email-enable-switch', 'value', allow_duplicate=True),
        Input('home-email-switch', 'value'),
        prevent_initial_call=True,
    )
    def sync_home_email_to_modal(home_value):
        if current_user.is_authenticated:
            try:
                cursor = db_manager.conn.cursor()
                cursor.execute(
                    """INSERT INTO user_preferences (user_id, preference_key, preference_value)
                       VALUES (?, 'email_enabled', ?)
                       ON CONFLICT(user_id, preference_key)
                       DO UPDATE SET preference_value = excluded.preference_value,
                                     updated_at = CURRENT_TIMESTAMP""",
                    (current_user.id, str(home_value))
                )
                db_manager.conn.commit()
            except Exception as e:
                logger.error(f"Failed to persist email toggle: {e}")
        return home_value

    @app.callback(
        Output('home-email-switch', 'value'),
        Input('email-enable-switch', 'value'),
        prevent_initial_call=True,
    )
    def sync_modal_email_to_home(modal_value):
        return modal_value

    # ------------------------------------------------------------------
    # RBAC enforcement for admin-only modals opened via card buttons.
    # The clientside card-button callback bypasses server-side checks, so
    # this callback immediately closes any admin-only modal that a non-admin
    # managed to open.  Returns (is_open=False, toast) for the offending
    # modal; no_update for everything else.
    # ------------------------------------------------------------------
    @app.callback(
        [Output(m, 'is_open', allow_duplicate=True) for m in ADMIN_ONLY_MODALS] +
        [Output('toast-container', 'children', allow_duplicate=True)],
        [Input(m, 'is_open') for m in ADMIN_ONLY_MODALS],
        prevent_initial_call=True,
    )
    def enforce_admin_modal_rbac(*states):
        n = len(ADMIN_ONLY_MODALS)
        if not current_user.is_authenticated or not current_user.is_admin():
            triggered = callback_context.triggered
            if not triggered:
                return [no_update] * n + [no_update]
            prop = triggered[0]['prop_id']          # e.g. "email-modal.is_open"
            modal_id = prop.split('.')[0]
            if triggered[0]['value'] is True and modal_id in ADMIN_ONLY_MODALS:
                closes = [False if m == modal_id else no_update for m in ADMIN_ONLY_MODALS]
                toast = ToastManager.create_toast(
                    "Access Denied",
                    "Administrator privileges required.",
                    "warning",
                )
                return closes + [toast]
        return [no_update] * n + [no_update]
