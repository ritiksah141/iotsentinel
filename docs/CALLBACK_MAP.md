# Comprehensive Callback Map — `dashboard/app.py`

> **Lines 11172–38604** · ~200+ callbacks · Organized by category with exact line ranges for extraction

---

## EXTRACTION LINE RANGES — QUICK REFERENCE

| #   | Category                                                                | Line Range  | ~Lines | Callbacks        |
| --- | ----------------------------------------------------------------------- | ----------- | ------ | ---------------- |
| 1   | **Overview / Header**                                                   | 11168–11625 | 458    | 7                |
| 2   | **Network Graph**                                                       | 11626–11876 | 251    | 5                |
| 3   | **Devices (Overview Panel)**                                            | 11877–12188 | 312    | 4                |
| 4   | **Toast / Notification History**                                        | 12067–12622 | 556    | 6                |
| 5   | **Alerts**                                                              | 12623–12894 | 272    | 5                |
| 6   | **AI-Powered Features**                                                 | 12895–13046 | 152    | 1                |
| 7   | **Onboarding**                                                          | 13047–13124 | 78     | 3                |
| 8   | **Lockdown Mode**                                                       | 13125–13270 | 146    | 2                |
| 9   | **Email / Notifications Settings**                                      | 13271–13478 | 208    | 3                |
| 10  | **Analytics**                                                           | 13479–13957 | 479    | 5                |
| 11  | **System Info / ML Models**                                             | 13958–14222 | 265    | 3                |
| 12  | **Voice Alerts**                                                        | 14223–14380 | 158    | 2                |
| 13  | **Utilities (Pause, Chat, Theme, Shortcuts, Visibility)**               | 14381–15203 | 823    | 8+clientside     |
| 14  | **WebSocket Background Thread**                                         | 15204–15354 | 151    | (thread+socket)  |
| 15  | **Authentication & Login**                                              | 15355–15855 | 501    | 5                |
| 16  | **2FA / TOTP**                                                          | 15856–16177 | 322    | 7                |
| 17  | **Password Recovery & Toggles**                                         | 16178–16512 | 335    | 8                |
| 18  | **Registration & Validation**                                           | 16513–17150 | 638    | 8                |
| 19  | **Email Verification (Flask route)**                                    | 17151–17543 | 393    | 1 (route)        |
| 20  | **User Management (Admin)**                                             | 17544–17983 | 440    | 6                |
| 21  | **Profile & Admin UI**                                                  | 17984–18173 | 190    | 6                |
| 22  | **Biometric / WebAuthn Security**                                       | 18174–18479 | 306    | 4                |
| 23  | **Device Management & Preferences**                                     | 18480–18830 | 351    | 4                |
| 24  | **Device Bulk Operations**                                              | 18831–19413 | 583    | 8                |
| 25  | **Device Details View**                                                 | 19414–19890 | 477    | 3                |
| 26  | **IoT-Specific Features (Protocol/Privacy/SmartHome/Firmware)**         | 19891–21388 | 1498   | 22               |
| 27  | **Main (modal toggles & card modals)**                                  | 21389–22095 | 707    | 14               |
| 28  | **Timeline Visualization Modal**                                        | 22096–22499 | 404    | 6                |
| 29  | **Protocol Deep-Dive Modal**                                            | 22500–22961 | 462    | 5                |
| 30  | **Threat Intelligence Modal**                                           | 22962–23587 | 626    | 5                |
| 31  | **Privacy & SmartHome Modals**                                          | 23588–23707 | 120    | 4                |
| 32  | **Network Segmentation Modal**                                          | 23708–24297 | 590    | 6                |
| 33  | **Firmware Modal (deep)**                                               | 24298–24393 | 96     | 3                |
| 34  | **Education / Firmware Settings / Privacy Export**                      | 24393–24647 | 255    | 5                |
| 35  | **SmartHome/Firmware Refresh**                                          | 24647–24807 | 161    | 2                |
| 36  | **Model Import/Export**                                                 | 24808–25003 | 196    | 2                |
| 37  | **System Refresh & Device Import**                                      | 25004–25136 | 133    | 2                |
| 38  | **Email History & Templates**                                           | 25137–25369 | 233    | 3                |
| 39  | **Export (Devices & Security Report)**                                  | 25370–25513 | 144    | 2                |
| 40  | **Automation Rules**                                                    | 25514–25717 | 204    | 3                |
| 41  | **Log Download**                                                        | 25718–25828 | 111    | 1                |
| 42  | **Threat Map & Risk Heatmap Modals**                                    | 25829–26432 | 604    | 7                |
| 43  | **Forensic Timeline Modal**                                             | 26433–27108 | 676    | 5                |
| 44  | **Compliance Modal**                                                    | 27109–27337 | 229    | 2                |
| 45  | **Automated Response Modal**                                            | 27338–27702 | 365    | 5                |
| 46  | **Vulnerability Scanner Modal**                                         | 27703–28215 | 513    | 5                |
| 47  | **API Integration Hub Modal**                                           | 28216–29202 | 987    | 12               |
| 48  | **Benchmarking Modal**                                                  | 29203–29645 | 443    | 4                |
| 49  | **Network Performance Analytics Modal**                                 | 29646–30188 | 543    | 4                |
| 50  | **Sustainability Dashboard**                                            | 30189–30544 | 356    | 4                |
| 51  | **Geographic Threat Map Cards**                                         | 30545–31041 | 497    | 3                |
| 52  | **Risk Heatmap Cards**                                                  | 31042–31335 | 294    | 3                |
| 53  | **Traffic Flow & Attack Surface Cards**                                 | 31336–31537 | 202    | 2                |
| 54  | **Compliance Dashboard Card**                                           | 31538–31771 | 234    | 1                |
| 55  | **Automated Response Dashboard Card**                                   | 31772–31905 | 134    | 1                |
| 56  | **Vulnerability Scanner Card**                                          | 31906–32082 | 177    | 1                |
| 57  | **API Integration Hub Card**                                            | 32083–32327 | 245    | 1                |
| 58  | **Benchmarking Card**                                                   | 32328–32428 | 101    | 1                |
| 59  | **Performance Analytics Card + Threat Forecast**                        | 32429–32631 | 203    | 2                |
| 60  | **Stats Cards (Network/Security/Activity/Recommendations/Threat Feed)** | 32632–32942 | 311    | 6                |
| 61  | **Quick Actions**                                                       | 32943–33936 | 994    | 16               |
| 62  | **Quick Settings**                                                      | 33937–34997 | 1061   | 20+              |
| 63  | **Customizable Widget Dashboard**                                       | 34998–35192 | 195    | 6                |
| 64  | **Spotlight Search**                                                    | 35193–35563 | 371    | 4+clientside     |
| 65  | **Masonry Layout (Category/View)**                                      | 35564–35679 | 116    | 1+clientside     |
| 66  | **Advanced Reporting & Analytics**                                      | 35680–36498 | 819    | 8                |
| 67  | **Report Scheduler**                                                    | 36499–37296 | 798    | 6                |
| 68  | **Privacy Dashboard**                                                   | 37297–37601 | 305    | 2                |
| 69  | **Role-Based Dashboard Templates**                                      | 37602–37881 | 280    | 4+clientside     |
| 70  | **Emergency Mode**                                                      | 37882–38209 | 328    | 4+clientside     |
| 71  | **WebAuthn/Passkey API Endpoints**                                      | 38210–38271 | 62     | 2 (Flask routes) |
| 72  | **Cross-Chart Filtering**                                               | 38272–38339 | 68     | 3                |
| 73  | **Advanced Visualization (Attack Path & Sunburst)**                     | 38340–38597 | 258    | 2                |
| 74  | **Main Entry Point**                                                    | 38598–38604 | 7      | 0                |

---

## DETAILED CALLBACK MAP BY CATEGORY

---

### 1. OVERVIEW / HEADER & NOTIFICATIONS — Lines 11168–11625

| Line  | Function                          | Outputs                                                                                                       | Inputs                                                                 | Description                                              |
| ----- | --------------------------------- | ------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------- | -------------------------------------------------------- |
| 11244 | `get_latest_alerts_content()`     | _(helper)_                                                                                                    | —                                                                      | Helper: builds notification dropdown content             |
| 11293 | `update_security_score_dashboard` | `security-score-dashboard.children`                                                                           | `security-score-interval.n_intervals`, `refresh-security-btn.n_clicks` | Updates security score ring, threat gauge, category bars |
| 11494 | `update_system_metrics`           | `cpu-metric.children`, `ram-metric.children`                                                                  | `ws-data-store.data`                                                   | CPU/RAM live metrics from WebSocket                      |
| 11510 | `update_header_stats`             | `device-count-stat.children`, `alert-count-stat.children`, `bandwidth-stat.children`, `threats-stat.children` | `ws-data-store.data`                                                   | Header bar stats                                         |
| 11533 | `update_notifications_from_ws`    | `notification-content.children`, `notification-bell-badge.children`                                           | `ws-data-store.data`                                                   | Live notification list                                   |
| 11553 | `toggle_notification_drawer`      | `notification-drawer.is_open`                                                                                 | `notification-bell-button.n_clicks`, `notification-drawer.is_open`     | Toggle notification panel                                |
| 11574 | _(clientside)_                    | `notification-bell-button.n_clicks`                                                                           | `ws-data-store.data`                                                   | Clientside: toast notification for new alerts            |

---

### 2. NETWORK GRAPH — Lines 11626–11876

| Line  | Function                  | Outputs                                                | Inputs                                               | Description                     |
| ----- | ------------------------- | ------------------------------------------------------ | ---------------------------------------------------- | ------------------------------- |
| 11630 | `update_network_graph`    | `network-graph.figure`                                 | `ws-data-store.data`                                 | 2D network topology graph       |
| 11643 | `toggle_graph_view`       | `2d-graph-container.style`, `3d-graph-container.style` | `graph-view-toggle.value`                            | Toggle 2D/3D view               |
| 11653 | `update_network_graph_3d` | `network-graph-3d.figure`                              | `ws-data-store.data`                                 | 3D network topology scatter     |
| 11811 | `update_traffic_timeline` | `traffic-timeline.figure`                              | `ws-data-store.data`                                 | Traffic volume over time        |
| 11834 | `update_protocol_pie`     | `protocol-pie.figure`                                  | `ws-data-store.data`, `protocol-device-filter.value` | Protocol distribution pie chart |

---

### 3. DEVICES (Overview Panel) — Lines 11877–12066

| Line  | Function                        | Outputs                           | Inputs                               | Description                     |
| ----- | ------------------------------- | --------------------------------- | ------------------------------------ | ------------------------------- |
| 11878 | `update_devices_status_compact` | `devices-status-compact.children` | `ws-data-store.data`                 | Compact device status cards     |
| 11944 | `update_active_devices_list`    | `active-devices-list.children`    | `ws-data-store.data`                 | Active device list with details |
| 12024 | `toggle_device_trust`           | `trust-switch-output.children`    | `trust-switch-{ALL}.value` (pattern) | Toggle trust status per device  |
| 12067 | _(section: Toast Detail Modal)_ | —                                 | —                                    | —                               |

---

### 4. TOAST / NOTIFICATION HISTORY — Lines 12067–12622

| Line  | Function                     | Outputs                                                                                  | Inputs                                                                                                                      | Description                     |
| ----- | ---------------------------- | ---------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------- | ------------------------------- |
| 12071 | `handle_toast_detail_modal`  | `toast-detail-modal.is_open`, `toast-detail-modal-body.children`                         | `{type:toast-detail-btn}.n_clicks` (ALL), `{type:history-detail-btn}.n_clicks` (ALL), `close-toast-detail.n_clicks`         | Show toast detail modal         |
| 12193 | `toggle_toast_history_modal` | `toast-history-modal.is_open`                                                            | `open-toast-history.n_clicks`                                                                                               | Open history modal              |
| 12289 | `update_toast_history_list`  | `toast-history-list.children`                                                            | `toast-history-category.value`, `toast-history-type.value`                                                                  | Filter & display history list   |
| 12384 | `clear_toast_history`        | `toast-history-list.children`                                                            | `clear-toast-history.n_clicks`                                                                                              | Clear all history               |
| 12443 | `show_block_device_modal`    | `block-device-modal.is_open`, `block-device-ip.children`, `block-device-action.children` | `{type:block-device-btn}.n_clicks` (ALL)                                                                                    | Block device confirmation modal |
| 12497 | `toggle_device_block`        | `block-result-output.children`, `block-device-modal.is_open`                             | `confirm-block-device.n_clicks`, `cancel-block-device.n_clicks`, `block-device-ip.children`, `block-device-action.children` | Execute block/unblock           |

---

### 5. ALERTS — Lines 12623–12894

| Line  | Function                     | Outputs                                                       | Inputs                                                                                | Description                     |
| ----- | ---------------------------- | ------------------------------------------------------------- | ------------------------------------------------------------------------------------- | ------------------------------- |
| 12626 | `store_alerts_data`          | `alerts-data-store.data`                                      | `ws-data-store.data`, `refresh-interval.n_intervals`                                  | Store latest alerts data        |
| 12681 | `update_alerts_compact`      | `alerts-container-compact.children`                           | `alerts-data-store.data`, `alert-severity-filter.value`, `show-reviewed-alerts.value` | Render alert cards with filters |
| 12776 | `toggle_alert_details`       | `alert-detail-modal.is_open`, `alert-detail-content.children` | `{type:alert-detail-btn}.n_clicks` (ALL), `close-alert-detail.n_clicks`               | Alert detail modal              |
| 12818 | `acknowledge_alert_callback` | `alert-ack-output.children`                                   | `acknowledge-alert-btn.n_clicks`, `alert-detail-id.children`                          | Acknowledge/review alert        |
| 12880 | `update_alert_filter`        | `alert-filter-output.children`                                | `alert-severity-filter.value`, `show-reviewed-alerts.value`                           | Alert filter feedback           |

---

### 6. AI-POWERED FEATURES — Lines 12895–13046

| Line  | Function             | Outputs                      | Inputs                                                   | Description                   |
| ----- | -------------------- | ---------------------------- | -------------------------------------------------------- | ----------------------------- |
| 12898 | `ask_ai_about_alert` | `ai-alert-analysis.children` | `ai-analyze-btn.n_clicks`, `alert-detail-title.children` | AI analysis of selected alert |

---

### 7. ONBOARDING — Lines 13047–13124

| Line  | Function                    | Outputs                                                    | Inputs                                                                         | Description                |
| ----- | --------------------------- | ---------------------------------------------------------- | ------------------------------------------------------------------------------ | -------------------------- |
| 13050 | `launch_onboarding_modal`   | `onboarding-modal.is_open`, `onboarding-store.data`        | `url.pathname`, `restart-tour-button.n_clicks`, `onboarding-store.data`        | Launch/restart guided tour |
| 13078 | `update_onboarding_content` | `onboarding-content.children`, `onboarding-progress.value` | `onboarding-step.data`                                                         | Render current tour step   |
| 13100 | `update_onboarding_step`    | `onboarding-step.data`, `onboarding-modal.is_open`         | `onboarding-next.n_clicks`, `onboarding-prev.n_clicks`, `onboarding-step.data` | Navigate tour steps        |

---

### 8. LOCKDOWN MODE — Lines 13125–13270

| Line  | Function                       | Outputs                                             | Inputs                                                                                                                           | Description                 |
| ----- | ------------------------------ | --------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------- | --------------------------- |
| 13132 | `toggle_lockdown_modal`        | `lockdown-modal.is_open`                            | `lockdown-switch.value`, `cancel-lockdown.n_clicks`, `confirm-lockdown.n_clicks`, `lockdown-modal.is_open`, `ws-data-store.data` | Lockdown confirmation modal |
| 13165 | `handle_lockdown_confirmation` | `lockdown-switch.value`, `lockdown-status.children` | `cancel-lockdown.n_clicks`, `confirm-lockdown.n_clicks`, `lockdown-switch.value`                                                 | Execute lockdown toggle     |

---

### 9. EMAIL / NOTIFICATION SETTINGS — Lines 13271–13478

| Line  | Function              | Outputs                                                                                 | Inputs                                                                                | Description             |
| ----- | --------------------- | --------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------- | ----------------------- |
| 13274 | `load_email_settings` | `email-alerts-enabled.value`, `email-recipient.value`, `email-settings-status.children` | `url.pathname`                                                                        | Load saved email config |
| 13309 | `save_email_settings` | `email-settings-status.children`                                                        | `save-email-settings.n_clicks`, `email-alerts-enabled.value`, `email-recipient.value` | Save email config       |
| 13369 | `send_test_email`     | `test-email-status.children`                                                            | `test-email-btn.n_clicks`, `email-recipient.value`                                    | Send test email         |

---

### 10. ANALYTICS — Lines 13479–13957

| Line  | Function                         | Outputs                            | Inputs                                                  | Description                  |
| ----- | -------------------------------- | ---------------------------------- | ------------------------------------------------------- | ---------------------------- |
| 13483 | `update_alert_timeline`          | `alert-timeline.figure`            | `ws-data-store.data`, `analytics-severity-filter.value` | Alert timeline chart         |
| 13531 | `update_anomaly_distribution`    | `anomaly-distribution.figure`      | `ws-data-store.data`                                    | Anomaly distribution chart   |
| 13549 | `update_bandwidth_chart`         | `bandwidth-chart.figure`           | `ws-data-store.data`                                    | Bandwidth usage chart        |
| 13568 | `update_device_heatmap`          | `device-heatmap.figure`            | `ws-data-store.data`, `heatmap-device-filter.value`     | Device activity heatmap      |
| 13615 | `update_security_summary_report` | `security-summary-report.children` | `ws-data-store.data`                                    | Security summary text report |

---

### 11. SYSTEM INFO / ML MODELS — Lines 13958–14222

| Line  | Function                  | Outputs                         | Inputs               | Description                           |
| ----- | ------------------------- | ------------------------------- | -------------------- | ------------------------------------- |
| 13959 | `update_system_info`      | `system-info-content.children`  | `ws-data-store.data` | CPU, RAM, disk, network, process info |
| 14153 | `update_model_info`       | `model-info-content.children`   | `ws-data-store.data` | ML model status display               |
| 14165 | `update_model_comparison` | `model-comparison-chart.figure` | `ws-data-store.data` | Model accuracy comparison chart       |

---

### 12. VOICE ALERTS — Lines 14223–14380

| Line  | Function                                | Outputs                       | Inputs                                                                               | Description                            |
| ----- | --------------------------------------- | ----------------------------- | ------------------------------------------------------------------------------------ | -------------------------------------- |
| 14293 | `sync_voice_alert_checklist_from_store` | `voice-alert-checklist.value` | `voice-alert-store.data`, `quick-settings-store.data`, `voice-alert-checklist.value` | Sync voice alert checkboxes with store |
| 14340 | `toggle_voice_alerts`                   | `voice-alert-store.data`      | `toggle-voice-btn.n_clicks`, `voice-alert-store.data`                                | Enable/disable voice alerts            |

---

### 13. UTILITIES — Lines 14381–15203

| Line  | Function                  | Outputs                                                        | Inputs                                                                                                          | Description                                          |
| ----- | ------------------------- | -------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------- |
| 14383 | `toggle_pause_monitoring` | `pause-button.children`, `refresh-interval.disabled`           | `pause-button.n_clicks`, `pause-button.children`                                                                | Pause/resume live monitoring                         |
| 14421 | `toggle_chat_modal`       | `chat-modal.is_open`, `chat-display.children`                  | `open-chat-button.n_clicks`, `chat-modal.is_open`, `chat-store.data`                                            | Open AI chat assistant                               |
| 14548 | `clear_chat_history`      | `chat-store.data`, `chat-display.children`                     | `clear-chat-btn.n_clicks`                                                                                       | Clear chat history                                   |
| 14596 | `handle_chat_message`     | `chat-store.data`, `chat-display.children`, `chat-input.value` | `chat-send-button.n_clicks`, `chat-input.n_submit`, `chat-input.value`, `chat-store.data`, `ws-data-store.data` | Process chat message & AI response                   |
| 14968 | _(clientside)_            | `keyboard-shortcut-store.data`                                 | `theme-store.data`                                                                                              | Copy message to clipboard                            |
| 14980 | `update_theme_store`      | `theme-store.data`                                             | `theme-selector.value`                                                                                          | Update theme selection                               |
| 14991 | _(clientside)_            | `keyboard-shortcut-store.id`                                   | `url.pathname`                                                                                                  | Keyboard shortcuts handler (N/D/A/P/H/C/S/F/U/T/Esc) |
| 15098 | _(clientside)_            | `chat-input.id`                                                | `chat-modal.is_open`                                                                                            | Chat input Enter key handler                         |
| 15114 | _(clientside)_            | `widget-visibility-dummy.children`                             | `widget-preferences.data`                                                                                       | Show/hide dashboard widget sections                  |
| 15144 | _(clientside)_            | `page-visibility-store.data`                                   | `page-visibility-store.data`                                                                                    | Auto-pause refresh when tab hidden                   |

---

### 14. WEBSOCKET BACKGROUND THREAD — Lines 15204–15354

| Line  | Function              | Outputs            | Inputs | Description                                                    |
| ----- | --------------------- | ------------------ | ------ | -------------------------------------------------------------- |
| 15210 | `background_thread()` | _(emits socketio)_ | —      | Main data collection loop: devices, alerts, ML, system metrics |
| 15343 | `test_connect(auth)`  | _(socketio event)_ | —      | WebSocket connect handler                                      |
| 15351 | `test_disconnect()`   | _(socketio event)_ | —      | WebSocket disconnect handler                                   |

---

### 15. AUTHENTICATION & LOGIN — Lines 15355–15855

| Line  | Function                    | Outputs                                            | Inputs                                                        | Description                                   |
| ----- | --------------------------- | -------------------------------------------------- | ------------------------------------------------------------- | --------------------------------------------- |
| 15359 | `display_page`              | `page-content.children`, `navbar-container.style`  | `url.pathname`                                                | URL routing: login/register/dashboard/verify  |
| 15408 | `redirect_after_auth_toast` | `url.pathname`                                     | `auth-notification-store.data`                                | Redirect to dashboard after successful auth   |
| 15432 | `clear_form_inputs`         | `login-username.value`, `login-password.value` ×2  | `url.pathname`, `auth-notification-store.data`                | Clear form fields on page change              |
| 15450 | `show_auth_notification`    | Toast notifications                                | `auth-notification-store.data`                                | Show login/register success/error toasts      |
| 15521 | `handle_login`              | `auth-notification-store.data`, `login-state.data` | `login-button.n_clicks`, `login-password.n_submit`, inputs... | Full login flow with TOTP/backup code support |

---

### 16. 2FA / TOTP — Lines 15856–16177

| Line  | Function                 | Outputs                                                                               | Inputs                                                      | Description                |
| ----- | ------------------------ | ------------------------------------------------------------------------------------- | ----------------------------------------------------------- | -------------------------- |
| 15862 | `load_totp_status`       | `totp-status-section.children`                                                        | `profile-tabs.active_tab`, `profile-edit-modal.is_open`     | Load current 2FA status    |
| 15912 | `enable_totp_setup`      | `totp-setup-section.children`, `totp-setup-data.data`                                 | `enable-totp-btn.n_clicks`                                  | Generate QR code & secret  |
| 15973 | `verify_and_enable_totp` | `totp-verify-result.children`, `totp-status-section.children`, `totp-setup-data.data` | `verify-totp-btn.n_clicks`, `totp-verify-code.value`        | Verify TOTP code & enable  |
| 16036 | `cancel_totp_setup`      | `totp-setup-section.children`, `totp-setup-data.data`                                 | `cancel-totp-setup.n_clicks`                                | Cancel TOTP setup          |
| 16053 | `disable_totp`           | `totp-status-section.children`                                                        | `disable-totp-btn.n_clicks`                                 | Disable 2FA                |
| 16109 | `copy_totp_secret`       | `copy-totp-feedback.children`                                                         | `copy-totp-secret.n_clicks`, `totp-secret-display.children` | Copy secret to clipboard   |
| 16129 | `download_backup_codes`  | `Download` component                                                                  | `download-backup-codes.n_clicks`, `totp-setup-data.data`    | Download backup codes file |

---

### 17. PASSWORD RECOVERY & TOGGLES — Lines 16178–16512

| Line  | Function                           | Outputs                          | Inputs                                                   | Description                       |
| ----- | ---------------------------------- | -------------------------------- | -------------------------------------------------------- | --------------------------------- |
| 16172 | `toggle_forgot_password_modal`     | `forgot-password-modal.is_open`  | link/cancel/submit clicks, is_open                       | Forgot password modal toggle      |
| 16201 | `send_reset_email`                 | `reset-password-result.children` | `submit-reset-email.n_clicks`, `reset-email-input.value` | Send password reset email         |
| 16259 | `send_password_reset_email`        | _(helper function)_              | —                                                        | Actually sends the email via SMTP |
| 16421 | `toggle_login_password`            | `login-password.type`            | `toggle-login-password.n_clicks`                         | Show/hide login password          |
| 16435 | `toggle_register_password`         | `register-password.type`         | `toggle-register-password.n_clicks`                      | Show/hide register password       |
| 16449 | `toggle_register_confirm_password` | `register-password-confirm.type` | `toggle-register-confirm.n_clicks`                       | Show/hide confirm password        |
| 16464 | `toggle_profile_current_password`  | `profile-current-password.type`  | `toggle-profile-current-password.n_clicks`               | Show/hide profile current pw      |
| 16478 | `toggle_profile_new_password`      | `profile-new-password.type`      | `toggle-profile-new-password.n_clicks`                   | Show/hide profile new pw          |
| 16492 | `toggle_profile_confirm_password`  | `profile-confirm-password.type`  | `toggle-profile-confirm-password.n_clicks`               | Show/hide profile confirm pw      |

---

### 18. REGISTRATION & VALIDATION — Lines 16513–17150

| Line  | Function                                    | Outputs                                                                  | Inputs                                                                                    | Description                          |
| ----- | ------------------------------------------- | ------------------------------------------------------------------------ | ----------------------------------------------------------------------------------------- | ------------------------------------ |
| 16506 | `validate_email_realtime`                   | `register-email-feedback.children`, `register-email.valid/invalid`       | `register-email.value`                                                                    | Real-time email validation           |
| 16568 | `validate_username_realtime`                | `register-username-feedback.children`, `register-username.valid/invalid` | `register-username.value`                                                                 | Real-time username validation        |
| 16619 | `validate_password_strength`                | `password-strength-bar.value/color/children`                             | `register-password.value`                                                                 | Password strength meter              |
| 16687 | `send_verification_email`                   | _(helper)_                                                               | —                                                                                         | Send verification code via SMTP      |
| 16735 | `send_verification_code`                    | `verification-code-sent.data`, `email-verify-status.children`            | `send-verification-btn.n_clicks`, `register-email.value`                                  | Trigger email verification code      |
| 16785 | `verify_code`                               | `email-verified-store.data`, `email-verify-status.children`              | `email-verify-code.value`, `register-email.value`, `verification-code-sent.data`          | Verify entered code                  |
| 16830 | `autofill_verification_code`                | `email-verify-code.value`                                                | `url.search`                                                                              | Auto-fill code from URL param        |
| 16867 | `update_password_feedback_and_button_state` | `password-match-feedback.children`, `register-button.disabled`           | `register-password.value`, `register-password-confirm.value`, `email-verified-store.data` | Password match check + button enable |
| 16982 | `handle_registration`                       | `auth-notification-store.data`                                           | `register-button.n_clicks`, all registration fields                                       | Full registration handler            |

---

### 19. EMAIL VERIFICATION (Flask Route) — Lines 17151–17543

| Line  | Function       | Outputs                         | Inputs             | Description                             |
| ----- | -------------- | ------------------------------- | ------------------ | --------------------------------------- |
| 17151 | `verify_email` | _(Flask route `/verify-email`)_ | `code` query param | Server-side email verification endpoint |

---

### 20. USER MANAGEMENT (Admin) — Lines 17544–17983

| Line  | Function                 | Outputs                                                            | Inputs                                                                                                             | Description                  |
| ----- | ------------------------ | ------------------------------------------------------------------ | ------------------------------------------------------------------------------------------------------------------ | ---------------------------- |
| 17537 | `display_user_list`      | `user-list-container.children`                                     | `user-management-modal.is_open`, `refresh-users-btn.n_clicks`, `user-search-input.value`, `user-role-filter.value` | User list with search/filter |
| 17655 | `display_activity_log`   | `activity-log-container.children`                                  | `user-mgmt-tabs.active_tab`, `refresh-activity-btn.n_clicks`                                                       | Activity/audit log display   |
| 17729 | `create_new_user`        | `create-user-result.children`                                      | `create-user-btn.n_clicks`, username/email/password/role                                                           | Admin create user            |
| 17835 | `show_delete_user_modal` | `delete-user-confirm-modal.is_open`, `delete-user-id-store.data`   | `{type:delete-user-btn}.n_clicks` (ALL), is_open, stored_id                                                        | Delete user confirmation     |
| 17870 | `delete_user_confirmed`  | `delete-user-result.children`, `delete-user-confirm-modal.is_open` | confirm/cancel clicks, user_id                                                                                     | Execute user deletion        |

---

### 21. PROFILE & ADMIN UI — Lines 17984–18173

| Line  | Function                       | Outputs                                                   | Inputs                                                        | Description                          |
| ----- | ------------------------------ | --------------------------------------------------------- | ------------------------------------------------------------- | ------------------------------------ |
| 17977 | `update_current_user_display`  | `current-user-display.children`                           | `url.pathname`                                                | Show logged-in username              |
| 17996 | `toggle_admin_menu_items`      | `admin-menu-item.style`                                   | `url.pathname`                                                | Show/hide admin menu for admin users |
| 18010 | `toggle_profile_edit_modal`    | `profile-edit-modal.is_open`                              | open/close clicks, is_open                                    | Profile edit modal toggle            |
| 18028 | `populate_profile_data`        | `profile-edit-username.value`, `profile-edit-email.value` | `profile-edit-modal.is_open`                                  | Load user profile data               |
| 18044 | `open_user_management_modal`   | `user-management-modal.is_open`                           | `open-user-management.n_clicks`, is_open                      | Open user management modal           |
| 18062 | `update_profile_info`          | `profile-update-result.children`                          | `save-profile-btn.n_clicks`, username, email                  | Save profile changes                 |
| 18107 | `change_password_from_profile` | `password-change-result.children`                         | `change-password-btn.n_clicks`, current/new/confirm passwords | Change password                      |

---

### 22. BIOMETRIC / WEBAUTHN SECURITY — Lines 18174–18479

| Line  | Function                             | Outputs                                                                         | Inputs                                             | Description                   |
| ----- | ------------------------------------ | ------------------------------------------------------------------------------- | -------------------------------------------------- | ----------------------------- |
| 18178 | `manage_biometric_section`           | `biometric-devices-section.children`                                            | `profile-edit-modal.is_open`                       | Load registered passkeys list |
| 18391 | `open_biometric_remove_confirmation` | `confirm-remove-biometric-modal.is_open`, `biometric-credential-to-remove.data` | `{type:remove-biometric-btn}.n_clicks` (ALL)       | Remove passkey confirmation   |
| 18423 | `cancel_biometric_removal`           | `confirm-remove-biometric-modal.is_open`                                        | `cancel-remove-biometric.n_clicks`                 | Cancel passkey removal        |
| 18439 | `confirm_remove_biometric_device`    | `biometric-devices-section.children`, modal is_open                             | `confirm-remove-biometric.n_clicks`, credential_id | Execute passkey removal       |

---

### 23. DEVICE MANAGEMENT & PREFERENCES — Lines 18480–18830

| Line  | Function                       | Outputs                                                                                          | Inputs                                                            | Description                         |
| ----- | ------------------------------ | ------------------------------------------------------------------------------------------------ | ----------------------------------------------------------------- | ----------------------------------- |
| 18485 | `update_device_counts`         | `total-devices-count.children`, `trusted/blocked/unknown-count.children`                         | `device-mgmt-modal.is_open`                                       | Device count badges                 |
| 18518 | `load_device_management_table` | `device-management-table.children`, `device-page-info.children`, `device-selected-info.children` | modal is_open, active_tab, clicks, search, filter, page, selected | Paginated device table with filters |
| 18752 | `save_preferences`             | `preferences-save-result.children`                                                               | `save-preferences-btn.n_clicks`, all preference inputs            | Save user preferences               |
| 18824 | `update_iot_security_widget`   | `iot-security-widget.children`                                                                   | `ws-data-store.data`                                              | IoT security overview widget        |

---

### 24. DEVICE BULK OPERATIONS — Lines 18831–19413

| Line  | Function                   | Outputs                                        | Inputs                                            | Description                     |
| ----- | -------------------------- | ---------------------------------------------- | ------------------------------------------------- | ------------------------------- |
| 18911 | `handle_bulk_operations`   | `bulk-operation-result.children`               | trust/block/delete clicks, checkbox values/ids    | Execute bulk trust/block/delete |
| 18988 | `toggle_bulk_delete_modal` | `bulk-delete-confirm-modal.is_open`            | delete/cancel/confirm clicks, is_open, checkboxes | Bulk delete confirmation        |
| 19017 | `bulk_delete_confirmed`    | `bulk-delete-result.children`, modal is_open   | confirm clicks, checkboxes                        | Execute bulk deletion           |
| 19118 | `bulk_trust_all_unknown`   | `bulk-trust-result.children`                   | `bulk-trust-all-unknown.n_clicks`                 | Trust all unknown devices       |
| 19202 | `bulk_block_suspicious`    | `bulk-block-result.children`                   | `bulk-block-suspicious.n_clicks`                  | Block all suspicious devices    |
| 19293 | `toggle_bulk_buttons`      | `bulk-trust-btn/block-btn/delete-btn.disabled` | checkbox values/ids                               | Enable/disable bulk buttons     |
| 19331 | `select_all_devices`       | `{type:device-checkbox}.value` (ALL)           | `select-all-devices.value`                        | Select/deselect all checkboxes  |
| 19348 | `display_selected_devices` | `selected-devices-display.children`            | `selected-devices-store.data`                     | Show selected device count      |

---

### 25. DEVICE DETAILS VIEW — Lines 19414–19890

| Line  | Function                     | Outputs                                                         | Inputs                                                      | Description                  |
| ----- | ---------------------------- | --------------------------------------------------------------- | ----------------------------------------------------------- | ---------------------------- |
| 19407 | `show_device_details_in_tab` | `device-mgmt-tabs.active_tab`, `device-detail-content.children` | `{type:device-detail-btn}.n_clicks` (ALL), ids, current_tab | Show device details tab      |
| 19751 | `save_device_details`        | `device-save-result.children`                                   | save clicks, trust/kids/name/type/location values           | Save device detail edits     |
| 19876 | `back_to_devices_list`       | `device-mgmt-tabs.active_tab`                                   | `back-to-devices.n_clicks`                                  | Navigate back to device list |

---

### 26. IoT-SPECIFIC FEATURES — Lines 19891–21388

| Line  | Function                           | Outputs                                                            | Inputs                                           | Description                     |
| ----- | ---------------------------------- | ------------------------------------------------------------------ | ------------------------------------------------ | ------------------------------- |
| 19891 | `update_protocol_stats`            | `mqtt-stat.children`, `coap-stat.children`, `zigbee-stat.children` | `privacy-interval.n_intervals`                   | MQTT/CoAP/Zigbee protocol stats |
| 19933 | `update_threat_stats`              | `botnet-stat.children`, `ddos-stat.children`, `mitm-stat.children` | `privacy-interval.n_intervals`                   | Threat type counters            |
| 19979 | `update_privacy_score`             | `privacy-score-value.children`, `privacy-score-bar.*`              | `privacy-interval.n_intervals`                   | Privacy score gauge             |
| 20031 | `update_privacy_modal_score`       | privacy modal content                                              | `privacy-modal.is_open`                          | Privacy modal detailed view     |
| 20134 | `update_cloud_upload_stats`        | cloud upload content                                               | `privacy-modal.is_open`                          | Cloud upload statistics         |
| 20194 | `update_tracker_stats`             | tracker detection content                                          | `privacy-modal.is_open`, refresh, search, filter | Tracker detection list          |
| 20304 | `update_dataflow_stats`            | data flow content                                                  | `privacy-modal.is_open`                          | Data flow diagram               |
| 20380 | `update_smarthome_hubs`            | hub list content                                                   | `smarthome-modal.is_open`                        | Smart home hub detection        |
| 20457 | `update_smarthome_ecosystems`      | ecosystem content                                                  | `smarthome-modal.is_open`                        | Smart home ecosystem analysis   |
| 20532 | `update_smarthome_rooms`           | room content                                                       | `smarthome-modal.is_open`                        | Room-by-room device mapping     |
| 20611 | `update_smarthome_automations`     | automation content                                                 | `smarthome-modal.is_open`                        | Automation detection            |
| 20635 | `update_firmware_stats`            | firmware stats content                                             | `firmware-modal.is_open`                         | Firmware overview stats         |
| 20690 | `update_eol_devices`               | EOL device list                                                    | `firmware-modal.is_open`                         | End-of-life device list         |
| 20781 | `open_replace_modal`               | replace modal is_open                                              | `{type:replace-btn}.n_clicks`, is_open           | Device replacement modal        |
| 20811 | `replace_device`                   | result content                                                     | `confirm-replace.n_clicks`, eol/new IPs          | Execute device replacement      |
| 20832 | `cancel_replacement`               | modal is_open                                                      | `cancel-replace.n_clicks`                        | Cancel replacement              |
| 20845 | `update_firmware_updates_list`     | firmware update list                                               | `firmware-modal.is_open`                         | Available firmware updates      |
| 20918 | `update_cloud_uploads_section`     | cloud upload section                                               | `firmware-modal.is_open`                         | Cloud upload volume section     |
| 20976 | `update_tracker_detection_section` | tracker section                                                    | `firmware-modal.is_open`, scan click             | Tracker detection section       |
| 21090 | `update_privacy_score_metric`      | privacy metric card                                                | `privacy-interval.n_intervals`                   | Privacy metric stat card        |
| 21122 | `update_network_health`            | network health card                                                | `privacy-interval.n_intervals`                   | Network health metric card      |
| 21174 | `update_firmware_status`           | firmware status card                                               | `privacy-interval.n_intervals`                   | Firmware status metric card     |
| 21233 | `update_threat_scenarios`          | threat scenarios card                                              | `privacy-interval.n_intervals`                   | IoT threat scenario card        |
| 21296 | `update_security_tips`             | security tips card                                                 | `privacy-interval.n_intervals`                   | Rotating security tips          |

---

### 27. MAIN (Modal Toggles & Card Modals) — Lines 21389–22095

| Line  | Function                        | Outputs                                    | Inputs                             | Description                    |
| ----- | ------------------------------- | ------------------------------------------ | ---------------------------------- | ------------------------------ |
| 21487 | `toggle_analytics_modal`        | `analytics-modal.is_open`                  | open/close clicks                  | Analytics modal toggle         |
| 21499 | `update_analytics_timestamp`    | `analytics-last-updated.children`          | is_open, refresh                   | Analytics modal timestamp      |
| 21532 | `toggle_system_modal`           | `system-modal.is_open`                     | open/close clicks                  | System info modal toggle       |
| 21552 | `update_system_timestamp`       | `system-last-updated.children`             | is_open, refresh                   | System modal timestamp         |
| 21587 | `update_performance_timestamp`  | `performance-last-updated.children`        | is_open, refresh                   | Performance modal timestamp    |
| 21622 | `update_threat_map_timestamp`   | `threat-map-last-updated.children`         | is_open, refresh                   | Threat map timestamp           |
| 21657 | `update_risk_heatmap_timestamp` | `risk-heatmap-last-updated.children`       | is_open, refresh                   | Risk heatmap timestamp         |
| 21689 | `update_model_accuracy_display` | `model-accuracy-content.children`          | is_open                            | ML model accuracy chart        |
| 21781 | `toggle_email_modal`            | `email-modal.is_open`                      | open/close clicks                  | Email settings modal toggle    |
| 21798 | `toggle_firewall_modal`         | `firewall-modal.is_open`                   | n_clicks, is_open                  | Firewall modal toggle          |
| 21809 | `handle_firewall_modal_actions` | `firewall-content.children`, modal is_open | save/cancel clicks, lockdown state | Firewall rules management      |
| 21897 | `toggle_user_modal`             | `user-modal.is_open`                       | open/close clicks                  | User modal toggle              |
| 21915 | `toggle_device_mgmt_modal`      | `device-mgmt-modal.is_open`                | open/close clicks                  | Device management modal toggle |
| 21935 | `update_device_mgmt_timestamp`  | `device-mgmt-last-updated.children`        | is_open, refresh                   | Device mgmt timestamp          |
| 21968 | `toggle_preferences_modal`      | `preferences-modal.is_open`                | open/cancel clicks                 | Preferences modal toggle       |
| 21995 | `load_preferences`              | all preference input values                | `preferences-modal.is_open`        | Load preferences into form     |

---

### 28. TIMELINE VISUALIZATION MODAL — Lines 22096–22499

| Line  | Function                              | Outputs                              | Inputs                  | Description                  |
| ----- | ------------------------------------- | ------------------------------------ | ----------------------- | ---------------------------- |
| 22089 | `toggle_timeline_viz_modal`           | `timeline-viz-modal.is_open`         | open/close clicks       | Timeline modal toggle        |
| 22102 | `update_timeline_viz_timestamp`       | `timeline-viz-last-updated.children` | is_open, refresh        | Timeline timestamp           |
| 22136 | `export_timeline_viz_csv`             | `download-timeline-data.data`        | export click, format    | Export timeline data         |
| 22178 | `update_activity_timeline`            | `activity-timeline-chart.figure`     | is_open, hours, refresh | Activity timeline chart      |
| 22243 | `update_device_activity_timeline`     | `device-activity-timeline.figure`    | is_open, refresh        | Per-device activity timeline |
| 22319 | `update_connection_patterns_timeline` | `connection-patterns-chart.figure`   | is_open, refresh        | Connection patterns chart    |
| 22394 | `update_anomaly_timeline`             | `anomaly-timeline-chart.figure`      | is_open, refresh        | Anomaly timeline chart       |

---

### 29. PROTOCOL DEEP-DIVE MODAL — Lines 22500–22961

| Line  | Function                         | Outputs                              | Inputs                  | Description                    |
| ----- | -------------------------------- | ------------------------------------ | ----------------------- | ------------------------------ |
| 22493 | `toggle_protocol_modal`          | `protocol-modal.is_open`             | open/close clicks       | Protocol modal toggle          |
| 22505 | `update_protocol_timestamp`      | `protocol-last-updated.children`     | is_open, refresh        | Protocol timestamp             |
| 22539 | `export_protocol_csv`            | `download-protocol-data.data`        | export click, format    | Export protocol data           |
| 22581 | `update_protocol_overview`       | `protocol-overview-content.children` | is_open, refresh        | Protocol distribution overview |
| 22692 | `update_mqtt_traffic`            | `mqtt-traffic-chart.figure`          | is_open, hours, refresh | MQTT traffic chart             |
| 22769 | `update_coap_traffic`            | `coap-traffic-chart.figure`          | is_open, hours, refresh | CoAP traffic chart             |
| 22857 | `update_protocol_device_summary` | `protocol-device-summary.children`   | is_open, refresh        | Protocol per-device summary    |

---

### 30. THREAT INTELLIGENCE MODAL — Lines 22962–23587

| Line  | Function                       | Outputs                            | Inputs                                                               | Description                   |
| ----- | ------------------------------ | ---------------------------------- | -------------------------------------------------------------------- | ----------------------------- |
| 22962 | `toggle_threat_modal`          | `threat-intel-modal.is_open`       | open/close clicks                                                    | Threat intel modal toggle     |
| 22973 | `update_threat_intel_overview` | `threat-intel-overview.children`   | is_open, refresh                                                     | Threat intel overview stats   |
| 23146 | `update_threat_intel_feed`     | `threat-intel-feed.children`       | is_open, active_tab, refresh, search, severity_filter, status_filter | Threat intelligence feed list |
| 23291 | `update_threat_intel_patterns` | `threat-patterns-content.children` | is_open, refresh                                                     | Attack pattern analysis       |
| 23407 | `update_threat_intel_response` | `threat-response-content.children` | is_open, refresh                                                     | Response recommendations      |

---

### 31. PRIVACY & SMARTHOME MODALS (Toggles) — Lines 23588–23707

| Line  | Function                     | Outputs                           | Inputs               | Description             |
| ----- | ---------------------------- | --------------------------------- | -------------------- | ----------------------- |
| 23588 | `toggle_privacy_modal`       | `privacy-modal.is_open`           | open/close clicks    | Privacy modal toggle    |
| 23606 | `toggle_smarthome_modal`     | `smarthome-modal.is_open`         | open/close clicks    | Smart home modal toggle |
| 23625 | `update_smarthome_timestamp` | `smarthome-last-updated.children` | is_open, refresh     | Smart home timestamp    |
| 23660 | `export_smarthome_csv`       | `download-smarthome-data.data`    | export click, format | Export smart home data  |

---

### 32. NETWORK SEGMENTATION MODAL — Lines 23708–24297

| Line  | Function                        | Outputs                              | Inputs                           | Description                      |
| ----- | ------------------------------- | ------------------------------------ | -------------------------------- | -------------------------------- |
| 23701 | `toggle_segmentation_modal`     | `segmentation-modal.is_open`         | open/close clicks                | Segmentation modal toggle        |
| 23712 | `update_segmentation_timestamp` | `segmentation-last-updated.children` | is_open, refresh                 | Segmentation timestamp           |
| 23747 | `update_segmentation_overview`  | `segmentation-overview.children`     | is_open, refresh                 | Segmentation health overview     |
| 23818 | `update_segments_list`          | `segments-list.children`             | is_open, refresh                 | Network segments list            |
| 23895 | `populate_segment_filter`       | `segment-filter-dropdown.options`    | is_open                          | Populate segment filter dropdown |
| 23925 | `update_device_mapping`         | `device-segment-mapping.children`    | is_open, segment_filter, refresh | Device-to-segment mapping        |
| 24027 | `update_violations`             | `segmentation-violations.children`   | is_open, hours, refresh          | Segmentation violations log      |
| 24148 | `update_vlan_recommendations`   | `vlan-recommendations.children`      | is_open, refresh                 | VLAN recommendations             |

---

### 33. FIRMWARE MODAL (Deep) — Lines 24298–24392

| Line  | Function                    | Outputs                          | Inputs               | Description           |
| ----- | --------------------------- | -------------------------------- | -------------------- | --------------------- |
| 24298 | `toggle_firmware_modal`     | `firmware-modal.is_open`         | open/close clicks    | Firmware modal toggle |
| 24317 | `update_firmware_timestamp` | `firmware-last-updated.children` | is_open, refresh     | Firmware timestamp    |
| 24352 | `export_firmware_csv`       | `download-firmware-data.data`    | export click, format | Export firmware data  |

---

### 34. EDUCATION / FIRMWARE SETTINGS / PRIVACY EXPORT — Lines 24393–24646

| Line  | Function                 | Outputs                                 | Inputs                                    | Description                   |
| ----- | ------------------------ | --------------------------------------- | ----------------------------------------- | ----------------------------- |
| 24393 | `toggle_education_modal` | `education-modal.is_open`               | open/close clicks                         | Education modal toggle        |
| 24405 | `save_firmware_settings` | `firmware-settings-result.children`     | save click, policy/schedule/notifications | Save firmware update settings |
| 24474 | `export_privacy_report`  | `download-privacy-report.data`          | export click, format                      | Export privacy report         |
| 24518 | `block_all_trackers`     | `block-trackers-result.children`, badge | block click, pending_count                | Block all detected trackers   |
| 24574 | `check_firmware_updates` | `firmware-check-result.children`        | check click                               | Check for firmware updates    |
| 24628 | `update_all_firmware`    | `firmware-update-result.children`       | update click                              | Update all firmware           |

---

### 35. SMARTHOME/FIRMWARE REFRESH — Lines 24647–24807

| Line  | Function            | Outputs                       | Inputs        | Description             |
| ----- | ------------------- | ----------------------------- | ------------- | ----------------------- |
| 24647 | `refresh_smarthome` | all smarthome section outputs | refresh click | Refresh smart home data |
| 24719 | `refresh_firmware`  | all firmware section outputs  | refresh click | Refresh firmware data   |

---

### 36. MODEL IMPORT/EXPORT — Lines 24808–25003

| Line  | Function        | Outputs                        | Inputs                           | Description                  |
| ----- | --------------- | ------------------------------ | -------------------------------- | ---------------------------- |
| 24808 | `export_models` | `download-models.data`         | export click                     | Export ML models as zip      |
| 24859 | `import_models` | `model-import-result.children` | `model-upload.contents/filename` | Import ML models from upload |

---

### 37. SYSTEM REFRESH & DEVICE IMPORT — Lines 25004–25136

| Line  | Function              | Outputs                         | Inputs                            | Description                  |
| ----- | --------------------- | ------------------------------- | --------------------------------- | ---------------------------- |
| 25004 | `refresh_system_info` | `system-info-content.children`  | refresh click                     | Refresh system info display  |
| 25022 | `import_devices`      | `device-import-result.children` | `device-upload.contents/filename` | Import devices from CSV/JSON |

---

### 38. EMAIL HISTORY & TEMPLATES — Lines 25137–25369

| Line  | Function               | Outputs                               | Inputs                        | Description                     |
| ----- | ---------------------- | ------------------------------------- | ----------------------------- | ------------------------------- |
| 25137 | `update_email_history` | `email-history-list.children`         | `ws-data-store.data`          | Email notification history      |
| 25235 | `save_email_template`  | `template-save-result.children`       | save click, type/subject/body | Save email template             |
| 25274 | `reset_email_template` | `template-subject/body.value`, result | reset click, type             | Reset email template to default |

---

### 39. EXPORT (Devices & Security Report) — Lines 25370–25513

| Line  | Function                 | Outputs                         | Inputs               | Description             |
| ----- | ------------------------ | ------------------------------- | -------------------- | ----------------------- |
| 25370 | `export_devices`         | `download-devices.data`         | export click, format | Export devices CSV/JSON |
| 25442 | `export_security_report` | `download-security-report.data` | export click, format | Export security report  |

---

### 40. AUTOMATION RULES — Lines 25514–25717

| Line  | Function            | Outputs                 | Inputs                                    | Description                   |
| ----- | ------------------- | ----------------------- | ----------------------------------------- | ----------------------------- |
| 25514 | `create_automation` | automation form content | create click                              | Show automation creation form |
| 25612 | `save_automation`   | result content          | save click, name/trigger/condition/action | Save automation rule          |
| 25693 | `cancel_automation` | form visibility         | cancel click                              | Cancel automation creation    |

---

### 41. LOG DOWNLOAD — Lines 25718–25828

| Line  | Function             | Outputs              | Inputs         | Description               |
| ----- | -------------------- | -------------------- | -------------- | ------------------------- |
| 25718 | `download_full_logs` | `download-logs.data` | download click | Download full system logs |

---

### 42. THREAT MAP & ATTACK SURFACE MODALS — Lines 25829–26432

| Line  | Function                           | Outputs                            | Inputs                                 | Description                   |
| ----- | ---------------------------------- | ---------------------------------- | -------------------------------------- | ----------------------------- |
| 25829 | `toggle_threat_map_modal`          | `threat-map-modal.is_open`         | open/close clicks                      | Threat map modal toggle       |
| 25849 | `toggle_risk_heatmap_modal`        | `risk-heatmap-modal.is_open`       | open/close clicks                      | Risk heatmap modal toggle     |
| 25859 | `toggle_attack_surface_modal`      | `attack-surface-modal.is_open`     | open/close clicks                      | Attack surface modal toggle   |
| 25870 | `update_attack_surface_overview`   | `attack-surface-overview.children` | is_open, refresh                       | Attack surface stats overview |
| 26007 | `update_attack_surface_services`   | `attack-surface-services.children` | is_open, tab, refresh, search, filters | Service vulnerability list    |
| 26169 | `update_attack_surface_ports`      | `open-ports-chart.figure`          | is_open, refresh                       | Open ports chart              |
| 26248 | `update_attack_surface_mitigation` | `mitigation-content.children`      | is_open, refresh                       | Mitigation recommendations    |

---

### 43. FORENSIC TIMELINE MODAL — Lines 26433–27108

| Line  | Function                          | Outputs                             | Inputs                                                 | Description              |
| ----- | --------------------------------- | ----------------------------------- | ------------------------------------------------------ | ------------------------ |
| 26433 | `toggle_forensic_timeline_modal`  | `forensic-timeline-modal.is_open`   | open/close clicks                                      | Forensic modal toggle    |
| 26445 | `populate_forensic_device_select` | `forensic-device-select.options`    | is_open                                                | Populate device dropdown |
| 26479 | `update_forensic_timeline`        | `forensic-timeline-chart.figure`    | device_ip, hours, refresh                              | Forensic timeline chart  |
| 26597 | `update_forensic_attack_patterns` | `forensic-attack-patterns.children` | device_ip, hours                                       | Attack pattern analysis  |
| 26717 | `update_forensic_event_log`       | `forensic-event-log.children`       | device_ip, hours, tab, refresh, search, severity, type | Event log table          |
| 26912 | `export_forensic_report`          | `download-forensic-report.data`     | export click, device, hours, format, sections          | Export forensic report   |

---

### 44. COMPLIANCE MODAL — Lines 27109–27337

| Line  | Function                         | Outputs                            | Inputs                                | Description                  |
| ----- | -------------------------------- | ---------------------------------- | ------------------------------------- | ---------------------------- |
| 27109 | `toggle_compliance_modal`        | `compliance-modal.is_open`         | open/close clicks                     | Compliance modal toggle      |
| 27129 | `update_compliance_requirements` | `compliance-requirements.children` | is_open, tab, refresh, search, filter | Compliance requirements list |

---

### 45. AUTOMATED RESPONSE MODAL — Lines 27338–27702

| Line  | Function                        | Outputs                           | Inputs                  | Description                  |
| ----- | ------------------------------- | --------------------------------- | ----------------------- | ---------------------------- |
| 27338 | `toggle_auto_response_modal`    | `auto-response-modal.is_open`     | open/close clicks       | Auto-response modal toggle   |
| 27342 | `update_auto_response_overview` | `auto-response-overview.children` | is_open, refresh        | Auto-response stats overview |
| 27478 | `update_alert_rules_table`      | `alert-rules-table.children`      | is_open, refresh        | Alert rules configuration    |
| 27554 | `update_auto_response_log`      | `auto-response-log.children`      | is_open, hours, refresh | Response action log          |
| 27635 | `update_rule_analytics`         | `rule-analytics-content.children` | is_open, refresh        | Rule effectiveness analytics |

---

### 46. VULNERABILITY SCANNER MODAL — Lines 27703–28215

| Line  | Function                      | Outputs                         | Inputs                                  | Description                               |
| ----- | ----------------------------- | ------------------------------- | --------------------------------------- | ----------------------------------------- |
| 27703 | `toggle_vuln_scanner_modal`   | `vuln-scanner-modal.is_open`    | open/close clicks                       | Vulnerability scanner modal toggle        |
| 27714 | `update_vuln_overview`        | `vuln-overview.children`        | is_open, refresh                        | Vulnerability overview stats              |
| 27827 | `update_cve_database`         | `cve-database.children`         | is_open, tab, refresh, search, severity | CVE database browser                      |
| 27949 | `update_device_scan_results`  | `device-scan-results.children`  | is_open, tab, filters, refresh, search  | Device scan results                       |
| 28101 | `update_vuln_recommendations` | `vuln-recommendations.children` | is_open, refresh                        | Vulnerability remediation recommendations |

---

### 47. API INTEGRATION HUB MODAL — Lines 28216–29202

| Line  | Function                      | Outputs                              | Inputs                                   | Description                      |
| ----- | ----------------------------- | ------------------------------------ | ---------------------------------------- | -------------------------------- |
| 28216 | `toggle_api_hub_modal`        | `api-hub-modal.is_open`              | open/close clicks                        | API hub modal toggle             |
| 28227 | `update_api_hub_overview`     | `api-hub-overview.children`          | is_open, refresh                         | API hub overview stats           |
| 28331 | `update_threat_intel_tab`     | `threat-intel-tab-content.children`  | active_tab                               | Threat intel integration config  |
| 28352 | `update_notifications_tab`    | `notifications-tab-content.children` | active_tab                               | Notifications integration config |
| 28373 | `update_ticketing_tab`        | `ticketing-tab-content.children`     | active_tab                               | Ticketing integration config     |
| 28394 | `update_geolocation_tab`      | `geolocation-tab-content.children`   | active_tab                               | Geolocation integration config   |
| 28415 | `update_webhooks_tab`         | `webhooks-tab-content.children`      | active_tab                               | Webhooks integration config      |
| 28437 | `update_api_hub_settings_tab` | `api-settings-tab-content.children`  | active_tab                               | API settings config              |
| 28755 | `handle_integration_config`   | modal is_open, store, result         | config/save/cancel clicks, store, inputs | Save integration configuration   |
| 28937 | `test_integration_handler`    | `integration-test-result.children`   | test clicks                              | Test integration connection      |
| 29009 | `toggle_integration_handler`  | `integration-toggle-result.children` | toggle clicks                            | Enable/disable integration       |
| 29058 | `toggle_clear_logs_modal`     | `clear-logs-modal.is_open`           | open/cancel/confirm clicks               | Clear API logs confirmation      |
| 29071 | `clear_request_logs_handler`  | `clear-logs-result.children`         | confirm click                            | Execute clear logs               |
| 29095 | `toggle_reset_health_modal`   | `reset-health-modal.is_open`         | open/cancel/confirm clicks               | Reset health confirmation        |
| 29108 | `reset_health_status_handler` | `reset-health-result.children`       | confirm click                            | Execute health reset             |
| 29136 | `export_config_handler`       | `download-api-config.data`           | export click, format                     | Export API configuration         |

---

### 48. BENCHMARKING MODAL — Lines 29203–29645

| Line  | Function                           | Outputs                              | Inputs            | Description                  |
| ----- | ---------------------------------- | ------------------------------------ | ----------------- | ---------------------------- |
| 29203 | `toggle_benchmark_modal`           | `benchmark-modal.is_open`            | open/close clicks | Benchmark modal toggle       |
| 29214 | `update_benchmark_overview`        | `benchmark-overview.children`        | is_open, refresh  | Benchmark overview stats     |
| 29306 | `update_benchmark_metrics`         | `benchmark-metrics.children`         | is_open, refresh  | Benchmark metrics comparison |
| 29400 | `update_benchmark_best_practices`  | `benchmark-best-practices.children`  | is_open, refresh  | Best practices checklist     |
| 29506 | `update_benchmark_recommendations` | `benchmark-recommendations.children` | is_open, refresh  | Benchmark recommendations    |

---

### 49. NETWORK PERFORMANCE ANALYTICS MODAL — Lines 29646–30188

| Line  | Function                          | Outputs                             | Inputs                        | Description                  |
| ----- | --------------------------------- | ----------------------------------- | ----------------------------- | ---------------------------- |
| 29646 | `toggle_performance_modal`        | `performance-modal.is_open`         | open/close clicks             | Performance modal toggle     |
| 29657 | `update_performance_overview`     | `performance-overview.children`     | is_open, refresh, n_intervals | Performance overview metrics |
| 29755 | `update_performance_bandwidth`    | `performance-bandwidth.children`    | is_open, refresh              | Bandwidth analytics          |
| 29873 | `update_performance_quality`      | `performance-quality.children`      | is_open, refresh              | Network quality metrics      |
| 30016 | `update_performance_optimization` | `performance-optimization.children` | is_open, refresh              | Optimization recommendations |

---

### 50. SUSTAINABILITY DASHBOARD — Lines 30189–30544

| Line  | Function                       | Outputs                               | Inputs               | Description                  |
| ----- | ------------------------------ | ------------------------------------- | -------------------- | ---------------------------- |
| 30193 | `toggle_sustainability_modal`  | `sustainability-modal.is_open`        | open/close clicks    | Sustainability modal toggle  |
| 30204 | `update_carbon_footprint`      | `carbon-footprint-content.children`   | is_open, refresh     | Carbon footprint analysis    |
| 30328 | `update_energy_consumption`    | `energy-consumption-chart.figure`     | active_tab, refresh  | Energy consumption chart     |
| 30404 | `update_green_best_practices`  | `green-practices-content.children`    | active_tab           | Green IT best practices      |
| 30493 | `export_sustainability_report` | `download-sustainability-report.data` | export click, format | Export sustainability report |

---

### 51. GEOGRAPHIC THREAT MAP CARDS — Lines 30545–31041

| Line  | Function                          | Outputs                             | Inputs                        | Description                  |
| ----- | --------------------------------- | ----------------------------------- | ----------------------------- | ---------------------------- |
| 30545 | `update_geographic_threat_map`    | `geographic-threat-map.figure`      | n_intervals, refresh          | Geographic threat map figure |
| 30702 | `update_threat_map_top_countries` | `threat-map-top-countries.children` | is_open, refresh, n_intervals | Top threat source countries  |
| 30800 | `update_threat_map_timeline`      | `threat-map-timeline.figure`        | is_open, refresh, n_intervals | Threat timeline chart        |

---

### 52. RISK HEATMAP CARDS — Lines 31042–31335

| Line  | Function                     | Outputs                             | Inputs                        | Description                |
| ----- | ---------------------------- | ----------------------------------- | ----------------------------- | -------------------------- |
| 30877 | `update_device_risk_heatmap` | `device-risk-heatmap.figure`        | is_open, refresh, n_intervals | Device risk heatmap figure |
| 31042 | `update_risk_device_details` | `risk-device-details.children`      | is_open, risk_filter, refresh | Risk details per device    |
| 31158 | `update_risk_factors`        | `risk-factors-content.children`     | is_open, refresh              | Risk factor breakdown      |
| 31232 | `update_risk_remediation`    | `risk-remediation-content.children` | is_open, refresh              | Risk remediation steps     |

---

### 53. TRAFFIC FLOW & ATTACK SURFACE CARDS — Lines 31336–31537

| Line  | Function                     | Outputs                       | Inputs      | Description                 |
| ----- | ---------------------------- | ----------------------------- | ----------- | --------------------------- |
| 31336 | `update_traffic_flow_sankey` | `traffic-flow-sankey.figure`  | n_intervals | Traffic flow Sankey diagram |
| 31446 | `update_attack_surface`      | `attack-surface-chart.figure` | n_intervals | Attack surface radar chart  |

---

### 54. COMPLIANCE DASHBOARD CARD — Lines 31538–31771

| Line  | Function                      | Outputs                                 | Inputs               | Description                          |
| ----- | ----------------------------- | --------------------------------------- | -------------------- | ------------------------------------ |
| 31546 | `update_compliance_dashboard` | `compliance-dashboard-content.children` | n_intervals, refresh | GDPR, NIST, IoT Act compliance cards |

---

### 55. AUTOMATED RESPONSE DASHBOARD CARD — Lines 31772–31905

| Line  | Function                              | Outputs                               | Inputs      | Description                  |
| ----- | ------------------------------------- | ------------------------------------- | ----------- | ---------------------------- |
| 31776 | `update_automated_response_dashboard` | `automated-response-content.children` | n_intervals | Auto-response rules & status |

---

### 56. VULNERABILITY SCANNER CARD — Lines 31906–32082

| Line  | Function                       | Outputs                                  | Inputs      | Description                     |
| ----- | ------------------------------ | ---------------------------------------- | ----------- | ------------------------------- |
| 31910 | `update_vulnerability_scanner` | `vulnerability-scanner-content.children` | n_intervals | Vulnerability scan summary card |

---

### 57. API INTEGRATION HUB CARD — Lines 32083–32327

| Line  | Function                     | Outputs                            | Inputs      | Description                 |
| ----- | ---------------------------- | ---------------------------------- | ----------- | --------------------------- |
| 32087 | `update_api_integration_hub` | `api-integration-content.children` | n_intervals | API integration status card |

---

### 58. BENCHMARKING CARD — Lines 32328–32428

| Line  | Function                      | Outputs                                 | Inputs      | Description               |
| ----- | ----------------------------- | --------------------------------------- | ----------- | ------------------------- |
| 32332 | `update_benchmark_comparison` | `benchmark-comparison-content.children` | n_intervals | Benchmark comparison card |

---

### 59. PERFORMANCE ANALYTICS CARD + THREAT FORECAST — Lines 32429–32631

| Line  | Function                       | Outputs                                  | Inputs      | Description                |
| ----- | ------------------------------ | ---------------------------------------- | ----------- | -------------------------- |
| 32433 | `update_performance_analytics` | `performance-analytics-content.children` | n_intervals | Performance analytics card |
| 32538 | `update_threat_forecast`       | `threat-forecast-chart.figure`           | n_intervals | Threat forecast ML chart   |

---

### 60. STATS CARDS — Lines 32632–32942

| Line  | Function                  | Outputs                            | Inputs         | Description             |
| ----- | ------------------------- | ---------------------------------- | -------------- | ----------------------- |
| 32632 | `update_network_stats`    | `network-stats-content.children`   | n_intervals    | Network stats card      |
| 32658 | `update_security_status`  | `security-status-content.children` | n_intervals    | Security status card    |
| 32711 | `update_recent_activity`  | `recent-activity-content.children` | n_intervals    | Recent activity feed    |
| 32776 | `update_recommendations`  | `recommendations-content.children` | n_intervals    | AI recommendations card |
| 32843 | `update_live_threat_feed` | `live-threat-feed.children`        | n_intervals    | Live threat feed ticker |
| 32931 | `update_user_role`        | `user-role-store.data`             | `url.pathname` | Store user role data    |

---

### 61. QUICK ACTIONS — Lines 32943–33936

| Line  | Function                         | Outputs                          | Inputs               | Description                       |
| ----- | -------------------------------- | -------------------------------- | -------------------- | --------------------------------- |
| 32943 | `populate_quick_actions_content` | `quick-actions-content.children` | is_open, user_data   | Render quick actions by user role |
| 33196 | `toggle_quick_actions_modal`     | `quick-actions-modal.is_open`    | open/close clicks    | Quick actions modal toggle        |
| 33221 | `quick_refresh`                  | `quick-action-result.children`   | refresh click        | Force data refresh                |
| 33239 | `quick_scan`                     | `quick-action-result.children`   | scan click           | Quick network scan                |
| 33277 | `quick_export`                   | `download-quick-export.data`     | export click, format | Quick data export                 |
| 33373 | `quick_clear_cache`              | `quick-action-result.children`   | clear click          | Clear application cache           |
| 33409 | `quick_update_db`                | `quick-action-result.children`   | update click         | Optimize database                 |
| 33436 | `quick_diagnostics`              | `quick-action-result.children`   | diagnostics click    | Run system diagnostics            |
| 33487 | `quick_block_unknown`            | `quick-action-result.children`   | block click          | Block all unknown devices         |
| 33551 | `quick_whitelist`                | `quick-action-result.children`   | whitelist click      | Whitelist all known devices       |
| 33615 | `quick_restart_monitor`          | `quick-action-result.children`   | restart click        | Restart monitoring                |
| 33642 | `quick_clear_net_cache`          | `quick-action-result.children`   | clear click          | Clear network cache               |
| 33678 | `quick_backup`                   | `quick-action-result.children`   | backup click         | Create backup                     |
| 33732 | `quick_clear_logs`               | `quick-action-result.children`   | clear click          | Clear old logs                    |
| 33767 | `quick_purge_alerts`             | `quick-action-result.children`   | purge click          | Purge reviewed alerts             |
| 33805 | `quick_restart_dash`             | `quick-action-result.children`   | restart click        | Restart dashboard                 |
| 33832 | `quick_check_updates`            | `quick-action-result.children`   | check click          | Check for updates                 |
| 33867 | `quick_view_logs`                | `quick-action-result.children`   | view click           | View system logs                  |

---

### 62. QUICK SETTINGS — Lines 33937–34997

| Line  | Function                          | Outputs                                    | Inputs                                          | Description                     |
| ----- | --------------------------------- | ------------------------------------------ | ----------------------------------------------- | ------------------------------- |
| 33937 | `handle_quick_settings`           | modal is_open, `quick-settings-store.data` | settings/close/save clicks, all settings inputs | Quick settings modal & save     |
| 34070 | `load_discovery_settings`         | discovery mode/features values             | is_open                                         | Load device discovery settings  |
| 34110 | `update_discovery_status_display` | `discovery-status-display.children`        | mode, features                                  | Update discovery status text    |
| 34161 | `clear_browser_cache`             | `cache-clear-result.children`              | clear click                                     | Clear browser cache             |
| 34201 | `reset_settings_to_defaults`      | `settings-reset-result.children`           | reset click                                     | Reset all settings to defaults  |
| 34241 | `export_settings`                 | `download-settings.data`                   | export click, settings/voice data               | Export settings as JSON         |
| 34287 | `autosave_alert_settings`         | `quick-settings-store.data`                | alert checklist, settings, voice                | Auto-save alert preferences     |
| 34347 | `autosave_debug_options`          | `quick-settings-store.data`                | debug checklist, settings                       | Auto-save debug settings        |
| 34391 | `autosave_performance_mode`       | `quick-settings-store.data`                | perf mode, settings                             | Auto-save performance mode      |
| 34435 | `autosave_display_options`        | `quick-settings-store.data`                | display checklist, settings                     | Auto-save display preferences   |
| 34475 | `autosave_network_options`        | `quick-settings-store.data`                | network checklist, settings                     | Auto-save network settings      |
| 34513 | `autosave_general_auto_settings`  | `quick-settings-store.data`                | auto checklist, settings                        | Auto-save general auto settings |
| 34551 | `autosave_refresh_interval`       | `quick-settings-store.data`                | interval value, settings                        | Auto-save refresh interval      |
| 34584 | `autosave_default_view`           | `quick-settings-store.data`                | view value, settings                            | Auto-save default view          |
| 34621 | `autosave_network_interface`      | `quick-settings-store.data`                | interface, settings                             | Auto-save network interface     |
| 34651 | `autosave_font_size`              | `quick-settings-store.data`                | font size, settings                             | Auto-save font size             |
| 34682 | `autosave_chart_animation`        | `quick-settings-store.data`                | animation value, settings                       | Auto-save chart animation       |
| 34713 | `autosave_notification_sound`     | `quick-settings-store.data`                | sound value, settings                           | Auto-save notification sound    |
| 34750 | `autosave_alert_duration`         | `quick-settings-store.data`                | duration, settings                              | Auto-save alert duration        |
| 34787 | `autosave_notification_position`  | `quick-settings-store.data`                | position, settings                              | Auto-save notification position |
| 34824 | `autosave_network_scan_interval`  | `quick-settings-store.data`                | interval, settings                              | Auto-save scan interval         |
| 34861 | `autosave_connection_timeout`     | `quick-settings-store.data`                | timeout, settings                               | Auto-save connection timeout    |
| 34893 | `sync_settings_from_store`        | all settings UI inputs                     | `quick-settings-store.data`                     | Sync UI from settings store     |
| 34947 | `toggle_dark_mode`                | `theme-store.data`                         | dark mode click, current theme                  | Toggle dark/light mode          |
| 34983 | `update_dark_mode_icon`           | `dark-mode-icon.className`                 | theme data                                      | Update dark mode toggle icon    |

---

### 63. CUSTOMIZABLE WIDGET DASHBOARD — Lines 34998–35192

| Line  | Function                  | Outputs                           | Inputs                                                           | Description                         |
| ----- | ------------------------- | --------------------------------- | ---------------------------------------------------------------- | ----------------------------------- |
| 35003 | `toggle_customize_modal`  | `customize-widgets-modal.is_open` | customize click                                                  | Widget customization modal          |
| 35016 | `load_widget_preferences` | widget checklist values           | is_open, prefs                                                   | Load saved widget selections        |
| 35029 | `save_widget_preferences` | `widget-preferences.data`, toast  | save click, selected widgets                                     | Save widget preferences             |
| 35056 | `cancel_preferences`      | modal is_open                     | cancel click                                                     | Cancel widget customization         |
| 35069 | `export_configuration`    | `download-dashboard-config.data`  | export click, toggles, widgets, density, layout, theme, interval | Export full dashboard configuration |
| 35131 | `import_configuration`    | import result                     | import click                                                     | Import dashboard configuration      |
| 35149 | `reset_preferences`       | `widget-preferences.data`, toast  | reset click                                                      | Reset widget preferences            |

---

### 64. SPOTLIGHT SEARCH — Lines 35193–35563

| Line  | Function                      | Outputs                           | Inputs                         | Description                        |
| ----- | ----------------------------- | --------------------------------- | ------------------------------ | ---------------------------------- |
| 35197 | `toggle_spotlight_modal`      | `spotlight-modal.is_open`         | btn clicks, clear clicks       | Open/close spotlight search        |
| 35222 | _(clientside)_                | `spotlight-search-data.data`      | `spotlight-search-input.value` | Clientside: fuzzy search filtering |
| 35262 | `render_spotlight_results`    | `spotlight-results-list.children` | `spotlight-search-data.data`   | Render search results list         |
| 35433 | `update_category_filter`      | `spotlight-search-data.data`      | all/badge clicks, badge ids    | Filter by category                 |
| 35462 | `spotlight_track_modal_click` | `spotlight-modal.is_open`         | go-to clicks                   | Close spotlight on navigation      |
| 35483 | _(clientside)_                | `spotlight-keyboard-store.data`   | `spotlight-modal.is_open`      | Keyboard navigation (arrows/enter) |
| 35516 | _(clientside)_                | `spotlight-search-input.id`       | `url.pathname`                 | Cmd+K global shortcut              |

---

### 65. MASONRY LAYOUT (Category/View) — Lines 35564–35679

| Line  | Function                 | Outputs                          | Inputs                                   | Description                        |
| ----- | ------------------------ | -------------------------------- | ---------------------------------------- | ---------------------------------- |
| 35569 | `update_category_filter` | card container visibility styles | all/security/management/analytics clicks | Filter dashboard cards by category |
| 35609 | _(clientside)_           | `masonry-view-store.data`        | `masonry-view-toggle.value`              | Toggle list/grid view              |

---

### 66. ADVANCED REPORTING & ANALYTICS — Lines 35680–36498

| Line  | Function                     | Outputs                                                                      | Inputs                                     | Description                    |
| ----- | ---------------------------- | ---------------------------------------------------------------------------- | ------------------------------------------ | ------------------------------ |
| 35685 | `toggle_reports_modal`       | `reports-modal.is_open`                                                      | open/close clicks                          | Reports modal toggle           |
| 35708 | `select_template_from_card`  | `report-template-select.value`                                               | exec/security/network/device/threat clicks | Select report template         |
| 35736 | `update_template_preview`    | `template-preview-content.children`                                          | template_name                              | Preview report template        |
| 35772 | `update_recent_reports_list` | `recent-reports-list.children`                                               | active_tab, n_intervals                    | Recent reports list            |
| 35882 | `download_report_with_toast` | `download-generated-report.data`, toast                                      | download clicks                            | Download generated report      |
| 35954 | `submit_report_generation`   | `report-generation-status.children`, `report-job-id.data`, interval disabled | generate click, template/format/days       | Submit async report generation |
| 36033 | `poll_job_status`            | `report-generation-status.children`, `report-job-id.data`, interval disabled | n_intervals, job_id                        | Poll background report job     |
| 36189 | `update_alert_trend_chart`   | `alert-trend-chart.figure`                                                   | active_tab                                 | Alert trend chart              |
| 36270 | `update_activity_heatmap`    | `activity-heatmap-chart.figure`                                              | active_tab                                 | Activity heatmap chart         |
| 36347 | `update_trend_statistics`    | `trend-statistics-content.children`                                          | active_tab                                 | Trend statistics display       |

---

### 67. REPORT SCHEDULER — Lines 36499–37296

| Line  | Function                      | Outputs                               | Inputs                              | Description               |
| ----- | ----------------------------- | ------------------------------------- | ----------------------------------- | ------------------------- |
| 36504 | `toggle_schedule_type_inputs` | daily/weekly/monthly input visibility | schedule_type                       | Show schedule type inputs |
| 36519 | `list_schedules`              | `scheduled-reports-list.children`     | refresh clicks, active_tab          | List scheduled reports    |
| 36695 | `add_new_schedule`            | `schedule-result.children`            | add click, all schedule fields      | Add new scheduled report  |
| 36802 | `pause_resume_schedule`       | `scheduled-reports-list.children`     | pause/resume clicks                 | Pause/resume schedule     |
| 36996 | `delete_schedule`             | `scheduled-reports-list.children`     | delete clicks                       | Delete schedule           |
| 37165 | `enable_daily_digest`         | `digest-result.children`              | enable click, hour/minute/recipient | Enable daily digest email |
| 37244 | `send_test_digest`            | `digest-test-result.children`         | test click, recipient               | Send test digest          |

---

### 68. PRIVACY DASHBOARD — Lines 37297–37601

| Line  | Function                      | Outputs                                                           | Inputs                     | Description                |
| ----- | ----------------------------- | ----------------------------------------------------------------- | -------------------------- | -------------------------- |
| 37301 | `update_privacy_dashboard`    | `privacy-dashboard-content.children`                              | n_intervals, refresh       | Privacy dashboard overview |
| 37454 | `toggle_privacy_detail_modal` | `privacy-detail-modal.is_open`, `privacy-detail-content.children` | detail clicks, close click | Privacy detail modal       |

---

### 69. ROLE-BASED DASHBOARD TEMPLATES — Lines 37602–37881

| Line  | Function                          | Outputs                                | Inputs                               | Description                             |
| ----- | --------------------------------- | -------------------------------------- | ------------------------------------ | --------------------------------------- |
| 37613 | `load_user_template_on_page_load` | `dashboard-template-store.data`        | `url.pathname`                       | Load user's dashboard template on login |
| 37649 | `save_dashboard_template`         | `dashboard-template-store.data`, toast | template selection, current template | Save selected template                  |
| 37731 | _(clientside)_                    | `dashboard-template-store.data`        | `dashboard-template-select.value`    | Apply template visibility rules         |
| 37815 | `sync_template_selection`         | `dashboard-template-select.value`      | is_open, stored_template             | Sync template dropdown                  |
| 37829 | `update_template_options`         | `dashboard-template-select.options`    | is_open                              | Populate template options               |

---

### 70. EMERGENCY MODE — Lines 37882–38209

| Line  | Function                    | Outputs                                                         | Inputs                               | Description                   |
| ----- | --------------------------- | --------------------------------------------------------------- | ------------------------------------ | ----------------------------- |
| 37887 | _(clientside)_              | `emergency-indicator.style`                                     | `emergency-mode-store.data`          | Show/hide emergency indicator |
| 37913 | `toggle_emergency_modal`    | `emergency-modal.is_open`                                       | activate/cancel/confirm clicks       | Emergency modal toggle        |
| 37938 | `activate_emergency_mode`   | `emergency-mode-store.data`, `emergency-log.children`           | confirm click, reason, current state | Activate emergency mode       |
| 38079 | `deactivate_emergency_mode` | `emergency-mode-store.data`, `emergency-log.children`           | deactivate click, current state      | Deactivate emergency mode     |
| 38171 | `update_emergency_ui`       | `emergency-status-badge.children`, `emergency-actions.children` | emergency state                      | Update emergency UI state     |

---

### 71. WEBAUTHN / PASSKEY API ENDPOINTS — Lines 38210–38271

| Line  | Function                         | Outputs                                              | Inputs | Description                      |
| ----- | -------------------------------- | ---------------------------------------------------- | ------ | -------------------------------- |
| 38215 | `generate_webauthn_auth_options` | _(Flask route `/api/webauthn/authenticate/options`)_ | POST   | Generate WebAuthn auth challenge |
| 38232 | `verify_webauthn_authentication` | _(Flask route `/api/webauthn/authenticate/verify`)_  | POST   | Verify WebAuthn auth response    |

---

### 72. CROSS-CHART FILTERING — Lines 38272–38339

| Line  | Function                           | Outputs                       | Inputs                                                       | Description                      |
| ----- | ---------------------------------- | ----------------------------- | ------------------------------------------------------------ | -------------------------------- |
| 38276 | `filter_by_severity_from_timeline` | `alert-severity-filter.value` | `alert-timeline.clickData`                                   | Click timeline → filter alerts   |
| 38296 | `filter_by_device_from_heatmap`    | `heatmap-device-filter.value` | `device-heatmap.clickData`                                   | Click heatmap → filter device    |
| 38316 | `show_filter_notification`         | Toast notification            | `alert-severity-filter.value`, `heatmap-device-filter.value` | Show filter applied notification |

---

### 73. ADVANCED VISUALIZATION (Attack Path & Sunburst) — Lines 38340–38597

| Line  | Function                           | Outputs                            | Inputs                   | Description                     |
| ----- | ---------------------------------- | ---------------------------------- | ------------------------ | ------------------------------- |
| 38344 | `create_attack_path_visualization` | `attack-path-sankey.figure`        | is_open, severity_filter | Attack path Sankey diagram      |
| 38469 | `create_device_hierarchy_sunburst` | `device-hierarchy-sunburst.figure` | is_open, device_filter   | Device hierarchy sunburst chart |

---

### 74. MAIN ENTRY POINT — Lines 38598–38604

```python
if __name__ == '__main__':
    main()
```

---

## SUGGESTED TAB FILE EXTRACTION GROUPS

For splitting into separate tab files, here are the recommended groupings:

### `callbacks_auth.py` — Lines 15355–18479 (~3,125 lines)

- Authentication & Login (15355–15855)
- 2FA / TOTP (15856–16177)
- Password Recovery & Toggles (16178–16512)
- Registration & Validation (16513–17150)
- Email Verification route (17151–17543)
- User Management (17544–17983)
- Profile & Admin UI (17984–18173)
- Biometric/WebAuthn (18174–18479)

### `callbacks_overview.py` — Lines 11168–12066 (~899 lines)

- Header & Notifications (11168–11625)
- Network Graph (11626–11876)
- Devices Overview Panel (11877–12066)

### `callbacks_alerts.py` — Lines 12067–13046 (~980 lines)

- Toast History (12067–12622)
- Alerts (12623–12894)
- AI-Powered Features (12895–13046)

### `callbacks_devices.py` — Lines 18480–19890 (~1,411 lines)

- Device Management & Preferences (18480–18830)
- Device Bulk Operations (18831–19413)
- Device Details View (19414–19890)

### `callbacks_analytics.py` — Lines 13479–14222 + 38272–38597 (~1,069 lines)

- Analytics charts (13479–13957)
- System Info / ML Models (13958–14222)
- Cross-Chart Filtering (38272–38339)
- Advanced Visualization (38340–38597)

### `callbacks_iot.py` — Lines 19891–21388 (~1,498 lines)

- IoT-Specific Features (protocols, privacy, smart home, firmware)

### `callbacks_modals.py` — Lines 21389–30188 (~8,800 lines)

- Main modal toggles (21389–22095)
- Timeline Viz (22096–22499)
- Protocol Deep-Dive (22500–22961)
- Threat Intel (22962–23587)
- Privacy/SmartHome modals (23588–23707)
- Segmentation (23708–24297)
- Firmware (24298–24646)
- SmartHome/Firmware refresh (24647–24807)
- Model Import/Export (24808–25003)
- System Refresh & Device Import (25004–25136)
- Email History & Templates (25137–25369)
- Export (25370–25513)
- Automation Rules (25514–25717)
- Log Download (25718–25828)
- Threat Map & Attack Surface (25829–26432)
- Forensic Timeline (26433–27108)
- Compliance (27109–27337)
- Auto Response (27338–27702)
- Vuln Scanner (27703–28215)
- API Hub (28216–29202)
- Benchmarking (29203–29645)
- Performance Analytics (29646–30188)

### `callbacks_dashboard_cards.py` — Lines 30189–32942 (~2,754 lines)

- Sustainability (30189–30544)
- Geographic Threat Map (30545–31041)
- Risk Heatmap (31042–31335)
- Traffic Flow & Attack Surface (31336–31537)
- Compliance card (31538–31771)
- Auto Response card (31772–31905)
- Vuln Scanner card (31906–32082)
- API Hub card (32083–32327)
- Benchmarking card (32328–32428)
- Performance card + Threat Forecast (32429–32631)
- Stats cards (32632–32942)

### `callbacks_admin.py` — Lines 32943–34997 (~2,055 lines)

- Quick Actions (32943–33936)
- Quick Settings (33937–34997)

### `callbacks_global.py` — Lines 13047–13478 + 14223–15354 + 34998–38271 (~4,500 lines)

- Onboarding (13047–13124)
- Lockdown Mode (13125–13270)
- Email Settings (13271–13478)
- Voice Alerts (14223–14380)
- Utilities (14381–15203)
- WebSocket (15204–15354)
- Widget Dashboard (34998–35192)
- Spotlight Search (35193–35563)
- Masonry Layout (35564–35679)
- Reporting & Analytics (35680–36498)
- Report Scheduler (36499–37296)
- Privacy Dashboard (37297–37601)
- Dashboard Templates (37602–37881)
- Emergency Mode (37882–38209)
- WebAuthn API Endpoints (38210–38271)

---

> **Total callbacks cataloged: ~210+** (including clientside callbacks and Flask routes)
> **File generated:** `docs/CALLBACK_MAP.md`
