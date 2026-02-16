# PRD: IoTSentinel Dashboard — Monolithic → Tabbed Multi-File Refactor

| Field       | Value                                                                |
| ----------- | -------------------------------------------------------------------- |
| **Author**  | IoTSentinel Team                                                     |
| **Created** | 2026-02-09                                                           |
| **Status**  | In Progress                                                          |
| **Scope**   | Dashboard UI restructuring only — zero feature additions or removals |

---

## 1. Problem Statement

The IoTSentinel dashboard (`dashboard/app.py`) is a **38,604-line monolithic file** containing:

- 60+ imports (stdlib, third-party, internal)
- 200+ function definitions
- 250+ Dash callbacks (`@app.callback`)
- 52 modal dialogs (each with internal tabs)
- 40+ `dcc.Store` components
- 15+ `dcc.Graph` charts
- 26+ feature card tiles
- Complete authentication system (password, OAuth, WebAuthn, TOTP 2FA)
- WebSocket (SocketIO) real-time data push
- AI chat assistant integration

This single-file architecture causes:

1. **Developer friction** — navigating 38K lines, merge conflicts on every PR
2. **Cognitive overload** — no separation between concerns
3. **IDE performance** — language servers struggle with files this large
4. **Testing difficulty** — cannot unit-test layout modules independently

---

## 2. Goal

Refactor the monolithic `dashboard/app.py` into a **tabbed multi-file architecture** where:

1. The main dashboard page uses **top-level `dcc.Tabs`** for navigation between major sections
2. Each tab's layout and callbacks live in a **separate Python file**
3. **Zero features are added or removed** — exact feature parity
4. **No callback logic or signatures are altered** — `Input`, `Output`, `State` decorators remain byte-identical
5. **No UI behavior changes** — every button, modal, chart, and interaction works identically
6. **Authentication, WebSocket, and routing remain unchanged**

---

## 3. Constraints

| Constraint                          | Rationale                                                                                |
| ----------------------------------- | ---------------------------------------------------------------------------------------- |
| No new features                     | Scope control — refactoring only                                                         |
| No removed features                 | Every existing element must exist post-refactor                                          |
| Callbacks unmodified                | Decorator signatures (`Input`, `Output`, `State`) and function bodies stay identical     |
| No new dependencies                 | Only existing packages used                                                              |
| `suppress_callback_exceptions=True` | Already enabled — allows cross-tab component references                                  |
| Eager tab rendering                 | All tab content rendered at once (no lazy loading) to preserve current callback behavior |
| Backward-compatible `main()`        | Entry point `dashboard/app.py → main()` unchanged                                        |

---

## 4. Recommended Tab Structure (7 Tabs)

After analyzing all 26+ feature cards, 52 modals, and the three-column layout, the optimal grouping is:

### Tab 1: 🏠 Overview (Default Tab)

**What it contains:**

- Header bar (logo, notification bell, user dropdown, AI chat button, dark mode, voice alerts, pause/resume, quick actions, customize layout)
- 6 metric cards (CPU, RAM, Bandwidth, Threats Blocked, Privacy Score, Network Health)
- Network Activity card (recent connections feed)
- Connected Devices list card
- Network Topology visualization (Cytoscape 2D + Plotly 3D toggle)
- Traffic stats, Protocol Distribution pie chart, Traffic Timeline 24h
- Security Status card, Recent Activity, Recommendations
- Live Threat Feed, Threat Forecast (AI)

**Rationale:** This is the "at-a-glance" landing page. It shows real-time system health and network state — the most commonly viewed section.

**Current layout lines:** ~3090–3800 (header + 3-column layout)

---

### Tab 2: 🚨 Alerts & Threats

**What it contains:**

- Security Alerts section (severity-filtered alert cards)
- Alert Detail modal (educational explanations, baseline comparisons)
- Threat Map modal (geographic threat visualization)
- Risk Heatmap modal (device risk matrix)
- Forensic Timeline modal (event reconstruction)
- Auto Response modal (alert rules, action history)
- Live Threat Feed card (if duplicated from Overview, or linked)

**Feature cards moved here:**

- `threat-card-btn` → Threat Intelligence
- `threat-map-card-btn` → Threat Map
- `risk-heatmap-card-btn` → Risk Heatmap
- `forensic-timeline-card-btn` → Forensic Timeline
- `auto-response-card-btn` → Auto Response

**Rationale:** Groups all alert-related views and threat analysis in one place — the "investigate" tab.

---

### Tab 3: 📱 Devices & IoT

**What it contains:**

- Device Management modal (device list, bulk actions, details, analytics, import/export)
- Device Detail modal (per-device deep dive, trust toggle)
- IoT Protocol Analysis modal
- Smart Home Manager modal
- Privacy Monitor modal
- Network Segmentation modal
- Firmware Manager modal
- Hardware Lifecycle / EOL modal
- Replace Device modal

**Feature cards moved here:**

- `device-mgmt-card-btn` → Device Management
- `protocol-card-btn` → Protocol Analysis
- `smarthome-card-btn` → Smart Home
- `privacy-card-btn` → Privacy Monitor
- `segmentation-card-btn` → Network Segmentation
- `firmware-card-btn` → Firmware Management
- `education-card-btn` → Security Education

**Rationale:** Everything device-specific — the "manage my devices" tab.

---

### Tab 4: 📊 Analytics & Reports

**What it contains:**

- Analytics modal (security status chart, alert timeline, anomaly analysis, reports, trend analysis)
- Custom Reports modal (template builder, report generation, download)
- Benchmarking modal (performance metrics, best practices)
- Performance modal (bandwidth, quality, optimization)
- Timeline Visualization modal (activity patterns, connections, anomalies)

**Feature cards moved here:**

- `analytics-card-btn` → Analytics
- `timeline-card-btn` → Timeline Visualization
- `benchmark-card-btn` → Benchmarking
- `performance-card-btn` → Performance

**Rationale:** All data-analysis and report-generation features — the "deep dive into data" tab.

---

### Tab 5: 🔗 Integrations & API

**What it contains:**

- API Integration Hub modal (threat intel services, notifications, ticketing, geolocation, webhooks, settings)
- Email Settings modal (SMTP config, recipients, templates, schedules, daily digest)
- Notification Dispatcher configuration

**Feature cards moved here:**

- `api-hub-card-btn` → API Integration Hub
- `email-card-btn` → Email Settings

**Rationale:** All external service integrations — the "connect to other tools" tab.

---

### Tab 6: 🛡️ Compliance & Security

**What it contains:**

- Compliance modal (overview, requirements, audit log)
- Vulnerability Scanner modal (CVE database, device scan, recommendations)
- Attack Surface modal (exposed services, open ports, mitigation)
- Sustainability modal (carbon footprint, energy, best practices)
- Firewall modal (rules, blocked devices, logs)
- Network Lockdown controls

**Feature cards moved here:**

- `compliance-card-btn` → Compliance
- `vuln-scanner-card-btn` → Vulnerability Scanner
- `attack-surface-card-btn` → Attack Surface
- `firewall-card-btn` → Firewall
- (Sustainability features)

**Rationale:** Security posture and compliance — the "are we compliant?" tab.

---

### Tab 7: ⚙️ Administration

**What it contains:**

- User Management modal (users list, activity log, create user)
- Profile Edit modal (profile info, security/2FA/WebAuthn, preferences)
- Preferences modal (appearance, performance, localization, alerts, backup/export)
- System modal (system info, ML models, model comparison, diagnostics)
- Onboarding wizard
- Quick Settings modal
- Spotlight Search modal

**Feature cards moved here:**

- `user-card-btn` → User Management
- `system-card-btn` → System Info
- `preferences-card-btn` → Preferences
- `quick-settings-btn` → Quick Settings

**Rationale:** System administration and user management — the "settings" tab.

---

## 5. File Structure

```
dashboard/
├── app.py                      # SLIM entry point (~500 lines)
│                                 - eventlet monkey-patch
│                                 - Dash app creation
│                                 - app.layout (Location, Stores, Tabs container, page-content)
│                                 - URL routing callback (display_page)
│                                 - main() entry point
│                                 - Imports all tab/component modules to register callbacks
│
├── shared.py                   # SHARED state & utilities (~1800 lines)
│                                 - All imports (stdlib, third-party, internal)
│                                 - Logging configuration (8 loggers)
│                                 - App instance reference (set by app.py after creation)
│                                 - SocketIO instance reference
│                                 - Service singletons (db_manager, auth_manager, etc.)
│                                 - All module initializations (IoT, ML, AI, reporting, etc.)
│                                 - Flask server config, Flask-Login, secret key
│                                 - Flask routes (health, download-report, OAuth, WebAuthn)
│                                 - Constants (MITRE_ATTACK_MAPPING, SEVERITY_CONFIG, etc.)
│                                 - Database helpers (get_db_connection, queries)
│                                 - UI helpers (format_bytes, create_status_indicator, etc.)
│                                 - Educational explanation builder
│                                 - Onboarding steps data
│                                 - Dashboard templates data
│                                 - WebSocket background thread + SocketIO handlers
│
├── layouts/
│   ├── __init__.py             # Exports layout functions
│   ├── login.py                # login_layout + auth callbacks (~2500 lines)
│   │                            - create login page layout
│   │                            - Login form callback
│   │                            - Registration callbacks (validation, submission)
│   │                            - Password toggle callbacks (6x)
│   │                            - Forgot password callbacks
│   │                            - Email verification callbacks
│   │                            - Auth notification toast callback
│   │                            - Form clearing callback
│   │                            - Redirect after auth callback
│   │
│   ├── tab_overview.py         # Tab 1 layout + callbacks (~4000 lines)
│   │                            - Header bar
│   │                            - 3-column dashboard layout
│   │                            - Metric cards, network topology, traffic charts
│   │                            - Security score callback
│   │                            - CPU/RAM update callback
│   │                            - Device list update callback
│   │                            - Network graph update callback
│   │                            - Traffic/protocol chart callbacks
│   │                            - Bandwidth/connection stats callbacks
│   │                            - Notification drawer callbacks
│   │
│   ├── tab_alerts.py           # Tab 2 layout + callbacks (~4500 lines)
│   │                            - Alert cards section
│   │                            - Alert detail modal + callback
│   │                            - Threat map modal + callbacks (3 tab callbacks)
│   │                            - Risk heatmap modal + callbacks
│   │                            - Forensic timeline modal + callbacks (5 callbacks)
│   │                            - Auto response modal + callbacks (4 callbacks)
│   │                            - Alert acknowledge/dismiss callbacks
│   │
│   ├── tab_devices.py          # Tab 3 layout + callbacks (~5000 lines)
│   │                            - Device management modal + callbacks
│   │                            - Device detail modal + callbacks
│   │                            - IoT protocol analysis modal + callbacks (4 tab callbacks)
│   │                            - Smart home modal + callbacks
│   │                            - Privacy monitor modal + callbacks
│   │                            - Network segmentation modal + callbacks
│   │                            - Firmware manager modal + callbacks
│   │                            - Lifecycle / EOL modal
│   │                            - Device trust toggle, block, replace callbacks
│   │                            - Bulk actions callbacks
│   │
│   ├── tab_analytics.py        # Tab 4 layout + callbacks (~4000 lines)
│   │                            - Analytics modal + callbacks (5 tab callbacks)
│   │                            - Custom reports modal + callbacks
│   │                            - Benchmarking modal + callbacks (4 tab callbacks)
│   │                            - Performance modal + callbacks (4 tab callbacks)
│   │                            - Timeline visualization modal + callbacks
│   │                            - Report generation + download callbacks
│   │
│   ├── tab_integrations.py     # Tab 5 layout + callbacks (~3000 lines)
│   │                            - API integration hub modal + callbacks (12+ callbacks)
│   │                            - Email settings modal + callbacks (7 tab callbacks)
│   │                            - Notification dispatcher config callbacks
│   │
│   ├── tab_compliance.py       # Tab 6 layout + callbacks (~3500 lines)
│   │                            - Compliance modal + callbacks
│   │                            - Vulnerability scanner modal + callbacks (4 tab callbacks)
│   │                            - Attack surface modal + callbacks (4 tab callbacks)
│   │                            - Sustainability modal + callbacks (4 callbacks)
│   │                            - Firewall modal + callbacks
│   │                            - Lockdown mode callbacks
│   │
│   └── tab_admin.py            # Tab 7 layout + callbacks (~3500 lines)
│                                - User management modal + callbacks
│                                - Profile/biometric modal + callbacks
│                                - Preferences modal + callbacks
│                                - System modal + callbacks
│                                - Onboarding callbacks
│                                - Quick settings callbacks
│                                - Spotlight search callbacks
│
├── components/
│   ├── __init__.py
│   ├── modals.py               # Generic modal toggle callbacks (~1000 lines)
│   │                            - 26 modal open/close toggle callbacks
│   │                            - Pattern: Input(open-btn) + Input(close-btn) → Output(modal, is_open)
│   │
│   ├── toasts.py               # Toast notification callbacks (~500 lines)
│   │                            - Toast container updates
│   │                            - Toast history modal callbacks
│   │                            - Toast detail modal callbacks
│   │
│   └── chat.py                 # AI chat panel callbacks (~600 lines)
│                                - Chat modal toggle
│                                - Chat message send callback
│                                - Chat history management
│                                - Chat clear callback
│
├── assets/                     # UNCHANGED (14 files)
│   ├── custom.css
│   ├── custom.css.backup
│   ├── mobile-responsive.css
│   ├── skeleton.css
│   ├── debounce.js
│   ├── notifications.js
│   ├── performance.js
│   ├── spotlight-search.js
│   ├── static-cache.js
│   ├── theme-toggle.js
│   ├── virtual-scroll.js
│   ├── webauthn.js
│   └── logo.png
│
└── __init__.py                 # UNCHANGED
```

---

## 6. Import / Dependency Graph

```
app.py
  ├── shared.py          (app instance, all services, helpers, constants)
  ├── layouts/
  │   ├── login.py       → imports from shared.py
  │   ├── tab_overview.py    → imports from shared.py
  │   ├── tab_alerts.py      → imports from shared.py
  │   ├── tab_devices.py     → imports from shared.py
  │   ├── tab_analytics.py   → imports from shared.py
  │   ├── tab_integrations.py→ imports from shared.py
  │   ├── tab_compliance.py  → imports from shared.py
  │   └── tab_admin.py       → imports from shared.py
  └── components/
      ├── modals.py      → imports from shared.py
      ├── toasts.py      → imports from shared.py
      └── chat.py        → imports from shared.py
```

### Circular Import Prevention Strategy

1. `shared.py` creates a module-level `app = None` placeholder
2. `app.py` creates the actual `dash.Dash()` instance and sets `shared.app = app`
3. All other modules import `app` from `shared.py` and register callbacks using it
4. `app.py` imports all layout/component modules **after** setting `shared.app`, ensuring callbacks register against the real app instance
5. `suppress_callback_exceptions=True` (already enabled) handles cross-tab component references

---

## 7. Tab Container Implementation

The top-level dashboard layout gains a `dcc.Tabs` component that wraps the 7 tabs. The header bar stays **outside** the tabs (always visible):

```python
# In app.py — the dashboard_layout becomes:
dashboard_layout = dbc.Container([
    # Header bar (always visible, from tab_overview.py)
    header_bar,

    # Tab navigation
    dcc.Tabs(
        id='main-dashboard-tabs',
        value='overview',
        children=[
            dcc.Tab(label='🏠 Overview',           value='overview',      children=[tab_overview_layout]),
            dcc.Tab(label='🚨 Alerts & Threats',    value='alerts',        children=[tab_alerts_layout]),
            dcc.Tab(label='📱 Devices & IoT',       value='devices',       children=[tab_devices_layout]),
            dcc.Tab(label='📊 Analytics & Reports',  value='analytics',     children=[tab_analytics_layout]),
            dcc.Tab(label='🔗 Integrations',         value='integrations',  children=[tab_integrations_layout]),
            dcc.Tab(label='🛡️ Compliance & Security',value='compliance',    children=[tab_compliance_layout]),
            dcc.Tab(label='⚙️ Administration',       value='admin',         children=[tab_admin_layout]),
        ],
        className='dashboard-main-tabs',
        persistence=True,
        persistence_type='session'
    ),

    # Global components that must be present on all tabs:
    # - All dcc.Store components
    # - All dcc.Interval components
    # - All dcc.Download components
    # - Toast container
    # - Modals that can be triggered from multiple tabs

], fluid=True, className="dashboard-container p-3")
```

### CSS for Tab Styling

```css
/* Add to assets/custom.css */
.dashboard-main-tabs .tab {
  font-weight: 600;
  font-size: 0.95rem;
  padding: 12px 20px;
  border-radius: 8px 8px 0 0;
}
.dashboard-main-tabs .tab--selected {
  background: var(--card-bg);
  border-bottom: 3px solid var(--accent-color);
}
```

---

## 8. Migration Checklist

### Phase 1: Create Infrastructure

- [ ] Create `dashboard/shared.py` with all shared state
- [ ] Create `dashboard/layouts/__init__.py`
- [ ] Create `dashboard/components/__init__.py`
- [ ] Verify `shared.py` imports work in isolation

### Phase 2: Extract Layouts (one file at a time)

- [ ] Extract `layouts/login.py` — login page + auth callbacks
- [ ] Extract `layouts/tab_overview.py` — main dashboard + core callbacks
- [ ] Extract `layouts/tab_alerts.py` — alert/threat views + callbacks
- [ ] Extract `layouts/tab_devices.py` — device/IoT views + callbacks
- [ ] Extract `layouts/tab_analytics.py` — analytics/reports + callbacks
- [ ] Extract `layouts/tab_integrations.py` — API hub/email + callbacks
- [ ] Extract `layouts/tab_compliance.py` — compliance/security + callbacks
- [ ] Extract `layouts/tab_admin.py` — admin/user mgmt + callbacks

### Phase 3: Extract Components

- [ ] Extract `components/modals.py` — generic toggle callbacks
- [ ] Extract `components/toasts.py` — toast management callbacks
- [ ] Extract `components/chat.py` — AI chat callbacks

### Phase 4: Slim Down `app.py`

- [ ] Replace monolithic layout with tab container
- [ ] Import all sub-modules for callback registration
- [ ] Verify `main()` entry point works
- [ ] Verify Flask routes still work (health, OAuth, WebAuthn)

### Phase 5: Validation

- [ ] All 250+ callbacks register without error
- [ ] All 52 modals open/close correctly
- [ ] Authentication flow works (login, register, logout, OAuth, WebAuthn)
- [ ] WebSocket real-time updates work
- [ ] All charts render correctly
- [ ] Dark mode / theme toggle works
- [ ] Keyboard shortcuts work
- [ ] Spotlight search works
- [ ] AI chat works
- [ ] All downloads (CSV, PDF, Excel, JSON) work
- [ ] No Python import errors
- [ ] No Dash callback ID conflicts

---

## 9. Component Ownership Matrix

Components that are referenced by callbacks in **multiple tabs** need special handling. These "shared components" remain in the global layout (outside any tab), or in `components/`:

| Component ID               | Referenced By           | Location            |
| -------------------------- | ----------------------- | ------------------- |
| `toast-container`          | All tabs                | `app.py` (global)   |
| `url` (dcc.Location)       | Auth + all tabs         | `app.py` (global)   |
| `user-session` (Store)     | Auth + all tabs         | `app.py` (global)   |
| `auth-notification-store`  | Auth callbacks          | `app.py` (global)   |
| `page-content`             | URL routing             | `app.py` (global)   |
| `ws` (WebSocket)           | Overview + System       | `app.py` (global)   |
| `main-interval`            | Multiple tabs           | `app.py` (global)   |
| `alert-check-interval`     | Alerts + Overview       | `app.py` (global)   |
| `notification-bell-button` | Header (always visible) | Header bar (global) |
| All `dcc.Store`            | Various tabs            | `app.py` (global)   |
| All `dcc.Download`         | Various tabs            | `app.py` (global)   |

---

## 10. Risk Assessment

| Risk                                          | Likelihood | Impact | Mitigation                                                   |
| --------------------------------------------- | ---------- | ------ | ------------------------------------------------------------ |
| Circular imports                              | Medium     | High   | `shared.py` pattern with deferred app reference              |
| Callback ID conflicts                         | Low        | High   | Each callback stays in its owning tab file                   |
| Missing callback registration                 | Medium     | High   | Import all modules in `app.py`; test each modal              |
| Cross-tab component references                | Medium     | Medium | `suppress_callback_exceptions=True` already on               |
| WebSocket data not reaching new tab structure | Low        | High   | WebSocket callbacks stay in `shared.py` or `tab_overview.py` |
| CSS breaking with new tab wrapper             | Low        | Low    | Tab container is transparent; existing CSS untouched         |
| Performance regression (eager rendering)      | Low        | Medium | Identical to current behavior (all components rendered)      |

---

## 11. Success Criteria

1. **Feature parity**: Every feature card, modal, chart, form, and button from the monolithic version exists and works identically
2. **No callback changes**: All `@app.callback` decorators have identical `Input`/`Output`/`State` signatures
3. **File size reduction**: `app.py` goes from ~38,600 lines to ~500 lines
4. **Navigability**: Each tab file is ≤5,000 lines, focused on one domain
5. **Startup**: `main()` in `app.py` starts the dashboard identically
6. **Tests pass**: All existing tests continue to pass without modification

---

## 12. Out of Scope

- Adding new features or UI elements
- Removing any existing features
- Changing callback logic or signatures
- Changing authentication flow
- Changing database schema
- Changing the orchestrator integration
- Adding new dependencies
- Performance optimization (separate effort)
- Mobile-specific layout changes
- API versioning

---

## Appendix A: Current File Line Ranges (Reference)

| Section                                | Lines       | Target File                                             |
| -------------------------------------- | ----------- | ------------------------------------------------------- |
| Imports                                | 1–100       | `shared.py`                                             |
| Logging config                         | 100–200     | `shared.py`                                             |
| App init + services                    | 200–450     | `shared.py` + `app.py`                                  |
| Flask routes (health, OAuth, WebAuthn) | 450–830     | `shared.py`                                             |
| AI fallback rules                      | 830–890     | `shared.py`                                             |
| Constants (MITRE, severity, icons)     | 890–1210    | `shared.py`                                             |
| DB helpers                             | 1210–1460   | `shared.py`                                             |
| UI helpers                             | 1460–1700   | `shared.py`                                             |
| Educational explanation builder        | 1700–2150   | `shared.py`                                             |
| Login layout                           | 2150–2980   | `layouts/login.py`                                      |
| Spotlight search data + helpers        | 2980–3090   | `shared.py`                                             |
| Dashboard layout (header)              | 3090–3300   | `layouts/tab_overview.py` (header extracted separately) |
| Dashboard layout (3-column)            | 3300–3800   | `layouts/tab_overview.py`                               |
| Feature cards (masonry grid)           | 3800–4800   | Split across `tab_alerts.py` through `tab_admin.py`     |
| Feature card modals (all 26+)          | 4800–11100  | Split across tab files by domain                        |
| Global stores/intervals/downloads      | 11100–11170 | `app.py` (global)                                       |
| app.layout definition                  | 11170–11210 | `app.py`                                                |
| Query helpers                          | 11210–11300 | `shared.py`                                             |
| Core dashboard callbacks               | 11300–12100 | `layouts/tab_overview.py`                               |
| Toast callbacks                        | 12100–12500 | `components/toasts.py`                                  |
| Alert callbacks                        | 12500–12900 | `layouts/tab_alerts.py`                                 |
| Onboarding + lockdown callbacks        | 12900–13200 | `layouts/tab_admin.py` + `tab_compliance.py`            |
| Email settings callbacks               | 13200–13400 | `layouts/tab_integrations.py`                           |
| Analytics modal callbacks              | 13400–13700 | `layouts/tab_analytics.py`                              |
| System modal callbacks                 | 13700–14200 | `layouts/tab_admin.py`                                  |
| Quick settings + voice callbacks       | 14200–14400 | `layouts/tab_admin.py`                                  |
| AI chat callbacks                      | 14400–15000 | `components/chat.py`                                    |
| WebSocket thread + SocketIO            | 15200–15400 | `shared.py`                                             |
| Auth callbacks (routing, login)        | 15400–16300 | `layouts/login.py`                                      |
| Email verification helpers             | 16300–16700 | `layouts/login.py`                                      |
| Password toggle callbacks              | 16700–16900 | `layouts/login.py`                                      |
| Registration callbacks                 | 16900–17500 | `layouts/login.py`                                      |
| User management callbacks              | 17500–17900 | `layouts/tab_admin.py`                                  |
| Profile + biometric callbacks          | 17900–18600 | `layouts/tab_admin.py`                                  |
| Preferences + IoT callbacks            | 18600–19400 | `layouts/tab_admin.py` + `tab_devices.py`               |
| Device detail + IoT feature callbacks  | 19400–21400 | `layouts/tab_devices.py`                                |
| main() function                        | 21400–21500 | `app.py`                                                |
| Modal toggle callbacks (26x)           | 21500–22500 | `components/modals.py`                                  |
| Remaining feature callbacks            | 22500–38604 | Split across tab files                                  |
