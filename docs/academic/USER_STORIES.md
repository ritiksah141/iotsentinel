# User Stories for IoTSentinel

**Created**: November 2024
**Last Updated**: December 2025
**Purpose**: Define functional requirements from user perspective

**MoSCoW Priority Key**:

- 🔴 **MUST HAVE** - Critical for MVP
- 🟡 **SHOULD HAVE** - Important but not critical
- 🟢 **COULD HAVE** - Nice to have
- ⚫ **WON'T HAVE** - Out of scope

---

## 🔴 MUST HAVE (8 stories)

### US-001: Device Discovery

**As a** non-technical home user (Sarah)
**I want to** see all devices connected to my network automatically
**So that** I can identify unknown or suspicious devices

**Priority**: 🔴 MUST HAVE

**Acceptance Criteria**:

- [x] Device list shows: IP address, friendly name, device type, last seen timestamp
- [x] Auto-discovery completes within 5 minutes of device connecting
- [x] User can assign custom names to devices (e.g., "Sarah's iPhone")
- [x] Status indicators: Green (active), Gray (inactive > 5min)
- [x] At least 8 device types auto-detected (Laptop, Phone, Smart TV, IoT, etc.)

**Test Cases**: TC-CAP-001, TC-DB-001, TC-INT-001, TC-VAL-001

**Design Reference**: Dashboard → Devices Tab → Device List Component

**Implementation Files**:

- `capture/zeek_log_parser.py` (lines 67-151): Device extraction from Zeek logs
- `database/db_manager.py` (lines 45-122): `add_device()` method
- `dashboard/app.py` (lines 823-913): Device table rendering

---

### US-002: Real-Time Connection Monitoring

**As a** tech-curious homeowner (David)
**I want to** see live network connections as they happen
**So that** I can understand what my devices are communicating with

**Priority**: 🔴 MUST HAVE

**Acceptance Criteria**:

- [x] Live feed shows: Device → Destination IP, Port, Protocol, Data volume
- [x] Updates every 5 seconds without page refresh
- [x] Displays last 30 connections
- [x] Color-coded by protocol (TCP=blue, UDP=green, ICMP=red)
- [x] Shows data transfer in human-readable format (KB, MB, GB)

**Test Cases**: TC-DB-010, TC-SYS-002, TC-VAL-003

**Design Reference**: Dashboard → Network Tab → Live Connection Feed

**Implementation Files**:

- `dashboard/app.py` (lines 580-650): `update_recent_activity()` callback
- `database/db_manager.py` (lines 150-168): Recent connections query

---

### US-003: Anomaly Alert Generation

**As a** concerned parent (Sarah)
**I want to** receive alerts when unusual activity is detected
**So that** I can investigate potential security threats

**Priority**: 🔴 MUST HAVE

**Acceptance Criteria**:

- [x] Alert generated within 5 minutes of anomaly detection
- [x] Severity levels: Critical, High, Medium, Low (color-coded)
- [x] Alert includes: Device name, timestamp, plain-English explanation
- [x] Alerts persist in database (not just notifications)
- [x] New alerts highlighted with pulsing indicator

**Test Cases**: TC-ML-012, TC-DB-014, TC-INT-005, TC-VAL-004

**Design Reference**: Dashboard → Alerts Tab → Alert Cards

**Implementation Files**:

- `ml/inference_engine.py` (lines 100-200): Alert generation logic
- `database/db_manager.py` (lines 246-269): `create_alert()` method
- `dashboard/app.py` (lines 710-820): Alert display logic

---

### US-004: Educational Alert Explanation

**As a** tech-curious homeowner (David)
**I want to** understand WHY an alert was triggered
**So that** I can learn about network security concepts

**Priority**: 🔴 MUST HAVE

**Acceptance Criteria**:

- [x] Each alert has an "Explain This" drill-down section
- [x] Explanation includes:
  - Plain English summary (< 50 words)
  - Visual comparison (bar chart: normal vs. anomalous value)
  - Top 3 contributing features with values
  - Definition of "anomaly score" in simple terms
- [x] No jargon without accompanying tooltip definitions
- [x] Example: "Your Smart TV sent 1GB of data today. Its normal daily average is 10MB."

**Test Cases**: TC-VAL-002 (Usability Test)

**Design Reference**: Dashboard → Alerts Tab → Alert Accordion Component

**Implementation Files**:

- `dashboard/app.py` (lines 710-820): Educational drill-down rendering
- `ml/inference_engine.py` (lines 208-220): `_generate_explanation()` method

---

### US-005: 7-Day Baseline Training Period

**As a** system administrator
**I want to** collect 7 days of "normal" traffic before detection starts
**So that** the ML model learns what typical behavior looks like

**Priority**: 🔴 MUST HAVE

**Acceptance Criteria**:

- [x] Baseline collection initiated via CLI command
- [x] Progress indicator shows: Days elapsed, Data collected, Estimated completion
- [x] User notified to use network normally during this period
- [x] Data automatically fed to ML training after 7 days
- [x] Cannot start monitoring without completed baseline

**Test Cases**: TC-INT-006, TC-ML-015 through TC-ML-021

**Design Reference**: CLI Tool → `baseline_collector.py`

**Implementation Files**:

- `scripts/baseline_collector.py` (lines 25-263): Collection orchestration
- `ml/train_isolation_forest.py` (lines 30-145): Training on baseline data
- `ml/train_autoencoder.py` (lines 60-212): Autoencoder training

---

### US-006: Device Activity Heatmap

**As a** tech-curious homeowner (David)
**I want to** see when each device is most active throughout the day
**So that** I can identify unusual usage patterns

**Priority**: 🔴 MUST HAVE

**Acceptance Criteria**:

- [x] Heatmap shows: Devices (Y-axis) × Hour of Day (X-axis)
- [x] Color intensity represents connection count
- [x] Covers last 24 hours
- [x] Limited to top 10 most active devices for readability
- [x] Hover shows exact connection count

**Test Cases**: TC-VAL-005

**Design Reference**: Dashboard → Devices Tab → Heatmap Component

**Implementation Files**:

- `dashboard/app.py` (lines 916-963): `update_device_heatmap()` callback

---

### US-007: Alert Timeline (7 Days)

**As a** concerned parent (Sarah)
**I want to** see a timeline of all alerts over the past week
**So that** I can identify patterns or recurring issues

**Priority**: 🔴 MUST HAVE

**Acceptance Criteria**:

- [x] Stacked bar chart: Date (X-axis) × Alert Count (Y-axis)
- [x] Color-coded by severity
- [x] Covers last 7 days
- [x] Click on bar to filter alerts for that day
- [x] Shows "All Clear" message if no alerts

**Test Cases**: TC-VAL-006

**Design Reference**: Dashboard → Analytics Tab → Alert Timeline Chart

**Implementation Files**:

- `dashboard/app.py` (lines 969-1021): `update_alert_timeline()` callback

---

### US-008: Dashboard Performance (< 3s Load)

**As a** budget-conscious user (Margaret)
**I want to** the dashboard to load quickly on my old iPad
**So that** I don't get frustrated waiting for pages to load

**Priority**: 🔴 MUST HAVE

**Acceptance Criteria**:

- [x] Initial page load < 3 seconds
- [x] Auto-refresh interval: 5 seconds (not constant polling)
- [x] No browser lag when viewing 50+ connections
- [x] Optimized database queries (indexes on timestamp, device_ip)
- [x] Lazy loading for large datasets

**Test Cases**: TC-DB-022, TC-INT-006, TC-SYS-003 (Performance Test)

**Design Reference**: Architecture → Performance Optimization

**Implementation Files**:

- `database/db_manager.py` (line 39): Database indexes
- `dashboard/app.py`: Dash configuration and optimized callbacks

---

## 🟡 SHOULD HAVE (6 stories)

### US-009: Alert Filtering by Severity

**As a** concerned parent (Sarah)
**I want to** filter alerts by severity level
**So that** I can focus on critical issues first

**Priority**: 🟡 SHOULD HAVE

**Acceptance Criteria**:

- [x] Button group: All, Critical, High, Medium, Low
- [x] Filter applies immediately (no page reload)
- [x] Badge shows count for each severity
- [x] Filtered state persists during session

**Test Cases**: TC-VAL-007

**Design Reference**: Dashboard → Alerts Tab → Filter Buttons

**Implementation Files**:

- `dashboard/app.py` (lines 710-843): Filter callback

---

### US-010: Model Accuracy Metrics Display

**As a** tech-curious homeowner (David)
**I want to** see how accurate the ML models are
**So that** I can trust the alert system

**Priority**: 🟡 SHOULD HAVE

**Acceptance Criteria**:

- [x] Display precision, recall, F1-score for each model
- [x] Show anomaly detection rate (% of connections flagged)
- [x] Comparison table: Isolation Forest vs. Autoencoder
- [x] Updated daily

**Test Cases**: TC-ML-023, TC-VAL-008, TC-ML-024, TC-VAL-013

**Design Reference**: Dashboard → System Tab → Model Performance Section

**Implementation Files**:

- `dashboard/app.py` (lines 389-432, 1015-1036): Model info and comparison display
- `ml/inference_engine.py` (lines 233-258): Metric calculation
- `scripts/compare_models.py` (lines 1-160): Offline model comparison script

---

### US-011: Privacy Controls (Pause Monitoring)

**As a** privacy-conscious user
**I want to** pause monitoring temporarily
**So that** I have control over when my network is being watched

**Priority**: 🟡 SHOULD HAVE

**Acceptance Criteria**:

- [x] "Pause Monitoring" button on dashboard
- [x] Stops Zeek log parsing and ML inference
- [x] Shows large "MONITORING PAUSED" banner
- [x] Can resume with single click
- [x] Pause state persists across restarts

**Test Cases**: TC-SEC-002

**Design Reference**: Dashboard → Header → Pause Button

**Implementation Files**:

- `dashboard/app.py` (lines 167-207): Pause button callback
- `ml/inference_engine.py` (lines 260-272): Pause state check

---

### US-012: System Health Monitoring

**As a** system administrator
**I want to** monitor Raspberry Pi resource usage
**So that** I know if the system is overloaded

**Priority**: 🟡 SHOULD HAVE

**Acceptance Criteria**:

- [x] Display: CPU %, RAM usage, Disk usage
- [x] Warning threshold: CPU > 80%, RAM > 90%
- [x] Alert if Zeek process crashes
- [x] Log rotation to prevent disk full

**Test Cases**: TC-SYS-004, TC-SYS-005

**Design Reference**: Dashboard → System Tab → Health Metrics

**Implementation Files**:

- `utils/metrics_collector.py` (lines 21-401): System metrics collection
- `orchestrator.py` (lines 1-122): System process management

---

### US-013: Data Export (CSV) & Reporting

**As a** tech-curious homeowner (David)
**I want to** export connection data to CSV and get weekly reports
**So that** I can analyze it in Excel or Python

**Priority**: 🟡 SHOULD HAVE

**Acceptance Criteria**:

- [x] Export button for: Connections, Alerts, ML Predictions
- [x] Date range selector
- [x] CSV includes all relevant columns
- [x] Automated weekly PDF report generation

**Test Cases**: TC-VAL-009, TC-VAL-014

**Design Reference**: Dashboard → Each Tab → Export Button

**Implementation Files**:

- `dashboard/app.py` (lines 155-158, 434-449): CSV export callbacks
- `scripts/generate_report.py` (lines 1-103): Weekly PDF report generator

---

### US-014: Alert Acknowledgment

**As a** concerned parent (Sarah)
**I want to** acknowledge alerts I've reviewed
**So that** I can focus on new unresolved alerts

**Priority**: 🟡 SHOULD HAVE

**Acceptance Criteria**:

- [x] "Acknowledge" button on each alert
- [x] Acknowledged alerts grayed out
- [x] Timestamp of acknowledgment stored
- [x] Filter: "Show only unacknowledged"

**Test Cases**: TC-DB-016, TC-VAL-010

**Design Reference**: Dashboard → Alerts Tab → Alert Actions

**Implementation Files**:

- `database/db_manager.py` (lines 404-417): `acknowledge_alert()` method
- `dashboard/app.py` (lines 710-820): Acknowledge button callback

---

## 🟢 COULD HAVE (4 stories)

### US-015: Device & Network Controls

**As a** concerned parent (Sarah)
**I want to** block a suspicious device from the network
**So that** I can immediately stop a potential threat

**Priority**: 🟢 COULD HAVE

**Acceptance Criteria**:

- [x] "Block Device" button on device details
- [x] Confirmation dialog (prevent accidental blocks)
- [x] Device added to firewall blocklist
- [x] "Network Lockdown" button to block all new/unknown devices

**Test Cases**: TC-SEC-004

**Design Reference**: Dashboard → Devices Tab / Header

**Implementation Files**:

- `scripts/firewall_manager.py` (lines 1-97): `iptables` rules management
- `dashboard/app.py` (lines 888-905, 1104-1145): Block & Lockdown callbacks

---

### US-016: Email Notifications

**As a** concerned parent (Sarah)
**I want to** receive email alerts for critical anomalies
**So that** I'm notified even when not viewing the dashboard

**Priority**: 🟢 COULD HAVE

**Acceptance Criteria**:

- [x] Email sent for severity = "Critical" only
- [x] Contains: Device name, explanation, link to dashboard
- [x] Rate-limited to 1 email per hour (prevent spam)
- [x] User can configure SMTP in settings

**Test Cases**: TC-INT-011

**Design Reference**: Alerting Subsystem

**Implementation Files**:

- `alerts/email_notifier.py` (lines 1-86): SMTP logic
- `ml/inference_engine.py` (lines 184-193): Hook to trigger email

---

### US-017: Mobile Responsiveness

**As a** budget-conscious user (Margaret)
**I want to** view the dashboard on my iPhone
**So that** I can check network status easily

**Priority**: 🟢 COULD HAVE

**Acceptance Criteria**:

- [x] Dashboard renders correctly on screens < 768px width
- [x] Navigation collapses to hamburger menu
- [x] Charts resize responsively
- [x] Touch-friendly buttons (44px min height)

**Test Cases**: TC-VAL-011

**Design Reference**: Dashboard → Mobile Layout

**Implementation Files**:

- `dashboard/assets/custom.css` (lines 1-22): Media queries for mobile
- `dashboard/app.py`: Use of Dash Bootstrap responsive classes

---

### US-018: Onboarding Wizard

**As a** budget-conscious user (Margaret)
**I want to** a step-by-step setup wizard
**So that** I don't need to call my son for help

**Priority**: 🟢 COULD HAVE

**Acceptance Criteria**:

- [x] Wizard (modal) starts on first launch
- [x] Steps: 1) Welcome, 2) Baseline explanation, 3) Start Baseline
- [x] Progress indicator (e.g., "Step 2 of 3")
- [x] Can be dismissed and re-opened
- [x] Large font, clear instructions

**Test Cases**: TC-VAL-012

**Design Reference**: Dashboard → Onboarding Modal

**Implementation Files**:

- `dashboard/app.py` (lines 142-207): Onboarding modal and callbacks

---

## ⚫ WON'T HAVE (2 items)

### NH-001: Deep Packet Inspection (DPI)

**Rationale**:

- Privacy concerns (analyzing packet payloads)
- Performance impact on Raspberry Pi
- Zeek provides sufficient metadata without DPI
- Scope: Educational transparency, not forensics

---

### NH-002: Multi-Network Support

**Rationale**:

- Designed for single home network
- Complexity: Managing multiple Zeek instances
- Target users have 1 network
- Scope: Home use, not enterprise

---

## User Story Statistics

| Category       | Count  | Status                |
| :------------- | :----- | :-------------------- |
| 🔴 MUST HAVE   | 8      | ✅ 100% Complete      |
| 🟡 SHOULD HAVE | 6      | ✅ 100% Complete      |
| 🟢 COULD HAVE  | 4      | ✅ 100% Complete      |
| ⚫ WON'T HAVE  | 2      | N/A                   |
| **TOTAL**      | **20** | **18/18 Implemented** |

---
