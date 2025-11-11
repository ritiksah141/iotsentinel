# User Stories for IoTSentinel

**Created**:
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

- [ ] Device list shows: IP address, friendly name, device type, last seen timestamp
- [ ] Auto-discovery completes within 5 minutes of device connecting
- [ ] User can assign custom names to devices (e.g., "Sarah's iPhone")
- [ ] Status indicators: Green (active), Gray (inactive > 5min)
- [ ] At least 8 device types auto-detected (Laptop, Phone, Smart TV, IoT, etc.)

**Test Cases**: TC-INT-001, TC-INT-002, TC-VAL-001

**Design Reference**: Dashboard → Devices Tab → Device List Component

**Implementation Files**:

- `capture/zeek_log_parser.py` (lines 67-89): Device extraction from Zeek logs
- `database/db_manager.py` (lines 45-72): `add_device()` method
- `dashboard/app.py` (lines 580-650): Device table rendering

---

### US-002: Real-Time Connection Monitoring

**As a** tech-curious homeowner (David)  
**I want to** see live network connections as they happen  
**So that** I can understand what my devices are communicating with

**Priority**: 🔴 MUST HAVE

**Acceptance Criteria**:

- [ ] Live feed shows: Device → Destination IP, Port, Protocol, Data volume
- [ ] Updates every 5 seconds without page refresh
- [ ] Displays last 30 connections
- [ ] Color-coded by protocol (TCP=blue, UDP=green, ICMP=red)
- [ ] Shows data transfer in human-readable format (KB, MB, GB)

**Test Cases**: TC-SYS-002, TC-VAL-003

**Design Reference**: Dashboard → Network Tab → Live Connection Feed

**Implementation Files**:

- `dashboard/app.py` (lines 450-520): `update_recent_activity()` callback
- `database/db_manager.py` (lines 150-180): Recent connections query

---

### US-003: Anomaly Alert Generation

**As a** concerned parent (Sarah)  
**I want to** receive alerts when unusual activity is detected  
**So that** I can investigate potential security threats

**Priority**: 🔴 MUST HAVE

**Acceptance Criteria**:

- [ ] Alert generated within 5 minutes of anomaly detection
- [ ] Severity levels: Critical, High, Medium, Low (color-coded)
- [ ] Alert includes: Device name, timestamp, plain-English explanation
- [ ] Alerts persist in database (not just notifications)
- [ ] New alerts highlighted with pulsing indicator

**Test Cases**: TC-INT-005, TC-VAL-004

**Design Reference**: Dashboard → Alerts Tab → Alert Cards

**Implementation Files**:

- `ml/inference_engine.py` (lines 120-180): Alert generation logic
- `database/db_manager.py` (lines 220-250): `create_alert()` method
- `dashboard/app.py` (lines 650-800): Alert display with educational features

---

### US-004: Educational Alert Explanation

**As a** tech-curious homeowner (David)  
**I want to** understand WHY an alert was triggered  
**So that** I can learn about network security concepts

**Priority**: 🔴 MUST HAVE

**Acceptance Criteria**:

- [ ] Each alert has an "Explain This" drill-down section
- [ ] Explanation includes:
  - Plain English summary (< 50 words)
  - Visual comparison (bar chart: normal vs. anomalous value)
  - Top 3 contributing features with values
  - Definition of "anomaly score" in simple terms
- [ ] No jargon without accompanying tooltip definitions
- [ ] Example: "Your Smart TV sent 1GB of data today. Its normal daily average is 10MB."

**Test Cases**: TC-VAL-002 (Usability Test)

**Design Reference**: Dashboard → Alerts Tab → Alert Accordion Component

**Implementation Files**:

- `dashboard/app.py` (lines 710-780): Educational drill-down rendering
- `ml/inference_engine.py` (lines 155-175): `_generate_explanation()` method

---

### US-005: 7-Day Baseline Training Period

**As a** system administrator  
**I want to** collect 7 days of "normal" traffic before detection starts  
**So that** the ML model learns what typical behavior looks like

**Priority**: 🔴 MUST HAVE

**Acceptance Criteria**:

- [ ] Baseline collection initiated via CLI command
- [ ] Progress indicator shows: Days elapsed, Data collected, Estimated completion
- [ ] User notified to use network normally during this period
- [ ] Data automatically fed to ML training after 7 days
- [ ] Cannot start monitoring without completed baseline

**Test Cases**: TC-INT-006

**Design Reference**: CLI Tool → `baseline_collector.py`

**Implementation Files**:

- `scripts/baseline_collector.py` (lines 50-200): Collection orchestration
- `ml/train_isolation_forest.py` (lines 40-120): Training on baseline data
- `ml/train_autoencoder.py` (lines 60-150): Autoencoder training

---

### US-006: Device Activity Heatmap

**As a** tech-curious homeowner (David)  
**I want to** see when each device is most active throughout the day  
**So that** I can identify unusual usage patterns

**Priority**: 🔴 MUST HAVE

**Acceptance Criteria**:

- [ ] Heatmap shows: Devices (Y-axis) × Hour of Day (X-axis)
- [ ] Color intensity represents connection count
- [ ] Covers last 24 hours
- [ ] Limited to top 10 most active devices for readability
- [ ] Hover shows exact connection count

**Test Cases**: TC-VAL-005

**Design Reference**: Dashboard → Devices Tab → Heatmap Component

**Implementation Files**:

- `dashboard/app.py` (lines 850-920): `update_device_heatmap()` callback

---

### US-007: Alert Timeline (7 Days)

**As a** concerned parent (Sarah)  
**I want to** see a timeline of all alerts over the past week  
**So that** I can identify patterns or recurring issues

**Priority**: 🔴 MUST HAVE

**Acceptance Criteria**:

- [ ] Stacked bar chart: Date (X-axis) × Alert Count (Y-axis)
- [ ] Color-coded by severity
- [ ] Covers last 7 days
- [ ] Click on bar to filter alerts for that day
- [ ] Shows "All Clear" message if no alerts

**Test Cases**: TC-VAL-006

**Design Reference**: Dashboard → Analytics Tab → Alert Timeline Chart

**Implementation Files**:

- `dashboard/app.py` (lines 950-1020): `update_alert_timeline()` callback

---

### US-008: Dashboard Performance (< 3s Load)

**As a** budget-conscious user (Margaret)  
**I want to** the dashboard to load quickly on my old iPad  
**So that** I don't get frustrated waiting for pages to load

**Priority**: 🔴 MUST HAVE

**Acceptance Criteria**:

- [ ] Initial page load < 3 seconds
- [ ] Auto-refresh interval: 5 seconds (not constant polling)
- [ ] No browser lag when viewing 50+ connections
- [ ] Optimized database queries (indexes on timestamp, device_ip)
- [ ] Lazy loading for large datasets

**Test Cases**: TC-SYS-003 (Performance Test)

**Design Reference**: Architecture → Performance Optimization

**Implementation Files**:

- `database/db_manager.py` (lines 25-40): Database indexes
- `dashboard/app.py` (lines 100-150): Dash configuration

---

## 🟡 SHOULD HAVE (6 stories)

### US-009: Alert Filtering by Severity

**As a** concerned parent (Sarah)  
**I want to** filter alerts by severity level  
**So that** I can focus on critical issues first

**Priority**: 🟡 SHOULD HAVE

**Acceptance Criteria**:

- [ ] Button group: All, Critical, High, Medium, Low
- [ ] Filter applies immediately (no page reload)
- [ ] Badge shows count for each severity
- [ ] Filtered state persists during session

**Test Cases**: TC-VAL-007

**Design Reference**: Dashboard → Alerts Tab → Filter Buttons

**Implementation Files**:

- `dashboard/app.py` (lines 680-710): Filter callback

---

### US-010: Model Accuracy Metrics Display

**As a** tech-curious homeowner (David)  
**I want to** see how accurate the ML models are  
**So that** I can trust the alert system

**Priority**: 🟡 SHOULD HAVE

**Acceptance Criteria**:

- [ ] Display precision, recall, F1-score for each model
- [ ] Show anomaly detection rate (% of connections flagged)
- [ ] Comparison table: Isolation Forest vs. Autoencoder
- [ ] Updated daily

**Test Cases**: TC-VAL-008

**Design Reference**: Dashboard → System Tab → Model Performance Section

**Implementation Files**:

- `dashboard/app.py` (lines 1200-1280): Model info display

---

### US-011: Privacy Controls (Pause Monitoring)

**As a** privacy-conscious user  
**I want to** pause monitoring temporarily  
**So that** I have control over when my network is being watched

**Priority**: 🟡 SHOULD HAVE

**Acceptance Criteria**:

- [ ] "Pause Monitoring" button on dashboard
- [ ] Stops Zeek log parsing and ML inference
- [ ] Shows large "MONITORING PAUSED" banner
- [ ] Can resume with single click
- [ ] Pause state persists across restarts

**Test Cases**: TC-SEC-002

**Design Reference**: Dashboard → Header → Pause Button

**Implementation Files**: (Not yet implemented)

---

### US-012: System Health Monitoring

**As a** system administrator  
**I want to** monitor Raspberry Pi resource usage  
**So that** I know if the system is overloaded

**Priority**: 🟡 SHOULD HAVE

**Acceptance Criteria**:

- [ ] Display: CPU %, RAM usage, Disk usage
- [ ] Warning threshold: CPU > 80%, RAM > 90%
- [ ] Alert if Zeek process crashes
- [ ] Log rotation to prevent disk full

**Test Cases**: TC-SYS-004

**Design Reference**: Dashboard → System Tab → Health Metrics

**Implementation Files**:

- `utils/metrics_collector.py` (lines 50-120): System metrics collection

---

### US-013: Data Export (CSV)

**As a** tech-curious homeowner (David)  
**I want to** export connection data to CSV  
**So that** I can analyze it in Excel or Python

**Priority**: 🟡 SHOULD HAVE

**Acceptance Criteria**:

- [ ] Export button for: Connections, Alerts, ML Predictions
- [ ] Date range selector
- [ ] CSV includes all relevant columns
- [ ] File size < 10MB (paginate if needed)

**Test Cases**: TC-VAL-009

**Design Reference**: Dashboard → Each Tab → Export Button

**Implementation Files**: (Not yet implemented)

---

### US-014: Alert Acknowledgment

**As a** concerned parent (Sarah)  
**I want to** acknowledge alerts I've reviewed  
**So that** I can focus on new unresolved alerts

**Priority**: 🟡 SHOULD HAVE

**Acceptance Criteria**:

- [ ] "Acknowledge" button on each alert
- [ ] Acknowledged alerts grayed out
- [ ] Timestamp of acknowledgment stored
- [ ] Filter: "Show only unacknowledged"

**Test Cases**: TC-VAL-010

**Design Reference**: Dashboard → Alerts Tab → Alert Actions

**Implementation Files**:

- `database/db_manager.py` (lines 270-290): `acknowledge_alert()` method
- `dashboard/app.py` (lines 780-800): Acknowledge button callback

---

## 🟢 COULD HAVE (4 stories)

### US-015: Device Blocking (Future Feature)

**As a** concerned parent (Sarah)  
**I want to** block a suspicious device from the network  
**So that** I can immediately stop a potential threat

**Priority**: 🟢 COULD HAVE

**Acceptance Criteria**:

- [ ] "Block Device" button on device details
- [ ] Confirmation dialog (prevent accidental blocks)
- [ ] Device added to router's MAC address filter
- [ ] Can unblock from dashboard

**Test Cases**: (Not yet defined)

**Design Reference**: Future enhancement

**Implementation Notes**: Requires router API integration (complexity high)

---

### US-016: Email Notifications

**As a** concerned parent (Sarah)  
**I want to** receive email alerts for critical anomalies  
**So that** I'm notified even when not viewing the dashboard

**Priority**: 🟢 COULD HAVE

**Acceptance Criteria**:

- [ ] Email sent for severity = "Critical" only
- [ ] Contains: Device name, explanation, link to dashboard
- [ ] Rate-limited to 1 email per hour (prevent spam)
- [ ] User can disable in settings

**Test Cases**: (Not yet defined)

**Design Reference**: Future enhancement

**Implementation Notes**: Requires SMTP configuration

---

### US-017: Mobile Responsiveness

**As a** budget-conscious user (Margaret)  
**I want to** view the dashboard on my iPhone  
**So that** I can check network status while away from home

**Priority**: 🟢 COULD HAVE

**Acceptance Criteria**:

- [ ] Dashboard renders correctly on screens < 768px width
- [ ] Navigation collapses to hamburger menu
- [ ] Charts resize responsively
- [ ] Touch-friendly buttons (44px min height)

**Test Cases**: TC-VAL-011

**Design Reference**: Dashboard → Mobile Layout

**Implementation Files**:

- `dashboard/app.py` (lines 80-100): Dash Bootstrap responsive classes

---

### US-018: Onboarding Wizard

**As a** budget-conscious user (Margaret)  
**I want to** a step-by-step setup wizard  
**So that** I don't need to call my son for help

**Priority**: 🟢 COULD HAVE

**Acceptance Criteria**:

- [ ] Wizard starts on first launch
- [ ] Steps: 1) Network selection, 2) Device naming, 3) Baseline start
- [ ] Progress indicator (e.g., "Step 2 of 3")
- [ ] Can skip and return later
- [ ] Large font, clear instructions

**Test Cases**: (Not yet defined)

**Design Reference**: Future enhancement

**Implementation Notes**: Requires multi-page Dash app structure

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

| Category       | Count  |
| -------------- | ------ |
| 🔴 MUST HAVE   | 8      |
| 🟡 SHOULD HAVE | 6      |
| 🟢 COULD HAVE  | 4      |
| ⚫ WON'T HAVE  | 2      |
| **TOTAL**      | **20** |

---
