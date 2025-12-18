# IoTSentinel API Reference

**Version**: 1.0
**Base URL**: `http://<raspberry-pi-ip>:8050`
**Protocol**: HTTP/HTTPS
**Architecture**: Dash Single-Page Application with Flask backend
**Authentication**: Session-based (Flask-Login)

---

## 📋 Overview

IoTSentinel is built using the **Dash framework** (Plotly), which provides a component-based single-page application. The system uses **Dash callbacks** for data updates rather than traditional REST API endpoints.

### Architecture

```
Web Browser
    ↓ HTTP/HTTPS + WebSocket
Dash Single-Page Application
    ↓ @app.callback decorators
Database Layer (db_manager.py)
    ↓ SQLite
network_monitoring.db
```

### Available Interfaces

1. **Web Dashboard** - Main user interface (GET /)
2. **Health Endpoint** - REST API for monitoring (GET /health)
3. **Dash Callbacks** - Internal component updates (automatic)
4. **Database Layer** - Direct database access (programmatic)

---

## 📋 Table of Contents

1. [Health Monitoring (REST Endpoint)](#health-monitoring-rest-endpoint)
2. [Web Dashboard](#web-dashboard)
3. [Dashboard Operations](#-dashboard-operations)
   - [Device Management](#device-management-operations)
   - [Alert Management](#alert-management-operations)
   - [System Configuration](#system-configuration-operations)
   - [Data Export](#data-export-operations)
   - [Analytics & Visualizations](#analytics--visualization-updates)
   - [AI Assistant](#ai-assistant-operations)
4. [Authentication](#authentication)
5. [Data Access Layer](#data-access-layer)
6. [Real-Time Updates](#real-time-updates)
7. [Security](#security)
8. [Integration Guide](#integration-guide)

---

## 🏥 Health Monitoring (REST Endpoint)

### Health Check

**Endpoint**: `GET /health`

**Description**: System health status (no authentication required)

**Implementation**: `dashboard/app.py:133-200`

**Request**:
```http
GET /health HTTP/1.1
```

**Response** (Healthy):
```json
{
  "status": "healthy",
  "timestamp": "2025-12-16T01:30:00Z",
  "components": {
    "database": {
      "status": "healthy",
      "device_count": 12
    },
    "authentication": {
      "status": "healthy",
      "user_count": 1
    }
  }
}
```

**Response** (Unhealthy):
```json
{
  "status": "unhealthy",
  "timestamp": "2025-12-16T01:30:00Z",
  "components": {
    "database": {
      "status": "unhealthy",
      "error": "Connection timeout"
    }
  }
}
```

**HTTP Status Codes**:
- `200 OK`: All components healthy
- `503 Service Unavailable`: One or more critical components down

**Use Cases**:
- Container health checks
- Deployment verification
- Uptime monitoring
- Load balancer health probes

---

## 🖥️ Web Dashboard

### Main Dashboard

**Endpoint**: `GET /`

**Description**: Single-page Dash application with all features

**Authentication**: Required (Flask-Login)

**Request**:
```http
GET / HTTP/1.1
Cookie: session=...
```

**Response**: HTML page with embedded React components

**Features**:
- Device list with real-time status
- Alert feed with severity indicators
- Network activity heatmap
- Alert timeline (7 days)
- System health metrics
- AI Assistant chat
- Settings panel
- Export functionality

**Update Frequency**: Components refresh every 5 seconds via Dash callbacks

---

## 🎛️ Dashboard Operations

All dashboard operations are performed through **Dash callbacks** triggered by user interactions. Below are the key operations available:

### Device Management Operations

#### Update Device Metadata

**Callback**: `save_device_changes` @ `app.py:4244`

**Trigger**: Edit device modal → Save button

**Operation**:
```python
db_manager.update_device_metadata(
    device_ip=ip,
    custom_name=name,
    device_type=device_type,
    notes=notes
)
```

**Fields**:
- Custom name
- Device type
- Group assignment
- Notes/description

---

#### Trust Device

**Callback**: `toggle_device_trust` @ `app.py:5012`

**Trigger**: Device card → Trust toggle switch

**Operation**:
```python
db_manager.update_device_trust(device_ip, is_trusted=True)
```

**Effect**:
- Marks device as trusted
- Excludes from lockdown mode blocking
- Visual indicator updates (green badge)

---

#### Block Device

**Callback**: `toggle_device_block` @ `app.py:5053`

**Trigger**: Device card → Block button

**Operation**:
```python
firewall_manager.block_device(device_ip)
db_manager.update_device_block_status(device_ip, is_blocked=True)
```

**Effect**:
- Adds firewall rule to block device
- Updates database status
- Device appears as "Blocked" in UI

**Requirements**: Firewall manager must be configured

---

#### View Device Details

**Callback**: `toggle_device_details` @ `app.py:4879`

**Trigger**: Click device card or list item

**Displays**:
- Device information (IP, MAC, hostname, manufacturer)
- Connection statistics (total connections, data sent/received)
- Activity timeline
- Trust/block controls
- Recent connections

**Data Sources**:
- `db_manager.get_device_by_ip()`
- `db_manager.get_device_connections()`
- `db_manager.get_device_baseline()`

---

### Alert Management Operations

#### View Alert Details

**Callback**: `toggle_alert_details` @ `app.py:5208`

**Trigger**: Click alert card → "Details" button

**Displays**:
- Alert severity and timestamp
- Device information
- Educational explanation
- Baseline vs Today comparison charts
- MITRE ATT&CK mapping
- Contributing factors
- Recommended actions

**Implementation**: `get_alert_with_context()` @ `app.py:722`

---

#### Filter Alerts by Severity

**Callback**: `update_alert_filter` @ `app.py:5235`

**Trigger**: Alert severity filter dropdown

**Options**:
- All alerts
- Critical only
- High severity
- Medium severity
- Low severity

**Effect**: Updates alert feed to show only selected severity level

---

#### Acknowledge Alert

**Database Method**: `db_manager.acknowledge_alert()`

**Location**: `db_manager.py:404-417`

**Operation**:
```python
db_manager.acknowledge_alert(
    alert_id=42,
    acknowledged_by="admin",
    notes="Investigated - false positive"
)
```

**Effect**:
- Marks alert as acknowledged
- Records username and timestamp
- Optional notes field

---

### System Configuration Operations

#### Lockdown Mode

**Callback**: `handle_lockdown_confirmation` @ `app.py:5368`

**Trigger**: Settings → Firewall Control → Lockdown toggle → Confirm

**Operation**:
```python
if lockdown_enabled:
    firewall_manager.enable_lockdown_mode()  # Block all untrusted devices
else:
    firewall_manager.disable_lockdown_mode()  # Restore normal access
```

**Effect**:
- Blocks ALL untrusted devices using firewall rules
- Only trusted devices can access network
- Emergency security measure

**Requirements**:
- Firewall manager configured
- At least one device marked as trusted (recommended)

---

#### Email Notifications Setup

**Callback**: `load_email_settings` @ `app.py:5444`

**Trigger**: Navigate to Settings → Notifications

**Configurable Settings**:
- Email alerts enabled/disabled
- Email address
- Notification severity threshold (critical, high, all)

**Storage**: User preferences in database

---

#### Pause/Resume Monitoring

**Database Method**: `db_manager.set_monitoring_status()`

**Trigger**: Settings → Privacy Controls

**Operations**:
```python
# Pause monitoring
db_manager.set_monitoring_status(enabled=False)
# Effect: Stops Zeek log parsing and ML inference

# Resume monitoring
db_manager.set_monitoring_status(enabled=True)
# Effect: Restarts monitoring services
```

**Use Case**: Privacy control when not monitoring needed

---

### Data Export Operations

#### Quick Export (CSV)

**Callback**: `quick_export` @ `app.py:10654-10697`

**Trigger**: Settings → Export → "Export Report" button

**Process**:
1. Fetches recent alerts (last 1000)
2. Fetches all devices
3. Generates CSV format
4. Returns download file

**Export Contents**:
- Alert history (timestamp, severity, device, explanation)
- Device inventory (IP, MAC, hostname, vendor, trust status)

**Format**: CSV file with two sections (Alerts, Devices)

**Filename**: `iotsentinel_report_YYYY-MM-DD.csv`

---

### Analytics & Visualization Updates

All charts and graphs update automatically every 5 seconds via these callbacks:

#### Network Activity Graph

**Callback**: `update_network_graph` @ `app.py:4497`

**Displays**: Device connections visualized as network graph

**Data**: Recent connections between devices and external IPs

---

#### Traffic Timeline

**Callback**: `update_traffic_timeline` @ `app.py:4684`

**Displays**: Network traffic over time (24 hours)

**Metrics**: Bytes sent/received per hour

---

#### Protocol Distribution

**Callback**: `update_protocol_pie` @ `app.py:4703`

**Displays**: Pie chart of protocol usage (TCP, UDP, ICMP)

**Data**: Connection counts by protocol

---

#### System Metrics

**Callback**: `update_system_metrics` @ `app.py:4329`

**Displays**:
- CPU usage
- Memory usage
- Disk usage
- System temperature (Raspberry Pi)

**Source**: `utils/metrics_collector.py`

---

#### Device Status Summary

**Callback**: `update_devices_status_compact` @ `app.py:4724`

**Displays**: Count of active/inactive/blocked devices

**Updates**: Every 5 seconds

---

#### Active Alerts Count

**Callback**: `update_header_stats` @ `app.py:4345`

**Displays**: Alert counts by severity in header

**Breakdown**: Critical, High, Medium, Low

---

### AI Assistant Operations

#### Chat with AI Assistant

**Implementation**: `call_ollama_api()` @ `app.py:223`

**Trigger**: Type message in AI Assistant chat

**Process**:
1. Check if Ollama API available
2. Build context (device count, alert count, recent alerts)
3. Send prompt to Ollama
4. Return AI-generated response
5. Fallback to rule-based responses if Ollama unavailable

**Supported Queries**:
- "Is my network secure?"
- "What devices are connected?"
- "Explain this alert"
- "How does IoTSentinel work?"
- "What is lockdown mode?"

**Fallback**: Rule-based responses @ `get_rule_based_response()` @ `app.py:265`

---

### Onboarding & Help

#### Launch Onboarding Tour

**Callback**: `launch_onboarding_modal` @ `app.py:5253`

**Trigger**: First login or Settings → "Restart Tour"

**Steps**:
1. Welcome & overview
2. Device monitoring explanation
3. Alert system walkthrough
4. Settings & controls guide

**Navigation**: Next/Previous buttons, step indicators

---

## 🔐 Authentication

### Login Flow

**Implementation**: Flask-Login with session management

**Location**: `dashboard/app.py:123-130`

**Process**:
1. User navigates to `/`
2. If not authenticated → redirect to login page
3. User submits credentials via form
4. Flask-Login validates credentials
5. Session created with HttpOnly cookie
6. Redirect back to dashboard

**Session Configuration**:
- Storage: Server-side Flask sessions
- Cookie: HttpOnly (prevents XSS)
- Timeout: 24 hours
- Secret Key: Environment variable `FLASK_SECRET_KEY`

### Rate Limiting

**Implementation**: `utils/rate_limiter.py`, `dashboard/app.py:91`

**Configuration**:
```python
login_rate_limiter = LoginRateLimiter(
    max_attempts=5,
    lockout_duration=300  # 5 minutes
)
```

**Protection**:
- 5 failed attempts per IP → 5-minute lockout
- Prevents brute force attacks
- IP-based tracking

---

## 📊 Data Access Layer

Since IoTSentinel uses Dash callbacks rather than REST endpoints, data access is handled through the **database layer** or **Dash callbacks**.

### Database Manager

**Location**: `database/db_manager.py` (876 lines)

**Key Methods**:

#### Devices

```python
# Get all devices
devices = db_manager.get_all_devices()
# Returns: List[Dict] with device information

# Get specific device
device = db_manager.get_device_by_ip(device_ip)
# Returns: Dict or None

# Update device metadata
db_manager.update_device_metadata(
    device_ip="192.168.1.100",
    custom_name="Living Room Camera",
    notes="Monitors entrance",
    group="Security"
)

# Get device connections
connections = db_manager.get_device_connections(
    device_ip="192.168.1.100",
    limit=100
)
```

**Implementation**: `db_manager.py:48-118, 150-168, 380-469`

#### Alerts

```python
# Get recent alerts
alerts = db_manager.get_recent_alerts(
    limit=100,
    severity=None,  # or 'critical', 'high', 'medium', 'low'
    acknowledged=False
)
# Returns: List[Dict] with alert information

# Acknowledge alert
db_manager.acknowledge_alert(
    alert_id=42,
    acknowledged_by="admin",
    notes="Investigated - firmware update"
)

# Get alert statistics
stats = db_manager.get_alert_statistics(days=7)
```

**Implementation**: `db_manager.py:246-269, 404-417`

#### Analytics

```python
# Get network statistics
stats = db_manager.get_network_statistics(days=7)
# Returns: Dict with connection counts, traffic volumes, etc.

# Get device activity timeline
timeline = db_manager.get_device_activity_timeline(
    device_ip="192.168.1.100",
    days=7
)
```

### Dash Callbacks

**Count**: 162 callbacks in `dashboard/app.py`

**Pattern**:
```python
@app.callback(
    Output('device-table', 'data'),
    Input('interval-component', 'n_intervals')
)
def update_device_table(n):
    """Update device table every 5 seconds"""
    devices = db_manager.get_all_devices()
    return devices  # Dash automatically serializes to JSON
```

**Key Callbacks**:
- Device table updates
- Alert feed updates
- Analytics chart updates
- System health metrics
- Export functionality
- Device management actions

---

## 🔄 Real-Time Updates

### Update Mechanism

**Technology**: Dash built-in WebSocket

**Endpoint**: `ws://<raspberry-pi-ip>:8050/_dash-update-component` (automatic)

**Frequency**: Configurable interval component (default: 5 seconds)

**How It Works**:
1. Interval component triggers every 5 seconds
2. Callbacks execute and fetch new data
3. Dash serializes data to JSON
4. WebSocket pushes updates to browser
5. React components re-render automatically

**Updated Components**:
- Device list and status
- Alert feed
- Network activity charts
- System metrics
- Connection counts

**No manual WebSocket code required** - Dash handles all serialization and transport.

---

## 📥 Data Export

### CSV Export

**Implementation**: Dash callback @ `dashboard/app.py:10648-10697`

**Trigger**: Button click in web interface

**Process**:
1. User clicks "Export" button
2. Callback fetches alerts and devices from database
3. Generates CSV format in-memory
4. Returns download file via `dcc.Download` component

**Export Contents**:
```csv
IoTSentinel Security Report
Generated: 2025-12-16 01:30:00

=== ALERTS ===
Timestamp,Severity,Device IP,Device Name,Explanation
2025-12-16T01:15:00,critical,192.168.1.100,Living Room Camera,"High outbound traffic detected"

=== DEVICES ===
IP Address,MAC Address,Hostname,Vendor,First Seen,Last Seen,Trust Level
192.168.1.100,AA:BB:CC:DD:EE:FF,camera-lr,Ring,2025-12-01,2025-12-16,trusted
```

**Access**: Via web dashboard Settings → Export section

---

## 🔒 Security

### Authentication & Sessions

**Framework**: Flask-Login

**Features**:
- Secure session management
- HttpOnly cookies (prevents XSS)
- Secure flag in production (HTTPS)
- Bcrypt password hashing
- 24-hour session timeout

**Implementation**: `utils/auth_manager.py`, `dashboard/app.py:123-130`

### Rate Limiting

**Login Protection**:
- 5 attempts per IP maximum
- 5-minute lockout after failed attempts
- IP-based tracking

**Implementation**: `utils/rate_limiter.py`

### Database Security

**Protection**:
- Parameterized queries (prevents SQL injection)
- Connection pooling with timeouts
- Row-level access control via Flask-Login

### CSRF Protection

**Framework**: Dash built-in CSRF protection

**Features**:
- Automatic CSRF tokens in forms
- Token validation on POST requests

---

## 🔗 Integration Guide

### Option 1: Database Layer (Recommended)

**For**: Python scripts, automation, integrations

**Method**: Import and use `db_manager.py` directly

```python
from database.db_manager import DatabaseManager

# Initialize
db = DatabaseManager('/path/to/network_monitoring.db')

# Get devices
devices = db.get_all_devices()
for device in devices:
    print(f"{device['device_ip']}: {device['device_name']}")

# Get alerts
alerts = db.get_recent_alerts(severity='critical', limit=10)
for alert in alerts:
    print(f"Alert: {alert['explanation']}")

# Acknowledge alert
db.acknowledge_alert(alert_id=42, acknowledged_by='script')
```

**Advantages**:
- ✅ Direct database access
- ✅ No HTTP overhead
- ✅ Full Python API
- ✅ Type hints and documentation

**Disadvantages**:
- ❌ Requires Python
- ❌ Must run on same host or access SQLite file
- ❌ No authentication layer

---

### Option 2: Web Scraping (Not Recommended)

**For**: External tools that can't access database

**Method**: Parse HTML from web dashboard

**Disadvantages**:
- ❌ Fragile (breaks with UI changes)
- ❌ Requires authentication handling
- ❌ HTML parsing overhead
- ❌ Not designed for programmatic access

**Better Alternative**: Request REST API implementation if needed

---

### Option 3: Future REST API (Planned)

If you need a REST API for external integrations, this can be added:

**Implementation Pattern**:
```python
# dashboard/api_routes.py (would need to be created)
from flask import Blueprint, jsonify
from flask_login import login_required

api_bp = Blueprint('api', __name__, url_prefix='/api')

@api_bp.route('/devices', methods=['GET'])
@login_required
def get_devices():
    devices = db_manager.get_all_devices()
    return jsonify({
        'devices': devices,
        'total': len(devices),
        'timestamp': datetime.now().isoformat()
    })

# Register in app.py
server.register_blueprint(api_bp)
```

**Effort**: 40-60 hours for full REST API implementation

---

## 📝 Error Handling

### Database Errors

```python
try:
    devices = db_manager.get_all_devices()
except Exception as e:
    logger.error(f"Database error: {e}")
    # Handle gracefully
```

### Authentication Errors

**Unauthorized Access**:
- Redirect to login page
- Clear invalid sessions
- Log access attempts

### Rate Limit Errors

**Response**: "Too many failed attempts. Please try again in 5 minutes."

---

## 🛠️ Development & Testing

### Running the Dashboard

```bash
# Start the dashboard
python dashboard/app.py

# Access at:
http://localhost:8050
```

### Health Check Testing

```bash
# Test health endpoint
curl http://localhost:8050/health

# Expected response (healthy):
{"status":"healthy","timestamp":"2025-12-16T01:30:00Z","components":{...}}
```

### Database Testing

```python
# Direct database testing
import sqlite3

conn = sqlite3.connect('data/network_monitoring.db')
conn.row_factory = sqlite3.Row
cursor = conn.cursor()

cursor.execute('SELECT * FROM devices')
devices = cursor.fetchall()

for device in devices:
    print(dict(device))
```

---

## 📚 Code Locations

| Component | File | Lines |
|-----------|------|-------|
| Main Dashboard | `dashboard/app.py` | 10,899 total |
| Health Endpoint | `dashboard/app.py` | 133-200 |
| Authentication Setup | `dashboard/app.py` | 123-130 |
| **Dashboard Operations** | | |
| - Save Device Changes | `dashboard/app.py` | 4244 |
| - Toggle Device Trust | `dashboard/app.py` | 5012 |
| - Toggle Device Block | `dashboard/app.py` | 5053 |
| - View Device Details | `dashboard/app.py` | 4879 |
| - View Alert Details | `dashboard/app.py` | 5208 |
| - Filter Alerts | `dashboard/app.py` | 5235 |
| - Lockdown Mode | `dashboard/app.py` | 5368 |
| - Email Settings | `dashboard/app.py` | 5444 |
| - Quick Export | `dashboard/app.py` | 10648-10697 |
| - Network Graph | `dashboard/app.py` | 4497 |
| - Traffic Timeline | `dashboard/app.py` | 4684 |
| - Protocol Distribution | `dashboard/app.py` | 4703 |
| - System Metrics | `dashboard/app.py` | 4329 |
| - Device Status Summary | `dashboard/app.py` | 4724 |
| - Alert Stats Header | `dashboard/app.py` | 4345 |
| - AI Assistant | `dashboard/app.py` | 223, 265 |
| - Onboarding Tour | `dashboard/app.py` | 5253 |
| **Database Layer** | | |
| Database Manager | `database/db_manager.py` | 876 total |
| - Device Operations | `database/db_manager.py` | 48-118, 380-469 |
| - Alert Operations | `database/db_manager.py` | 246-269, 404-417 |
| - Connection Data | `database/db_manager.py` | 150-168 |
| **Security & Auth** | | |
| Auth Manager | `utils/auth_manager.py` | Full file |
| Rate Limiter | `utils/rate_limiter.py` | Full file |
| Firewall Manager | `scripts/firewall_manager.py` | Full file |

---

## 📊 Technical Specifications

### Technology Stack

- **Frontend**: Dash (React components)
- **Backend**: Flask (via Dash)
- **Database**: SQLite3
- **Authentication**: Flask-Login + bcrypt
- **Real-time**: Dash WebSocket (automatic)
- **Styling**: Dash Bootstrap Components

### Performance

- **Dashboard Load**: < 2 seconds
- **Component Updates**: Every 5 seconds
- **Database Queries**: Cached where appropriate
- **Concurrent Users**: Single-user design (home deployment)

### Scalability

**Current Design**:
- ✅ Single home network
- ✅ 10-50 IoT devices
- ✅ Single user
- ✅ SQLite database

**Scaling Considerations**:
- For multi-user: Add PostgreSQL/MySQL
- For high traffic: Add Redis caching
- For multiple networks: Add tenant isolation

---

## 🎯 Use Cases

### 1. Health Monitoring

```bash
# Docker health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s \
  CMD curl -f http://localhost:8050/health || exit 1
```

### 2. Device Monitoring

**Method**: Use web dashboard or database layer

```python
# Check device status
device = db_manager.get_device_by_ip('192.168.1.100')
if device['last_seen'] > datetime.now() - timedelta(minutes=10):
    print("Device online")
else:
    print("Device offline")
```

### 3. Alert Processing

**Method**: Query alerts via database layer

```python
# Get critical alerts
critical_alerts = db_manager.get_recent_alerts(
    severity='critical',
    acknowledged=False
)

# Send notifications
for alert in critical_alerts:
    send_notification(alert['explanation'])
    db_manager.acknowledge_alert(alert['id'], 'automation')
```

### 4. Reporting

**Method**: Use export callback or direct database queries

```python
# Generate weekly report
stats = db_manager.get_network_statistics(days=7)
devices = db_manager.get_all_devices()
alerts = db_manager.get_recent_alerts(days=7)

# Create report
report = generate_weekly_report(stats, devices, alerts)
email_report(report)
```

---

## ❓ FAQ

**Q: Why no REST API endpoints?**

A: IoTSentinel uses the Dash framework, which provides a component-based architecture with built-in callbacks and WebSocket support. This eliminates the need for manual REST endpoint creation for the web interface. For programmatic access, use the database layer directly.

**Q: Can I integrate with external tools?**

A: Yes, use the database layer (`db_manager.py`) for Python integrations. For other languages, access the SQLite database directly or request REST API implementation.

**Q: How do I get device data programmatically?**

A: Import and use `DatabaseManager` from `database/db_manager.py`:
```python
from database.db_manager import DatabaseManager
db = DatabaseManager('/path/to/db')
devices = db.get_all_devices()
```

**Q: Is there an API for mobile apps?**

A: Not currently. The web dashboard is mobile-responsive. For native mobile apps, a REST API layer would need to be implemented.

**Q: How do I monitor system health?**

A: Use the `/health` endpoint for health checks. This is the only REST endpoint and requires no authentication.

**Q: Can I export data via API?**

A: Export is currently available through the web dashboard. For programmatic export, query the database directly and format as needed.

---

## 📞 Support & Documentation

- **System Configuration**: `docs/SYSTEM_CONFIGURATION_MANUAL.md`
- **Deployment Guide**: See deployment documentation
- **Database Schema**: `database/schema.sql`
- **Testing**: `tests/test_dashboard_api_integration.py`

---

**Last Updated**: December 16, 2025
**Version**: 1.0
**Architecture**: Dash Single-Page Application
**Maintained by**: Ritik Sah
