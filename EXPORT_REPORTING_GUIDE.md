# 📊 Export & Reporting - Integration Guide

This guide shows how to integrate export and reporting features into the IoTSentinel dashboard.

---

## ✅ What's Already Complete

- ✅ Report generator module (`utils/report_generator.py`)
- ✅ CSV export functions for devices, alerts, connections, and rules
- ✅ Summary statistics generator
- ✅ Executive summary text generator
- ✅ File saving utilities

---

## 📝 Step 1: Verify Report Generator

```bash
cd /Users/ritiksah/iotsentinel

# Test the report generator module
python3 -c "from utils.report_generator import ReportGenerator; print('✓ Report generator loaded')"

# Create reports directory
mkdir -p data/reports
```

---

## 📝 Step 2: Update dashboard/app.py

### **2.1: Add Import** (after existing imports, around line 30)

```python
# Report generator import
from utils.report_generator import ReportGenerator, save_report_to_file

# Initialize report generator
report_generator = ReportGenerator(DB_PATH)
```

### **2.2: Add Export Section to Dashboard** (in Settings accordion, around line 1500)

Add this new card to the Settings section:

```python
dbc.AccordionItem([
    dbc.Card([
        dbc.CardBody([
            html.H5([html.I(className="fa fa-download me-2"), "Export & Reports"], className="text-primary mb-4"),

            # Quick Export Section
            html.Div([
                html.H6("Quick Exports", className="mb-3"),
                dbc.Row([
                    dbc.Col([
                        dbc.Button(
                            [html.I(className="fa fa-file-csv me-2"), "Export Devices"],
                            id="export-devices-btn",
                            color="primary",
                            outline=True,
                            className="w-100 cyber-button mb-2"
                        ),
                    ], width=3),
                    dbc.Col([
                        dbc.Button(
                            [html.I(className="fa fa-file-csv me-2"), "Export Alerts"],
                            id="export-alerts-btn",
                            color="warning",
                            outline=True,
                            className="w-100 cyber-button mb-2"
                        ),
                    ], width=3),
                    dbc.Col([
                        dbc.Button(
                            [html.I(className="fa fa-file-csv me-2"), "Export Connections"],
                            id="export-connections-btn",
                            color="info",
                            outline=True,
                            className="w-100 cyber-button mb-2"
                        ),
                    ], width=3),
                    dbc.Col([
                        dbc.Button(
                            [html.I(className="fa fa-file-csv me-2"), "Export Rules"],
                            id="export-rules-btn",
                            color="success",
                            outline=True,
                            className="w-100 cyber-button mb-2"
                        ),
                    ], width=3),
                ]),
            ], className="mb-4"),

            html.Hr(),

            # Custom Report Section
            html.Div([
                html.H6("Generate Custom Report", className="mb-3"),
                dbc.Row([
                    dbc.Col([
                        dbc.Label("Report Period (days):"),
                        dbc.Input(
                            id="report-days",
                            type="number",
                            value=7,
                            min=1,
                            max=365,
                            className="cyber-input"
                        ),
                    ], width=4),
                    dbc.Col([
                        dbc.Label("Report Type:"),
                        dbc.Select(
                            id="report-type",
                            options=[
                                {"label": "Executive Summary", "value": "summary"},
                                {"label": "Detailed Security Report", "value": "detailed"},
                                {"label": "Alert Report", "value": "alerts"},
                                {"label": "Connection Report", "value": "connections"},
                            ],
                            value="summary"
                        ),
                    ], width=4),
                    dbc.Col([
                        dbc.Label("Action:", className="d-block"),
                        dbc.Button(
                            [html.I(className="fa fa-chart-bar me-2"), "Generate Report"],
                            id="generate-report-btn",
                            color="primary",
                            className="cyber-button mt-0"
                        ),
                    ], width=4),
                ]),
            ], className="mb-4"),

            # Export Status
            html.Div(id="export-status", className="mt-3"),

            # Download Components (hidden, used for triggering downloads)
            dcc.Download(id="download-devices"),
            dcc.Download(id="download-alerts"),
            dcc.Download(id="download-connections"),
            dcc.Download(id="download-rules"),
            dcc.Download(id="download-report"),
        ])
    ], className="cyber-card")
], title="📊 Export & Reports", className="mb-3"),
```

### **2.3: Add Export Callbacks** (around line 2800, before `__main__`)

```python
# ============================================================================
# EXPORT & REPORTING CALLBACKS
# ============================================================================

@app.callback(
    [Output('download-devices', 'data'),
     Output('export-status', 'children', allow_duplicate=True)],
    Input('export-devices-btn', 'n_clicks'),
    prevent_initial_call=True
)
def export_devices(n_clicks):
    """Export all devices to CSV"""
    if n_clicks is None:
        raise dash.exceptions.PreventUpdate

    try:
        csv_data = report_generator.export_devices_csv()

        if csv_data:
            filename = f"iotsentinel_devices_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
            return (
                dict(content=csv_data, filename=filename),
                dbc.Alert([
                    html.I(className="fa fa-check-circle me-2"),
                    f"Successfully exported devices to {filename}"
                ], color="success", dismissable=True, duration=4000)
            )
        else:
            return (
                dash.no_update,
                dbc.Alert([
                    html.I(className="fa fa-exclamation-triangle me-2"),
                    "Failed to export devices - no data available"
                ], color="warning", dismissable=True, duration=4000)
            )

    except Exception as e:
        logger.error(f"Error exporting devices: {e}")
        return (
            dash.no_update,
            dbc.Alert([
                html.I(className="fa fa-times-circle me-2"),
                f"Error exporting devices: {str(e)}"
            ], color="danger", dismissable=True, duration=4000)
        )


@app.callback(
    [Output('download-alerts', 'data'),
     Output('export-status', 'children', allow_duplicate=True)],
    Input('export-alerts-btn', 'n_clicks'),
    prevent_initial_call=True
)
def export_alerts(n_clicks):
    """Export alerts from last 7 days to CSV"""
    if n_clicks is None:
        raise dash.exceptions.PreventUpdate

    try:
        csv_data = report_generator.export_alerts_csv(days=7)

        if csv_data:
            filename = f"iotsentinel_alerts_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
            return (
                dict(content=csv_data, filename=filename),
                dbc.Alert([
                    html.I(className="fa fa-check-circle me-2"),
                    f"Successfully exported alerts to {filename}"
                ], color="success", dismissable=True, duration=4000)
            )
        else:
            return (
                dash.no_update,
                dbc.Alert([
                    html.I(className="fa fa-exclamation-triangle me-2"),
                    "No alerts found in the last 7 days"
                ], color="warning", dismissable=True, duration=4000)
            )

    except Exception as e:
        logger.error(f"Error exporting alerts: {e}")
        return (
            dash.no_update,
            dbc.Alert([
                html.I(className="fa fa-times-circle me-2"),
                f"Error exporting alerts: {str(e)}"
            ], color="danger", dismissable=True, duration=4000)
        )


@app.callback(
    [Output('download-connections', 'data'),
     Output('export-status', 'children', allow_duplicate=True)],
    Input('export-connections-btn', 'n_clicks'),
    prevent_initial_call=True
)
def export_connections(n_clicks):
    """Export connections from last 24 hours to CSV"""
    if n_clicks is None:
        raise dash.exceptions.PreventUpdate

    try:
        csv_data = report_generator.export_connections_csv(hours=24)

        if csv_data:
            filename = f"iotsentinel_connections_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
            return (
                dict(content=csv_data, filename=filename),
                dbc.Alert([
                    html.I(className="fa fa-check-circle me-2"),
                    f"Successfully exported connections to {filename}"
                ], color="success", dismissable=True, duration=4000)
            )
        else:
            return (
                dash.no_update,
                dbc.Alert([
                    html.I(className="fa fa-exclamation-triangle me-2"),
                    "No connections found in the last 24 hours"
                ], color="warning", dismissable=True, duration=4000)
            )

    except Exception as e:
        logger.error(f"Error exporting connections: {e}")
        return (
            dash.no_update,
            dbc.Alert([
                html.I(className="fa fa-times-circle me-2"),
                f"Error exporting connections: {str(e)}"
            ], color="danger", dismissable=True, duration=4000)
        )


@app.callback(
    [Output('download-rules', 'data'),
     Output('export-status', 'children', allow_duplicate=True)],
    Input('export-rules-btn', 'n_clicks'),
    prevent_initial_call=True
)
def export_rules(n_clicks):
    """Export alert rules to CSV"""
    if n_clicks is None:
        raise dash.exceptions.PreventUpdate

    try:
        csv_data = report_generator.export_alert_rules_csv()

        if csv_data:
            filename = f"iotsentinel_alert_rules_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
            return (
                dict(content=csv_data, filename=filename),
                dbc.Alert([
                    html.I(className="fa fa-check-circle me-2"),
                    f"Successfully exported alert rules to {filename}"
                ], color="success", dismissable=True, duration=4000)
            )
        else:
            return (
                dash.no_update,
                dbc.Alert([
                    html.I(className="fa fa-exclamation-triangle me-2"),
                    "No alert rules found"
                ], color="warning", dismissable=True, duration=4000)
            )

    except Exception as e:
        logger.error(f"Error exporting alert rules: {e}")
        return (
            dash.no_update,
            dbc.Alert([
                html.I(className="fa fa-times-circle me-2"),
                f"Error exporting alert rules: {str(e)}"
            ], color="danger", dismissable=True, duration=4000)
        )


@app.callback(
    [Output('download-report', 'data'),
     Output('export-status', 'children', allow_duplicate=True)],
    Input('generate-report-btn', 'n_clicks'),
    [State('report-days', 'value'),
     State('report-type', 'value')],
    prevent_initial_call=True
)
def generate_custom_report(n_clicks, days, report_type):
    """Generate custom report based on user selection"""
    if n_clicks is None:
        raise dash.exceptions.PreventUpdate

    try:
        days = int(days) if days else 7

        if report_type == 'summary':
            # Generate executive summary
            report_content = report_generator.generate_executive_summary(days=days)
            filename = f"iotsentinel_summary_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
            content_type = "text/plain"

        elif report_type == 'alerts':
            # Export alerts CSV
            report_content = report_generator.export_alerts_csv(days=days)
            filename = f"iotsentinel_alerts_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
            content_type = "text/csv"

        elif report_type == 'connections':
            # Export connections CSV
            hours = days * 24
            report_content = report_generator.export_connections_csv(hours=hours)
            filename = f"iotsentinel_connections_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
            content_type = "text/csv"

        elif report_type == 'detailed':
            # Generate detailed report with statistics
            stats = report_generator.get_summary_statistics(days=days)
            summary = report_generator.generate_executive_summary(days=days)

            # Add additional details
            report_lines = [summary, "\n\n" + "=" * 80 + "\n"]
            report_lines.append("\n## Detailed Statistics\n")

            # Top talkers
            top_talkers = stats.get('top_talkers', [])
            if top_talkers:
                report_lines.append("\n### Top Data Consumers (by traffic volume)\n")
                for i, talker in enumerate(top_talkers, 1):
                    report_lines.append(f"{i}. {talker['name']} ({talker['ip']}): {talker['data_mb']:.2f} MB")

            # Top destinations
            top_destinations = stats.get('top_destinations', {})
            if top_destinations:
                report_lines.append("\n\n### Most Contacted Destinations\n")
                for i, (dest_ip, count) in enumerate(list(top_destinations.items())[:10], 1):
                    report_lines.append(f"{i}. {dest_ip}: {count:,} connections")

            # Top protocols
            top_protocols = stats.get('top_protocols', {})
            if top_protocols:
                report_lines.append("\n\n### Protocol Distribution\n")
                for protocol, count in top_protocols.items():
                    report_lines.append(f"- {protocol}: {count:,} connections")

            report_content = "\n".join(report_lines)
            filename = f"iotsentinel_detailed_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
            content_type = "text/plain"

        else:
            return (
                dash.no_update,
                dbc.Alert("Unknown report type", color="warning", dismissable=True, duration=4000)
            )

        if report_content:
            return (
                dict(content=report_content, filename=filename),
                dbc.Alert([
                    html.I(className="fa fa-check-circle me-2"),
                    f"Successfully generated {report_type} report: {filename}"
                ], color="success", dismissable=True, duration=4000)
            )
        else:
            return (
                dash.no_update,
                dbc.Alert([
                    html.I(className="fa fa-exclamation-triangle me-2"),
                    "Failed to generate report - no data available"
                ], color="warning", dismissable=True, duration=4000)
            )

    except Exception as e:
        logger.error(f"Error generating report: {e}")
        return (
            dash.no_update,
            dbc.Alert([
                html.I(className="fa fa-times-circle me-2"),
                f"Error generating report: {str(e)}"
            ], color="danger", dismissable=True, duration=4000)
        )
```

---

## 📝 Step 3: Add Device-Specific Export (Optional)

Add export button to device details modal (in the device modal section, around line 1990):

```python
# Add this inside the device details modal, in the Actions section
html.Div([
    html.Strong("Export Device Data: ", className="mb-2"),
    dbc.Button(
        [html.I(className="fa fa-download me-2"), "Export Connections"],
        id={'type': 'export-device-connections', 'ip': device_ip},
        color="info",
        outline=True,
        size="sm",
        className="w-100 mt-2"
    ),
    html.Div(id={'type': 'device-export-status', 'ip': device_ip}, className="mt-2")
], className="mb-2"),

# Add Download component
dcc.Download(id={'type': 'download-device-data', 'ip': device_ip})
```

### **Device Export Callback:**

```python
@app.callback(
    [Output({'type': 'download-device-data', 'ip': dash.dependencies.MATCH}, 'data'),
     Output({'type': 'device-export-status', 'ip': dash.dependencies.MATCH}, 'children')],
    Input({'type': 'export-device-connections', 'ip': dash.dependencies.MATCH}, 'n_clicks'),
    State({'type': 'export-device-connections', 'ip': dash.dependencies.MATCH}, 'id'),
    prevent_initial_call=True
)
def export_device_connections(n_clicks, button_id):
    """Export connections for a specific device"""
    if n_clicks is None:
        raise dash.exceptions.PreventUpdate

    device_ip = button_id['ip']

    try:
        # Export last 7 days of connections for this device
        csv_data = report_generator.export_connections_csv(device_ip=device_ip, hours=168)

        if csv_data:
            filename = f"iotsentinel_device_{device_ip.replace('.', '_')}_connections_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
            return (
                dict(content=csv_data, filename=filename),
                dbc.Alert([
                    html.I(className="fa fa-check-circle me-2"),
                    f"Exported connections for {device_ip}"
                ], color="success", dismissable=True, duration=4000)
            )
        else:
            return (
                dash.no_update,
                dbc.Alert("No connections found for this device", color="warning", dismissable=True, duration=4000)
            )

    except Exception as e:
        logger.error(f"Error exporting device connections: {e}")
        return (
            dash.no_update,
            dbc.Alert(f"Error: {str(e)}", color="danger", dismissable=True, duration=4000)
        )
```

---

## 📝 Step 4: Add Scheduled Reports (Advanced - Optional)

For automated scheduled reports, add this background task:

```python
import threading
import time
from datetime import datetime

def scheduled_report_generator():
    """Background task to generate daily reports"""
    while True:
        try:
            # Wait until 2 AM
            now = datetime.now()
            target_hour = 2

            if now.hour == target_hour and now.minute < 10:
                logger.info("Generating scheduled daily report...")

                # Generate executive summary
                summary = report_generator.generate_executive_summary(days=1)

                # Save to file
                filename = f"daily_report_{now.strftime('%Y%m%d')}.txt"
                filepath = save_report_to_file(summary, filename)

                if filepath:
                    logger.info(f"Daily report saved to {filepath}")

                    # Optional: Email the report (if email notifications are configured)
                    # email_manager.send_email(
                    #     subject=f"IoTSentinel Daily Report - {now.strftime('%Y-%m-%d')}",
                    #     body=summary,
                    #     to=config.get('email', 'admin_email')
                    # )

                # Sleep for 1 hour to avoid multiple reports
                time.sleep(3600)
            else:
                # Check every 10 minutes
                time.sleep(600)

        except Exception as e:
            logger.error(f"Error in scheduled report generation: {e}")
            time.sleep(600)

# Start scheduled reports in background
report_thread = threading.Thread(target=scheduled_report_generator, daemon=True)
report_thread.start()
logger.info("Scheduled report generator started (daily at 2 AM)")
```

---

## 🧪 Step 5: Test Export Features

### **5.1: Start Dashboard**

```bash
python3 dashboard/app.py
```

### **5.2: Test Quick Exports**

1. Navigate to Settings → Export & Reports
2. Click "Export Devices" - should download a CSV file
3. Click "Export Alerts" - should download alerts from last 7 days
4. Click "Export Connections" - should download connections from last 24 hours
5. Click "Export Rules" - should download alert rules configuration

### **5.3: Test Custom Reports**

1. Set "Report Period" to 7 days
2. Select "Executive Summary" from dropdown
3. Click "Generate Report"
4. Should download a text file with summary statistics
5. Try other report types: Detailed, Alerts, Connections

### **5.4: Test Device-Specific Export**

1. Click on any device in the device list
2. In device details modal, scroll to "Export Device Data"
3. Click "Export Connections"
4. Should download CSV with connections for that specific device

### **5.5: Verify CSV Content**

Open downloaded CSV files and verify:
- Proper headers
- Data is correctly formatted
- Timestamps are readable
- No missing critical fields

---

## 📊 Report Examples

### **Executive Summary Example:**

```
# IoTSentinel Security Report
Generated: 2024-01-15 14:30:00
Report Period: Last 7 days

## Network Overview
- Total Devices: 42
- Active Devices (24h): 38
- Blocked Devices: 2

## Security Alerts
- Total Alerts: 156
- Alerts by Severity:
  - CRITICAL: 3
  - HIGH: 12
  - MEDIUM: 87
  - LOW: 54

## Network Activity
- Total Connections: 1,234,567
- Data Transferred: 45,678.90 MB
- Top Protocols:
  - TCP: 987,654 connections
  - UDP: 234,567 connections
  - ICMP: 12,346 connections

## Top Data Consumers
1. Smart TV (192.168.1.100): 12,345.67 MB
2. Laptop (192.168.1.50): 8,901.23 MB
3. iPhone (192.168.1.75): 4,567.89 MB
```

### **Devices CSV Example:**

```csv
IP Address,Device Name,Type,MAC Address,Manufacturer,First Seen,Last Seen,Trusted,Blocked
192.168.1.100,Smart TV,media,AA:BB:CC:DD:EE:01,Samsung,2024-01-01 10:00:00,2024-01-15 14:25:00,Yes,No
192.168.1.50,Laptop,computer,AA:BB:CC:DD:EE:02,Apple,2024-01-01 10:05:00,2024-01-15 14:30:00,Yes,No
192.168.1.75,iPhone,mobile,AA:BB:CC:DD:EE:03,Apple,2024-01-02 08:15:00,2024-01-15 14:28:00,Yes,No
```

### **Alerts CSV Example:**

```csv
Alert ID,Timestamp,Device IP,Device Name,Severity,Anomaly Score,Explanation,Acknowledged
1,2024-01-15 14:00:00,192.168.1.100,Smart TV,HIGH,0.8542,Unusual data transfer detected,No
2,2024-01-15 13:45:00,192.168.1.50,Laptop,MEDIUM,0.6234,Excessive connections detected,Yes
```

---

## 🎨 UI Enhancements (Optional)

### **Add Export Icons to Tables:**

Add quick export buttons next to table titles:

```python
# In device list header
html.Div([
    html.H5("Network Devices", className="d-inline-block"),
    dbc.Button(
        html.I(className="fa fa-download"),
        id="quick-export-devices",
        color="link",
        size="sm",
        className="float-end",
        title="Quick export to CSV"
    ),
], className="d-flex justify-content-between align-items-center mb-3")
```

### **Add Report Preview Modal:**

Show report preview before downloading:

```python
dbc.Modal([
    dbc.ModalHeader("Report Preview"),
    dbc.ModalBody([
        html.Pre(id="report-preview-content", style={"maxHeight": "500px", "overflow": "auto"})
    ]),
    dbc.ModalFooter([
        dbc.Button("Download", id="confirm-download-report", color="primary"),
        dbc.Button("Close", id="close-preview", color="secondary")
    ])
], id="report-preview-modal", size="lg")
```

---

## 🔧 Advanced Features

### **1. Email Reports:**

Integrate with the email notification system:

```python
def email_report(report_content: str, report_type: str, recipient: str):
    """Email a report to recipient"""
    from utils.notification_manager import EmailNotificationManager

    email_manager = EmailNotificationManager()

    subject = f"IoTSentinel {report_type.title()} Report - {datetime.now().strftime('%Y-%m-%d')}"

    email_manager.send_email(
        subject=subject,
        body=report_content,
        to=recipient
    )
```

### **2. PDF Reports (requires additional libraries):**

Install dependencies:

```bash
pip install reportlab matplotlib
```

Create PDF generator:

```python
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet

def generate_pdf_report(stats: dict, filename: str):
    """Generate PDF report with charts"""
    doc = SimpleDocTemplate(filename, pagesize=letter)
    styles = getSampleStyleSheet()
    story = []

    # Title
    title = Paragraph("IoTSentinel Security Report", styles['Title'])
    story.append(title)
    story.append(Spacer(1, 12))

    # Summary table
    summary_data = [
        ['Metric', 'Value'],
        ['Total Devices', str(stats.get('total_devices', 0))],
        ['Active Devices', str(stats.get('active_devices', 0))],
        ['Total Alerts', str(stats.get('total_alerts', 0))],
    ]

    summary_table = Table(summary_data)
    summary_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
        ('GRID', (0, 0), (-1, -1), 1, colors.black)
    ]))

    story.append(summary_table)
    doc.build(story)
```

### **3. Scheduled Report Subscriptions:**

Allow users to subscribe to automated reports:

```python
# Add to database schema
cursor.execute('''
    CREATE TABLE IF NOT EXISTS report_subscriptions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        report_type TEXT,
        frequency TEXT CHECK(frequency IN ('daily', 'weekly', 'monthly')),
        email TEXT,
        is_active INTEGER DEFAULT 1,
        FOREIGN KEY (user_id) REFERENCES users(id)
    )
''')
```

---

## 🔒 Security Considerations

### **1. Access Control:**

Only allow authenticated users to export data:

```python
@app.callback(...)
def export_devices(n_clicks):
    # Check if user is authenticated
    if not current_user.is_authenticated:
        return dash.no_update, dbc.Alert("Please login to export data", color="danger")

    # Only admins can export
    if current_user.role != 'admin':
        return dash.no_update, dbc.Alert("Insufficient permissions", color="danger")

    # Continue with export...
```

### **2. Rate Limiting:**

Prevent abuse of export functionality:

```python
from functools import wraps
from time import time

export_timestamps = {}

def rate_limit_export(seconds=60):
    """Rate limit decorator for export functions"""
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            user_id = current_user.id if current_user.is_authenticated else 'anonymous'

            if user_id in export_timestamps:
                time_since_last = time() - export_timestamps[user_id]
                if time_since_last < seconds:
                    return dash.no_update, dbc.Alert(
                        f"Please wait {int(seconds - time_since_last)} seconds before exporting again",
                        color="warning"
                    )

            export_timestamps[user_id] = time()
            return func(*args, **kwargs)
        return wrapper
    return decorator

@app.callback(...)
@rate_limit_export(seconds=60)
def export_devices(n_clicks):
    ...
```

### **3. Data Sanitization:**

Ensure exported data doesn't contain sensitive information:

```python
def sanitize_export_data(data: str, redact_ips: bool = False) -> str:
    """Remove or redact sensitive information from exports"""
    if redact_ips:
        # Redact last octet of IP addresses
        data = re.sub(r'(\d+\.\d+\.\d+\.)\d+', r'\1XXX', data)

    return data
```

---

## 📈 Usage Analytics

Track export usage for monitoring:

```python
# Add to database schema
cursor.execute('''
    CREATE TABLE IF NOT EXISTS export_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        user_id INTEGER,
        export_type TEXT,
        record_count INTEGER,
        file_size_bytes INTEGER,
        FOREIGN KEY (user_id) REFERENCES users(id)
    )
''')

# Log export activity
def log_export(user_id: int, export_type: str, record_count: int, file_size: int):
    """Log export activity"""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO export_logs (user_id, export_type, record_count, file_size_bytes)
        VALUES (?, ?, ?, ?)
    """, (user_id, export_type, record_count, file_size))
    conn.commit()
    conn.close()
```

---

## 🎉 Completion Checklist

- [ ] Verified report generator module
- [ ] Created data/reports directory
- [ ] Added import to dashboard/app.py
- [ ] Added Export & Reports section to Settings
- [ ] Added export callbacks for devices, alerts, connections, rules
- [ ] Added custom report generation callback
- [ ] (Optional) Added device-specific export
- [ ] (Optional) Added scheduled report generation
- [ ] (Optional) Added PDF report generation
- [ ] Tested all export buttons
- [ ] Verified CSV file contents
- [ ] Tested custom report generation
- [ ] Added access control for exports
- [ ] Configured rate limiting

---

## ❓ Troubleshooting

**"No data exported" error**
- Check if database has data: `sqlite3 data/database/iotsentinel.db "SELECT COUNT(*) FROM devices;"`
- Verify time windows (e.g., alerts last 7 days, connections last 24 hours)

**CSV file is empty**
- Check database query results
- Verify date filtering logic
- Check logger output for SQL errors

**Download doesn't trigger**
- Check browser console for JavaScript errors
- Verify dcc.Download component IDs match callback outputs
- Check that callback is not prevented

**Report generation is slow**
- Add database indexes: `CREATE INDEX idx_timestamp ON connections(timestamp);`
- Limit time windows for large datasets
- Add progress indicator in UI

**Permission denied saving reports**
- Check data/reports directory permissions: `chmod 755 data/reports`
- Verify disk space availability

---

**Your dashboard now has comprehensive export and reporting capabilities!** 📊
