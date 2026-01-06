# IoTSentinel: Advanced Export & Reporting System Guide

## Overview

This document provides a comprehensive guide to the IoTSentinel's Advanced Export & Reporting system. The system provides comprehensive trend analysis, executive summaries, custom report templates, and automated scheduling - transforming IoTSentinel into an enterprise-grade security analytics platform. It also provides a Universal Export System with comprehensive export capabilities in multiple formats.

## Combined System Overview

### Export Capabilities
- **Basic Exports:** CSV, JSON
- **Professional Reports:** PDF, Excel with formatting
- **Advanced Reports:** Template-based, multi-section
- **Scheduled Reports:** Automated generation and delivery

### Analysis Capabilities
- **Basic Statistics:** Summary stats, top talkers
- **Trend Analysis:** Time-series, patterns, anomalies
- **Executive Summaries:** KPIs, top concerns
- **Security Posture:** Comprehensive security analysis

### Visualization Capabilities
- **Basic Charts:** Pie, bar, line
- **Advanced Charts:** Trend, area, heatmap, gauge, waterfall, box plot
- **Dashboard Integration:** Ready for dcc.Graph

## Features Deep Dive

### Universal Export System

The Universal Export System now supports **4 export formats** (CSV, JSON, PDF, Excel) for all major data types, with all data fetched fresh from the database.

#### Features Delivered
- **Universal Export:** Export buttons support 4 formats with a format selection dropdown component. All data is fetched fresh from database with consistent error handling.
- **PDF Reports:** Professional formatting, summary statistics, color-coded tables, headers and footers, and IoTSentinel branding.
- **Excel Workbooks:** Multi-sheet support, color-coded cells, auto-sized columns, summary sheets, and professional formatting.
- **JSON Export:** Structured data with metadata inclusion in an API-ready format.
- **CSV Export (Enhanced):** Integrated with the universal system, consistent with other formats, proper headers, and compatible with all tools.

#### Export Format Details

| Format | Best for | Features | File size |
|---|---|---|---|
| **CSV** | Excel imports, data analysis, simple reporting | Headers, formatted columns, compatible with all spreadsheet apps | Small |
| **JSON** | API integrations, programmatic access, data exchange | Structured data, metadata included, machine-readable | Medium |
| **PDF** | Professional reports, presentations, archiving | Formatted tables, headers/footers, summary statistics, professional styling | Medium |
| **Excel** | Advanced analysis, charts, multi-sheet reports | Multiple sheets, formatted tables, color coding, auto-sized columns | Medium to large |

### Advanced Reporting & Analytics

This system provides comprehensive trend analysis, executive summaries, custom report templates, and automated scheduling.

#### Features Delivered
- **Trend Analysis:** Time-series alert analysis, device activity patterns, network traffic analysis, anomaly detection (Z-score), trend direction detection, and percentage change calculations.
- **Executive Summaries:** Security posture overview, network activity metrics, device status summary, top concerns identification, and professional PDF/Excel output.
- **Advanced Charts:** Area charts, Trend charts with MA, Heatmaps, Gauge charts, Waterfall charts, Box plots.
- **Report Templates:** 5 predefined templates, custom template creation, section-based architecture, JSON save/load, and configurable parameters.
- **Report Builder:** Template execution engine, multi-format output (JSON/PDF/Excel/HTML), database integration, chart generation, and error handling.
- **Custom Scheduling:** Cron expression support, interval-based scheduling, pause/resume capabilities, schedule management, and template integration.


## Installation

1.  **Install Required Libraries**
    ```bash
    pip install reportlab==4.0.7 openpyxl==3.1.2 Pillow==10.1.0
    ```
    Or if using the project's requirements file:
    ```bash
    pip install -r requirements.txt
    ```

2.  **Import in your dashboard**
    ```python
    from utils.export_helpers import DashExportHelper
    ```

3.  **Initialize the helper**
    ```python
    # After DB_PATH is defined in app.py
    export_helper = DashExportHelper(DB_PATH)
    ```

## Integration and Usage

### Quick Start: Basic Exports

#### Basic Device Export

```python
@app.callback(
    Output('download-devices', 'data'),
    Input('export-devices-btn', 'n_clicks'),
    State('format-select', 'value')
)
def export_devices(n_clicks, format):
    if not n_clicks:
        raise dash.exceptions.PreventUpdate

    return export_helper.export_devices(format=format)
```

#### Alert Export with Time Range

```python
@app.callback(
    Output('download-alerts', 'data'),
    Input('export-alerts-btn', 'n_clicks'),
    [State('format-select', 'value'),
     State('days-input', 'value')]
)
def export_alerts(n_clicks, format, days):
    if not n_clicks:
        raise dash.exceptions.PreventUpdate

    return export_helper.export_alerts(
        format=format,
        days=int(days) if days else 7
    )
```

#### Connection Export with Device Filter

```python
@app.callback(
    Output('download-connections', 'data'),
    Input('export-connections-btn', 'n_clicks'),
    [State('format-select', 'value'),
     State('device-ip', 'value'),
     State('hours-input', 'value')]
)
def export_connections(n_clicks, format, device_ip, hours):
    if not n_clicks:
        raise dash.exceptions.PreventUpdate

    return export_helper.export_connections(
        format=format,
        device_ip=device_ip,
        hours=int(hours) if hours else 24
    )
```

### Advanced Reporting Examples

#### Generate Executive Summary
```python
from utils.report_builder import ReportBuilder

builder = ReportBuilder('data/iot_monitor.db')

# Generate PDF executive summary for last 7 days
report = builder.build_report(
    template_name='executive_summary',
    format='pdf',
    parameters={'days': 7}
)

# Save to file
with open(report['filename'], 'wb') as f:
    f.write(report['content'])
```

#### Schedule Daily Security Audit
```python
from alerts.report_scheduler import ReportScheduler

scheduler = ReportScheduler(db_manager, alert_service, dispatcher)

# Schedule daily security audit at 8am
scheduler.add_custom_schedule(
    schedule_id='daily_security_audit',
    template_name='security_audit',
    cron_expression='0 8 * * *',  # Every day at 8am
    format='pdf',
    parameters={'days': 30}
)

scheduler.start()
```

### UI Components

#### Universal Export Dropdown

Add this to any modal or section that needs export functionality:

```python
dbc.Row([
    dbc.Col([
        dbc.Label("Export Format"),
        dbc.Select(
            id='export-format-dropdown',
            options=[
                {'label': '📄 CSV Format', 'value': 'csv'},
                {'label': '📋 JSON Format', 'value': 'json'},
                {'label': '📕 PDF Report', 'value': 'pdf'},
                {'label': '📊 Excel Workbook', 'value': 'excel'}
            ],
            value='csv'
        )
    ], width=6),
    dbc.Col([
        dbc.Label("Download"),
        dbc.Button(
            [html.I(className="fa fa-download me-2"), "Export"],
            id='export-btn',
            color="success",
            className="w-100"
        )
    ], width=6)
])

# Don't forget the download component
dcc.Download(id='download-data')
```

### Advanced Usage

#### Custom Export with Toast Notifications

```python
from utils.toast_manager import ToastManager

@app.callback(
    [Output('download-devices', 'data'),
     Output('toast-container', 'children')],
    Input('export-devices-btn', 'n_clicks'),
    State('format-select', 'value')
)
def export_with_toast(n_clicks, format):
    if not n_clicks:
        raise dash.exceptions.PreventUpdate

    try:
        download_data = export_helper.export_devices(format=format)

        if download_data:
            toast = ToastManager.success(
                "Export Complete",
                detail_message=f"Devices exported as {format.upper()}"
            )
            return download_data, toast
        else:
            toast = ToastManager.error(
                "Export Failed",
                detail_message="No data available"
            )
            return None, toast

    except Exception as e:
        toast = ToastManager.error(
            "Export Error",
            detail_message=str(e)
        )
        return None, toast
```

#### Direct UniversalExporter Usage

For advanced use cases, you can use the UniversalExporter directly:

```python
from utils.universal_exporter import UniversalExporter

exporter = UniversalExporter(DB_PATH)

# Export devices as PDF
result = exporter.export_devices(format='pdf')
# result = {'content': b'...', 'filename': 'devices_20260104_120000.pdf', 'mimetype': 'application/pdf'}

# Export alerts as Excel
result = exporter.export_alerts(format='excel', days=30)

# Export connections as JSON
result = exporter.export_connections(
    format='json',
    device_ip='192.168.1.100',
    hours=48
)

# Check supported formats
formats = exporter.get_supported_formats('devices')
# Returns: ['csv', 'json', 'pdf', 'excel']
```

### Updating Existing Exports

#### Before (CSV Only)

```python
@app.callback(
    Output('download-devices-csv', 'data'),
    Input('export-csv-btn', 'n_clicks')
)
def export_devices_csv(n_clicks):
    if not n_clicks:
        raise dash.exceptions.PreventUpdate

    # Manual CSV generation
    csv_data = generate_csv_content(...)
    return {
        'content': csv_data,
        'filename': 'devices.csv'
    }
```

#### After (Universal Formats)

```python
@app.callback(
    Output('download-devices', 'data'),
    Input('export-btn', 'n_clicks'),
    State('format-dropdown', 'value')
)
def export_devices_universal(n_clicks, format):
    if not n_clicks:
        raise dash.exceptions.PreventUpdate

    # Universal export with format selection
    return export_helper.export_devices(format=format)
```

## System Architecture & Files

```
utils/
├── universal_exporter.py    # Main export orchestrator
├── pdf_exporter.py          # PDF generation (ReportLab)
├── excel_exporter.py        # Excel generation (openpyxl)
├── report_generator.py      # CSV/JSON exports & advanced report generation
├── export_helpers.py        # Dash integration helpers
├── trend_analyzer.py        # Trend analysis engine
├── report_templates.py      # Template system
├── report_builder.py        # Report building engine
└── chart_factory.py         # Advanced chart generation
alerts/
└── report_scheduler.py      # Custom report scheduling
```

### Core Export Modules
- **PDF Exporter (`utils/pdf_exporter.py`)**: Professional PDF reports with ReportLab, formatted tables, custom styling, headers/footers, and summary statistics.
- **Excel Exporter (`utils/excel_exporter.py`)**: Multi-sheet workbooks, color-coded cells, auto-sized columns, and summary sheets.
- **Universal Exporter (`utils/universal_exporter.py`)**: Single interface for all export types, format-agnostic data fetching, and consistent error handling.
- **Dashboard Integration Helper (`utils/export_helpers.py`)**: Dash-optimized export methods and simplified callback integration.

### Core Analytics Modules
- **Trend Analysis Engine (`utils/trend_analyzer.py`)**: Alert trend analysis, device activity pattern detection, network traffic analysis, and anomaly detection.
- **Enhanced Chart Factory (`utils/chart_factory.py`)**: Generates over 12 chart types including area charts, trend charts with moving averages, heatmaps, and gauge charts.
- **Enhanced Report Generator (`utils/report_generator.py`)**: Integrates with TrendAnalyzer, PDFExporter, and ExcelExporter to generate rich reports.
- **Report Templates System (`utils/report_templates.py`)**: Provides pre-defined templates (Executive Summary, Security Audit, etc.) and supports custom templates.
- **Report Builder Engine (`utils/report_builder.py`)**: Template execution engine that compiles reports into JSON, PDF, Excel, and HTML.
- **Enhanced Report Scheduler (`alerts/report_scheduler.py`)**: Allows scheduling of custom template reports using cron expressions or intervals.


## Performance & Security

### Performance Considerations

#### Large Datasets & Memory Usage
The exporters include limits to manage performance and memory. For very large exports, consider adding time range filters, using device-specific filters, implementing pagination for web display, or using background tasks for scheduled exports.

- **Small datasets (<100 records):** <10 MB
- **Medium datasets (100-1000 records):** 10-50 MB
- **Large datasets (1000-5000 records):** 50-200 MB
- **Trend Analysis:** ~10-50 MB
- **Chart Generation:** ~5-20 MB per chart
- **PDF Generation:** ~20-100 MB during compilation
- **Excel Generation:** ~30-150 MB during compilation

#### Database Queries & Generation Time
All exports fetch fresh data from the database. Queries are optimized with appropriate indexes and limited result sets to prevent memory issues.

- **CSV/JSON:** <1 second
- **PDF:** 1-3 seconds
- **Excel:** 2-5 seconds
- **Executive Summary (PDF):** 2-5 seconds
- **Security Audit (PDF):** 3-8 seconds

### Security Considerations

- **Data Protection:** All exports use read-only database connections. No user input is used directly in SQL queries. Proper error handling prevents data leakage.
- **Access Control:** Exports respect existing dashboard authentication. No direct file system access is exposed. Downloads are handled through the Dash framework. Temporary files are cleaned up automatically.


## Testing

A test suite is available at `tests/test_exports.py`. To run the tests:
```bash
python3 tests/test_exports.py
```
**Test Coverage:**
- CSV, JSON, PDF, and Excel export for all data types
- Dash helper integration
- Error handling
- Sample file generation


## Troubleshooting

### "ReportLab not installed" Error
```bash
pip install reportlab==4.0.7
```

### "openpyxl not installed" Error
```bash
pip install openpyxl==3.1.2
```

### PDF Generation Fails
- Check if data exists in database
- Verify database path is correct
- Check logs for specific error

### Excel File Won't Open
- Ensure full file is downloaded
- Check file size isn't 0 bytes
- Verify mimetype is correct

### No Data in Export
- Verify time range filters aren't too restrictive
- Check database has data in the requested period
- Review query parameters (device_ip, days, hours)


## Future Enhancements

The following enhancements are planned for the reporting and export system.

### Compliance Reports
- GDPR compliance report
- NIST Cybersecurity Framework report
- ISO 27001 report
- Automated compliance checking

### Email Enhancements (LOW PRIORITY)
Estimated Effort: 6-8 hours

**1. Daily Alert Digest**
- Summary of last 24 hours
- Critical alerts only
- Configurable send time

**2. Incident Timeline Reports**
- Automated incident detection
- Email with full timeline
- PDF attachment with details

**3. Email Attachments**
- Attach PDF/Excel reports
- MIME multipart support
- File size limits

*Update target: `alerts/email_notifier.py`*

## Support

For issues or questions:
1. Check logs: `data/logs/iotsentinel.log`
2. Test exports in Python shell
3. Verify database connectivity
4. Check export format compatibility
