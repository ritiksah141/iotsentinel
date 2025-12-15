# Academic Evidence Dashboard - Integration Guide

## Overview

This guide explains how to integrate the comprehensive academic evidence collection system into your IoTSentinel dashboard. The system provides:

1. **BCS Compliance Dashboard** - Evidence of meeting BCS accreditation requirements
2. **Requirements Traceability Matrix (RTM)** - Mapping from requirements to implementation to tests
3. **Risk Register** - 8 major risks with 3-stage mitigation strategies
4. **Performance Metrics** - Real-time system performance monitoring
5. **C4 Architecture Diagrams** - System Context, Container, and Component diagrams

## Quick Start

### Step 1: Install Dependencies

```bash
# Install the diagrams library for C4 diagram generation
pip install diagrams psutil

# Update requirements.txt
echo "diagrams>=0.23.3" >> requirements.txt
echo "psutil>=5.9.0" >> requirements.txt
```

### Step 2: Integrate into Dashboard

Add the following to your `dashboard/app.py` file:

#### At the top of the file (after other imports):

```python
# Import academic evidence components
from academic.dashboard_components import (
    create_academic_evidence_button,
    create_academic_modal,
    register_callbacks as register_academic_callbacks
)
```

#### In your dashboard layout (add button to navbar or header):

```python
# Add this button somewhere in your main layout (e.g., in the navbar)
create_academic_evidence_button(),

# Add this modal to your layout (can be at the end)
create_academic_modal(DB_PATH),
```

#### After app layout definition, register callbacks:

```python
# Register academic evidence callbacks
register_academic_callbacks(app, DB_PATH)
```

### Step 3: Initialize Database Tables

The performance metrics table will be automatically created when you first run the app. To manually initialize:

```python
from academic.performance_metrics import PerformanceMetricsCollector

collector = PerformanceMetricsCollector(DB_PATH)
# Database table is created in __init__
```

## Detailed Integration Example

Here's a complete example of how to integrate into your existing `app.py`:

```python
# ===== IMPORTS SECTION =====
# Add after your existing imports
from academic.dashboard_components import (
    create_academic_evidence_button,
    create_academic_modal,
    register_callbacks as register_academic_callbacks
)

# ===== LAYOUT SECTION =====
# Example: Adding to navbar
navbar = dbc.Navbar([
    dbc.Container([
        dbc.NavbarBrand("IoTSentinel"),
        dbc.Nav([
            dbc.NavItem(create_academic_evidence_button()),  # Add here
            # ... other nav items
        ])
    ])
])

# At the end of your layout, add the modal
app.layout = html.Div([
    navbar,
    # ... your existing layout components ...

    # Add academic evidence modal
    create_academic_modal(DB_PATH),
])

# ===== CALLBACKS SECTION =====
# After your existing callbacks, add:
register_academic_callbacks(app, DB_PATH)

# ===== START SERVER =====
if __name__ == '__main__':
    app.run_server(debug=True)
```

## Features Breakdown

### 1. BCS Compliance Tab

Shows evidence for all 4 BCS requirements:
- **Substantial Technical Challenge**: Dual ML models, optimized packet processing, complex codebase
- **Integration of Learning**: ML, Networks, Software Engineering, Databases
- **Professional Practice**: Git, testing, documentation, deployment
- **Real-World Applicability**: Raspberry Pi deployment, production features

**Export**: JSON format with full evidence

### 2. Requirements Traceability Matrix (RTM)

- Maps 25+ user stories across 8 epics
- Shows implementation files and test coverage
- Visual coverage charts by epic
- Full traceability table

**Export**: CSV for AT2 appendix

### 3. Risk Register

Documents 8 major project risks:
1. Raspberry Pi Performance Bottleneck
2. Insufficient Baseline Data
3. False Positive Rate
4. Unauthorized Dashboard Access
5. Service Reliability
6. Database Growth
7. Network Configuration Compatibility
8. Model Drift Over Time

Each risk includes:
- 3-stage mitigation approach
- Quantified evidence (CPU%, time, metrics)
- Current status and residual risk

**Export**: JSON with HTML report generation

### 4. Performance Metrics Dashboard

Real-time monitoring:
- CPU usage (target: <70%)
- RAM usage (target: <75%)
- Packet processing rate (target: >500 pps)
- ML inference latency (target: <100ms)

Features:
- 24-hour trend charts
- Benchmark comparisons (Pcap+dpkt vs PyShark)
- Background metrics collection every 5 minutes

**Export**: CSV performance report

### 5. C4 Architecture Diagrams

Generates three levels:
- **Level 1**: System Context (IoTSentinel, User, Router, Internet)
- **Level 2**: Container Diagram (Dashboard, Capture, Zeek, ML Engine, Database)
- **Level 3**: Component Diagram (ML Pipeline components)

Includes:
- Layered architecture description
- Design patterns used
- Technology decision justifications

**Export**: PNG diagrams + JSON documentation

## Usage Recommendations

### For AT2 (Implementation Report)

1. **BCS Compliance**: Include JSON export in appendix
2. **RTM**: Export CSV and include as appendix table
3. **Risk Register**: Reference in risk management section
4. **Architecture**: Include C4 diagrams in design section

### For AT3 (Final Report)

1. **Performance Metrics**: Export 24-hour CSV before submission
2. **Evidence Package**: Use "Export All" to generate complete package
3. **Screenshots**: Take screenshots of each dashboard tab

### During Development

- Monitor performance metrics tab weekly
- Update RTM when adding new features
- Review risk register when issues arise
- Generate updated C4 diagrams after major changes

## Customization

### Update Student Information

Edit `academic/bcs_compliance.py`:

```python
"metadata": {
    "generated_at": datetime.now().isoformat(),
    "project_name": "IoTSentinel",
    "student": "Your Name",  # <-- UPDATE THIS
    "degree": "BSc Computer Science"  # <-- UPDATE THIS
}
```

### Add More Risks

Edit `academic/risk_register.py` and add to `get_risk_register()`:

```python
{
    "risk_id": "RISK-009",
    "category": "Your Category",
    "title": "Your Risk Title",
    # ... full risk structure
}
```

### Add More User Stories

Edit `academic/rtm_generator.py` and add to `get_rtm_data()`:

```python
{
    "epic": "YOUR_EPIC",
    "epic_name": "Epic Name",
    "feature": "Feature Name",
    "user_story": "US026",
    # ... full story structure
}
```

## Troubleshooting

### Issue: Modal not opening

**Solution**: Ensure callbacks are registered:
```python
register_academic_callbacks(app, DB_PATH)
```

### Issue: Diagrams not generating

**Solution**: Install diagrams library:
```bash
pip install diagrams graphviz
# On Mac: brew install graphviz
# On Linux: sudo apt-get install graphviz
```

If diagrams library is not available, text-based diagrams will be generated instead.

### Issue: Performance metrics showing "No data"

**Solution**: Wait 5 minutes for first collection, or manually trigger:
```python
from academic.performance_metrics import PerformanceMetricsCollector
collector = PerformanceMetricsCollector(DB_PATH)
metrics = collector.collect_metrics()
collector.store_metrics(metrics)
```

### Issue: Export files not found

**Solution**: Ensure `data/` directory exists:
```bash
mkdir -p /Users/ritiksah/iotsentinel/data/diagrams
```

## Testing

Test the integration:

```python
# Test BCS compliance
from academic.bcs_compliance import BCSComplianceManager
bcs = BCSComplianceManager(DB_PATH)
data = bcs.get_compliance_data()
print(f"BCS Evidence collected: {len(data['substantial_technical_challenge']['evidence'])} items")

# Test RTM
from academic.rtm_generator import RTMGenerator
rtm = RTMGenerator(DB_PATH)
stats = rtm.get_summary_statistics()
print(f"RTM: {stats['total_user_stories']} user stories, {stats['average_coverage']}% coverage")

# Test Risk Register
from academic.risk_register import RiskRegisterManager
risks = RiskRegisterManager(DB_PATH)
summary = risks.get_risk_summary()
print(f"Risk Register: {summary['total_risks']} risks, {summary['mitigation_rate']}% mitigated")

# Test Performance Metrics
from academic.performance_metrics import PerformanceMetricsCollector
perf = PerformanceMetricsCollector(DB_PATH)
current = perf.collect_metrics()
print(f"Performance: {current['cpu_usage']}% CPU, {current['ram_usage_percent']}% RAM")

# Test C4 Diagrams
from academic.c4_generator import C4DiagramGenerator
c4 = C4DiagramGenerator(DB_PATH)
arch = c4.get_architecture_description()
print(f"Architecture: {len(arch['layers'])} layers, {len(arch['design_patterns'])} patterns")
```

## File Structure

```
iotsentinel/
├── academic/
│   ├── __init__.py
│   ├── bcs_compliance.py           # BCS evidence collection
│   ├── rtm_generator.py            # Requirements traceability
│   ├── risk_register.py            # Risk management
│   ├── performance_metrics.py      # Performance monitoring
│   ├── c4_generator.py             # Architecture diagrams
│   └── dashboard_components.py     # UI components & callbacks
├── dashboard/
│   └── app.py                      # Main dashboard (integrate here)
├── data/
│   └── diagrams/                   # Generated C4 diagrams
└── ACADEMIC_EVIDENCE_INTEGRATION_GUIDE.md
```

## Export Locations

All exports go to `data/` directory:

- BCS Compliance: `data/bcs_evidence_YYYYMMDD_HHMMSS.json`
- RTM: `data/rtm_YYYYMMDD_HHMMSS.csv`
- Risk Register: `data/risk_register_YYYYMMDD_HHMMSS.json`
- Performance: `data/performance_metrics_YYYYMMDD_HHMMSS.csv`
- Architecture: `data/architecture_docs_YYYYMMDD_HHMMSS.json`
- C4 Diagrams: `data/diagrams/c4_level1_system_context.png`, etc.

## Support

For issues or questions:
1. Check the troubleshooting section above
2. Review module docstrings in `academic/*.py` files
3. Test individual modules using the testing code above

## License & Attribution

This academic evidence system was generated to support BCS accreditation requirements for the IoTSentinel major project.

**Remember to cite properly in your report:**
> The academic evidence collection system was implemented to systematically document compliance with BCS accreditation criteria, including automated requirements traceability, risk management tracking, and performance benchmarking.
