# IoTSentinel Logging System

## Overview

IoTSentinel implements a comprehensive 8-log system with **built-in credential sanitization** to ensure production-ready logging without security risks.

## ✅ Implemented Logs

### Core Logs (Production Critical)

| Log File             | Purpose                                               | Logger Name               | Production Status |
| -------------------- | ----------------------------------------------------- | ------------------------- | ----------------- |
| **iotsentinel.log**  | Main application events, dashboard operations         | `__name__` (various)      | ✅ Active         |
| **audit.log**        | Authentication, user actions, security events         | `audit`                   | ✅ Active         |
| **orchestrator.log** | Network capture, Zeek integration, packet processing  | `__name__` (orchestrator) | ✅ Active         |
| **ml.log**           | ML training/inference, anomaly detection, forecasting | `ml`                      | ✅ Configured     |
| **alerts.log**       | Alert generation, notifications, integrations         | `alerts`                  | ✅ Configured     |

### Optional Logs (Environment-Specific)

| Log File         | Purpose                                          | Logger Name | Production Status   |
| ---------------- | ------------------------------------------------ | ----------- | ------------------- |
| **hardware.log** | GPIO events, LED status, Raspberry Pi hardware   | `hardware`  | ✅ Active (Pi only) |
| **database.log** | DB operations, maintenance, query optimization   | `database`  | ✅ Configured       |
| **error.log**    | Centralized ERROR/CRITICAL from all modules      | `errors`    | ✅ Active           |
| **api.log**      | External API calls (NVD, webhooks, integrations) | `api`       | ✅ Active           |

## 🔒 Security Features

### Credential Sanitization

All logs use the **log_sanitizer** module to prevent credential leaks:

```python
from utils.log_sanitizer import safe_log_data, sanitize_dict

# ❌ UNSAFE - DO NOT DO THIS
logger.info(f"Config: {user_credentials}")

# ✅ SAFE - Credentials automatically redacted
logger.info(f"Config: {safe_log_data(user_credentials)}")
```

### What Gets Redacted

The sanitizer automatically redacts:

- Passwords (`password`, `passwd`, `pwd`, `smtp_password`)
- API Keys (`api_key`, `apikey`, `api-key`)
- Tokens (`token`, `bot_token`, `bearer`, `oauth`)
- Secrets (`secret`, `client_secret`)
- Credentials in URLs (`https://user:pass@host`) # pragma: allowlist secret
- Webhook URLs
- Session IDs and cookies

### Example

```python
# Input (test data for documentation)  # pragma: allowlist secret
{
    "username": "admin",
    "password": "SuperSecret123!",  # pragma: allowlist secret
    "api_key": "sk_live_51H8vY2eZvKYlo2C0aIiXyZ",  # pragma: allowlist secret
    "email": "user@example.com"
}

# Output (logged)
{
    "username": "admin",
    "password": "Supe...***REDACTED***", # pragma: allowlist secret
    "api_key": "sk_l...***REDACTED***", # pragma: allowlist secret
    "email": "user@example.com"
}
```

## 📝 Log Usage by Module

### Dashboard (`dashboard/app.py`)

- **Logger**: `__name__`, `audit`
- **Logs to**: `iotsentinel.log`, `audit.log`
- **Usage**: User actions, authentication, role changes

### Orchestrator (`orchestrator.py`)

- **Logger**: `__name__`
- **Logs to**: `orchestrator.log`
- **Usage**: Network capture, Zeek parsing, device discovery

### ML Modules (`ml/*.py`)

- **Logger**: `ml`
- **Logs to**: `ml.log`
- **Usage**: Model training, anomaly detection, forecasting

### Alert System (`alerts/*.py`)

- **Logger**: `alerts`
- **Logs to**: `alerts.log`
- **Usage**: Alert creation, email notifications, report generation

### Hardware Monitor (`services/hardware_monitor.py`)

- **Logger**: `hardware`
- **Logs to**: `hardware.log`
- **Usage**: GPIO control, LED status, button events (Raspberry Pi only)

### Database (`database/*.py`)

- **Logger**: `database`
- **Logs to**: `database.log`
- **Usage**: DB operations, query optimization, maintenance

### API Integrations

- **Logger**: `api`
- **Logs to**: `api.log`
- **Modules**:
  - `alerts/integration_actions.py` - Slack, Discord, Telegram, webhooks
  - `utils/nvd_api_client.py` - NVD API calls
- **Usage**: External API calls with safe credential logging

### Error Aggregation

- **Logger**: `errors`
- **Logs to**: `error.log`
- **Usage**: All ERROR and CRITICAL messages from any module

## 🔧 Configuration

All loggers are configured in `dashboard/app.py` (lines 115-185):

```python
# Example: ML Logger
ml_logger = logging.getLogger('ml')
ml_logger.setLevel(logging.INFO)
ml_handler = logging.FileHandler(os.path.join(log_dir, 'ml.log'))
ml_handler.setFormatter(log_formatter)
ml_logger.addHandler(ml_handler)
```

## 📊 Log Format

```
2026-01-21 16:45:23,456 - module.name - INFO - Message here
```

Components:

- **Timestamp**: ISO format with milliseconds
- **Module**: Python module name
- **Level**: DEBUG, INFO, WARNING, ERROR, CRITICAL
- **Message**: Log message (credentials redacted)

## 🚀 Production Deployment Checklist

- [x] All core logs implemented
- [x] Credential sanitization in place
- [x] Security test suite passing
- [x] Hardware logging for Pi deployments
- [x] API logging for external integrations
- [x] Error centralization working
- [x] Audit trail functional

## 🧪 Testing

Run the security test suite to verify no credentials leak:

```bash
python3 tests/test_log_sanitization.py
```

Expected output:

```
✅ ALL TESTS PASSED!
🔒 Log sanitization is working correctly.
✅ Safe to use in production - credentials will be redacted.
```

## 📂 Log File Locations

```
data/logs/
├── iotsentinel.log     # Main application log
├── audit.log           # Security audit trail
├── orchestrator.log    # Network monitoring
├── ml.log             # Machine learning operations
├── alerts.log         # Alert system
├── hardware.log       # GPIO/Pi hardware (if applicable)
├── database.log       # Database operations
├── error.log          # Centralized errors
└── api.log            # External API calls
```

## 🔄 Log Rotation

For production deployments, configure log rotation in `/etc/logrotate.d/iotsentinel`:

```bash
/opt/iotsentinel/data/logs/*.log {
    daily
    rotate 30
    compress
    delaycompress
    notifempty
    create 0640 iotsentinel iotsentinel
    sharedscripts
    postrotate
        systemctl reload iotsentinel-dashboard || true
    endscript
}
```

## 📖 Usage Examples

### Standard Logging

```python
import logging

logger = logging.getLogger(__name__)
logger.info("Application started")
logger.warning("Low disk space detected")
logger.error("Failed to connect to database")
```

### Audit Logging

```python
audit_logger = logging.getLogger('audit')
audit_logger.info(f"User {username} logged in successfully")
audit_logger.warning(f"Failed login attempt for {username}")
audit_logger.info(f"User {username} changed role from {old_role} to {new_role}")
```

### ML Logging

```python
ml_logger = logging.getLogger('ml')
ml_logger.info("Starting model training")
ml_logger.info(f"Model accuracy: {accuracy:.2f}")
ml_logger.warning("Anomaly detected in traffic pattern")
```

### API Logging (with credential safety)

```python
from utils.log_sanitizer import safe_log_data

api_logger = logging.getLogger('api')
api_logger.info("Making Slack API request")
api_logger.debug(f"Request config: {safe_log_data(config)}")
api_logger.info(f"API response: {response.status_code}")
```

### Hardware Logging

```python
hardware_logger = logging.getLogger('hardware')
hardware_logger.info("🔧 HARDWARE: GPIO initialized - LED:GPIO18, Button:GPIO23")
hardware_logger.info("🔧 HARDWARE: LED ON (GPIO18)")
hardware_logger.warning("🔧 HARDWARE: Button pressed (GPIO23)")
```

## 🛡️ Security Best Practices

1. **Never log raw credentials** - Always use `safe_log_data()`
2. **Use appropriate log levels** - DEBUG for development, INFO for production
3. **Sanitize user input** - Prevent log injection attacks
4. **Rotate logs regularly** - Prevent disk space issues
5. **Secure log files** - Set proper permissions (0640 or 0600)
6. **Monitor error.log** - Critical for production debugging

## 🎯 Production Readiness

**Status**: ✅ **100% PRODUCTION READY**

All logging infrastructure is implemented and tested:

- ✅ 8 specialized logs configured
- ✅ Credential sanitization working
- ✅ Security tests passing
- ✅ Hardware/API logging active
- ✅ Error centralization functional
- ✅ Audit trail complete

No action required - ready for deployment and public release.
