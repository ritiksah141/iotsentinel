# Production Logging Deployment Guide

## 🚀 Quick Start - Production Ready in 5 Minutes

IoTSentinel logging is **already production-ready** with industry-standard features built-in. This guide shows you how to optimize for your specific deployment.

## ✅ Current Status: Production Ready

Your logging system already includes:

- ✅ **Log rotation** - Automatic (50MB max, 10 backups)
- ✅ **Credential sanitization** - Built-in PII/secret redaction
- ✅ **Multiple log streams** - 8 specialized logs
- ✅ **Error centralization** - All errors in one place
- ✅ **Audit trails** - Complete security event logging
- ✅ **Environment-aware** - Development vs Production modes

## 📊 Industry Standard Compliance

### Logging Standards Met

| Standard      | Requirement                     | IoTSentinel Implementation          | Status |
| ------------- | ------------------------------- | ----------------------------------- | ------ |
| **OWASP**     | Audit trail for security events | `audit.log` with all auth events    | ✅     |
| **PCI-DSS**   | Log rotation & retention        | 50MB rotation, 10 backups = ~500MB  | ✅     |
| **GDPR**      | No PII in logs                  | Automatic credential sanitization   | ✅     |
| **SOC 2**     | Centralized error logging       | `error.log` aggregates all errors   | ✅     |
| **ISO 27001** | Access logging                  | `audit.log` tracks all user actions | ✅     |
| **NIST**      | Security event monitoring       | Separate security logs              | ✅     |

## 🔧 Environment Configuration

### Default (Development)

```bash
# Uses existing dashboard/app.py configuration
# - INFO level logging
# - Console output enabled
# - Plain text format
# - Log rotation: 50MB, 10 backups
```

### Production (Recommended)

```bash
# Set these environment variables:
export IOTSENTINEL_ENV=production
export CONSOLE_LOGGING=false
export LOG_MAX_BYTES=104857600  # 100MB
export LOG_BACKUP_COUNT=30      # Keep 30 days

# Optional: Enable structured logging for log aggregation
export STRUCTURED_LOGGING=true   # JSON format for ELK/Splunk
```

### Docker Deployment

```dockerfile
# Dockerfile
ENV IOTSENTINEL_ENV=production
ENV CONSOLE_LOGGING=false
ENV STRUCTURED_LOGGING=true
ENV LOG_MAX_BYTES=104857600
ENV LOG_BACKUP_COUNT=30

# Mount logs volume
VOLUME /opt/iotsentinel/data/logs
```

### Docker Compose

```yaml
version: "3.8"
services:
  iotsentinel:
    image: iotsentinel:latest
    environment:
      - IOTSENTINEL_ENV=production
      - CONSOLE_LOGGING=false
      - STRUCTURED_LOGGING=true
      - LOG_MAX_BYTES=104857600
      - LOG_BACKUP_COUNT=30
    volumes:
      - ./data/logs:/opt/iotsentinel/data/logs
      - ./data/database:/opt/iotsentinel/data/database
```

### Systemd Service

```ini
# /etc/systemd/system/iotsentinel.service
[Unit]
Description=IoTSentinel Network Security Monitor
After=network.target

[Service]
Type=simple
User=iotsentinel
WorkingDirectory=/opt/iotsentinel
Environment="IOTSENTINEL_ENV=production"
Environment="CONSOLE_LOGGING=false"
Environment="LOG_MAX_BYTES=104857600"
Environment="LOG_BACKUP_COUNT=30"
ExecStart=/opt/iotsentinel/venv/bin/python3 dashboard/app.py
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
```

## 📈 Log Rotation Strategies

### Default (Built-in)

- **Size-based**: Rotate at 50MB
- **Backups**: Keep 10 files (~500MB total)
- **Format**: `logfile.log`, `logfile.log.1`, `logfile.log.2`, ...

### Time-based (Optional - via logrotate)

```bash
# /etc/logrotate.d/iotsentinel
/opt/iotsentinel/data/logs/*.log {
    daily                # Rotate daily
    rotate 30            # Keep 30 days
    compress             # Gzip old logs
    delaycompress        # Don't compress most recent
    notifempty           # Don't rotate if empty
    create 0640 iotsentinel iotsentinel
    sharedscripts
    postrotate
        systemctl reload iotsentinel || true
    endscript
}
```

Install: `sudo cp logrotate.conf /etc/logrotate.d/iotsentinel`

## 🔍 Log Aggregation & Monitoring

### ELK Stack (Elasticsearch, Logstash, Kibana)

#### Enable Structured Logging

```bash
export STRUCTURED_LOGGING=true
```

#### Filebeat Configuration

```yaml
# filebeat.yml
filebeat.inputs:
  - type: log
    enabled: true
    paths:
      - /opt/iotsentinel/data/logs/*.log
    json.keys_under_root: true
    json.add_error_key: true
    fields:
      application: iotsentinel
      environment: production

output.elasticsearch:
  hosts: ["localhost:9200"]
  index: "iotsentinel-%{+yyyy.MM.dd}"
```

### Splunk

#### Inputs Configuration

```conf
# /opt/splunk/etc/apps/iotsentinel/local/inputs.conf
[monitor:///opt/iotsentinel/data/logs/*.log]
disabled = false
index = iotsentinel
sourcetype = iotsentinel:log
```

### AWS CloudWatch

```python
# Add to dashboard/app.py for CloudWatch integration
import watchtower

cloudwatch_handler = watchtower.CloudWatchLogHandler(
    log_group='iotsentinel',
    stream_name='production'
)
logger.addHandler(cloudwatch_handler)
```

### Prometheus + Grafana

```python
# Export log metrics
from prometheus_client import Counter, Histogram

log_counter = Counter('iotsentinel_logs_total', 'Total logs', ['level', 'logger'])
log_errors = Counter('iotsentinel_errors_total', 'Total errors', ['module'])
```

## 🔒 Security Best Practices

### 1. File Permissions

```bash
# Production permissions
sudo chown -R iotsentinel:iotsentinel /opt/iotsentinel/data/logs
sudo chmod 750 /opt/iotsentinel/data/logs
sudo chmod 640 /opt/iotsentinel/data/logs/*.log
```

### 2. Log Encryption (Optional)

```bash
# Encrypt archived logs
find /opt/iotsentinel/data/logs -name "*.log.[1-9]" -exec gzip {} \;
find /opt/iotsentinel/data/logs -name "*.gz" -exec gpg --encrypt --recipient admin@example.com {} \;
```

### 3. Remote Syslog (Enterprise)

```python
# Add to logging setup
import logging.handlers

syslog_handler = logging.handlers.SysLogHandler(
    address=('syslog.company.com', 514)
)
logger.addHandler(syslog_handler)
```

## 📊 Monitoring & Alerts

### Log File Growth Monitoring

```bash
#!/bin/bash
# monitor_logs.sh - Alert if logs grow too fast

LOG_DIR="/opt/iotsentinel/data/logs"
MAX_SIZE_MB=500

total_size=$(du -sm "$LOG_DIR" | cut -f1)

if [ $total_size -gt $MAX_SIZE_MB ]; then
    echo "WARNING: Log directory exceeds ${MAX_SIZE_MB}MB (current: ${total_size}MB)"
    # Send alert via email or webhook
fi
```

### Error Rate Monitoring

```bash
#!/bin/bash
# check_errors.sh - Alert on high error rate

error_count=$(tail -1000 data/logs/error.log | wc -l)

if [ $error_count -gt 100 ]; then
    echo "ALERT: High error rate detected (${error_count} errors in last 1000 lines)"
fi
```

### Systemd Integration

```bash
# Monitor via journald
sudo journalctl -u iotsentinel -f --no-pager

# Alert on errors
sudo journalctl -u iotsentinel -p err -f
```

## 🧪 Production Verification Checklist

### Pre-Deployment

- [ ] Log rotation configured (check `LOG_MAX_BYTES`, `LOG_BACKUP_COUNT`)
- [ ] Console logging disabled in production (`CONSOLE_LOGGING=false`)
- [ ] Appropriate log level set (`IOTSENTINEL_ENV=production` → WARNING level)
- [ ] Log directory permissions correct (640 for files, 750 for dir)
- [ ] Credential sanitization tested (`python3 tests/test_log_sanitization.py`)
- [ ] Log directory mounted/backed up (Docker volumes, etc.)

### Post-Deployment

- [ ] Logs being written (`ls -lh data/logs/`)
- [ ] Log rotation working (wait for file > MAX_BYTES)
- [ ] No credentials in logs (`grep -r "password\|token\|api_key" data/logs/`)
- [ ] Error log receiving errors (`tail -f data/logs/error.log`)
- [ ] Audit log tracking security events (`tail -f data/logs/audit.log`)
- [ ] Disk space monitoring configured
- [ ] Log aggregation working (if using ELK/Splunk)

## 📦 Backup & Retention

### Automated Backup Script

```bash
#!/bin/bash
# backup_logs.sh - Daily log backup

BACKUP_DIR="/backup/iotsentinel/logs"
LOG_DIR="/opt/iotsentinel/data/logs"
DATE=$(date +%Y%m%d)

# Create backup
tar -czf "${BACKUP_DIR}/logs_${DATE}.tar.gz" -C "$LOG_DIR" .

# Keep only 90 days
find "$BACKUP_DIR" -name "logs_*.tar.gz" -mtime +90 -delete

# Upload to S3 (optional)
# aws s3 cp "${BACKUP_DIR}/logs_${DATE}.tar.gz" s3://company-backups/iotsentinel/
```

### Cron Setup

```bash
# Add to crontab
0 2 * * * /opt/iotsentinel/scripts/backup_logs.sh
```

## 🚨 Troubleshooting

### Logs Not Rotating

```bash
# Check current log sizes
ls -lh data/logs/

# Verify MAX_BYTES setting
echo $LOG_MAX_BYTES

# Force rotation test
python3 -c "
import logging.handlers
handler = logging.handlers.RotatingFileHandler('test.log', maxBytes=1024, backupCount=3)
for i in range(2000):
    handler.emit(logging.LogRecord('test', logging.INFO, '', 0, f'Test {i}', (), None))
"
```

### High Disk Usage

```bash
# Check log directory size
du -sh data/logs/

# Find largest logs
du -h data/logs/*.log | sort -h

# Increase rotation (emergency)
export LOG_MAX_BYTES=10485760  # 10MB
export LOG_BACKUP_COUNT=5
systemctl restart iotsentinel
```

### Missing Logs

```bash
# Check permissions
ls -la data/logs/

# Check environment
env | grep IOTSENTINEL

# Verify logging initialized
tail -100 data/logs/iotsentinel.log | grep "Logging System Initialized"
```

## 📚 Additional Resources

- [OWASP Logging Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html)
- [Python Logging Best Practices](https://docs.python.org/3/howto/logging.html)
- [Log4j Security Considerations](https://logging.apache.org/log4j/2.x/security.html)
- [NIST Cybersecurity Framework - Logging](https://www.nist.gov/cyberframework)

## ✅ Summary

**Your IoTSentinel logging is production-ready out of the box!**

- ✅ No code changes required
- ✅ Works with default configuration
- ✅ Meets industry standards
- ✅ Secure by default (credential sanitization)
- ✅ Scalable (log rotation built-in)

**Optional enhancements** for specific environments:

- Set `IOTSENTINEL_ENV=production` for WARNING-level logging
- Enable `STRUCTURED_LOGGING=true` for log aggregation platforms
- Configure logrotate for time-based rotation
- Integrate with monitoring tools (ELK, Splunk, CloudWatch)

**You're ready to deploy!** 🚀
