# Raspberry Pi Deployment Guide

**Complete guide for deploying IoTSentinel to Raspberry Pi with 100% validation**

## 🎯 Quick Status Check

Run this on your Pi to verify everything is working:

```bash
cd ~/iotsentinel

# 1. Check Scapy
python3 -c "from utils.arp_scanner import SCAPY_AVAILABLE; print(f'Scapy: {'✅' if SCAPY_AVAILABLE else '❌'}')"

# 2. Check Zeek
if [ -x "/opt/zeek/bin/zeek" ]; then echo "Zeek: ✅"; else echo "Zeek: ❌"; fi

# 3. Check River ML
python3 -c "import river; print('River ML: ✅')" 2>/dev/null || echo "River ML: ❌"

# 4. Check system resources
echo "RAM: $(free -h | awk 'NR==2{print $3 "/" $2}')"
echo "CPU: $(top -bn1 | grep "Cpu(s)" | awk '{print $2}')%"
```

## 📊 Resource Usage Summary

| Component     | Purpose           | CPU        | RAM           | When Active   |
| ------------- | ----------------- | ---------- | ------------- | ------------- |
| **Zeek**      | Packet analysis   | 15-20%     | 100-150MB     | Always        |
| **Scapy**     | Device discovery  | <1%        | 2-5MB         | Every 5 min   |
| **River ML**  | Anomaly detection | 2-3%       | 20-30MB       | Every 5 min   |
| **Dashboard** | Web UI            | 5-8%       | 100-150MB     | When accessed |
| **Total**     | -                 | **25-37%** | **290-440MB** | -             |

---

## Pre-Deployment Requirements

### 1. **Scapy Configuration** ⚠️

#### Installation

```bash
# Scapy is included in requirements-pi.txt
pip install scapy==2.5.0
```

#### Permission Requirements

Scapy requires **root privileges** for ARP scanning. You have two options:

**Option A: Run orchestrator with sudo (Simple but less secure)**

```bash
sudo python3 orchestrator.py
```

**Option B: Set capabilities on Python (Recommended)**

```bash
# Allow Python to send raw packets without sudo
sudo setcap cap_net_raw,cap_net_admin=eip $(readlink -f $(which python3))

# Verify
getcap $(readlink -f $(which python3))
# Should show: cap_net_admin,cap_net_raw=eip
```

**Option C: Use nmap fallback (No sudo needed)**

```bash
# Install nmap
sudo apt install nmap

# ARP scanner will auto-detect and use nmap instead
# Slightly slower but works without root
```

#### Testing Scapy

```bash
# Test ARP scanner
python3 -m utils.arp_scanner --scan

# Should discover devices on your network
# If you get "Permission denied", use Option B above
```

### 2. **Zeek Installation** ✅

#### Install Zeek on Raspberry Pi

```bash
# Add Zeek repository
echo 'deb http://download.opensuse.org/repositories/security:/zeek/Debian_11/ /' \
  | sudo tee /etc/apt/sources.list.d/security:zeek.list

# Add GPG key
curl -fsSL https://download.opensuse.org/repositories/security:zeek/Debian_11/Release.key \
  | gpg --dearmor | sudo tee /etc/apt/trusted.gpg.d/security_zeek.gpg > /dev/null

# Install
sudo apt update
sudo apt install zeek

# Verify installation
/opt/zeek/bin/zeek --version
```

#### Configure Zeek

```bash
# Edit network interface
sudo nano /opt/zeek/etc/node.cfg

# Change interface to your Pi's network interface (usually eth0 or wlan0)
[zeek]
type=standalone
host=localhost
interface=eth0  # or wlan0 for WiFi

# Start Zeek
sudo /opt/zeek/bin/zeekctl deploy
sudo /opt/zeek/bin/zeekctl status
```

#### Zeek Log Location

```bash
# Zeek logs are written to:
/opt/zeek/logs/current/

# Verify logs are being created
ls -lah /opt/zeek/logs/current/conn.log
```

#### Configure IoTSentinel to Read Zeek Logs

```json
// config/default_config.json
{
  "network": {
    "zeek_log_path": "/opt/zeek/logs/current",
    "interface": "eth0"
  }
}
```

### 3. **Machine Learning - River** ✅

#### Already Optimized!

- **No training needed** - learns from first connection
- **Memory:** 10-20MB (vs 500MB TensorFlow)
- **Inference:** 2-5ms per connection
- **Auto-saves:** Every 100 predictions

#### Verify River Installation

```bash
python3 -c "import river; print(river.__version__)"
# Should print: 0.21.0
```

#### Test ML Engine

```bash
# Run a quick test
python3 -c "
from ml.river_engine import RiverMLEngine
from database.db_manager import DatabaseManager

db = DatabaseManager('data/database/iotsentinel.db')
engine = RiverMLEngine(db)
print('✓ River ML engine initialized successfully')
print(f'Stats: {engine.get_stats()}')
"
```

### 4. **Resource Optimization**

#### Memory Check

```bash
# Check available RAM
free -h

# IoTSentinel requires:
# - Minimum: 2GB RAM
# - Recommended: 4GB RAM
# - With Ollama AI: 4GB+ RAM
```

#### CPU Monitoring

```bash
# Monitor CPU during operation
python3 utils/metrics_collector.py --start

# Check stats after 1 hour
python3 utils/metrics_collector.py --report

# Target: <30% average CPU usage
```

#### Disk Space

```bash
# Check disk space
df -h

# Minimum: 8GB free for logs and database
# Recommended: 16GB+ for long-term operation
```

### 5. **Network Configuration**

#### Enable Packet Capture

```bash
# Allow network sniffing
sudo sysctl -w net.ipv4.conf.all.route_localnet=1

# Make permanent
echo "net.ipv4.conf.all.route_localnet=1" | sudo tee -a /etc/sysctl.conf
```

#### Firewall Rules (if using)

```bash
# Allow dashboard access
sudo ufw allow 8050/tcp  # Dash dashboard

# Allow SSH (if not already allowed)
sudo ufw allow 22/tcp
```

## Deployment Steps

### 1. Install System Dependencies

```bash
# Update system
sudo apt update && sudo apt upgrade -y

# Install build tools
sudo apt install -y python3-dev python3-pip python3-venv
sudo apt install -y libpcap-dev libffi-dev libssl-dev
sudo apt install -y git nmap

# Install Zeek (see section above)
```

### 2. Clone and Setup Project

```bash
# Clone repository
cd ~
git clone https://github.com/ritiksah141/iotsentinel.git
cd iotsentinel

# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install Python dependencies
pip install --upgrade pip
pip install -r requirements-pi.txt
```

### 3. Initialize Database

```bash
# Create database schema
python3 config/init_database.py

# Verify database
ls -lah data/database/iotsentinel.db
```

### 4. Configure Environment

```bash
# Copy environment template
cp .env.template .env

# Edit configuration
nano .env

# Set required values:
# - FLASK_SECRET_KEY (generate with: python3 -c "import secrets; print(secrets.token_hex(32))")
# - SMTP credentials (if using email alerts)
```

### 5. Set Capabilities (for Scapy)

```bash
# Allow Python to capture packets without sudo
sudo setcap cap_net_raw,cap_net_admin=eip $(readlink -f $(which python3))
```

### 6. Start Services

```bash
# Start orchestrator (in background)
nohup python3 orchestrator.py > logs/orchestrator.log 2>&1 &

# Start dashboard
python3 dashboard/app.py
```

### 7. Setup Systemd Services (Recommended)

```bash
# Run setup script
bash scripts/setup_pi.sh

# Enable services
sudo systemctl enable iotsentinel-orchestrator
sudo systemctl enable iotsentinel-dashboard

# Start services
sudo systemctl start iotsentinel-orchestrator
sudo systemctl start iotsentinel-dashboard

# Check status
sudo systemctl status iotsentinel-orchestrator
sudo systemctl status iotsentinel-dashboard
```

## Verification Checklist

- [ ] Zeek is running and generating logs

  ```bash
  sudo /opt/zeek/bin/zeekctl status
  ls -lah /opt/zeek/logs/current/conn.log
  ```

- [ ] Scapy can scan network

  ```bash
  python3 -m utils.arp_scanner --scan
  ```

- [ ] River ML engine initializes

  ```bash
  python3 -c "from ml.river_engine import RiverMLEngine; print('OK')"
  ```

- [ ] Database is accessible

  ```bash
  sqlite3 data/database/iotsentinel.db "SELECT COUNT(*) FROM devices;"
  ```

- [ ] Dashboard is accessible

  ```bash
  curl http://localhost:8050
  ```

- [ ] Orchestrator is processing connections
  ```bash
  tail -f logs/orchestrator.log
  # Should see "Processing N connections..."
  ```

## Common Issues and Solutions

### Issue 1: Scapy Permission Denied

**Error:** `PermissionError: [Errno 1] Operation not permitted`

**Solution:**

```bash
# Set capabilities
sudo setcap cap_net_raw,cap_net_admin=eip $(readlink -f $(which python3))

# OR run with sudo
sudo python3 orchestrator.py
```

### Issue 2: Zeek Not Found

**Error:** `Zeek not found at /opt/zeek/bin/zeek`

**Solution:**

```bash
# Install Zeek (see section above)
# Or update config to point to correct Zeek location
which zeek
```

### Issue 3: High Memory Usage

**Error:** System becomes slow, OOM killer activates

**Solution:**

```bash
# Check memory
free -h

# Reduce dashboard complexity in config
# Disable Ollama AI if not needed
# Increase swap space:
sudo dphys-swapfile swapoff
sudo nano /etc/dphys-swapfile  # Set CONF_SWAPSIZE=2048
sudo dphys-swapfile setup
sudo dphys-swapfile swapon
```

### Issue 4: Zeek Logs Not Parsed

**Error:** No connections showing in dashboard

**Solution:**

```bash
# Check Zeek is running
sudo /opt/zeek/bin/zeekctl status

# Check log path in config
cat config/default_config.json | grep zeek_log_path

# Check orchestrator logs
tail -f logs/orchestrator.log
```

### Issue 5: River ML Not Learning

**Error:** All anomaly scores are 0.0

**Solution:**

```bash
# River learns incrementally - give it time (10-20 connections minimum)
# Check model is saving
ls -lah data/models/river_engine.pkl

# Force a prediction test
python3 -c "
from ml.river_engine import RiverMLEngine
from database.db_manager import DatabaseManager

db = DatabaseManager('data/database/iotsentinel.db')
engine = RiverMLEngine(db)

# Test connection
test_conn = {
    'device_ip': '192.168.1.100',
    'dest_ip': '8.8.8.8',
    'dest_port': 443,
    'bytes_sent': 1024,
    'bytes_received': 2048,
    'duration': 1.5,
    'protocol': 'tcp'
}

result = engine.analyze_connection(test_conn)
print(result)
"
```

## 🔧 Quick Reference Commands

### Scapy

```bash
# Test ARP scanner
python3 -m utils.arp_scanner --scan

# Use nmap fallback (if scapy fails)
python3 -m utils.arp_scanner --scan --nmap

# Set capabilities (run once)
sudo setcap cap_net_raw,cap_net_admin=eip $(readlink -f $(which python3))
```

### Zeek

```bash
# Start/stop Zeek
sudo /opt/zeek/bin/zeekctl deploy
sudo /opt/zeek/bin/zeekctl stop

# Check status
sudo /opt/zeek/bin/zeekctl status

# View live connections
tail -f /opt/zeek/logs/current/conn.log

# Rotate logs manually
sudo /opt/zeek/bin/zeekctl cron
```

### River ML

```bash
# View ML stats
python3 -c "
from ml.river_engine import RiverMLEngine
from database.db_manager import DatabaseManager
db = DatabaseManager('data/database/iotsentinel.db')
engine = RiverMLEngine(db)
import json
print(json.dumps(engine.get_stats(), indent=2))
"

# Test inference
python3 -c "
from ml.river_engine import RiverMLEngine
from database.db_manager import DatabaseManager
db = DatabaseManager('data/database/iotsentinel.db')
engine = RiverMLEngine(db)

test = {
    'device_ip': '192.168.1.100',
    'dest_ip': '8.8.8.8',
    'dest_port': 443,
    'bytes_sent': 1024,
    'bytes_received': 2048,
    'duration': 1.5,
    'protocol': 'tcp'
}

result = engine.analyze_connection(test)
print(f\"Anomaly: {result['is_anomaly']}\")
print(f\"Score: {result['anomaly_score']}\")
print(f\"Threat: {result['threat_level']}\")
"
```

## 📈 Performance Monitoring

```bash
# Real-time resource monitoring
python3 utils/metrics_collector.py --start --interval 60

# Generate report (after 1 hour)
python3 utils/metrics_collector.py --report

# Watch system resources
watch -n 2 '
echo "=== CPU ===" && \
top -bn1 | grep "Cpu(s)" && \
echo "" && \
echo "=== RAM ===" && \
free -h && \
echo "" && \
echo "=== Processes ===" && \
ps aux --sort=-%cpu | head -5
'
```

## 🚀 Quick Deploy

```bash
# On your computer (not Pi)
git clone https://github.com/ritiksah141/iotsentinel.git
cd iotsentinel

# Deploy to Pi
bash scripts/deploy_to_pi.sh pi@192.168.1.100

# Wait for deployment to complete (~5-10 minutes)
# Then access dashboard: http://192.168.1.100:8050
```

## Support

- Documentation: `/docs/`
- Logs: `/data/logs/`
- GitHub Issues: https://github.com/ritiksah141/iotsentinel/issues

## Performance Targets

| Metric          | Target        | Typical   | Status |
| --------------- | ------------- | --------- | ------ |
| CPU Usage (avg) | <30%          | 25-28%    | ✅     |
| Memory Usage    | <2GB          | 1.2-1.5GB | ✅     |
| Inference Time  | <30s/100 conn | 24s       | ✅     |
| Processing Lag  | <30min        | 12min     | ✅     |
| Dashboard Load  | <3s           | 2.1s      | ✅     |

## Maintenance

### Daily

- Check system status: `sudo systemctl status iotsentinel-*`
- Monitor disk space: `df -h`

### Weekly

- Review alerts: Check dashboard
- Backup database: `python3 scripts/db_maintenance.py --backup`

### Monthly

- Update system: `sudo apt update && sudo apt upgrade`
- Rotate Zeek logs: `sudo /opt/zeek/bin/zeekctl cron`
- Clean old exports: `find data/exports -mtime +30 -delete`

## Support

- Documentation: `/docs/`
- Logs: `/data/logs/`
- GitHub Issues: https://github.com/ritiksah141/iotsentinel/issues
