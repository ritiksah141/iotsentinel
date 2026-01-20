# 🔌 API Integration Hub

IoTSentinel's API Integration Hub provides secure management of **28 free-tier external API integrations** across 5 categories. All credentials are encrypted using **Fernet (AES-256)** before storage.

## 🎯 Features

- **28 Free-Tier Integrations** - No paid subscriptions required
- **Encrypted Credential Storage** - Military-grade AES-256 encryption for all API keys
- **Dashboard Configuration** - Complete UI for managing integrations (no .env editing needed)
- **Real-Time Health Monitoring** - Live status checks for all services
- **Usage Analytics** - Track requests, success rates, and errors
- **Priority System** - High/Medium/Low priority guidance
- **Auto-Generated Setup Guides** - Step-by-step instructions for each integration
- **Export/Import Config** - Backup and restore integration settings
- **Production-Ready** - Secure mode with database-only credential storage

## 📊 Integration Categories

### 🛡️ Threat Intelligence (8 integrations)

| Service            | Free Tier     | Description                               |
| ------------------ | ------------- | ----------------------------------------- |
| **AbuseIPDB**      | 1,000/day     | IP reputation database with abuse reports |
| **VirusTotal**     | 500/day       | Multi-engine malware scanner              |
| **AlienVault OTX** | Unlimited     | Open threat intelligence community        |
| **GreyNoise**      | Community API | Internet scanning detection               |
| **IPQualityScore** | 5,000/month   | Proxy/VPN detection, fraud prevention     |
| **ThreatFox**      | Unlimited     | Malware IOC sharing platform              |
| **Shodan**         | 100/month     | Internet-connected device search engine   |
| **NVD**            | Unlimited     | National Vulnerability Database (NIST)    |

### 🌍 Geolocation (3 integrations)

| Service           | Free Tier    | Description                            |
| ----------------- | ------------ | -------------------------------------- |
| **IPinfo**        | 50,000/month | IP geolocation, ASN, company info      |
| **IP-API**        | 45/min       | Free IP geolocation (no key required)  |
| **IPGeolocation** | 1,000/day    | Geolocation with timezone and currency |

### 🔔 Notifications (5 integrations)

| Service          | Free Tier   | Description                   |
| ---------------- | ----------- | ----------------------------- |
| **Slack**        | Unlimited   | Team messaging via webhooks   |
| **Discord**      | Unlimited   | Voice/video/text via webhooks |
| **Telegram**     | Unlimited   | Cloud messaging via bot API   |
| **Pushover**     | 7,500/month | Mobile push notifications     |
| **Email (SMTP)** | Unlimited   | Standard email notifications  |

### 🎫 Ticketing (4 integrations)

| Service           | Free Tier | Description                      |
| ----------------- | --------- | -------------------------------- |
| **GitHub Issues** | Unlimited | Create issues in GitHub repos    |
| **GitLab Issues** | Unlimited | Create issues in GitLab projects |
| **Trello**        | Unlimited | Create cards in Trello boards    |
| **Linear**        | Unlimited | Create issues in Linear          |

### 🔗 Webhooks (4 integrations)

| Service            | Free Tier       | Description                     |
| ------------------ | --------------- | ------------------------------- |
| **Custom Webhook** | Unlimited       | Send to any HTTP endpoint       |
| **Zapier**         | 100 tasks/month | Connect 5,000+ apps             |
| **IFTTT**          | Unlimited       | If This Then That automation    |
| **n8n**            | Unlimited       | Open-source workflow automation |

## 🔐 Security Architecture

### Encryption Flow

1. **User enters credentials** → Dashboard UI
2. **Credentials encrypted** → Fernet (AES-128 CBC + HMAC)
3. **Stored in database** → SQLite with encrypted blobs
4. **Retrieved when needed** → Auto-decrypted for API calls
5. **Never logged** → Credentials excluded from all logs

### Encryption Key Management

- Encryption key stored in `.env` file (never in code/database)
- Auto-generated on first run if not present
- Uses `cryptography.Fernet` with **AES-256 CBC + HMAC** (symmetric encryption)
- Key rotation supported (decrypt with old, re-encrypt with new)

### Database Schema

```sql
CREATE TABLE api_integrations (
    id INTEGER PRIMARY KEY,
    integration_name TEXT UNIQUE,
    category TEXT CHECK(category IN ('threat_intel', 'geolocation', 'notifications', 'ticketing', 'webhooks')),
    is_enabled INTEGER,
    api_key_encrypted TEXT,      -- Encrypted with Fernet
    api_secret_encrypted TEXT,    -- Encrypted with Fernet
    config_json TEXT,             -- Encrypted sensitive fields
    health_status TEXT,
    total_requests INTEGER,
    successful_requests INTEGER,
    ...
);
```

## 🚀 Quick Start

### 1. Production Setup (Recommended)

IoTSentinel uses **secure database-only storage** in production mode. No API keys in `.env` file needed!

```bash
# 1. Ensure encryption key exists (auto-generated if missing)
# Check .env file for:
IOTSENTINEL_ENCRYPTION_KEY=<auto-generated-key>

# 2. Start the dashboard
python dashboard/app.py

# 3. Open http://localhost:8050
# 4. Click "API Integration Hub" card
# 5. Configure integrations via the UI
```

### 2. Dashboard Configuration (Easiest Method)

1. **Access Integration Hub**
   - Open IoTSentinel Dashboard
   - Click **"API Integration Hub"** card in the main dashboard

2. **Configure an Integration**
   - Select a category tab (Threat Intel, Notifications, etc.)
   - Click **"Configure"** button on any integration
   - Fill in the required credentials
   - Credentials are automatically encrypted before storage
   - Click **"Save Configuration"**

3. **Test Integration**
   - Click **"Test"** button to verify connectivity
   - Health status updates automatically
   - Review test results in toast notifications

4. **Enable Integration**
   - Toggle the **"Enabled"** switch
   - Integration is now active and ready to use

5. **Monitor Usage**
   - View real-time usage statistics on each card
   - Track success rates and error counts
   - Check health status indicators

### 3. Settings Tab Features

The Settings tab provides management tools:

- **🔄 Refresh Data** - Reload all integration stats from database
- **🗑️ Clear Request Logs** - Remove historical request logs (with confirmation)
- **🏥 Reset Health Status** - Clear all health check results (with confirmation)
- **📥 Export Configuration** - Download integration config as JSON (credentials excluded for security)

### 4. Configure Encryption Key (Auto-Generated)

The encryption key is auto-generated on first run. To manually set or rotate:

```bash
# Generate a new key (AES-256)
python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"

# Add to .env
echo "IOTSENTINEL_ENCRYPTION_KEY=your-generated-key" >> .env
```

**⚠️ Important:** Never commit the `.env` file to version control!

### 5. Legacy .env Configuration (Not Recommended)

In production, use the **Dashboard UI** instead of `.env` file. However, for programmatic configuration:

```python
from database.db_manager import DatabaseManager
from alerts.integration_system import IntegrationManager

db = DatabaseManager()
mgr = IntegrationManager(db)

# Configure AbuseIPDB
mgr.configure_integration(
    'abuseipdb',
    enabled=True,
    api_key='your-api-key-here'  # Will be encrypted automatically # pragma: allowlist secret
)

# Configure Slack
mgr.configure_integration(
    'slack',
    enabled=True,
    webhook_url='https://hooks.slack.com/services/...'  # Will be encrypted
)

# Configure Email
mgr.configure_integration(
    'email_smtp',
    enabled=True,
    smtp_server='smtp.gmail.com',
    smtp_port=587,
    username='your-email@gmail.com',
    password='your-app-password',  # Will be encrypted # pragma: allowlist secret
    from_email='your-email@gmail.com',
    to_email='alerts@example.com'
)
```

## 🎨 Dashboard UI Overview

### Main Integration Hub Modal

The Integration Hub features a modern tabbed interface:

- **Category Tabs**: Threat Intel, Geolocation, Notifications, Ticketing, Webhooks
- **Integration Cards**: Show name, description, status, and usage stats
- **Configure Button**: Opens credential entry modal
- **Test Button**: Validates API connectivity
- **Enable Toggle**: Activates/deactivates integration
- **Health Indicators**: 🟢 Healthy | 🟡 Degraded | 🔴 Error | ⚪ Untested

### Configuration Modal

When you click "Configure" on any integration:

1. **Dynamic Form** - Fields auto-generate based on integration requirements
2. **Field Types** - Text, password, number, select dropdowns
3. **Validation** - Required fields marked with asterisk
4. **Secure Input** - Password fields masked automatically
5. **Encryption Notice** - Reminder that credentials will be encrypted

### Settings Tab

Management tools for your integrations:

- **Refresh** - Reload data without closing modal
- **Clear Logs** - Remove old request logs (shows confirmation)
- **Reset Health** - Clear health check history (shows confirmation)
- **Export Config** - Download integration settings as JSON (credentials excluded)

## 📘 Usage Examples

### Sending Alerts

```python
from database.db_manager import DatabaseManager
from alerts.integration_actions import IntegrationActions

db = DatabaseManager()
actions = IntegrationActions(db)

# Send to Slack
actions.send_slack_alert(
    "Critical: Suspicious device detected on network!",
    severity="critical"
)

# Send to Discord
actions.send_discord_alert(
    "Warning: High data transfer detected",
    severity="high"
)

# Send to Telegram
actions.send_telegram_alert(
    "Alert: New IoT device joined network"
)

# Send email
actions.send_email_alert(
    subject="Security Alert",
    message="Anomaly detected in network traffic"
)
```

### Creating Tickets

```python
# Create GitHub issue
issue_url = actions.create_github_issue(
    title="[IoTSentinel] Suspicious Activity Detected",
    body="Device 192.168.1.100 showing unusual behavior",
    labels=["security", "high-priority"]
)

# Create Trello card
card_url = actions.create_trello_card(
    name="Investigate Device Anomaly",
    desc="IoTSentinel detected unusual traffic patterns"
)
```

### Querying Threat Intelligence

```python
# Query multiple threat intel sources
threat_data = actions.query_threat_intel("8.8.8.8")

print(f"Is malicious: {threat_data['is_malicious']}")
print(f"Confidence: {threat_data['confidence']}%")
print(f"Sources: {', '.join(threat_data['sources'].keys())}")

# Results aggregated from:
# - AbuseIPDB
# - VirusTotal
# - AlienVault OTX
# - GreyNoise
```

### Getting Geolocation

```python
# Get IP geolocation
geo_data = actions.get_ip_geolocation("8.8.8.8")

print(f"Country: {geo_data['country']}")
print(f"City: {geo_data['city']}")
print(f"ISP: {geo_data['org']}")
```

### Triggering Webhooks

```python
# Trigger Zapier zap
actions.trigger_zapier_zap({
    'device_ip': '192.168.1.100',
    'alert_type': 'anomaly',
    'severity': 'high'
})

# Trigger IFTTT applet
actions.trigger_ifttt_applet(
    event_name='iotsentinel_alert',
    values=['192.168.1.100', 'High', 'Anomaly detected']
)
```

## 🔧 Getting API Keys

### Threat Intelligence

- **AbuseIPDB**: https://www.abuseipdb.com/register → API → Create Key
- **VirusTotal**: https://www.virustotal.com/gui/join-us → My API Key
- **AlienVault OTX**: https://otx.alienvault.com/ → Settings → API Integration
- **GreyNoise**: https://www.greynoise.io/ → Sign Up → API Key
- **IPQualityScore**: https://www.ipqualityscore.com/create-account → API Keys
- **ThreatFox**: No key required (free access)
- **Shodan**: https://account.shodan.io/register → My Account → API Key
- **NVD**: https://nvd.nist.gov/developers/request-an-api-key → Request API Key

### Geolocation

- **IPinfo**: https://ipinfo.io/signup → Access Token
- **IP-API**: No key required (free tier)
- **IPGeolocation**: https://ipgeolocation.io/signup.html → API Key

### Notifications

- **Slack**: Workspace Settings → Apps → Incoming Webhooks
- **Discord**: Server Settings → Integrations → Webhooks
- **Telegram**: Talk to @BotFather → `/newbot` → Get token and chat ID
- **Pushover**: https://pushover.net/ → Create Application
- **Email**: Use your email provider's SMTP settings

### Ticketing

- **GitHub**: Settings → Developer settings → Personal access tokens → Generate new token (repo scope)
- **GitLab**: User Settings → Access Tokens → Create personal access token (api scope)
- **Trello**: https://trello.com/app-key → Get API Key and Token
- **Linear**: Settings → API → Create API Key

### Webhooks

- **Zapier**: Create Zap → Webhooks by Zapier → Catch Hook
- **IFTTT**: https://ifttt.com/maker_webhooks → Settings → Get Webhook Key
- **n8n**: Self-host n8n → Create Webhook node

## 📊 Health Monitoring

All integrations support real-time health checks:

```python
# Get health status
integration = mgr.get_integration('abuseipdb')
print(f"Status: {integration['health_status']}")  # healthy/degraded/error/untested
print(f"Last check: {integration['last_health_check']}")
print(f"Last error: {integration['last_error']}")

# Update health status after test
mgr.update_health_status('abuseipdb', 'healthy')
```

## 📈 Usage Analytics

Track API usage to avoid rate limits:

```python
# Get usage stats
integration = mgr.get_integration('virustotal')
print(f"Total requests: {integration['total_requests']}")
print(f"Successful: {integration['successful_requests']}")
print(f"Failed: {integration['failed_requests']}")
print(f"Success rate: {integration['successful_requests'] / integration['total_requests'] * 100}%")

# Requests are automatically logged
actions.send_slack_alert("Test")  # Logged automatically
```

## 🛡️ Best Practices

### Security

1. **Never commit .env file** - Add to `.gitignore`
2. **Use environment variables** - Don't hardcode credentials
3. **Rotate keys regularly** - Update API keys periodically
4. **Monitor health status** - Check for compromised keys
5. **Use read-only tokens** - When possible (e.g., GitHub)

### Rate Limiting

1. **Monitor daily usage** - Check usage analytics in dashboard
2. **Implement backoffs** - Automatic retry with exponential backoff
3. **Prioritize integrations** - Use high-priority services first
4. **Cache results** - Don't query same IP multiple times

### Reliability

1. **Test before enabling** - Always test integration before activating
2. **Monitor health checks** - Review health status regularly
3. **Have fallbacks** - Configure multiple notification channels
4. **Log errors** - Review error logs for patterns

## 🔄 Migration Guide

### From .env to Integration Hub (One-Time)

If you previously used `.env` file for API keys:

```python
# Manual migration example
from database.db_manager import DatabaseManager
from alerts.integration_system import IntegrationManager
import os

db = DatabaseManager()
mgr = IntegrationManager(db)

# Migrate API keys from .env to Integration Hub
mgr.configure_integration('abuseipdb', enabled=True, api_key=os.getenv('ABUSEIPDB_API_KEY'))
mgr.configure_integration('virustotal', enabled=True, api_key=os.getenv('VIRUSTOTAL_API_KEY'))
# ... etc for all integrations

# After migration, comment out the keys in .env file
```

**Post-Migration:**

1. Comment out all API keys in `.env` file
2. Keep only `IOTSENTINEL_ENCRYPTION_KEY` active
3. All credentials now managed via Integration Hub UI
4. More secure - no plaintext keys in configuration files

### Updating Encryption Key (Advanced)

```python
from utils.credential_manager import CredentialManager
from alerts.integration_system import IntegrationManager

# 1. Generate new key
new_key = CredentialManager.generate_new_key()

# 2. Decrypt with old key
old_mgr = CredentialManager()
integrations = IntegrationManager(db)

for integration in integrations.get_all_integrations():
    if integration['is_enabled']:
        old_creds = integrations.get_integration_credentials(integration['id'])
        # Re-configure with new encryption
        integrations.configure_integration(integration['id'], **old_creds)

# 3. Update .env with new key
```

## 📚 API Reference

See `alerts/integration_system.py` and `alerts/integration_actions.py` for complete API documentation.

## ❓ FAQ

**Q: Are my API keys safe?**
A: Yes. All credentials are encrypted with **Fernet (AES-256 CBC + HMAC)** before storage. The encryption key is stored separately in `.env` and never in the database or code.

**Q: Do I need to edit .env file for API keys?**
A: No! In production mode, use the **Dashboard UI** to configure all integrations. API keys are stored encrypted in the database, not in `.env`.

**Q: What's in my .env file then?**
A: Only the `IOTSENTINEL_ENCRYPTION_KEY`. All API keys should be commented out and managed via Integration Hub.

**Q: Can I use my own encryption key?**
A: Yes. Set `IOTSENTINEL_ENCRYPTION_KEY` in your `.env` file before first run.

**Q: What happens if I lose my encryption key?**
A: You will need to re-configure all integrations. Encrypted data cannot be recovered without the key.

**Q: Can I export my integration settings?**
A: Yes, but credentials will remain encrypted. Only the encryption key can decrypt them.

**Q: Are there any paid integrations?**
A: No. All **28 integrations** have free tiers suitable for home/small business use.

**Q: Can I add custom integrations?**
A: Yes. Add to `INTEGRATIONS` dict in `alerts/integration_system.py` and implement actions in `alerts/integration_actions.py`.

## 📝 License

Part of IoTSentinel - MIT License

---

**Need help?** Open an issue on GitHub or check the documentation.
