# 🌐 Threat Intelligence Setup Guide (AbuseIPDB)

Add **IP reputation lookups** to your IoTSentinel dashboard for real-world threat context!

---

## ✨ What You'll Get

When enabled, IoTSentinel will:

- ✅ Check external IPs against AbuseIPDB threat database
- ✅ Show reputation scores (0-100) for suspicious connections
- ✅ Display threat categories (Botnet, Malware, DDoS, etc.)
- ✅ Provide actionable recommendations
- ✅ Cache results for 24 hours (reduces API calls)

### **Before & After Example:**

**Before:**

```
🚨 HIGH: Connection to Known Malicious IP
Device: Smart TV (192.168.1.50)
Connected to: 45.142.213.111
```

**After:**

```
🚨 HIGH: Connection to Known Malicious IP
Device: Smart TV (192.168.1.50)
Connected to: 45.142.213.111

🌐 THREAT INTELLIGENCE
⛔ MALICIOUS (Score: 92/100)

IP Address: 45.142.213.111
Country: Russia
ISP: SuspiciousHostingCo
Total Reports: 873
Threat Categories: Botnet C&C, Malware Distribution

⛔ BLOCK IMMEDIATELY - High abuse score (92/100). This IP is known for malicious activity.
```

---

## 🆓 Step 1: Get Your Free AbuseIPDB API Key

### **Quick Signup (2 minutes)**

1. Visit https://www.abuseipdb.com/register
2. Fill in:
   - Email address
   - Username
   - Password
3. Click **"Create Account"**
4. Check your email and verify your account
5. Log in to AbuseIPDB

### **Get Your API Key**

1. After logging in, go to https://www.abuseipdb.com/api
2. Scroll down to **"Your API Key"**
3. Click **"Create Key"** (if you don't have one)
4. Copy the API key (looks like: `abc123def456ghi789...`)
5. **Keep it safe!** Don't share it publicly

**Free Tier Limits:**

- ✅ **1,000 lookups per day**
- ✅ **More than enough for home use** (typical: 50-200/day)
- ✅ **No credit card required**
- ✅ **No expiration**

---

## ⚙️ Step 2: Configure IoTSentinel

### **Option A: Edit Config File (Recommended)**

Edit `/Users/ritiksah/iotsentinel/config/default_config.json`:

```json
{
  ...
  "threat_intelligence": {
    "enabled": true,
    "abuseipdb_api_key": "YOUR_API_KEY_HERE", # pragma: allowlist secret
    "cache_hours": 24
  }
}
```

**Replace** `"YOUR_API_KEY_HERE"` with your actual API key from Step 1.

### **Option B: Use Environment Variable (More Secure)**

Create/edit `/Users/ritiksah/iotsentinel/.env`:

```bash
# Threat Intelligence Configuration
THREAT_INTELLIGENCE_ENABLED=true
THREAT_INTELLIGENCE_ABUSEIPDB_API_KEY=your_actual_api_key_here  # pragma: allowlist secret
THREAT_INTELLIGENCE_CACHE_HOURS=24
```

This method keeps your API key out of version control.

---

## 🚀 Step 3: Restart the Dashboard

```bash
cd /Users/ritiksah/iotsentinel
python3 dashboard/app.py
```

**Look for this in the startup logs:**

```
======================================================================
IoTSentinel Dashboard - Enhanced Educational Edition
======================================================================
Dashboard URL: http://0.0.0.0:8050

🌐 Threat Intelligence: ✅ ENABLED (AbuseIPDB with 24h cache)
```

If you see **"❌ DISABLED"**, double-check your API key configuration.

---

## 🎯 Step 4: Test It Out

### **Trigger a Test Alert (Optional)**

If you want to see threat intelligence in action:

1. Wait for an alert about "Connection to Known Malicious IP"
2. Click **"Details"** on the alert
3. Scroll down to **"🌐 Threat Intelligence"** section
4. You'll see the full reputation report!

### **Check the Database**

Threat intelligence results are cached in the database:

```bash
sqlite3 data/database/iotsentinel.db
```

```sql
-- View cached IP reputations
SELECT ip_address, reputation_level, abuse_confidence_score, country_code, total_reports
FROM ip_reputation
ORDER BY last_checked DESC
LIMIT 10;
```

---

## 📊 Understanding the Results

### **Reputation Levels**

| Level          | Score Range | Meaning          | Color     |
| -------------- | ----------- | ---------------- | --------- |
| **Safe**       | 0           | No reports       | 🟢 Green  |
| **Low Risk**   | 1-24        | Minimal reports  | 🔵 Blue   |
| **Suspicious** | 25-74       | Moderate reports | 🟡 Yellow |
| **Malicious**  | 75-100      | High reports     | 🔴 Red    |
| **Private**    | N/A         | Local network IP | ⚪ Gray   |

### **Threat Categories**

Common categories you might see:

- **Botnet C&C**: Command & Control server
- **Malware Distribution**: Hosting malicious files
- **DDoS Attack**: Denial of service attacks
- **Phishing**: Fake websites stealing credentials
- **Port Scan**: Network reconnaissance
- **Brute-Force**: Password guessing attempts
- **SSH**: SSH brute-force attacks
- **IoT Targeted**: Specifically targeting IoT devices

---

## ⚙️ Configuration Options

### **cache_hours**

How long to cache reputation results (default: 24 hours)

```json
"cache_hours": 24  // Check each IP once per day
```

**Why caching matters:**

- Reduces API calls (stays under 1,000/day limit)
- Faster dashboard performance
- IP reputations don't change frequently

**Recommended values:**

- `24` (default) - Good balance
- `48` - For very stable networks
- `12` - For high-security environments

### **enabled**

Toggle threat intelligence on/off

```json
"enabled": true   // Turn on
"enabled": false  // Turn off
```

---

## 🔧 Troubleshooting

### **Dashboard shows "❌ DISABLED"**

**Cause**: API key not configured or invalid.

**Fix**:

```bash
# Check your config
cat config/default_config.json | grep -A 3 threat_intelligence

# Should show:
#   "enabled": true,
#   "abuseipdb_api_key": "your_key_here", # pragma: allowlist secret
```

### **Threat Intel section not appearing in alerts**

**Cause**: Only shows for connection-based alerts.

**What to check**:

1. Alert type must be "Connection to Known Malicious IP" or "Unusual Port Activity"
2. Alert must have a destination IP address
3. Threat intelligence must be enabled

### **API Rate Limit Errors**

**Symptoms**: Logs show `"AbuseIPDB rate limit reached"`

**Cause**: Exceeded 1,000 lookups/day.

**Fix**:

1. Check how many unique IPs you're looking up:
   ```sql
   SELECT COUNT(*) FROM ip_reputation WHERE date(last_checked) = date('now');
   ```
2. If over 1,000, increase `cache_hours` to 48 or 72
3. Consider upgrading to paid plan ($19/month for 100,000/day)

### **"Unable to check reputation" message**

**Cause**: Network connectivity issue or API timeout.

**Fix**:

1. Check internet connection
2. Try manual test:
   ```bash
   curl -G https://api.abuseipdb.com/api/v2/check \
     --data-urlencode "ipAddress=8.8.8.8" \
     -H "Key: YOUR_API_KEY" \ # pragma: allowlist secret
     -H "Accept: application/json"
   ```
3. Should return JSON with IP data

---

## 📈 Usage Statistics

Monitor your API usage:

```sql
-- Count lookups today
SELECT COUNT(*) as lookups_today
FROM ip_reputation
WHERE date(last_checked) = date('now');

-- Count by reputation level
SELECT reputation_level, COUNT(*)
FROM ip_reputation
GROUP BY reputation_level;

-- Recent malicious IPs
SELECT ip_address, abuse_confidence_score, country_code, isp
FROM ip_reputation
WHERE reputation_level = 'malicious'
ORDER BY last_checked DESC
LIMIT 10;
```

---

## 🔐 Security Best Practices

1. **Never commit your API key to git**

   ```bash
   # Add to .gitignore
   echo ".env" >> .gitignore
   echo "config/default_config.json" >> .gitignore
   ```

2. **Use environment variables for production**

   - Keeps secrets out of config files
   - Easier to rotate keys

3. **Rotate your API key periodically**

   - Every 6-12 months
   - If accidentally exposed

4. **Monitor your AbuseIPDB dashboard**
   - Check usage at https://www.abuseipdb.com/account/api
   - Set up email alerts for 80% usage

---

## 🎉 All Done!

Your IoTSentinel dashboard now has **professional-grade threat intelligence**!

### **What to Expect:**

- ✅ Alerts now show real-world threat context
- ✅ Know if connections are actually dangerous
- ✅ Reduce false positives (legitimate cloud IPs won't look scary)
- ✅ Get actionable security recommendations
- ✅ 100% free for home use

### **Next Steps:**

1. Monitor your dashboard for new alerts
2. Click "Details" on any connection-based alert
3. Check the "🌐 Threat Intelligence" section
4. Take action based on recommendations

---

## 📚 Additional Resources

- **AbuseIPDB Documentation**: https://docs.abuseipdb.com/
- **API Reference**: https://docs.abuseipdb.com/#introduction
- **Threat Categories**: https://www.abuseipdb.com/categories
- **Your API Dashboard**: https://www.abuseipdb.com/account/api

---

## ❓ Need Help?

If you run into issues:

1. Check the dashboard startup logs
2. Look for errors in `data/logs/`
3. Verify your API key at https://www.abuseipdb.com/account/api
4. Test your API key with the manual curl command above

**The threat intelligence module will gracefully fall back** if the API is unavailable - your dashboard will never break! 🛡️
