# 🔌 API Integration Hub - Configuration Guide

This guide shows you how to configure **FREE** threat intelligence APIs for IoTSentinel.

## ✅ Currently Configured

Your `.env` file already has:
- **AbuseIPDB** ✓ Configured (should show as "Connected" in dashboard)

## 🆓 Free APIs You Can Add

### 1. **AbuseIPDB** ✅ ALREADY CONFIGURED
- **Status**: Connected (FREE: 1000 queries/day)
- **What it does**: IP reputation database - checks if IPs are malicious
- **Your key**: Already in `.env` as `THREAT_INTELLIGENCE_ABUSEIPDB_API_KEY`

---

### 2. **AlienVault OTX** 🌟 RECOMMENDED (100% FREE)
- **Free tier**: UNLIMITED - Completely free forever!
- **What it does**: Open Threat Exchange - community threat intelligence
- **Sign up**: https://otx.alienvault.com/accounts/signup
- **Add to .env**:
  ```env
  OTX_API_KEY=your_key_here
  ```

---

### 3. **VirusTotal**
- **Free tier**: 4 requests/minute (500/day)
- **What it does**: Malware and URL scanning using 70+ antivirus engines
- **Sign up**: https://www.virustotal.com/gui/join-us
- **Add to .env**:
  ```env
  VIRUSTOTAL_API_KEY=your_key_here
  ```

---

### 4. **IPinfo** 🌟 RECOMMENDED
- **Free tier**: 50,000 queries/month
- **What it does**: IP geolocation, ASN, company info
- **Sign up**: https://ipinfo.io/signup
- **Add to .env**:
  ```env
  IPINFO_API_KEY=your_key_here
  ```

---

### 5. **GreyNoise**
- **Free tier**: 50 queries/day
- **What it does**: Identifies internet scanners vs. targeted attacks
- **Sign up**: https://www.greynoise.io/signup
- **Add to .env**:
  ```env
  GREYNOISE_API_KEY=your_key_here
  ```

---

### 6. **Shodan**
- **Free tier**: 100 queries/month
- **What it does**: IoT device search engine - find vulnerable devices
- **Sign up**: https://account.shodan.io/register
- **Add to .env**:
  ```env
  SHODAN_API_KEY=your_key_here
  ```

---

### 7. **MITRE ATT&CK** ✅ AUTO-CONFIGURED
- **Free tier**: 100% FREE - No API key needed
- **What it does**: Threat intelligence framework
- **Status**: Shows as "Connected" automatically

---

## 📝 How to Configure

### Step 1: Sign up for APIs
Choose which APIs you want (AlienVault OTX and IPinfo are highly recommended for their generous free tiers).

### Step 2: Add to .env file
Open `/Users/ritiksah/iotsentinel/.env` and add your API keys:

```env
# Threat Intelligence Configuration (existing)
THREAT_INTELLIGENCE_ENABLED=true
THREAT_INTELLIGENCE_ABUSEIPDB_API_KEY=ad49048a4aa5ed14150a3148387f29115db49dca0823be15c33764e7126c4657e4ec52a48c9e71c7
THREAT_INTELLIGENCE_CACHE_HOURS=24

# Add these new API keys (get from signup links above)
OTX_API_KEY=your_otx_key_here
VIRUSTOTAL_API_KEY=your_virustotal_key_here
IPINFO_API_KEY=your_ipinfo_key_here
GREYNOISE_API_KEY=your_greynoise_key_here
SHODAN_API_KEY=your_shodan_key_here
```

### Step 3: Restart the dashboard
```bash
# Stop the dashboard (Ctrl+C)
# Then restart it
python3 dashboard/app.py
```

### Step 4: Verify in API Integration Hub
1. Open the dashboard
2. Click on **API Integration Hub** card
3. All configured APIs should show "✓ Connected"
4. Unconfigured APIs will show instructions to set them up

---

## 🎯 Recommended Setup (All Free)

For maximum threat intelligence coverage, configure these 3:

1. **AlienVault OTX** - Unlimited, best value
2. **IPinfo** - 50k/month geolocation
3. **VirusTotal** - Industry-standard malware detection

Total cost: **$0** 🎉

---

## 🔍 API Usage in IoTSentinel

These APIs are used for:
- **IP Reputation Checking**: When devices connect, check if IPs are malicious
- **Geolocation**: Map threats on Geographic Threat Map
- **Malware Detection**: Scan URLs and file hashes
- **IoT Device Discovery**: Find vulnerable devices on your network
- **Threat Intelligence**: Enrich alerts with community threat data

---

## ⚡ Performance Notes

- APIs are cached for 24 hours (configurable via `THREAT_INTELLIGENCE_CACHE_HOURS`)
- Rate limits are automatically respected
- Failed API calls don't block the dashboard
- Connection status updates every 5 seconds

---

## 🆘 Troubleshooting

### API shows "Not Configured"
- Check the environment variable name matches exactly
- Restart the dashboard after adding keys
- Verify the API key is valid (not expired)

### API shows "✗ Connection Failed"
- Check your internet connection
- Verify the API key is correct
- Check if you've exceeded the free tier limit
- Some APIs require email verification before activation

### AbuseIPDB not showing as connected
- Your key is already in `.env` as `THREAT_INTELLIGENCE_ABUSEIPDB_API_KEY`
- It should show as "✓ Connected" in the API Hub modal
- If not, the key might be invalid - get a new one from https://www.abuseipdb.com

---

## 📊 Free Tier Comparison

| API | Free Limit | Best For | Value |
|-----|------------|----------|-------|
| AlienVault OTX | ∞ Unlimited | Threat intel | ⭐⭐⭐⭐⭐ |
| IPinfo | 50k/month | Geolocation | ⭐⭐⭐⭐⭐ |
| AbuseIPDB | 1k/day | IP reputation | ⭐⭐⭐⭐ |
| VirusTotal | 500/day | Malware scan | ⭐⭐⭐⭐ |
| GreyNoise | 50/day | Scanner ID | ⭐⭐⭐ |
| Shodan | 100/month | IoT search | ⭐⭐⭐ |
| MITRE ATT&CK | FREE | Framework | ⭐⭐⭐⭐ |

---

**Questions?** Check the API Integration Hub modal in the dashboard - it shows live status and configuration instructions for each API.
