# 📧 Email Notifications Setup Guide

Get real-time security alerts delivered straight to your inbox!

---

## ✨ What You'll Get

When enabled, IoTSentinel will:
- ✅ Send instant email alerts for critical/high severity anomalies
- ✅ Beautiful HTML-formatted emails with detailed explanations
- ✅ Weekly and monthly security summary reports
- ✅ Educational explanations of what each alert means
- ✅ Recommended actions for each severity level

### **Example Alert Email:**

```
🛡️ IoTSentinel Alert
🚨 CRITICAL

Device: Smart Camera (192.168.1.45)
Anomaly Score: 0.9847
Time: 2025-12-03 14:32:15

📋 What Happened:
This device is sending an unusually large amount of data (547 MB)
to an external server, which is 15× higher than normal.

🔍 What This Means:
This is a severe anomaly that requires immediate attention. The
detected behavior significantly deviates from normal patterns and
may indicate data exfiltration or a compromised device.

⚡ Recommended Actions:
1. Check if the affected device is behaving normally
2. Review the device's recent activity on your dashboard
3. Consider temporarily isolating the device if suspicious
4. Check for unauthorized access or malware
```

---

## ⚙️ Step 1: Configure Email Settings in Dashboard

1. **Open IoTSentinel Dashboard**
   ```bash
   python3 dashboard/app.py
   ```
   Navigate to http://localhost:8050

2. **Go to Settings**
   - Scroll down to the Analytics tab
   - Click on "⚙️ Settings & Controls" accordion
   - Find the "📧 Email Notifications" card

3. **Fill in Email Settings**

   | Field | Example | Notes |
   |-------|---------|-------|
   | **Enable** | Toggle ON | Master switch |
   | **SMTP Host** | `smtp.gmail.com` | Gmail, Outlook, etc. |
   | **Port** | `587` | Usually 587 for TLS |
   | **SMTP Username** | `your-email@gmail.com` | Your email address |
   | **SMTP Password** | `••••••••` | App Password (not regular password!) |
   | **Sender Email** | `iotsentinel@gmail.com` | "From" address |
   | **Recipient Email** | `your-email@gmail.com` | Where alerts go |

4. **Click "Save Settings"**
   - Status badge will show **ENABLED** if all fields are filled
   - Shows **INCOMPLETE** if required fields are missing
   - Shows **DISABLED** if toggle is off

---

## 🔐 Step 2: Gmail App Password Setup

**Important:** Gmail requires an App Password (not your regular password) for security.

### **Quick Setup (2 minutes)**

1. **Enable 2-Factor Authentication** (if not already)
   - Go to https://myaccount.google.com/security
   - Click "2-Step Verification"
   - Follow setup wizard

2. **Generate App Password**
   - Go to https://myaccount.google.com/apppasswords
   - Select app: "Mail"
   - Select device: "Other (Custom name)"
   - Enter "IoTSentinel"
   - Click **Generate**

3. **Copy the 16-Character Password**
   - Looks like: `abcd efgh ijkl mnop`
   - **Use this in the dashboard**, not your regular password!

4. **Paste into Dashboard**
   - Paste the app password into "SMTP Password" field
   - Click "Save Settings"

---

## 🧪 Step 3: Send Test Email

1. Click the **"Send Test Email"** button in the dashboard
2. Wait 5-10 seconds
3. Check your inbox for the test email

**Success indicators:**
- ✅ Green alert: "Test email sent successfully!"
- ✅ Email arrives in your inbox

**Common errors:**
- ❌ "Authentication failed" → Check App Password
- ❌ "Connection timeout" → Check SMTP host/port
- ❌ "Invalid email" → Verify email addresses

---

## 📋 Email Configuration for Other Providers

### **Microsoft Outlook / Hotmail**

```
SMTP Host: smtp-mail.outlook.com
Port: 587
Username: your-email@outlook.com
Password: Your Outlook password
```

### **Yahoo Mail**

```
SMTP Host: smtp.mail.yahoo.com
Port: 587
Username: your-email@yahoo.com
Password: App Password (generate at https://login.yahoo.com/account/security)
```

### **Custom SMTP Server**

```
SMTP Host: mail.yourdom

ain.com
Port: 587 (or 465 for SSL)
Username: your-username
Password: your-password
```

---

## 🎯 How It Works

### **Alert Emails**

When IoTSentinel detects an anomaly:

1. **Severity Check**: Only **Critical** and **High** alerts trigger emails
2. **Rate Limiting**: Max 5 emails per device per hour
3. **Formatting**: Professional HTML email with color-coded severity
4. **Content**:
   - Device name and IP
   - Anomaly score
   - Plain English explanation
   - Educational "What this means" section
   - Recommended actions

### **Weekly Reports** (Optional)

Every Sunday at 9 AM:
- Summary of all alerts for the week
- Breakdown by severity and device
- Network statistics (devices, connections, data)
- Recent high-priority alerts

### **Monthly Reports** (Optional)

First day of each month at 9 AM:
- Comprehensive monthly summary
- Trends and patterns
- Device statistics
- Security recommendations

---

## 🔧 Troubleshooting

### **"Authentication failed" Error**

**Cause**: Wrong password or 2FA not set up

**Fix**:
```bash
# For Gmail:
1. Verify 2FA is enabled: https://myaccount.google.com/security
2. Generate new App Password: https://myaccount.google.com/apppasswords
3. Use the 16-character password (with or without spaces)
4. Click "Save Settings" and "Send Test Email"
```

### **"Connection timeout" Error**

**Cause**: Firewall blocking SMTP port or wrong host

**Fix**:
```bash
# Test connection manually:
telnet smtp.gmail.com 587

# If it connects, you'll see:
# Trying 142.251.10.109...
# Connected to smtp.gmail.com.

# If it hangs, check firewall rules
```

### **Emails Going to Spam**

**Cause**: Sender reputation or SPF/DKIM missing

**Fix**:
- Mark IoTSentinel emails as "Not Spam"
- Add sender email to contacts
- For custom domains, configure SPF/DKIM records

### **Test Email Works, But No Alert Emails**

**Cause**: Alerts may not be triggered yet, or email notifications disabled

**Check**:
```bash
# Check config file:
cat config/default_config.json | grep -A 6 email

# Should show:
#   "enabled": true,

# Check logs:
tail -f data/logs/iotsentinel.log | grep -i email
```

---

## 📊 Monitoring Email Usage

Check if emails are being sent:

```bash
# View email-related logs
grep -i "email" data/logs/iotsentinel.log

# Should see entries like:
# 2025-12-03 14:32:15 - EmailNotifier initialized and enabled
# 2025-12-03 14:45:22 - Email sent to your-email@gmail.com
```

---

## 🔐 Security Best Practices

1. **Use App Passwords** (not regular passwords)
   - More secure
   - Can be revoked without changing main password
   - Prevents password exposure

2. **Don't Commit Passwords to Git**
   ```bash
   # Already in .gitignore:
   echo "config/default_config.json" >> .gitignore
   ```

3. **Rotate App Passwords Periodically**
   - Every 6-12 months
   - If accidentally exposed

4. **Use Dedicated Email**
   - Consider a separate email for IoTSentinel alerts
   - Easier to filter and manage

---

## 📈 Advanced: Configuring Report Schedules

Edit `config/default_config.json`:

```json
{
  "alerting": {
    "enabled": true,
    "reports": {
      "weekly_enabled": true,
      "weekly_day": "sunday",
      "weekly_hour": 9,
      "monthly_enabled": true,
      "monthly_day": 1,
      "monthly_hour": 9
    }
  }
}
```

**Options:**
- `weekly_day`: "monday" through "sunday"
- `weekly_hour`: 0-23 (24-hour format)
- `monthly_day`: 1-28 (day of month)

Restart dashboard after changes:
```bash
python3 dashboard/app.py
```

---

## 🎉 All Done!

Your IoTSentinel dashboard now sends **professional email alerts** for security events!

### **What to Expect:**

- ✅ Instant notification of critical threats
- ✅ Educational explanations for non-technical users
- ✅ Weekly/monthly summaries
- ✅ Professional HTML emails
- ✅ Mobile-friendly formatting

### **Next Steps:**

1. Wait for an anomaly to trigger an alert (or simulate one)
2. Check your inbox for the alert email
3. Review the explanation and take recommended actions
4. Enjoy peace of mind with real-time monitoring!

---

## ❓ Need Help?

If you run into issues:

1. Check the troubleshooting section above
2. Review dashboard logs: `data/logs/iotsentinel.log`
3. Test email sending with the "Send Test Email" button
4. Verify all fields are correctly filled in the UI

**The email system has retry logic and graceful fallback** - your dashboard will never break if email fails! 🛡️
