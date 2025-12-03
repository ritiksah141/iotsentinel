# 🚫 Device Blocking Setup Guide

Block suspicious or untrusted devices from accessing your network with one click!

---

## ✨ What You'll Get

When enabled, IoTSentinel allows you to:
- ✅ Block individual devices by MAC address via iptables
- ✅ Visual indicators for blocked devices in the dashboard
- ✅ One-click block/unblock from device details modal
- ✅ Automatic firewall rule management
- ✅ Works alongside "Lockdown Mode" for comprehensive control

### **How It Works:**

```
User clicks "Block Device" in dashboard
        ↓
Database updated (is_blocked = 1)
        ↓
Firewall script called with MAC address
        ↓
iptables rule created: DROP traffic from MAC
        ↓
Device loses network access immediately
```

---

## 🔧 Prerequisites

**Required:**
1. **Router with SSH access** (OpenWrt, pfSense, DD-WRT, custom Linux router)
2. **SSH key authentication** configured between Raspberry Pi and router
3. **iptables** installed on router (standard on OpenWrt/pfSense)
4. **Firewall integration enabled** in IoTSentinel config

**Compatibility:**
- ✅ OpenWrt
- ✅ pfSense (with SSH enabled)
- ✅ DD-WRT
- ✅ Custom Linux routers
- ❌ Consumer routers without SSH (Netgear, TP-Link, Linksys standard firmware)

---

## ⚙️ Step 1: Configure SSH Access to Router

### **Option A: OpenWrt Router**

1. **Enable SSH** (usually enabled by default)
   ```bash
   # From router SSH:
   /etc/init.d/dropbear enable
   /etc/init.d/dropbear start
   ```

2. **Generate SSH key on Raspberry Pi** (if not already done)
   ```bash
   ssh-keygen -t rsa -b 4096 -f ~/.ssh/id_rsa_router
   # Press Enter for no passphrase (for automated scripts)
   ```

3. **Copy public key to router**
   ```bash
   # Method 1: Manual
   cat ~/.ssh/id_rsa_router.pub
   # Copy the output

   # SSH to router and add to authorized_keys
   ssh root@192.168.1.1
   mkdir -p /etc/dropbear
   vi /etc/dropbear/authorized_keys
   # Paste the public key, save and exit

   # Method 2: Automatic (if password auth works)
   ssh-copy-id -i ~/.ssh/id_rsa_router.pub root@192.168.1.1
   ```

4. **Test SSH key authentication**
   ```bash
   ssh -i ~/.ssh/id_rsa_router root@192.168.1.1
   # Should connect without password prompt
   ```

### **Option B: pfSense Router**

1. **Enable SSH** in pfSense web interface:
   - System → Advanced → Secure Shell
   - Enable "Enable Secure Shell"
   - Save

2. **Add public key**:
   - System → User Manager
   - Edit "admin" user
   - Paste public key in "Authorized keys"
   - Save

3. **Test connection**:
   ```bash
   ssh -i ~/.ssh/id_rsa_router admin@192.168.1.1
   ```

---

## 📝 Step 2: Configure IoTSentinel

Edit `/Users/ritiksah/iotsentinel/config/default_config.json`:

```json
{
  "firewall": {
    "enabled": true,
    "router_ip": "192.168.1.1",
    "router_user": "root",
    "router_private_key_path": "/home/pi/.ssh/id_rsa_router"
  }
}
```

**Field explanations:**
- `enabled`: Set to `true` to enable firewall integration
- `router_ip`: Your router's IP address (usually 192.168.1.1 or 192.168.0.1)
- `router_user`: SSH username (usually "root" for OpenWrt, "admin" for pfSense)
- `router_private_key_path`: **Absolute path** to your private key file

**Important:** Use absolute paths, not relative paths like `~/.ssh/...`

---

## 🧪 Step 3: Test Firewall Integration

### **Manual Test**

```bash
cd /Users/ritiksah/iotsentinel

# Test blocking a device (use a test device MAC, not critical device!)
python3 scripts/firewall_manager.py --block AA:BB:CC:DD:EE:FF

# Check if rules were applied (SSH to router)
ssh -i ~/.ssh/id_rsa_router root@192.168.1.1
iptables -L IoTSentinel -v -n

# Should show:
# Chain IoTSentinel (1 references)
#  pkts bytes target  prot opt in  out source    destination
#     0     0 DROP    all  --  *   *   0.0.0.0/0 0.0.0.0/0    MAC AA:BB:CC:DD:EE:FF

# Unblock the device
exit  # Back to Pi
python3 scripts/firewall_manager.py --unblock AA:BB:CC:DD:EE:FF
```

### **From Dashboard**

1. Open IoTSentinel dashboard: http://localhost:8050
2. Click on any device in the device list
3. Device details modal opens
4. Scroll to "Network Access" section
5. Click "Block Device" button
6. Wait for confirmation message
7. Refresh page - device should show "BLOCKED" badge with red border

---

## 🎯 Step 4: Using Device Blocking

### **Block a Device**

1. **Identify suspicious device** in dashboard (e.g., device with alerts)
2. **Click the device** to open details modal
3. **Scroll to "Network Access"** section
4. **Click "Block Device"** button
5. **Confirm** - device loses network access immediately

**What happens:**
- Device's MAC address is added to iptables DROP rule
- Database updated (`is_blocked = 1`)
- Device shown with red "BLOCKED" badge and red left border
- Device cannot send/receive network traffic

### **Unblock a Device**

1. **Click the blocked device** (shown with BLOCKED badge)
2. **Device details modal** opens showing "This device is currently BLOCKED"
3. **Click "Unblock Device"** button (green)
4. **Confirm** - device regains network access

**What happens:**
- Device's MAC address removed from iptables
- Database updated (`is_blocked = 0`)
- BLOCKED badge and red border removed
- Device can use network normally

---

## 🔍 Visual Indicators

### **In Device List**

**Normal Device:**
```
🟢 📱 Smart Phone       [NORMAL]
   192.168.1.45
```

**Blocked Device:**
```
| 🔴 📱 Suspicious Device [ALERT] [🚫 BLOCKED]
|    192.168.1.66
```
(Red left border, BLOCKED badge)

### **In Device Details Modal**

**Normal Device:**
- Green "Block Device" button (outlined)
- No warning message

**Blocked Device:**
- Red alert: "⚠️ This device is currently BLOCKED from network access"
- Green "Unblock Device" button
- Status message after clicking

---

## 🛡️ Lockdown Mode vs Individual Blocking

IoTSentinel offers **two complementary blocking modes**:

### **Individual Device Blocking** (This Feature)
- **Purpose**: Block specific suspicious devices
- **Use case**: Malware-infected device, unknown device, compromised IoT camera
- **Effect**: Only blocks selected devices
- **Reversible**: Yes, click "Unblock Device"

### **Lockdown Mode** (Settings → Firewall Control)
- **Purpose**: Emergency mode - allow ONLY trusted devices
- **Use case**: Under attack, unauthorized access, network compromise
- **Effect**: Blocks ALL untrusted devices
- **Reversible**: Yes, toggle switch off

**Example scenario:**
```
Normal operation:
- 10 devices total
- 8 devices trusted
- 1 device blocked (suspicious camera)
- 1 device untrusted (guest phone)
→ Blocked device: no access
→ All others: full access

Lockdown Mode activated:
- 10 devices total
- 8 devices trusted
- 1 device blocked
- 1 device untrusted
→ Blocked device: no access (still)
→ Untrusted device: no access (lockdown)
→ Trusted devices: full access
```

---

## 🔧 Troubleshooting

### **"Firewall integration is disabled in config"**

**Cause**: `firewall.enabled` is `false` in config

**Fix**:
```bash
# Edit config
vi config/default_config.json

# Change:
"firewall": {
  "enabled": true,  // <-- Make sure this is true
  ...
}

# Restart dashboard
python3 dashboard/app.py
```

### **"Cannot block device: MAC address unknown"**

**Cause**: Device's MAC address not in database (ARP not working)

**Fix**:
```bash
# IoTSentinel uses ARP scanner to get MAC addresses
# Check if ARP scanner is running:
ps aux | grep arp

# Check device MAC manually:
arp -a | grep 192.168.1.XX

# If still unknown, wait for device to generate traffic
# IoTSentinel will discover it via Zeek logs
```

### **"Operation timed out. Check firewall configuration"**

**Cause**: SSH connection to router failed or timed out

**Fix**:
```bash
# Test SSH connection manually:
ssh -i ~/.ssh/id_rsa_router root@192.168.1.1

# If connection fails:
# 1. Check router IP is correct
# 2. Check router is reachable: ping 192.168.1.1
# 3. Check SSH is enabled on router
# 4. Check firewall on router allows SSH from Pi
# 5. Verify private key path is correct and absolute
```

### **"Failed to block device" with stderr output**

**Cause**: iptables command failed on router

**Fix**:
```bash
# SSH to router and check iptables
ssh -i ~/.ssh/id_rsa_router root@192.168.1.1

# Check if IoTSentinel chain exists
iptables -L IoTSentinel

# If chain doesn't exist, it will be created on next block
# If you see permission errors, check router user has root/admin access
```

### **Device still has network access after blocking**

**Cause**: iptables rules not applied or device using different MAC

**Possible reasons:**
1. **Wrong network interface**: IoTSentinel blocks FORWARD chain, which works for routed traffic. If Pi is the router, use INPUT/OUTPUT chains instead.
2. **MAC spoofing**: Attacker changed device MAC address
3. **VPN/proxy**: Device using VPN, bypassing local firewall

**Fix**:
```bash
# SSH to router and verify rule exists
ssh -i ~/.ssh/id_rsa_router root@192.168.1.1
iptables -L IoTSentinel -v -n

# Should show DROP rule with correct MAC
# If not, check logs:
cat /Users/ritiksah/iotsentinel/data/logs/iotsentinel.log | grep -i block
```

---

## 📊 Monitoring Blocked Devices

### **View Blocked Devices in Database**

```bash
sqlite3 /Users/ritiksah/iotsentinel/data/database/iotsentinel.db

# Query blocked devices
SELECT device_ip, device_name, mac_address, is_blocked, last_seen
FROM devices
WHERE is_blocked = 1;

# Count blocked devices
SELECT COUNT(*) as blocked_count
FROM devices
WHERE is_blocked = 1;
```

### **Check Firewall Rules on Router**

```bash
# SSH to router
ssh -i ~/.ssh/id_rsa_router root@192.168.1.1

# List all IoTSentinel rules
iptables -L IoTSentinel -v -n --line-numbers

# Count blocked MACs
iptables -L IoTSentinel -n | grep -c DROP
```

### **Check Logs**

```bash
# View blocking actions in logs
tail -f data/logs/iotsentinel.log | grep -i block

# Should show entries like:
# 2025-12-03 15:32:10 - Set device 192.168.1.66 blocked to True
# 2025-12-03 15:32:11 - Blocked device: AA:BB:CC:DD:EE:FF
```

---

## 🔐 Security Considerations

### **Use Blocking Responsibly**

- ⚠️ **Don't block critical devices** (router itself, Pi, your computer during remote access)
- ⚠️ **Test blocking on non-critical device first** (old phone, test IoT device)
- ⚠️ **Document why you blocked** each device (add notes in a separate file)
- ⚠️ **Review blocked devices periodically** (weekly/monthly)

### **SSH Key Security**

```bash
# Protect your SSH private key
chmod 600 ~/.ssh/id_rsa_router

# Don't share your private key
# Don't commit it to git
echo ".ssh/" >> .gitignore
```

### **Backup Firewall Rules**

```bash
# Before making changes, backup router iptables
ssh -i ~/.ssh/id_rsa_router root@192.168.1.1
iptables-save > /tmp/iptables_backup.txt
```

### **Recovery Plan**

If you accidentally block yourself:

**Plan A: Physical Access**
1. Connect keyboard/monitor to router
2. Log in as root
3. Run: `iptables -F IoTSentinel` (flushes all rules)

**Plan B: Factory Reset**
1. Press router reset button for 10 seconds
2. Reconfigure router and IoTSentinel

**Plan C: Alternative Device**
1. Use another device (phone hotspot, backup Pi)
2. SSH to router
3. Clear IoTSentinel rules

---

## 🎉 You're Ready!

Device blocking is now fully configured and operational!

### **Quick Reference:**

| Action | Steps |
|--------|-------|
| Block device | Click device → "Block Device" button |
| Unblock device | Click device → "Unblock Device" button |
| Check blocked devices | Look for red "BLOCKED" badges |
| Clear all blocks | Settings → Firewall Control → Disable Lockdown |
| View firewall rules | SSH to router → `iptables -L IoTSentinel` |

**Remember:**
- Blocking is immediate and persistent
- Blocked devices stay blocked until you unblock them
- Works independently from Lockdown Mode
- Requires firewall integration to be enabled

---

## ❓ FAQ

**Q: Can I block devices without SSH access to router?**
A: No, device blocking requires SSH access to router to modify iptables rules. Consider upgrading to OpenWrt or using a Linux-based router.

**Q: Will blocking affect Lockdown Mode?**
A: No, they work independently. Blocked devices stay blocked even when Lockdown Mode is off. In Lockdown Mode, untrusted devices are also blocked.

**Q: Can blocked devices still be detected by IoTSentinel?**
A: No, blocked devices cannot send traffic, so Zeek won't see their connections. They'll appear "offline" in the dashboard.

**Q: What happens if I block the Raspberry Pi itself?**
A: Don't do this! The Pi is running IoTSentinel and needs network access. If you accidentally do this, use physical access to router to clear rules.

**Q: Can I block by IP address instead of MAC?**
A: Currently no, blocking is MAC-based (Layer 2) which is more effective since devices can change IPs (DHCP) but usually keep the same MAC.

**Q: How do I unblock all devices at once?**
A: SSH to router and run: `iptables -F IoTSentinel` to flush all blocking rules. Or use the dashboard to unblock each device individually.

---

**Enjoy secure, granular control over your network!** 🛡️
