#!/bin/bash
# IoTSentinel — Gateway / Access-Point Validation
#
# Run this ON THE RASPBERRY PI after enabling gateway capture mode (USB Wi-Fi
# adapter plugged in, wizard set to Gateway). It verifies the full inline-IDS path:
# the AP is up, devices get DHCP+DNS+NAT through the Pi, Zeek captures on the AP
# interface, the home uplink is intact, and inline enforcement is wired — without
# ever touching the home Wi-Fi.
#
# Usage:   bash scripts/validate_gateway.sh
# Exit:    0 if all critical checks pass, 1 if any critical check fails.

set -uo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BLUE='\033[0;34m'; NC='\033[0m'
PASS=0; WARN=0; FAIL=0
pass() { echo -e "  ${GREEN}✓${NC}  $*"; PASS=$((PASS+1)); }
warn() { echo -e "  ${YELLOW}⚠${NC}  $*"; WARN=$((WARN+1)); }
fail() { echo -e "  ${RED}✗${NC}  $*"; FAIL=$((FAIL+1)); }
section() { echo -e "\n${BLUE}▶  $*${NC}"; }

PROJECT="${HOME}/iotsentinel"
CFG="$PROJECT/config/default_config.json"

# Pull AP settings from config.
read_cfg() {
    python3 -c "
import json, ipaddress
try:
    n = json.load(open('$CFG')).get('network', {})
    net = ipaddress.ip_network(n.get('ap_subnet') or '10.42.0.0/24', strict=False)
    print('|'.join([
        n.get('capture_mode') or 'passive',
        n.get('ap_interface') or '',
        n.get('interface') or '',
        n.get('ap_ssid') or '',
        str(net.network_address + 1),
    ]))
except Exception:
    print('passive||||')
" 2>/dev/null
}
IFS='|' read -r MODE AP_IFACE HOME_IFACE SSID AP_GW <<< "$(read_cfg)"

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo -e "${BLUE}  IoTSentinel — Gateway Validation${NC}"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

# ── 1. Mode & config ────────────────────────────────────────────────────────────
section "1/7  Capture mode & config"
if [ "$MODE" = "gateway" ]; then
    pass "capture_mode = gateway"
else
    fail "capture_mode = '$MODE' (expected gateway) — nothing else will apply"
fi
[ -n "$AP_IFACE" ] && pass "ap_interface = $AP_IFACE" || fail "ap_interface not set"
[ -n "$SSID" ] && pass "ap_ssid = $SSID" || warn "ap_ssid not set"
pass "AP gateway address = $AP_GW"

# ── 2. Hardware: USB Wi-Fi adapter ──────────────────────────────────────────────
section "2/7  USB Wi-Fi adapter (AP)"
if [ -n "$AP_IFACE" ] && [ -e "/sys/class/net/$AP_IFACE" ]; then
    pass "AP interface $AP_IFACE present"
    if command -v iw >/dev/null 2>&1; then
        PHY=$(iw dev "$AP_IFACE" info 2>/dev/null | awk '/wiphy/{print "phy"$2}')
        if [ -n "$PHY" ] && iw phy "$PHY" info 2>/dev/null | grep -q "\* AP$"; then
            pass "$AP_IFACE chipset supports AP mode"
        else
            warn "Could not confirm AP-mode support on $AP_IFACE (check 'iw phy')"
        fi
    fi
else
    fail "AP interface $AP_IFACE not present — is the USB Wi-Fi adapter plugged in?"
fi

# ── 3. Packages ─────────────────────────────────────────────────────────────────
section "3/7  Packages"
command -v nmcli  >/dev/null 2>&1 && pass "nmcli present"  || fail "nmcli missing"
dpkg -s dnsmasq-base >/dev/null 2>&1 && pass "dnsmasq-base present (NM shared DHCP/DNS)" \
    || fail "dnsmasq-base missing — NM shared mode has no DHCP/DNS"
[ -x /opt/zeek/bin/zeekctl ] && pass "Zeek present" || warn "Zeek not found at /opt/zeek"

# ── 4. Access point up ──────────────────────────────────────────────────────────
section "4/7  Access point"
if nmcli -t -f NAME connection show --active 2>/dev/null | grep -qx "iotsentinel-ap"; then
    pass "AP connection 'iotsentinel-ap' is ACTIVE"
else
    fail "AP connection not active — run: sudo bash $PROJECT/config/configure_ap.sh"
fi
if ip -4 addr show "$AP_IFACE" 2>/dev/null | grep -q "$AP_GW"; then
    pass "$AP_IFACE holds the AP gateway $AP_GW"
else
    warn "$AP_IFACE does not have $AP_GW (AP may not be fully up)"
fi

# ── 5. Routing: NAT + forwarding ────────────────────────────────────────────────
section "5/7  Routing (DHCP/DNS/NAT/forwarding)"
if [ "$(cat /proc/sys/net/ipv4/ip_forward 2>/dev/null)" = "1" ]; then
    pass "ip_forward enabled"
else
    fail "ip_forward disabled — devices on the AP cannot reach the internet"
fi
if pgrep -a dnsmasq 2>/dev/null | grep -q "$AP_IFACE"; then
    pass "dnsmasq serving DHCP/DNS on $AP_IFACE"
else
    warn "dnsmasq not detected on $AP_IFACE (NM normally starts it for shared mode)"
fi
if { nft list ruleset 2>/dev/null; iptables -t nat -S 2>/dev/null; } | grep -qi "masquerade"; then
    pass "NAT masquerade present (AP → uplink)"
else
    warn "Could not confirm NAT masquerade rule"
fi

# ── 6. Zeek targets the AP ──────────────────────────────────────────────────────
section "6/7  Zeek capture on AP"
NODE_CFG="/opt/zeek/etc/node.cfg"
if [ -f "$NODE_CFG" ] && grep -q "interface=$AP_IFACE" "$NODE_CFG"; then
    pass "Zeek node.cfg targets $AP_IFACE"
else
    fail "Zeek not pointed at $AP_IFACE — run: sudo bash $PROJECT/config/configure_zeek.sh"
fi
if pgrep -f '/opt/zeek/bin/zeek' >/dev/null 2>&1; then
    pass "Zeek is running"
else
    warn "Zeek process not detected (zeek_monitor cron should restart it)"
fi

# ── 7. Home uplink intact ───────────────────────────────────────────────────────
section "7/7  Home Wi-Fi uplink (must be untouched)"
if [ -n "$HOME_IFACE" ] && ip -4 addr show "$HOME_IFACE" 2>/dev/null | grep -q "inet "; then
    pass "Home interface $HOME_IFACE has an IP (uplink connected)"
else
    warn "Home interface $HOME_IFACE has no IPv4 — check the uplink"
fi
if ping -c 2 -W 2 1.1.1.1 >/dev/null 2>&1; then
    pass "Internet reachable from the Pi"
else
    fail "No internet from the Pi — uplink or NAT problem"
fi

# ── Manual E2E (needs a real device) ────────────────────────────────────────────
section "Manual end-to-end (do these with a real IoT device)"
cat <<EOF
  [ ] Join a device to the "$SSID" Wi-Fi network
  [ ] It appears on the dashboard within ~1 min (DHCP + ARP discovery)
  [ ] Its connections show up (Zeek conn.log → connections table)
  [ ] Block it from the dashboard → it loses internet within seconds
  [ ] Unblock it → internet returns
  [ ] Reboot the Pi → AP comes back automatically, home Wi-Fi still works
EOF

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo -e "  ${GREEN}${PASS} passed${NC}  ${YELLOW}${WARN} warnings${NC}  ${RED}${FAIL} failed${NC}"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
[ "$FAIL" -eq 0 ]
