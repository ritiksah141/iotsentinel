#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# firstboot_diag.sh — write a first-boot diagnostic report to the SD card's FAT
# boot partition, which is readable on any Mac/Windows/Linux computer by simply
# putting the card back in.
#
# This is the headless escape hatch: if the IoTSentinel-Setup hotspot does NOT
# appear, the user has no screen, no keyboard, and (often) no Ethernet — so there
# is no way to see what went wrong. This dumps the exact Wi-Fi/AP/service state to
# `iotsentinel-firstboot.txt` on the boot partition so the cause is visible offline.
#
# Run late (After=multi-user.target) by iotsentinel-firstboot-report.service so it
# captures the FINAL state after provisioning has tried to bring the AP up. Always
# best-effort; never fatal.
# ─────────────────────────────────────────────────────────────────────────────
set +e

# Bookworm mounts the FAT boot partition at /boot/firmware; older layouts at /boot.
BOOTDIR="/boot/firmware"
[ -d "$BOOTDIR" ] || BOOTDIR="/boot"
OUT="$BOOTDIR/iotsentinel-firstboot.txt"

{
    echo "IoTSentinel first-boot diagnostic"
    echo "Generated: $(date -u '+%Y-%m-%d %H:%M:%S UTC')"
    echo "Host: $(hostname 2>/dev/null)   Kernel: $(uname -r 2>/dev/null)"
    echo "Model: $(tr -d '\0' < /proc/device-tree/model 2>/dev/null)"
    echo "==================================================================="

    echo; echo "## Is the IoTSentinel-Setup hotspot active?"
    if nmcli -t -f NAME connection show --active 2>/dev/null | grep -q '^IoTSentinel-Setup$'; then
        echo "YES — hotspot connection is active."
    else
        echo "NO — hotspot is NOT active. (This is why you don't see the Wi-Fi.)"
    fi

    echo; echo "## Wi-Fi radio (rfkill) — 'Soft blocked: yes' stops the AP"
    rfkill list 2>&1

    echo; echo "## Regulatory domain — 'country 00' (unset) blocks AP channels on Pi"
    iw reg get 2>&1 | grep -iE 'country|global' | head

    echo; echo "## NetworkManager running + device state (wlan0 should be 'disconnected'/'connected', not 'unavailable')"
    systemctl is-active NetworkManager 2>&1
    nmcli general status 2>&1
    nmcli device status 2>&1

    echo; echo "## NetworkManager connections"
    nmcli -f NAME,TYPE,DEVICE,ACTIVE connection show 2>&1

    echo; echo "## Wi-Fi interfaces present (kernel)"
    iw dev 2>&1 | grep -iE 'Interface|type' | head
    ip -brief addr 2>&1

    echo; echo "## Does the chip support AP mode? (look for 'AP' under Supported interface modes)"
    iw list 2>&1 | sed -n '/Supported interface modes/,/Band/p' | head -20

    echo; echo "## IoTSentinel services"
    for s in iotsentinel-provision iotsentinel-backend iotsentinel-dashboard iotsentinel-connectivity.timer; do
        echo "--- $s ---"
        systemctl is-enabled "$s" 2>&1
        systemctl status "$s" --no-pager 2>&1 | head -8
    done

    echo; echo "## Provision service log (why the hotspot did/didn't come up)"
    journalctl -u iotsentinel-provision --no-pager 2>&1 | tail -40

    echo; echo "## Dashboard bind (want 0.0.0.0:8050, not 127.0.0.1)"
    ss -tlnp 2>&1 | grep 8050 || echo "nothing listening on 8050"

    echo; echo "## Kernel Wi-Fi / brcmfmac messages"
    dmesg 2>&1 | grep -iE 'brcmfmac|cfg80211|regulatory|wlan' | tail -25

    echo; echo "==================================================================="
    echo "What to do: open this file and look at the first few sections."
    echo " - 'Soft blocked: yes' or 'country 00'  -> Wi-Fi country/regulatory problem."
    echo " - wlan0 'unavailable'                  -> NetworkManager isn't managing the radio."
    echo " - provision log shows an error         -> read that error."
    echo "Share this file's contents for help."
} > "$OUT" 2>&1

# Make sure it's flushed to the (FAT) card.
sync 2>/dev/null
chmod 644 "$OUT" 2>/dev/null
echo "[firstboot-diag] wrote $OUT"
