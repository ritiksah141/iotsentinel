# Gateway Mode: full per-device protection

By default IoTSentinel runs in **passive** mode: it watches the interface it's on and
sees broadcast traffic + device discovery, but on modern Wi-Fi it cannot see the
*unicast* traffic between other devices and the router. That's enough for an
inventory and DNS/posture checks, but not for per-device flow analysis (data
exfiltration, command-and-control, traffic anomalies).

**Gateway mode** turns the Pi into a small access point for your IoT devices, so all
their traffic flows *through* the Pi. Zeek then sees every connection and DNS query,
and IoTSentinel can **block** a device inline, a real IDS/IPS. Your **home Wi-Fi is
never touched**: the Pi joins it as an ordinary client for its own internet uplink,
and serves a separate network for the IoT devices.

```
        Internet
           |
   [ Home Router ] == Wi-Fi ==>  phones / laptops  (untouched)
           |  Wi-Fi (wireless uplink, no cable)
           v
      [  Pi 4  ]   wlan0  = home Wi-Fi client (uplink)
           |        wlan1 (USB) = "IoTSentinel" access point
           v
   IoT devices (camera, plug, TV)
     -> ALL traffic + DNS seen by Zeek
     -> inline block / allow
```

This is the **recommended** mode if you want true per-device intrusion detection and
prevention. It costs one inexpensive USB Wi-Fi adapter and a few minutes of moving
your IoT devices onto a new network name. Everything below walks through it in plain
steps.

## 1. Buy the adapter

You need **one USB Wi-Fi adapter that supports AP (access-point) mode**. The Pi's
built-in radio stays your home-Wi-Fi uplink; the USB adapter broadcasts the IoT
network. A single radio cannot reliably be both a home-Wi-Fi client and an access
point at once, which is why the adapter is required for a cable-free setup.

When shopping, search for "USB Wi-Fi adapter AP mode Linux" and look for one of these
chipsets, which are known to do AP mode well:

| Chipset | Notes |
|---|---|
| MT7612U | Dual-band, very reliable AP support, recommended |
| MT7610U | Single-band, low cost |
| RTL8811AU / RTL8812AU | Common and cheap; works with the right driver |

Any adapter built on these chipsets will do. No cables are involved.

## 2. Enable it in the setup wizard

1. **Plug the USB Wi-Fi adapter into the Pi.**
2. In the setup wizard's **network step**, set **Monitoring mode** to
   **Gateway / Access Point**. A short panel appears with three fields:
   - **USB Wi-Fi adapter**: pick the adapter you just plugged in (not the built-in
     home Wi-Fi). If you don't see it, click **Rescan**.
   - **IoT network name (SSID)**: the name your IoT devices will join. The default
     `IoTSentinel` is fine.
   - **IoT network password**: at least 8 characters. Your devices use this to join.
3. Finish the wizard. On the next boot the orchestrator brings the access point up
   (NetworkManager shared mode: DHCP + DNS + NAT) and points Zeek at the AP interface.

Config keys (in `config/default_config.json`, also set for you by the wizard):

| key | meaning | default |
|---|---|---|
| `network.capture_mode` | `passive` or `gateway` | `passive` |
| `network.ap_interface` | the USB adapter | `wlan1` |
| `network.ap_ssid` | IoT network name | `IoTSentinel` |
| `network.ap_password` | IoT network password | _(set in wizard)_ |
| `network.ap_subnet` | IoT subnet (gateway = `.1`) | `10.42.0.0/24` |

## 3. Move your IoT devices onto the new network

This is the one hands-on part, and you only do it once. For each IoT device (camera,
smart plug, TV, doorbell, and so on):

1. Open that device's app or settings and **forget / remove your old home Wi-Fi**.
2. **Join the new network** you named in step 2 (for example `IoTSentinel`), using
   the password you set.

Your **phones, laptops, and computers stay on your normal home Wi-Fi**. Only the IoT
devices you want IoTSentinel to protect move to the new network. As each device joins,
it appears on the dashboard and its traffic becomes fully visible.

You don't have to move everything at once. Any device left on home Wi-Fi simply keeps
the passive-mode level of visibility; devices on the IoTSentinel network get full
per-device detection and inline blocking.

## 4. Verify on hardware

After enabling gateway mode on the Pi:

```bash
bash scripts/validate_gateway.sh
```

It checks the AP is up, DHCP/DNS/NAT/forwarding work, Zeek targets the AP interface,
and the home uplink is intact, then prints a short manual end-to-end checklist (join a
device, confirm it appears, block/unblock it, reboot). All automated checks must pass
and the manual steps must succeed before gateway mode is considered production-ready.

## Safety: it can't break your home Wi-Fi

- The AP script only manages its own `iotsentinel-ap` profile on the USB adapter; it
  never modifies the home-Wi-Fi connection.
- After bringing the AP up, the orchestrator immediately checks the internet uplink and
  **rolls the AP back** if it was disrupted. A periodic watchdog repeats this check.
- The firewall never blocks the AP gateway, the home router/gateway, or the admin's
  device, and it keeps SSH (22) and the dashboard (8050) reachable.
- To revert to passive at any time: set `capture_mode` back to `passive`, or run
  `sudo bash config/configure_ap.sh --down`.

## Troubleshooting

| Problem | Fix |
|---|---|
| USB adapter not listed in the wizard | Replug it and click **Rescan**. Some adapters take a few seconds to enumerate. Confirm the chipset supports AP mode (see the table above). |
| The IoT network name doesn't appear on a device | Check the adapter is plugged in and the Pi has finished booting. Re-run `bash scripts/validate_gateway.sh` to confirm the AP is up. |
| A device joined but has no internet | The uplink watchdog may have rolled the AP back to protect your connection. Check the home Wi-Fi uplink is healthy, then reboot the Pi to bring the AP up again. |
| Devices keep falling back to home Wi-Fi | Forget the home network on the device so it stops auto-reconnecting, then rejoin the IoTSentinel network. |
| You want to go back to passive | Set `network.capture_mode` to `passive` in `config/default_config.json`, or run `sudo bash config/configure_ap.sh --down`, then reboot. |
