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

## What you need

- A Raspberry Pi 4 (4 GB+) running the IoTSentinel image.
- **One USB Wi-Fi adapter that supports AP (access-point) mode.** The built-in radio
  stays your home-Wi-Fi uplink; the dongle broadcasts the IoT network. Chipsets known
  to do AP mode well: MT7612U, MT7610U, RTL8811AU/RTL8812AU (with the right driver).
- No cables.

> A single radio can't reliably be both a home-Wi-Fi client and an access point at
> once, which is why the USB adapter is required for a cable-free setup.

## Enabling it

1. Plug in the USB Wi-Fi adapter.
2. In the setup wizard's network step, choose **Gateway / Access Point**, pick the USB
   adapter, and set the IoT network name + password (≥ 8 characters).
3. Finish the wizard. On the next boot the orchestrator brings the AP up (Network
   Manager shared mode: DHCP + DNS + NAT) and points Zeek at the AP interface.
4. Join your IoT devices to the new network.

Config keys (in `config/default_config.json`, also settable via the wizard):

| key | meaning | default |
|---|---|---|
| `network.capture_mode` | `passive` or `gateway` | `passive` |
| `network.ap_interface` | the USB adapter | `wlan1` |
| `network.ap_ssid` | IoT network name | `IoTSentinel` |
| `network.ap_password` | IoT network password | _(set in wizard)_ |
| `network.ap_subnet` | IoT subnet (gateway = `.1`) | `10.42.0.0/24` |

## Safety: it can't break your home Wi-Fi

- The AP script only manages its own `iotsentinel-ap` profile on the USB adapter; it
  never modifies the home-Wi-Fi connection.
- After bringing the AP up, the orchestrator immediately checks the internet uplink and
  **rolls the AP back** if it was disrupted. A periodic watchdog repeats this check.
- The firewall never blocks the AP gateway, the home router/gateway, or the admin's
  device, and it keeps SSH (22) and the dashboard (8050) reachable.
- To revert to passive at any time: set `capture_mode` back to `passive`, or run
  `sudo bash config/configure_ap.sh --down`.

## Verifying on hardware

After enabling gateway mode on the Pi:

```bash
bash scripts/validate_gateway.sh
```

It checks the AP is up, DHCP/DNS/NAT/forwarding work, Zeek targets the AP interface,
and the home uplink is intact, then prints a short manual end-to-end checklist (join a
device, confirm it appears, block/unblock it, reboot). All automated checks must pass
and the manual steps must succeed before gateway mode is considered production-ready.
