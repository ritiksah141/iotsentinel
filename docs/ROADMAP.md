# IoTSentinel Roadmap and Product Tiers

## Vision
Bring the kind of network intrusion detection and prevention that used to need an
enterprise appliance to ordinary homes, on cheap, open hardware, with the threats
explained in plain English by a local AI. Protect the devices that cannot protect
themselves (cameras, plugs, TVs, sensors), without sending anyone's traffic to a cloud.

## The one hard constraint
Full per-device protection, meaning detecting a specific device exfiltrating data or
talking to a command-and-control server and then blocking it, requires that device's
traffic to physically pass through IoTSentinel. On modern switched, encrypted Wi-Fi
there is no way to see another device's unicast traffic by passively listening. So the
product's tiers are really about how the box gets into the traffic path with the least
effort for the user.

## Product tiers (good, better, best)

### Tier 1: Passive monitor (plug-and-play, ships in v1.0.0)
- **Hardware:** a Raspberry Pi only.
- **Setup:** flash the image, run the on-screen wizard. No command line, no extra hardware.
- **Features:** device inventory, new-device alerts, firmware end-of-life and vulnerability
  posture, DNS-level threat intelligence, the dashboard, and the local AI plain-English
  explanations (Ask-Why, agent timeline).
- **Who it is for:** every non-technical user. Real, differentiated value out of the box.

### Tier 2: Gateway / Access Point (cable-free full IDS/IPS, ships in v1.0.0)
- **Hardware:** Pi plus one AP-capable USB Wi-Fi adapter. No cables.
- **Setup:** in the same wizard, choose Gateway, pick the adapter, name the IoT network,
  then move IoT devices onto that network.
- **Features:** everything in Tier 1 plus full per-device flow capture, ML anomaly detection
  (exfiltration, C2, scanning), MITRE kill-chain mapping, and inline block and allow of any
  device.
- **Who it is for:** prosumers willing to add a low-cost adapter and move their IoT devices
  onto a dedicated network.

### Tier 3: Appliance / whole-network gateway (post-1.0, the plug-and-play full-feature path)
- **Hardware:** a pre-built and pre-flashed unit (Pi or CM4 board plus radio in a case).
- **Setup:** plug it in, optionally place it between the modem and router.
- **Features:** the Tier 2 features for the whole network with no device re-pairing.
- **Who it is for:** non-technical users who want full protection with appliance-level
  simplicity.

## Path to plug-and-play full features
The friction that keeps Tier 2 full features out of non-technical hands is three manual
steps: flashing, adding a dongle, and re-pairing devices. The roadmap removes them in order
of payoff:

1. **Appliance bundle.** Ship pre-flashed with the radio built in. Removes "flash plus add
   dongle" and turns setup into "plug in power."
2. **Whole-network gateway (inline or router mode).** The unit sits between modem and router,
   or is the router. Every device routes through it automatically, which removes re-pairing.
   This is the model the commercial leaders use; the capture-mode engine, AP manager,
   connectivity watchdog, and inline enforcer already built are the foundation.
3. **Safe DHCP-gateway insertion (simple mode).** Software only: the unit becomes the gateway
   on the existing network with no rewiring and no re-pairing. The most plug-and-play option,
   and the hardest to do safely; it builds directly on the connectivity watchdog and
   instant-rollback safety already in place.

## How it maps to releases
- **v1.0.0:** Tiers 1 and 2, both driven entirely by the on-screen wizard. Non-technical users
  get the full plug-and-play passive experience; prosumers get full IDS/IPS by adding one USB
  adapter. No feature requires the command line.
- **v1.x:** the Tier 3 appliance image and whole-network gateway mode (no re-pairing).
- **later:** safe DHCP-insertion simple mode, curated threat-intel feeds, and a mobile companion.

## How this stands against competitors
Architecturally IoTSentinel now plays in the same category as the commercial inline
home-security boxes (for example Firewalla): real per-device IDS/IPS with inline blocking. Its
differentiators are open source on commodity hardware, local AI plain-English explanations,
unsupervised on-device ML (no cloud training), and data that stays local. The gaps it is
closing on the roadmap are appliance polish, whole-network coverage without re-pairing, and
throughput.
