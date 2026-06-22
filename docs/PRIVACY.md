# Privacy Policy - IoTSentinel

> **DRAFT - not legal advice.** This template reflects how IoTSentinel actually
> handles data (verified against the codebase). Before any commercial or public
> release, have it reviewed by a qualified data-protection professional and fill in
> the bracketed `[...]` fields. If you operate in the UK/EU this needs to satisfy the
> UK GDPR / EU GDPR.

**Effective date:** [DATE]
**Data controller:** [LEGAL ENTITY / NAME], [ADDRESS], [CONTACT EMAIL]

## 1. Summary
IoTSentinel is a self-hosted network-security monitor that runs on your own
Raspberry Pi (or computer). **By design, your monitoring data stays on your device.**
We (the software provider) do not operate a cloud service that receives your network
data, and the software contains **no analytics, tracking, or telemetry** that phones
home.

Some **optional** features you explicitly enable send limited data to third parties
(see section 4). You control all of them.

## 2. What the device processes (stored locally on your Pi)
To monitor your network, IoTSentinel observes traffic on the interface you configure
and stores the following **locally** in its on-device database:
- Device inventory: IP addresses, MAC addresses, hostnames, vendor (from MAC OUI), and
  device names you assign.
- Connection metadata (via Zeek): source/destination IPs and ports, protocol, DNS
  queries, timestamps, byte counts. IoTSentinel does **not** record packet payloads.
- Security events: anomaly scores, alerts, threat-intel matches, blocking actions.
- Account data: your username and a bcrypt **hash** of your password (never the
  plaintext), and, if you enable them, 2FA/passkey credentials.
- Operational logs and system metrics (CPU/RAM/bandwidth).

**Retention:** detailed records are kept for a configurable window (default **30
days**) and then automatically pruned. You can change or shorten this.

## 3. Legal basis (UK/EU GDPR)
Where GDPR applies, processing is based on your **consent** (you deploy and configure
the device) and the controller's **legitimate interests** in securing the network you
operate. You are the controller for the personal data observed on your own network;
[PROVIDER] is a software provider, not a processor of your monitoring data.

## 4. Optional features that send data to third parties
None of these are active unless you turn them on. When enabled, only the data needed
for that feature is sent:

| Feature | Data sent | Recipient | When |
|---|---|---|---|
| Cloud AI assistant | Summaries/metadata about alerts and devices you ask about | Groq, Anthropic, and/or Google (Gemini) per your configuration | Only in **cloud** AI mode. A **local** on-device AI mode (Ollama) keeps everything on the Pi. |
| Threat intelligence | Individual IP addresses to be reputation-checked | AbuseIPDB | When you provide an AbuseIPDB key |
| Email / push alerts | Alert contents you choose to be notified about | Your SMTP provider, ntfy.sh, Telegram, Discord, or your webhook | When you configure a notifier |
| Remote access | Encrypted dashboard traffic relayed to your devices | Tailscale | When you enable remote access |
| Vulnerability/blocklist sync | Standard update requests (no personal data) | NVD, URLhaus | When enabled (default on) |

Each third party processes data under its own privacy policy. Review theirs before
enabling a feature. [PROVIDER] does not receive a copy of this data.

## 5. What we (the provider) collect
Nothing automatically. The software ships with no telemetry. If you contact support at
[SUPPORT EMAIL] or submit diagnostics, we process only what you send us.

## 6. Security
Passwords are hashed with bcrypt; optional TOTP 2FA and WebAuthn passkeys are
supported. The dashboard sets standard security headers (CSP, X-Frame-Options, etc.),
enforces login rate-limiting/lockout, and supports HTTPS via the remote-access proxy.
The first interactive login over SSH forces a password change away from the shipped
default. No system is perfectly secure; keep your device updated and use a strong
password.

## 7. Your rights
Because your data lives on your own device, you have direct control: you can view,
export (Reports/Exports), and delete it (clear records, change retention, or re-flash
the device). Where GDPR applies you also have rights of access, rectification, erasure,
restriction, portability, and objection - exercise them via your own device, or contact
[CONTACT EMAIL] for matters concerning [PROVIDER].

## 8. Children
IoTSentinel includes optional family/kids-device monitoring intended for use by a
network owner (e.g. a parent/guardian) on a network they control. Configure it lawfully
for your jurisdiction.

## 9. Changes
We may update this policy; material changes will be noted in the release notes /
CHANGELOG.

## 10. Contact
[LEGAL ENTITY], [ADDRESS] - [CONTACT EMAIL]. [If UK/EU and required: Data Protection
contact / representative details.]
