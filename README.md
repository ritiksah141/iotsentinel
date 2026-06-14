# IoTSentinel

**Autonomous network security for every home. Runs on a $75 Raspberry Pi.**

[![Tests](https://github.com/ritiksah141/iotsentinel/actions/workflows/test.yml/badge.svg)](https://github.com/ritiksah141/iotsentinel/actions/workflows/test.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/Platform-Raspberry%20Pi%204%2F5-red)]()
[![ML](https://img.shields.io/badge/ML-River%20ML%20(Incremental)-green)]()
[![Tests](https://img.shields.io/badge/Tests-640%20passed-brightgreen)]()
[![Coverage](https://img.shields.io/badge/Coverage-84%25-brightgreen)]()

> **[Download for Raspberry Pi](https://github.com/ritiksah141/iotsentinel/releases/latest)** — Flash `.img.xz` with **Raspberry Pi Imager**, boot, connect to `IoTSentinel-Setup` WiFi, complete the 6-step browser wizard. No terminal required.

---

Most home networks are invisible to the people who own them. Smart TVs, thermostats, cameras, and plugs communicate constantly with external servers — and there is no way to know when something goes wrong until a breach has already happened.

IoTSentinel makes your network visible, understandable, and actively defended. It runs entirely on a Raspberry Pi, keeps all your data on-device, and explains every decision it makes in plain English.

---

## Why IoTSentinel

| | **IoTSentinel** | Firewalla | Fing | Pi-hole |
|---|---|---|---|---|
| **Price** | ~$75 (Pi hardware) | $179 to $349 | $99/yr subscription | Free (DNS only) |
| **Traffic analysis** | Deep (Zeek C++ engine) | Yes | Limited | No |
| **Unsupervised ML** | Yes, River ML, on-device | No | No | No |
| **Autonomous IDS** | Yes, auto-blocks threats | Basic | No | No |
| **AI investigation timeline** | Yes, 5-step, transparent | No | No | No |
| **CVE scanning on join** | Yes, NVD pipeline | No | No | No |
| **Plain-English alerts** | Yes, proactive LLM rewrite | Beta, cloud-only | No | No |
| **Per-alert AI chat** | Yes, grounded in your network | Beta, cloud-only | No | No |
| **AI works fully on-device** | Yes, preinstalled in the Pi image | No, requires their cloud | No | No |
| **Choose your AI provider** | Yes, 6-tier: OpenAI, Claude, Groq, Gemini, local | No, theirs only | No | No |
| **Weekly AI security story** | Yes, auto-narrated | No | No | No |
| **Per-device AI personality profiles** | Yes, from learned baselines | No | No | No |
| **AI source transparency** | Yes, badge per explanation | No | No | No |
| **Privacy** | 100% on-device | Cloud sync | Cloud | Local |
| **Open source** | Yes (MIT) | Partial | No | Yes |

---

## What it does

### Active Intrusion Detection

IoTSentinel runs an autonomous `SecurityAgent` that polls every 60 seconds. When a threat is detected it does not just send a notification — it investigates.

**5-step investigation, fully transparent:**

1. Device connection history and recent alert count
2. External destinations contacted in the last hour
3. Live [AbuseIPDB](https://abuseipdb.com) reputation lookup for each external IP, cached 24 h
4. Traffic volume vs baseline (flags deviations above 1.5x)
5. Policy decision with plain-English rationale

Every step is recorded and shown in the dashboard as a color-coded vertical timeline. Users see exactly how the agent reached its conclusion — no black-box scores.

For **critical threats** (command-and-control, data breach, DDoS), the agent enforces a firewall block autonomously without waiting for approval. A **self-lockout guard** ensures the admin's own IP, the router, and the default gateway can never be blocked — even during autonomous enforcement. A **circuit breaker** suspends auto-blocking if 3 devices are blocked within 10 minutes, preventing false-positive storms from locking out the network.

### CVE Scanning on Device Join

When a device joins the network for the first time, IoTSentinel matches its manufacturer, model, and device type against the NVD vulnerability database. Matched CVEs surface immediately in the device Security tab with CVSS scores and descriptions. No manual scanning required.

### A Privacy-First AI Layer

Competitors are starting to bolt cloud AI onto their products — Firewalla's Ask AI (beta) sends your alarms to LLMs in their cloud. IoTSentinel's AI layer is different in kind, not just degree: **every AI feature works fully on-device or offline**, every explanation **shows which engine wrote it**, and you choose the provider — OpenAI, Claude, Groq, Gemini, a local model, or no cloud at all.

**Proactive Plain-English Alert Rewriting** — A background worker rewrites every alert into plain English as it arrives, using a 6-tier AI fallback: OpenAI gpt-4o-mini → Anthropic Claude Haiku → Groq llama-3.1-8b → Google Gemini → Ollama (local, on-device) → smart rule templates. No alert stays as raw technical jargon. The alerts card header pulses when the AI is actively explaining new alerts.

**Per-Alert Conversational AI Analyst ("Ask Why")** — Open any alert and ask follow-up questions in plain English: "Why is this bad?", "What should I do?", "Is my data safe?". Answers are grounded in your actual network — the specific device, its baseline traffic, recent destinations, and smart recommendations. No generic advice: answers are about *your* network at that moment.

**"This Week on Your Network" Weekly Story** — A weekly plain-English narrative that tells the security story of your home network: alert summary, autonomous actions taken, new devices, bandwidth trends, and what to watch. Generated by the AI from your real data, with a rule-based fallback that always renders something useful. No competitor produces an auto-narrated weekly story.

**Agent Investigation Timeline** — The transparent, step-by-step reasoning behind every automated decision. Displayed as an interactive timeline in the dashboard so users see exactly what the agent found and why it acted.

**AI New-Device Triage** — When an unknown device joins, the agent generates a plain-English summary: what the device likely is, whether it looks safe, and what to do next. A Trust / Block card appears in the Agent panel.

**Natural Language Network Queries** — Ask your network questions in plain English: *"Did any device contact a flagged IP this week?"* or *"Show me high-risk devices."* The system generates a validated, read-only SQL query, runs it, and returns a plain-English answer with a results table. Thirteen regex templates provide coverage when no LLM is configured.

**Device Personality Profiles** — Open any device and the Overview tab shows an AI-generated behavioural summary: when it's typically active, how much data it moves, how many external hosts it usually contacts, and whether today looks normal. Generated from River ML baselines and real connection history — not generic descriptions. A source badge shows which AI provider wrote it; a clean rule-based summary renders when no LLM is configured. No home security product ships per-device AI personality profiles.

**AI Source Transparency** — Every AI-generated explanation shows which provider wrote it: a labelled badge (Groq AI, OpenAI, Claude AI, Gemini AI, Local AI, Smart Template) appears on each alert card and agent action. The Network Briefing, AI Insights, weekly story, and device personality cards all show their source. Nothing is anonymous.

**AI Privacy Mode** — A single toggle switches the AI stack to Ollama-first mode, keeping all network data and explanations on-device. No API keys required, no data leaves the Pi.

**AI in the Box** — The official Pi image provisions on-device AI automatically: on first boot (once online) it installs Ollama and pulls the local model in the background, niced so the dashboard stays responsive. No account, no API key, no cloud — unplug the internet afterwards and the AI keeps explaining. Skipped automatically on low-RAM devices; cloud providers and rule templates work regardless.

**Weekly Story on Your Phone** — The "This Week on Your Network" narrative is delivered through your configured push channels (ntfy, Telegram, Discord, webhook, email) with the Sunday report — your network's week, narrated, in your pocket.

### Real-Time ML Anomaly Detection

IoTSentinel uses [River ML](https://riverml.xyz) — an incremental, online machine learning library — to score every device on every connection. Models update continuously with no training phase. Two ensemble algorithms (HalfSpaceTrees and HoeffdingAdaptive) score traffic in real time against a rolling baseline. The Overview page shows the current anomaly index, risk badge, trend arrow, and per-device breakdown, all wired directly to live prediction data.

### Frosted-Glass Dashboard

A mobile-responsive web UI with Apple-vibrancy frosted-glass design, full dark mode, low-power mode auto-detected from device capabilities, keyboard shortcuts, and Spotlight-style search. Accessible from your home network or via an optional permanent HTTPS URL (Tailscale Funnel).

---

## Getting Started

### Raspberry Pi (recommended, no terminal needed)

**1. Flash**

Download `IoTSentinel-<version>.img.xz` from the [latest release](https://github.com/ritiksah141/iotsentinel/releases/latest). Open **[Raspberry Pi Imager](https://www.raspberrypi.com/software/)**, select the `.img.xz`, select your SD card, and click Write.

**2. Boot and connect**

Insert the SD card, power on the Pi. After about 90 seconds a WiFi network called **`IoTSentinel-Setup`** appears. Connect your phone or laptop to it, then open `http://10.42.0.1:8050/setup`.

**3. Complete the 6-step wizard**

| Step | What you configure |
|------|-------------------|
| 1. WiFi and Admin | Home WiFi credentials, admin password |
| 2. Who is this for? | Household or Small Business feature tier |
| 3. Optional features | Email alerts, AI explanations (Groq), local AI (Ollama) + privacy mode, threat intel (AbuseIPDB) |
| 4. Access from anywhere | Optional permanent remote HTTPS URL via Tailscale Funnel |
| 5. Review | Confirm settings and click Launch |
| 6. Done | Reconnect to your home WiFi, open `http://iotsentinel.local:8050` |

All API keys are optional. The system works without them using local threat feeds and rule-based fallbacks.

> **Windows / Android:** `iotsentinel.local` requires Bonjour (ships with iTunes on Windows). Without it, use the Pi's IP address from your router's connected-devices page.

---

### Laptop / Desktop (macOS / Linux / Windows)

**macOS / Linux**
```bash
git clone https://github.com/ritiksah141/iotsentinel.git
cd iotsentinel
bash install.sh
```

**Windows**
```
git clone https://github.com/ritiksah141/iotsentinel.git
cd iotsentinel
install.bat
```

Your browser opens automatically to `http://localhost:8050/setup` where the wizard guides you through setup.

<details>
<summary>Manual install (developers)</summary>

```bash
# 1. Create virtual environment
python3 -m venv venv
source venv/bin/activate          # Windows: venv\Scripts\activate

# 2. Install dependencies
pip install -r requirements.txt          # laptop; Pi uses requirements-pi.txt

# 3. Initialise database
python3 config/init_database.py

# 4. Start the dashboard
python3 dashboard/app.py
```

For a full Raspberry Pi setup (Zeek + all services):
```bash
bash scripts/setup_pi.sh
```
</details>

---

## Architecture

```
                    Raspberry Pi
    +-----------------------------------------+
    |                                         |
    |  Zeek (C++)                             |
    |  Deep protocol analysis                 |
    |  conn.log / dns.log / http.log ...      |
    |                 |                       |
    |  Python Log Parser                      |
    |  Parses Zeek JSON -> SQLite             |
    |                 |                       |
    |  River ML Engine                        |
    |  HalfSpaceTrees + HoeffdingAdaptive     |
    |  Incremental scoring, no training       |
    |                 |                       |
    |  SecurityAgent (60s cycle)              |
    |  5-step investigation + enforcement     |
    |  AbuseIPDB lookup + auto-block          |
    |                 |                       |
    |  Dash Dashboard                         |
    |  Real-time UI, AI features              |
    |  Mobile-responsive, dark mode           |
    +-----------------------------------------+
```

All processing stays on-device. No data leaves the Pi unless you configure optional external services (AbuseIPDB, cloud AI providers, email notifications). Privacy mode keeps all AI on-device via Ollama.

---

## Security Architecture

**Login protection:** Rate limiting (5 failures = 5-minute lockout), bcrypt password hashing, persistent `SECRET_KEY`, role-based access (Admin / Viewer), forced password change when default credentials are detected on first login.

**Autonomous IDS policy:**

| Severity | Attack type | Action |
|---|---|---|
| critical | C2, data breach, DDoS | Auto-block (device + malicious destination IPs) |
| critical | Any | Auto-block |
| high | Brute force, compromise | Mark suspicious |
| high | Port scan | Notify |
| medium | Any | Notify |
| low | Any | Acknowledge |

Set `config.agent.auto_block.enabled = false` to switch to approval-queue mode. All investigation and classification continues — only autonomous enforcement is paused.

**Remote access:** Optional Tailscale Funnel integration (wizard step 4) provides a permanent HTTPS URL without port forwarding or VPN setup.

**Install it like an app:** IoTSentinel is a Progressive Web App. Open it over your Tailscale Funnel HTTPS URL (or `http://localhost:8050` on the Pi itself) and choose **Install** / **Add to Home Screen** — it then opens in its own window with its own icon, no browser chrome, on phone and desktop. The `install.sh` / `install.bat` scripts also launch it in a chromeless app window automatically. (App install needs a secure context, so it works over the Tailscale HTTPS URL or `localhost`, not a plain-LAN `http://` address — the dashboard still works fine there, it just isn't installable.)

---

## Testing

**997 tests** across 36 files covering the full data pipeline, ML engine, security flows, alert system, AI feature helpers, device intelligence, and setup wizard.

| Module | Coverage |
|---|---|
| Zeek parser | 86% |
| Feature extractor | 81% |
| Name resolver | 83% |
| DB manager | 72% |
| Email notifier | 73% |
| Alert service | 75% |

```bash
pytest tests/                          # all 997 tests
pytest tests/ -x                       # stop at first failure
./scripts/run_tests.sh report          # HTML coverage report
```

See **[tests/README.md](tests/README.md)** for full test documentation.

---

## Technology Stack

| Layer | Technology |
|---|---|
| Capture | Zeek (formerly Bro) — enterprise-grade C++ network analysis |
| Backend | Python 3.11, SQLite |
| ML | River 0.21.0 — HalfSpaceTrees, HoeffdingAdaptive, SNARIMAX |
| AI | HybridAIAssistant — 6-tier fallback (OpenAI gpt-4o-mini, Anthropic claude-haiku-4-5, Groq llama-3.1-8b-instant, Google gemini-2.5-flash, Ollama gemma2:2b, rule templates). Config-driven models, response cache, provider health panel, proactive rewrite worker, per-alert chat, weekly story, device personality profiles, NL queries. |
| IDS | Custom SecurityAgent — autonomous 5-step investigation |
| Frontend | Dash by Plotly — frosted-glass, dark mode, mobile-responsive |
| Notifications | ntfy, Telegram, Discord, email, webhook |
| Hardware | Raspberry Pi 4 or 5 (4 GB RAM recommended) |

---

## Roadmap

Post-v1.0.0, in priority order:

- **Incident Stories** — correlate related alerts into a single narrated attack chain: "Your camera was port-scanned at 9:14, then attempted SSH to your NAS at 9:20." One incident, one story, one decision — instead of a pile of separate alerts.
- **One-Tap AI Action Plans** — the AI proposes a complete, reviewable response ("block for 24 hours, notify me, auto-unblock, watch for recurrence") executed through the existing firewall enforcer with the circuit breaker and self-lockout guard.
- **Predictive Deviation Alerts** — the on-device traffic forecaster learns each device's daily rhythm and narrates breaks from it: "Your camera is normally silent between 1 and 5 am. It just started uploading."

---

## Documentation

- **[tests/README.md](tests/README.md)** — Full test suite documentation
- **[.github/CHANGELOG.md](.github/CHANGELOG.md)** — Full version history
- **[.github/SECURITY.md](.github/SECURITY.md)** — Security policy and responsible disclosure

---

## License

MIT — see [LICENSE](LICENSE).
