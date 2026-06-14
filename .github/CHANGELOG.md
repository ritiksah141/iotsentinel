# Changelog

All notable changes to IoTSentinel are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

---

## [1.0.0] - 2026-05-15

### Tier UX overhaul - Simple / Advanced mode
- Replaced the three-tier model (`home_user` / `security_admin` / `developer`) with a clean binary **Simple / Advanced** toggle
- Simple mode: focused card set, traffic-light security score, one-tap email alerts
- Advanced mode: full security console - threat intelligence, forensics, API hub, all 24 cards
- Segmented pill control in the navbar replaces the old icon-flip button
- Colour-coded mode banner (green = Simple, blue = Advanced) with one-line description
- Single source of truth for tier rules in `dashboard/shared.py`; clientside callback reads from a `dcc.Store` - duplicate 80-line JS literal removed
- Legacy tier values (`home_user`, `security_admin`, `developer`) aliased automatically on read; writes emit canonical values only
- One-shot DB migration on startup updates existing user preferences to new names

### Pi install - zero-friction setup
- **Hotspot provisioning**: Pi creates a `IoTSentinel-Setup` WiFi network on first boot if no home WiFi is configured; users connect and complete setup entirely in the browser - no Raspberry Pi Imager config screen needed
- **Unified `scripts/setup_pi.sh`**: one script handles everything end-to-end - system checks, Zeek installation (OBS Debian 12 repo), Python venv, DB init, cron jobs, systemd services, Ollama + gemma2:2b (skipped automatically if RAM < 4 GB), inline validation
- Removed `setup_ollama_pi.sh`, `validate_pi_deployment.sh`, `deploy_to_pi.sh` - absorbed into the unified script
- `iotsentinel-provision.service`: systemd unit that runs the hotspot logic on every boot (inline, no extra script file)
- Port 80 to 8050 iptables redirect so any HTTP URL typed on the hotspot reaches the wizard
- Setup wizard Step 1 gains a WiFi section: scan for networks, enter password, connect - the Pi switches to home WiFi automatically
- avahi-daemon included in the image for `iotsentinel.local` mDNS discovery (macOS / Linux clients)
- balenaEtcher recommended over Raspberry Pi Imager - 3-click flash, no config screen

### Documentation - consolidated to two user-facing files
- `README.md` - project pitch, key features, and a clear 3-path Getting Started section (Pi / Mac+Windows / advanced)
- All developer and academic docs moved to `docs/internal/` (subsequently removed from the public repo - see Unreleased section)
- Removed `DEPLOYMENT_GUIDE.md`, `PI_IMAGE_GUIDE.md`, `DOCUMENTATION_INDEX.md` - content folded into `README.md`
- Removed broken references to deleted scripts (`deploy_to_pi.sh`, `validate_pi_deployment.sh`)
- Fixed "compile Zeek from source" instructions (replaced with OBS apt repo)

### Release artifacts
- `VERSION = "1.0.0"` constant in `dashboard/shared.py`, read from `config/default_config.json`
- GitHub Actions `build-pi-image.yml` supports `workflow_dispatch` - image can be rebuilt from the Actions UI without creating a new tag
- `CHANGELOG.md` (this file)

### Test suite - consolidated
- `test_setup_wizard_step0.py` merged into `test_setup_wizard.py`
- `test_river_coverage.py` merged into `test_ml.py`
- `test_traffic_light.py` updated to `simple` / `advanced` tier names
- Removed the three merged source files

---

## [Unreleased] - post 1.0.0

### Installable app, image wiring, wizard privacy/security, CI hardening (2026-06-13)

#### Added - Progressive Web App (install like a native app)

- The dashboard is now installable as a PWA: home-screen icon, standalone window, no browser chrome. Open it once over the Tailscale Funnel HTTPS URL (or `localhost` on the Pi) and install.
- New root-scoped routes `/sw.js` and `/manifest.webmanifest`; manifest, icons, service worker and an offline fallback page ship in `dashboard/assets/`.
- Square app icons (192/512/maskable/apple-touch) are generated from `logo.png` at startup (`dashboard/asset_build.py::ensure_pwa_icons`) and gitignored as build artifacts, mirroring the existing `.min.css` pattern — no binary icons in the repo.
- The service worker is intentionally conservative: every non-GET, all navigations, and all `/api`, `/auth`, `/login`, `/_dash-update-component`, and live endpoints are network-only. Only content-hashed Dash bundles and immutable `/assets` files are cached, so it can never serve a stale login or stale security data.
- `theme-color` now tracks the active light/dark theme.
- `install.sh` / `install.bat` launch the dashboard in a chromeless `--app` window (Chrome/Edge) for a native feel on desktop, falling back to the default browser.
- Limitation (documented): PWA install needs a secure context, so it works over the Tailscale Funnel HTTPS URL or `localhost`, not plain-LAN `http://`.

#### Fixed - capture pipeline, shipped-image wiring, and latent NameErrors

- **Zeek now actually captures the chosen interface.** The image installed Zeek but never wrote `node.cfg` or ran the initial `zeekctl deploy`, and the orchestrator's restart used `sudo` that the sudoers file did not permit — so on a fresh image the core monitoring could capture nothing. New `config/configure_zeek.sh` writes `node.cfg` for the wizard-selected interface and deploys (idempotent); the orchestrator runs it on startup; the wizard restarts the backend when the interface changes; and the Pi sudoers now allows `zeekctl` and the configure script without a password.
- Created the three ops scripts `scripts/setup_pi.sh` expected but that were missing (silently skipped): `config/optimize_pi.sh` (GPU split, swappiness, CPU governor), `config/zeek_monitor.sh` (Zeek watchdog, cron `*/5`), `config/zeek_cleanup.sh` (log rotation, cron `0 3`). The shipped image now actually tunes the Pi, self-heals Zeek, and rotates capture logs.
- Fixed missing imports that would `NameError` at runtime: `sqlite3` and `timedelta` in `utils/excel_exporter.py` and `utils/pdf_exporter.py` (referenced inside `except sqlite3.Error` handlers), an undefined `severity_colors` in the CVE recommendations card, and an undefined `services` in `utils/privacy_analyzer.py`.
- `agents/security_agent._get_auto_block_config` read the config with the wrong argument shape and always returned the default, so the auto-block setting was never honoured. Fixed to read `agent.auto_block` correctly - the wizard's consent choice now takes effect.

#### Added - wizard privacy and security setup

- **Auto-block consent**: Step 2 now discloses that the AI can autonomously firewall a device on a critical alert, with a toggle persisted to `agent.auto_block.enabled`. No longer a silent default.
- **Alert sensitivity**: Low / Medium / High choice mapped to `alerting` rate-limit thresholds.
- **Firewall enforcement (advanced)**: optional Step 3 accordion to enter router SSH details (`firewall.*`) so blocks are actually enforced; off by default.
- **Security hardening prompt**: the completion step now points users to set up two-factor authentication or a passkey.
- The review step summarises auto-block, alert sensitivity, and firewall enforcement.
- **Firewall "Test connection"** button verifies the router SSH credentials during setup instead of failing silently on the first real block.
- The non-Linux (macOS/Windows) account-setup screen now carries the same auto-block consent toggle, so dev installs match the Pi wizard's privacy behaviour.

#### Added - capture-pipeline health visibility

- `/health` now reports a `capture` component (freshness of the most recent connection) so a dead Zeek/parser pipeline is visible instead of looking healthy. Reported as `idle` rather than a warning so a genuinely quiet network never trips a false alarm. The service worker also caps its static cache at 120 entries.

#### Changed - industry-standard CI / repo hygiene

- New workflows: `lint.yml` (ruff), `security.yml` (bandit SAST + pip-audit, weekly schedule). `test.yml` now reports coverage and is reusable; `build-pi-image.yml` only builds after the test suite passes.
- Added `pyproject.toml` (ruff/bandit/coverage config), `.editorconfig`, `dependabot.yml`, `CODEOWNERS`, `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md`, issue templates, and a PR template. Ruff added to pre-commit. Two non-security MD5 fingerprints marked `usedforsecurity=False`.

#### Tests

- 997 passing / 9 skipped / 0 failing (was 964). New: `test_pwa.py` (PWA routes, manifest, service-worker safety guards, icon generation, capture-health), `test_pi_scripts.py` (the Pi ops scripts exist/run and every `setup_pi.sh` reference resolves), and protection-setting + router-SSH tests in `test_setup_wizard.py`.

### AI engine overhaul - 6-tier fallback, health visibility, cold-start fixes (2026-06-12)

#### Fixed - Groq free tier was silently dead

The hardcoded Groq model `llama3-8b-8192` was decommissioned by Groq (deprecated May 2025), so every Groq call failed silently and fell through to Ollama or rule templates - the flagship free cloud AI tier had stopped working without any visible error. Now:

- Default Groq model is `llama-3.1-8b-instant` (the official replacement).
- All model names are config-driven (`ai_assistant.groq_model`, `openai_model`, `anthropic_model`, `gemini_model`) so a future deprecation is a config edit, not a release.
- A regression test pins that the decommissioned model can never return as a default.
- Second independent breakage found by the new health tracking: `groq==0.4.1` cannot construct its client at all with `httpx>=0.28` (`unexpected keyword argument 'proxies'`). Requirement bumped to `groq>=0.13.0`; the call shape is unchanged. Verified with a live round-trip (`source: groq`).

#### Added - two new AI providers (6-tier fallback)

`HybridAIAssistant` now falls back through OpenAI → Anthropic Claude (`claude-haiku-4-5`, official `anthropic` SDK, lazy/optional dependency) → Groq → Google Gemini (`gemini-2.5-flash`, plain REST so no new dependency; free tier ~250 req/day as a Groq backup) → Ollama → rule templates. New providers get source badges (Claude AI / Gemini AI), admin Settings key inputs with live singleton reload, `.env.example` entries (`ANTHROPIC_API_KEY`, `GEMINI_API_KEY`), and `from_config()` wiring in both the dashboard and orchestrator (the orchestrator previously constructed a bare assistant that ignored config entirely).

#### Added - AI failure visibility (no more silent degradation)

- Per-provider health tracking (`last_error`, `last_error_time`, `last_success_time`) with provider failures logged at WARNING (rate-limited to one per provider per 10 minutes; Ollama connection-refused stays quiet for LAN-only installs).
- New "AI Engine Health" card in admin Settings → AI: per-provider status rows with error tooltips, request distribution, cache hits, daily chat allowance, and privacy-mode state (pure helpers in `utils/ai_health.py`).
- The chat welcome status chip turns amber ("Some cloud AI providers unreachable") or red ("Cloud AI unreachable, using local templates") with the underlying error in the tooltip, driven by the new `get_status_level()` (`ok` / `degraded` / `local-only`).

#### Added - LLM response cache

In-memory TTL cache (default 10 min, 100 entries, thread-safe) inside `get_response()`: identical prompts no longer burn provider quota. Chat turns (history) and rule-template responses are never cached.

#### Added - wizard Step 3: local AI detection + privacy choice

New "Local AI (Ollama)" accordion: a Detect button probes `localhost:11434`, lists installed models, and suggests `ollama pull gemma2:2b` when missing; a radio choice (Cloud first / Local only first) persists the same `ai_privacy_mode` setting the admin toggle uses, and the review step shows the chosen AI mode.

#### Fixed - alert dedup fingerprint collisions

`Alert.get_fingerprint()` truncated the explanation at 50 characters, but every River explanation starts with the same preamble - distinct attack types on one device deduped into a single alert, while embedded anomaly scores stopped true repeats from matching. The fingerprint now includes the predicted attack type and a score-stripped, whitespace-normalized hash of the first 160 characters.

#### Added - cold-start handling for new devices

Devices with fewer than 100 connections or first seen under 2 days ago have ML-driven severities damped one level (critical→high, high→medium, medium→low) and their plain-English alerts say "IoTSentinel is still learning this device's normal behaviour, so this may be routine activity." Threat-intel (malicious IP) alerts are never damped. Config-toggleable via `ml.cold_start_damping`.

#### Added - baseline std-deviation in alert sentences

The previously unused `std_deviation` column in `device_behavior_baselines` now qualifies spike sentences: when the current value is 2+ sigma outside the learned range, alerts add "That is more than N times outside its normal range." (same-unit comparisons: last-hour destinations vs the hourly baseline, this connection's bytes vs the per-connection baseline).

#### Added - AI in the box (Pi image)

The Pi image now provisions on-device AI automatically: a new `iotsentinel-localai.service` (oneshot, after network-online, Nice=19 / idle IO) runs `scripts/setup_local_ai.sh` on first boot — installs Ollama via the official installer and pulls the configured `ollama_model` (~1.6 GB) in the background. Idempotent via a stamp file; retries on next boot after transient failures; skips automatically on <3 GB RAM or when `ai_assistant.ollama_enabled` is false. The image stays small (no model baked in) and boot is never blocked. Result: zero-config, key-free, offline-capable AI out of the box — structurally impossible for cloud-AI competitors to match.

#### Added - weekly story push digest

The Sunday weekly report now carries the full "This Week on Your Network" narrative (`report_data['weekly_story']` + source, generated via `utils/weekly_story`). The shared push formatter prefers the story over the short ai_narrative over bare counts (truncated to fit Telegram/Discord limits), so ntfy/Telegram/Discord subscribers get the narrated week on their phone; the generic webhook payload carries the story verbatim for n8n/Home Assistant consumers. Story generation failure never breaks the report.

#### Changed - README competitive claims tightened

Firewalla's Ask AI (beta, cloud-only) is now acknowledged in the comparison table instead of a blanket "No" for AI features; the section header "AI Features No Competitor Offers" became "A Privacy-First AI Layer" with the defensible differentiators (fully on-device, source transparency, provider choice). New Roadmap section documents Incident Stories, One-Tap AI Action Plans, and Predictive Deviation Alerts as post-v1.0.0.

#### Deferred

Cross-alert correlation (attack-chain grouping across devices) is deferred to post-v1.0.0: it requires an incidents table, schema migration, a grouping job, and incident lifecycle UI. The attack-sequence tracker, Active Incidents grouping, and the fingerprint fix above cover the main user-visible duplicate-noise pain in the meantime.

#### Tests

802 → 964 passing (9 skipped, 0 failing). New: `test_ai_assistant.py` (85 - module previously had zero coverage), `test_ai_health.py` (19), `test_cold_start.py` (26). Extended: `test_alerts.py` (+11 fingerprint + report story), `test_setup_wizard.py` (+11 Ollama/privacy), `test_alert_explainer.py` (+4 badges), `test_push_notifiers.py` (+6 story digest).

---

### Launch performance - asset payload cut by ~385 KB (2026-06-12)

#### Boot-time CSS minification (`dashboard/asset_build.py`)

First-party stylesheets are now minified automatically at app start and Dash serves only the minified copies:

- New `dashboard/asset_build.py`: a conservative, dependency-free CSS minifier (strips comments, collapses whitespace, preserves string literals, `calc()` spacing, descendant-pseudo selectors, and media-query syntax). `ensure_minified_css()` regenerates `custom.min.css` / `mobile-responsive.min.css` / `skeleton.min.css` whenever the source file is newer, then returns the `assets_ignore` regex that `app.py` passes to `dash.Dash` so the unminified sources are not injected.
- Sources stay readable for development; the `.min.css` artifacts are gitignored and rebuilt on every boot if stale. Any minification failure falls back to serving the original files - never a broken page.
- Result: 305 KB of first-party CSS drops to 204 KB before gzip (-33% browser parse cost on Pi-class hardware). Cascade order is unchanged because each `.min.css` sorts into the same alphabetical slot as its source.
- `tests/test_asset_build.py` (22 tests): minifier safety guarantees (strings untouched, selector semantics preserved, brace-count parity against the real shipped stylesheets) plus staleness/fallback logic.

#### Logo image optimised (`dashboard/assets/logo.png`)

The logo shipped at 1031x1280 (314 KB) but renders at a maximum of 120 px. Resized to 300 px height with a 256-colour palette: now 30 KB (-284 KB on every cold load, the single largest asset on the page).

#### Spotlight search selection highlight fixed in light mode (`dashboard/assets/custom.css`)

`.spotlight-result-selected` referenced `var(--accent-rgb)` which was never defined, so the keyboard-selected result silently lost its background tint and focus ring in light mode (dark mode worked via hardcoded values). `--accent-rgb` is now defined in both theme token blocks alongside `--accent-color`.

#### Geolocation rewritten — batched + cached (`utils/ip_geolocator.py`)

The threat map and country-stats callbacks each looped up to 20 external IPs making sequential blocking requests to ip-api.com (2 s timeout each) — up to 40 requests per refresh against the free tier's 45 req/min cap, so requests were throttled into `Read timed out` warnings on every refresh, and the same IPs were re-queried every time.

- New `utils/ip_geolocator.py`: ONE batch POST to `ip-api.com/batch` (up to 100 IPs per call), 24 h cache for successes (geo data is effectively static), 10 min negative cache for failures, thread-safe, 5 s timeout on the single batched call.
- Both callbacks now share the cache, so a dashboard refresh makes at most one geolocation request total — and zero once warm.
- Failures log at **debug**, not warning: an offline LAN-only Pi is an expected deployment, not an error condition.
- `tests/test_ip_geolocator.py` (14 tests): batch behaviour, both cache TTLs, timeout/HTTP-error/bad-JSON fallbacks, de-dupe, batch cap.

#### Webfont slimming — 646 KB of unreachable fonts removed

`assets/webfonts/` exists because Font Awesome is self-hosted (the dashboard must render on LAN-only / offline Pi installs where a CDN would fail). Audit: solid is used by 1,150 icons and brands by the Google/GitHub icons — kept (`.woff2`). Removed: `fa-regular-400.*` (zero `far` icons anywhere in the app; browsers never download a font that no glyph requests) and all three `.ttf` files (fallbacks only reachable by pre-2014 browsers that cannot run the app anyway). `webfonts/` is now two files, 258 KB.

#### Dead CSS and asset cleanup

Maintainability sweep over `dashboard/assets/` — everything removed was verified unreferenced by a corpus scan (all .py + .js) with protection for library-generated classes (bootstrap/dash/driver/plotly) and dynamically constructed class strings (`f"bg-{color}"`):

- **77 dead CSS classes removed** (20 custom.css — old status-dot/password-strength/wizard primitives; 55 skeleton.css — only the `skeleton-device-*` family was ever used; skeleton.css shrinks 14.2 KB → 3.8 KB), plus 9 orphaned `@keyframes` and 20 dead custom properties (legacy `--dark-*` alias family, unused `--enable-*` flags). Verified safe: `--bs-*` overrides kept (referenced inside bootstrap.min.css), `bg-smart-template` kept (built via `f"bg-{color}"`), `annotation-text` kept (plotly-generated).
- **Dead JS deleted**: `notifications.js` (12 KB — a desktop-notification system whose `/notifications/stream` SSE endpoint never existed server-side and whose permission flow was never wired to any UI), `virtual-scroll.js` (exported class never instantiated), `debounce.js` (no consumers; performance.js and the spotlight have their own).
- **theme-toggle.js rewritten 96 → 23 lines**: the floating-button code was disabled long ago, but it still ran a `MutationObserver` over the entire body subtree firing a no-op on every Dash re-render. Now it only does the early `body.dark-mode` apply (incl. `auto` via `prefers-color-scheme`) that prevents a light-flash before hydration.
- **Setup wizard fix**: the Gmail "Show me how" button opened a collapse with `/assets/setup/gmail_apppassword.gif` — a file that does not exist (empty dir). Button, collapse, and callback removed; the vendor help link remains. Empty `assets/setup/` and stray `.DS_Store` deleted.
- **Test guard added** (`test_parens_balanced`): during the sweep, an automated edit truncated `cubic-bezier(0.4, 0, 0.2, 1)` mid-value, leaving braces balanced but parens not — which silently killed ALL styling after `:root`. Caught by browser-parse verification (style-sheet rule count), repaired, and pinned with a parenthesis-balance test on every first-party stylesheet.
- **Verification**: every removal was validated with a browser-parsed selector diff (Chromium walks both stylesheets; the removed-selector set must exactly equal the intended dead set). This caught and reverted one false positive — `body.dark-mode .js-plotly-plot .xaxis/.yaxis .crisp` (`.crisp` is a plotly-generated SVG class that themes chart axis lines in dark mode) — and two comment-corruption artifacts in custom.css and mobile-responsive.css.

Result: 3 fewer JS files on every page load, custom.css source 267 KB → 252 KB, minified bundle 174 KB (27.6 KB gzipped). Suite: 788 passing / 9 skipped / 0 failing.

#### Scroll jank eliminated — backdrop-filter moved off in-flow content

Scrolling was laggy and cards visibly "re-rendered" after each scroll gesture. Three compounding causes, all fixed:

- **Always-on blur on in-flow content.** A late `.glass-card` rule (`!important`) had silently overridden the W15 "no blur on cards" optimization, and every `.btn`, `.card`, input, table, alert and list item also carried `backdrop-filter: blur(...)`. Backdrop blur is sampled in screen space, so the browser re-blurred every visible element on every scrolled frame. Removed blur from all in-flow content (102 declarations across 60 rules); blur now lives only on overlay chrome — navbar, sidebar, modal surfaces, dropdowns, toasts, tooltips, overlays, mobile tab bar (24 rules). Since in-flow elements scroll together with the flat page background, the change is **pixel-identical** in both themes (verified by screenshot diff) — the glass look comes from the translucent backgrounds, borders and noise texture, which are untouched.
- **`body.is-scrolling` toggle removed** (CSS + performance.js listener). Flipping a body class on scroll start/stop invalidated styles for the entire document, and on stop it re-applied blur+shadow+noise to ~25 cards simultaneously with a 0.5s transition — the visible post-scroll repaint storm. Its `html:not(.is-scrolling)` re-enable rule never matched anything anyway (the JS toggled the class on `body`, not `html`).
- **skeleton.css**: 18 backdrop-filter declarations removed from shimmer placeholders (in-flow, animated — blur added cost, no visuals).

Benchmark (40-card page, 6x CPU throttle, programmatic scroll + 600 ms post-scroll window): worst frame 54.8 ms → 15.9 ms, p95 17 ms → 10.5 ms, frames over 32 ms: 4 → 0. custom.css minified output drops to 180 KB (was 186 KB).

#### performance.js — GPU-layer regression removed, honest metrics added

- Removed the DOMContentLoaded loop that forced inline `translateZ(0)` onto every `button, a, .card, .dropdown-item`. This silently re-created the blanket GPU layer promotion that W15 removed from CSS for the Pi 4's Mali GPU (layers are promoted on-demand via `.glass-card:hover` instead). Also removed the dead Google Fonts preconnects (all fonts are self-hosted in `assets/webfonts/`).
- The console performance breakdown now also prints **First Paint** (FCP) and **Interactive** (domInteractive). "Render Time" (`domComplete - domLoading`) includes async work such as the plotly chunk download/parse, so FCP is the honest "how fast does the page appear" number. Both values exposed on `window.performanceMetrics`.
- Headless Chrome profiling (login page): FCP 96 ms cold / 32 ms warm; under 6x CPU throttle (Pi-class) FCP 72-88 ms, interactive ~150 ms.

#### Stale test expectation updated

`test_source_badge_class_contains_color[rules-secondary]` still expected `bg-secondary` for the `rules` source; the implementation intentionally moved to the custom `bg-smart-template` badge class (light + dark variants exist in `custom.css`). Test updated to match.

**Test suite total: 785 passing / 9 skipped / 0 failing** (up from 763 / 9 / 0).

---

### Device Personality Profiles + AI test coverage (2026-06-10)

#### Device Personality Profiles — novel AI feature (`utils/device_personality.py`, `dashboard/callbacks/callbacks_devices.py`)

A per-device AI behavioural summary card added to the top of the device detail modal's Overview tab. When a user opens any device, the card shows a plain-English profile of that device's normal behaviour: when it is typically active, how much data it transfers, how many external hosts it contacts, and whether today looks normal compared to its learned baseline.

**Architecture** — follows the established `weekly_story` pattern end-to-end:
- `utils/device_personality.py` (new module): `build_profile_facts(db, device_ip)` gathers baseline metrics from `device_behavior_baselines`, today's stats from `connections`, peak-activity hours (new query: `strftime('%H')` grouped by hour, top 3), device identity, and total alert count. `generate_personality(facts, ai_assistant)` builds a low-temperature LLM prompt, strips em-dashes/bold from the response, and falls back to `_template_fallback` when no LLM is configured, the provider returns `source == 'rules'`, or the call raises. All LLM output rendered via `dcc.Markdown` per the AI output formatting rule.
- `dashboard/app.py`: global `dcc.Store(id='device-personality-cache')` added alongside `weekly-story-cache`.
- `dashboard/callbacks/callbacks_devices.py`: personality card inserted at the top of `tab_overview` (glass card, source badge from `alert_explainer.source_label/source_badge_class`, refresh button, timestamp). `update_device_personality` callback with 1-hour TTL cache keyed by device IP, matching the weekly story TTL pattern.

No home IoT security product ships per-device AI personality profiles grounded in live behavioral baselines.

#### Ask-why grounding extracted to testable helper (`utils/alert_explainer.py`)

`build_followup_prompt(alert_row, today_count, destinations, recs, history, question) -> (prompt, network_context)` extracted from the inline closure in `alert_followup_chat` (`callbacks_alerts.py:3493`). The callback now delegates its context-lines and prompt-assembly to this helper. No behaviour change — same grounding, same history bounding (last 4 non-system turns), same `network_context` preamble.

#### Test coverage — three previously-zero modules now fully covered

All three AI utility modules had 0% test coverage. New test files:

- **`tests/test_alert_explainer.py`** (56 tests): every exported function in `utils/alert_explainer.py`, including `build_followup_prompt`. Covers all fallback paths, em-dash stripping, 500-char DB truncation, worry-level separator variants, and the None / empty / exception paths for `rewrite_alert`.
- **`tests/test_weekly_story.py`** (32 tests): `_facts_to_text`, `_template_fallback`, `generate_story` (4 fallback branches + success + exception), and `build_facts` against a real SQLite fixture.
- **`tests/test_device_personality.py`** (35 tests): full coverage of the new `device_personality` module including `build_profile_facts` DB integration tests.

**Test suite total: 763 passing / 9 skipped / 0 failing** (up from 640 / 10 / 0).

---

### Active IDS - autonomous enforcement, CVE on join, Shodan removal (2026-06-08)

#### Active IDS — SecurityAgent becomes an enforcer

`SecurityAgent` is now an active intrusion detection system. When a high-risk alert fires, the agent autonomously blocks the offending device and any malicious external destinations rather than queuing the action for human approval.

**Policy table** — `_POLICY` in `agents/security_agent.py` maps `(severity, attack_type)` → `(action_type, risk_level)`. `critical/*` always maps to `firewall_block / high`. `high/*` maps to `mark_suspicious / low` (escalates if the device floods alerts — see below).

**Investigation** — `_investigate()` now returns `(steps, threat_meta)`. Step 3 performs a **live AbuseIPDB lookup** via `ThreatIntelligence.get_ip_reputation(ip)` for up to 3 external destination IPs; results cached 24 h in `ip_reputation`. Hard cap of 3 API calls per 60 s cycle (≤72/h, within AbuseIPDB 1 000/day free tier). `threat_meta` carries `max_confidence` and `malicious_dests: [(ip, score)]`.

**Risk routing** — `_process_alert()` routes `risk_level == 'high'` to `_execute_auto_block()` when `enabled = true`; falls back to `status='pending'` queue when disabled.

**`_execute_auto_block()`**:
1. Circuit breaker check — 3+ distinct devices auto-blocked in last 10 min → trip breaker, set `auto_block_suspended = '1'`, send critical alert, queue as `pending`. Clear via Admin > Agent.
2. `FirewallEnforcer.block_device(ip, mac)` — self-lockout guard runs inside enforcer.
3. `FirewallEnforcer.block_ip(dest)` for each `malicious_dests` entry with `confidence >= threshold`.
4. `create_agent_action(..., status='auto', risk_level='high')` + critical notification.

**Alert escalation** — `_check_alert_escalation()` counts unacknowledged high/critical alerts from the same device in the last 10 minutes. Three or more promotes a `risk_level='low'` action to `_execute_auto_block` — catches devices that flood high-severity alerts without a single `critical` event.

Set `config.agent.auto_block.enabled = false` to revert to approval-only mode.

#### Self-lockout guard (`utils/firewall_enforcer.py`, `dashboard/shared.py`, `dashboard/callbacks/callbacks_auth.py`)

Autonomous blocking cannot lock the admin out of their own dashboard.

- `FirewallEnforcer.block_ip()` and `block_device()` now call `_is_protected_ip(ip)` at the top. Protected IPs: (1) the stored `protected_admin_ip` setting (the browser IP recorded on last login), (2) `config.firewall.router_ip`, (3) `utils.network_monitor.get_default_gateway()`. A match returns `False` and writes an audit log entry — the IP is never blocked.
- `callbacks_auth.py` `handle_login()` persists `protected_admin_ip = request.remote_addr` into the `system_settings` KV store on every successful login.
- `dashboard/shared.py` injects the provider callable via `set_protected_ip_provider(lambda: db_manager.get_setting('protected_admin_ip'))` after firewall enforcer initialisation.

#### Auto-quarantine for new devices that fire critical alerts on join

`_scan_new_devices()` now:
1. **CVE scan on join** — `_run_cve_scan_for_device(device)` performs LIKE matching on `iot_vulnerabilities.affected_vendors` and `affected_models` using the device's manufacturer, model, and device_type. Matches are written to `device_vulnerabilities_detected` with `risk_score = cvss_score * 0.8` (80% confidence for a text match) and `auto_detected = 1`. Skips CVEs already recorded for that device IP.
2. **Auto-quarantine check** — `_device_has_critical_alert(device_ip, within_hours=1)`. If the new device already generated a critical alert in its first hour **and** auto-block is enabled, `_auto_quarantine_new_device()` runs instead of the normal triage card: blocks via `FirewallEnforcer.block_device`, sets `is_blocked = 1`, records `device_triage` action with `status='auto'` and `risk_level='high'`.
3. Otherwise: normal Trust/Block triage card. Deduplication window: 720 hours (30 days) — `action_already_queued(device_ip, 'device_triage', hours=720)` skips reconnecting known devices.

#### CVE surfaced in Device details panel (`dashboard/callbacks/callbacks_devices.py`)

The Security tab of the device detail panel now shows a "Known Vulnerabilities (CVE)" card after the Network Access Control section. It queries `CVEMatcher.get_device_vulnerabilities(device_ip)`, lists up to 10 CVEs with severity badge, CVE ID, CVSS score, and description excerpt. Empty state shows a green check "No known CVEs matched".

`utils/cve_matcher.py` updated: `CVEMatcher.__init__` now accepts `db_manager` parameter (uses it directly when provided, falls back to creating a new `DatabaseManager(db_path=...)`). `get_cve_matcher()` accepts a matching kwarg.

#### Real vulnerability scanner — no more fake CVE IDs (`dashboard/callbacks/callbacks_alerts.py`)

`update_vulnerability_scanner` now queries `device_vulnerabilities_detected` for real NVD CVE counts by severity. Port-based signals (Telnet/FTP) are still counted as additional risk factors but are **no longer assigned placeholder CVE IDs** (`CVE-2021-36260`, `CVE-2020-27403`, etc.). Badge numbers now reflect genuine CVE data.

#### Shodan removed (`alerts/integration_system.py`, tests)

Shodan had no client implementation, no `.env` key, no DB seed, and no dashboard coupling — shipping it would misrepresent the integration list. Removed from `INTEGRATIONS` dict; integration count is now **24** (was 25, Threat Intelligence sub-count "(8)" → "(7)"). Tests updated: `test_total_integration_count_is_24`, `test_advanced_count_is_12`, `test_advanced_sees_all` (24), `test_shodan_configured` deleted.

---

### AI differentiation suite - four competitor-beating features (2026-06-06)

These four features give IoTSentinel capabilities that Firewalla, Fing, eero, and Pi-hole do not offer: on-device AI reasoning with transparent evidence, triage guidance for new devices, a narrative weekly digest, and natural-language database queries.

#### Agent investigation timeline

When the SecurityAgent processes an alert, it now runs a 5-step investigation before creating the action record:

1. Device history - total connections and alert count over the last 7 days
2. External destinations - top IPs contacted in the last hour (non-RFC-1918)
3. Threat intelligence - cross-reference destinations against the `malicious_ips` table
4. Traffic vs baseline - compare current outbound bytes to `device_behavior_baselines`
5. Agent decision - policy match (action type + risk level) with plain-English rationale

Each step carries a verdict: `ok`, `warn`, or `bad`. The full step list is serialised as JSON into a new `agent_actions.investigation TEXT` column (schema migration v6). The Agent panel renders each step as a vertical timeline with color-coded icons (green check, yellow warning, red X). Users can see exactly how the agent reached its conclusion.

Schema changes: `database/db_manager.py` gains `_migrate_to_v6()` and `get_new_devices(since_minutes)`. `config/init_database.py` adds the column to the fresh-schema CREATE TABLE. `create_agent_action()` gains an `investigation` parameter.

#### AI new-device triage

When a device is seen for the first time, the agent generates a plain-English summary and queues a `device_triage` pending action. The agent panel shows a distinct card with **Trust** and **Block** buttons instead of Approve/Reject. Triage actions are deduplicated over a 720-hour (30-day) window so known devices are never re-triaged on reconnection.

Trust: calls `update_device_metadata(ip, is_trusted=1)` and resolves the action.
Block: calls `set_device_blocked`, enforces via `firewall_enforcer.block_device` if available, and resolves the action.

The triage report is generated via `HybridAIAssistant` with a no-em-dash, no-jargon prompt. A fallback template is used when no AI backend is configured.

#### AI weekly security digest

`ReportGenerator` now accepts an `ai_assistant` parameter (wired from the orchestrator's existing assistant instance). `generate_weekly_report()` and `generate_monthly_report()` call `generate_ai_narrative(report_data)` before returning, injecting an `ai_narrative` key into the report dict.

The narrative is a 3-4 sentence plain-English summary of the week: new devices, unusual behavior, critical alert count, and any standout patterns. It is generated with a structured prompt that enforces no em dashes, no markdown bold, and no bullet points. Output is post-processed with `.replace('--', '-')` as a belt-and-suspenders check.

`_format_report_html()` in `email_notifier.py` renders the narrative in a highlighted block (blue left border, light background) above the stats tables. A fallback template is used when AI is unavailable.

#### Natural language network queries (LLM-powered NL-to-SQL)

Users can ask questions about their network in plain English from the chat modal, for example "Did any device contact a flagged IP this week?" or "Show me high-risk devices". The system now uses the LLM to generate SQL before falling back to 13 regex templates.

`utils/nl_to_sql.py` gains:
- `generate_sql_llm(natural_query)`: sends the full schema dict to the LLM and requests a single SELECT statement
- `validate_sql(sql)`: enforces SELECT-only, no semicolons, no blocked keywords (`DROP`, `DELETE`, `UPDATE`, `INSERT`, `EXEC`, `PRAGMA`), only known tables, force-appends `LIMIT 100` if absent
- `answer_in_plain_english(natural_query, results)`: 1-2 sentence plain-English summary of the rows returned
- `execute_query()` now tries LLM SQL first; any failure falls back to the existing template matcher

The chat callback auto-detects data-lookup phrasing using four patterns. When the LLM or template returns `no_match`, the message falls through to the conversational AI chat instead of showing an error. Two new starter chips are added: "Did any device contact a flagged IP today?" and "Show me high-risk devices".

Security guardrails: `validate_sql()` is non-negotiable. The LLM cannot produce a write statement that reaches the database.

#### AI UX consistency pass (2026-06-06)

All AI-facing surfaces now follow the same UX contract:

- **Source badge in chat**: AI chat messages now show the same color-coded source badge as the alert analysis modal (Groq AI = blue, OpenAI = indigo, Local AI = grey, Smart Template = grey, Data Query = green). The badge appears inline with the "IoTSentinel AI" label.
- **Response cleaning in chat**: AI chat responses are now post-processed to strip em dashes and stray bold markers before being stored and displayed.
- **Agent AI badge**: Every action card in the Agent panel now shows a small "AI" badge next to the device name, confirming the report was AI-generated.
- **Agent source text removed**: `_generate_report()` no longer appends `[Groq]`/`[OpenAI]` text to the plain_report field - the UI badge handles this.
- **Em dash sweep**: All user-visible em dashes replaced with hyphens across callbacks_overview, callbacks_global, callbacks_alerts, callbacks_analytics, callbacks_agent, and agents/security_agent.
- **Stat placeholders**: Overview stat card fallback values and error tuples updated from em dash characters to plain hyphens.
- **System prompt style rule**: Chat system prompt now includes an explicit "No em dashes, no markdown asterisks" style instruction so the LLM avoids them without relying on post-processing alone.
- **NL-to-SQL fallback bug fixed**: "What's connected right now?" and similar conversational questions were being incorrectly routed to NL-to-SQL because the detection regex matched `what` + `connected`. Fixed by removing `connect` from the broad pattern (connection-verb queries are handled by a more specific pattern that also requires a device noun). Additionally, when NL-to-SQL returns `no_match`, the message now falls through to conversational AI rather than showing an error.

---

### v1.0.0 pre-release cleanup - mock removal, security hardening, Smart Context (2026-06-02)

#### Fake features replaced with real implementations
- **Block trackers** (`block_all_trackers`): now queries `cloud_connections` (privacy_concern_level = high/critical) and `third_party_trackers` for real destination IPs, then calls `firewall_enforcer.block_ip()` for each. Returns true success/failure counts.
- **Replace device** (`replace_device`): now writes to the DB - copies `notes`/`device_type`/`manufacturer` from the old device to the replacement via `db_manager.update_device_metadata`, marks the EOL device blocked via `set_device_blocked`, and appends a replacement note.
- **Firmware updates** (`update_firmware_updates_list`, `check_firmware_updates`): replaced fake cycling badges and `time.sleep(0.5)` with real queries to `device_firmware_status`. Shows `current_firmware` to `latest_firmware`, EOL flag, and age in days.
- **Smart Context modal** - Rooms and Automations tabs now backed by the database:
  - Rooms: reads from `smart_home_rooms` + `device_room_assignments` via new `db_manager.get_all_rooms()`. "Add Room" card persists via `db_manager.add_room()`. Replaced `device_name LIKE '%Living%'` name-matching heuristic.
  - Automations: new `smart_home_automations` table (trigger_type, condition_text, action_text, is_enabled). `save_automation` persists via `db_manager.save_automation()`. Delete buttons wired to `db_manager.delete_automation()`. Cancel reloads from DB.
  - Refresh button no longer clobbers rooms/automations with static placeholders.

#### Security hardening
- **Forced first-login password change**: `must_change_password INTEGER DEFAULT 0` column added to `users` table (idempotent `ALTER TABLE` migration). Set to 1 when non-interactive DB init creates the default `admin/admin` account. `display_page` now redirects to a standalone change-password screen until cleared. `auth_manager.change_password` clears the flag atomically. Wizard path also clears it.
- **`eval()` removed** from `callbacks_integrations.py` - replaced with `json.loads()` for all pattern-matched component IDs.

#### Dead code / callback cleanup
- Removed `update_api_integration_hub` (Output `api-integration-status` - ID no longer exists).
- Removed `update_model_accuracy_display` (Output `model-accuracy-display` - ID no longer exists).
- Fixed `autofill_verification_code`: stale Output `'tabs'` updated to `'auth-tabs'` (real component ID in login.py).
- Fixed `save_widget_preferences`: removed two orphaned `widget-prefs-toast` outputs.
- Removed unused imports across multiple callback files.
- Removed dead `shared.py` functions with zero callers: `get_rule_based_response`, `generate_csv_content`, `create_alert_skeleton`, `create_graph_skeleton`, `create_stat_skeleton`.
- Deleted unused dev scripts: `scripts/test_optimizations.py`, `scripts/soak_test.py`, `scripts/test_reports.py`.

#### CSS double-load fix
- `bootstrap.min.css` and `fontawesome.min.css` were listed in `external_stylesheets` and also auto-served from `dashboard/assets/`, causing each to load twice. Removed the explicit entries - Dash auto-serve is sufficient.

#### Remote access gap fixes
- `_enable_tailscale_funnel()` now reads the real app port (`IOTSENTINEL_PORT` / config `dashboard.port`, default 8050) instead of a hardcoded 8050.
- Funnel activation now surfaces a warning alert if `tailscale funnel` fails (previously the return value was silently ignored).

#### Wizard and release polish
- Progress bar initial value corrected from 33% to 17% (step-1 value in `_PROG`).
- DB path fallback mismatch fixed: `app.py` now falls back to `data/database/iotsentinel.db` (matching `config/default_config.json`) instead of the legacy `iot_monitor.db`.
- README updated with AI Forecast, Device Name Resolution, Frosted-Glass UI, Remote Access, and security features.

#### Repo cleanup
- Removed `dashboard/app.py.backup` - stale Feb-5 snapshot (38k lines vs current 9.8k); no longer needed.
- Removed `data/logs/soak_test_results.csv` - orphan artefact from the already-deleted `scripts/soak_test.py`.
- Removed `docs/internal/archive/` (18 internal dev/planning docs) from the public repo - retained in git history; no public-facing docs linked to them.
- Added `tests/README.md` - full test suite documentation: all 24 test files with what each covers, why it exists, key test classes, and the coverage strategy.

---

### Database - long-run scalability hardening

Changes aimed at stable 6-month+ continuous operation on Raspberry Pi 4/5.

#### Write-path batching
- `capture/zeek_log_parser.py`: `parse_conn_log` no longer calls `add_connection` per log line. Rows are collected in memory and flushed via `add_connections_batch` (executemany) every 5,000 rows and once at end-of-file. Result: thousands of commits per parse cycle reduced to a handful. `add_connection` (single-row) is unchanged for all other callers.
- `database/db_manager.py` - `add_connections_batch`: now also runs a bulk `UPDATE devices SET last_seen = CURRENT_TIMESTAMP` for all IPs in the batch so active-device tracking stays correct even for pre-existing devices.

#### Thread safety
- `DatabaseManager._write_lock`: a `threading.RLock` (reentrant) now guards every mutating method: `add_device`, `add_connection`, `add_connections_batch`, `store_prediction`, `create_alert`, `acknowledge_alert`, `suppress_device_alerts`, `set_setting`, `add_malicious_ips`, `create_indexes`, `optimize_database`, `cleanup_old_data`, `create_agent_action`, `update_agent_action_status`, and all device/group setter methods.
- The `transaction()` context manager now acquires and releases the lock so multi-statement transactions are also fully serialised.
- `add_device` was restructured: the device classifier now runs outside the lock (CPU-bound, can be slow) while only the INSERT/commit is locked. Also fixes a pre-existing bug where the `INSERT` ran outside the `transaction()` block.
- Singleton `__new__` is now guarded by `_singleton_lock` (class-level `threading.Lock`) to prevent races on first construction.

#### WAL configuration
- `PRAGMA wal_autocheckpoint = 1000` added to `_connect` - SQLite now automatically checkpoints every ~4 MB of WAL growth, bounding WAL file size between manual checkpoints.

#### Tiered retention (15 tables)
The daily cleanup now prunes every ever-growing table, not just the original three (`connections`, `ml_predictions`, `alerts`). Retention windows are config-driven via `config/default_config.json -> database.retention`:

| Table | Default retention |
|---|---|
| `connections`, `ml_predictions` | 30 days |
| `alerts` | 90 days |
| `audit_log`, `security_audit_log`, `agent_actions` | 180 days (compliance) |
| `rate_limit_log` | 7 days |
| `api_integration_logs`, `toast_history`, `discovery_events` | 30 days |
| `security_score_history`, `sustainability_metrics`, `device_energy_estimates`, `model_performance`, `model_drift_history` | 90 days |

Expired `alert_suppressions` rows (past their `expires_at`) are also removed. All values are overridable in `config/default_config.json`.

#### Size-guarded VACUUM
The daily `cleanup_old_data` now:
1. Always runs `PRAGMA wal_checkpoint(TRUNCATE)` - flushes WAL back to the main file whether or not VACUUM runs.
2. Runs `VACUUM` only when the DB is below `database.vacuum_threshold_mb` (default 100 MB). Above that threshold the checkpoint is sufficient and the long blocking VACUUM is skipped, preventing stalls on a 6-month-old DB.

#### Weekly optimisation
`orchestrator.py` - `_cleanup_loop` now calls `optimize_database()` (ANALYZE + WAL checkpoint) once every seven daily cycles, keeping query-planner statistics fresh without adding another long-running thread.

#### Runtime index creation
`DatabaseManager.create_indexes()` is called once at orchestrator startup so the performance indexes (`idx_connections_*`, `idx_alerts_*`, etc.) are always present, not just after a manual `scripts/db_maintenance.py --weekly` run.

#### Automated maintenance cron wired into installers
`install.sh` and `scripts/setup_pi.sh` now invoke `scripts/setup_db_automation.sh` during setup, registering cron jobs for daily backup + backup rotation and weekly optimisation.

---

### AI Assistant - chat modal redesign

- **UI redesign**: Chat modal now mirrors the Spotlight Search design language. No `ModalHeader`, `ModalBody p-0`, frosted-glass shell. Top bar shows robot icon + "AI Assistant" title with an icon-only Clear button. Input is a rounded pill bar with a leading comment icon and a circular indigo send button (no underline). Footer shows `Enter to send` hint + per-user daily quota.
- **Empty / welcome state**: replaced the bullet-list capability dump with a centered greeting + four plain-English starter chips ("Is my network safe?", "What's connected right now?", "Explain my latest alert", "How do I block a device?"). Chips are clickable and submit the prompt directly.
- **Scoped responses**: LLM system prompt now allows general security/networking/IoT education questions while declining only clearly off-topic requests (recipes, personal advice, creative writing). Rule-based fallback intent ordering fixed - specific keywords (device/alert/etc.) always win over greeting words.
- **Usage counter fixed**: all AI responses (Groq, Ollama, rules) now count toward the daily cap, not just cloud-sourced ones.
- **Daily cap corrected**: `daily_cap_household` and `daily_cap_business` updated from 20 to 1400 to match Groq's actual free-tier allowance (~1,400 req/day).
- **Dark mode text**: explicit `color: var(--ink-primary)` added to both bubble types in dark mode - bubble text and icons were previously invisible on dark backgrounds.

---

### Device name resolution - ARP scanner enrichment

Devices are now shown with human-readable names (e.g. `living-room-tv`, `Samsung TV`) instead of `Device-A1B2C3` or a raw IP address. All methods are no-sudo and dependency-free (Python stdlib only).

#### New module: `utils/name_resolver.py`

Three-tier pipeline, first non-None result wins:

1. **Reverse DNS (PTR)**: `socket.gethostbyaddr` on a daemon thread with a configurable timeout (default 1 s). Result cleaned: trailing `.local` / `.lan` / `.home` / `.localdomain` stripped, title-cased when all-lowercase.
2. **NetBIOS/NBNS node-status request**: pure UDP socket to port 137, no `nmblookup` binary required. Extracts the workstation (suffix `0x00`) or file-server (suffix `0x20`) name from the reply; group names ignored. Best-effort, silently returns None on timeout or parse failure.
3. **Manufacturer friendly fallback**: combines OUI vendor string with the device type already inferred by the classifier (e.g. `"Samsung Electronics"` + `smart_tv` becomes `"Samsung TV"`). Covers 40+ known brands.

Results are cached per-IP for 1 h (configurable via `discovery.name_resolution.cache_ttl_seconds`) so the 60-second scan loop does not re-query DNS/NetBIOS on every cycle.

New helper `is_synthetic(name) -> bool` detects placeholder names (`None`, `''`, `Device-XXXXXX`, raw IP) so the scanner knows whether to attempt resolution.

#### `utils/arp_scanner.py` - priority-preserving enrichment

`scan_and_update_database` no longer unconditionally writes `Device-{mac_suffix}`. Resolution now:
- If the device already has a real name in the DB (from DHCP, mDNS, or a previous resolve), the existing name is preserved.
- Otherwise `name_resolver.resolve_name(ip, mac, manufacturer)` is called; the result is used if truthy, falling back to the synthetic name only when all three tiers miss.

#### `utils/auto_provisioner.py` - broken INSERT fixed

`_add_device_to_database` was calling a raw `INSERT INTO devices` with non-existent column names (`ip_address`, `hostname`, `vendor`), raising `sqlite3.OperationalError` silently on every mDNS / UPnP discovery. Fixed to use `db_manager.add_device(...)`.

#### Tests: `tests/test_name_resolver.py` (30 new tests)

Covers: `is_synthetic` (8), reverse-DNS clean + error handling (4), NetBIOS parse + socket error (4), manufacturer fallback corner cases (7), tier-ordering + fallthrough (4), and cache hit/miss behaviour (3).

---

### On-device AI model - phi3.5:mini replaced by gemma2:2b

Switched the Ollama local model from `phi3.5:mini` to `gemma2:2b` across `utils/ai_assistant.py`, `dashboard/shared.py`, and `config/default_config.json`.

Why gemma2:2b:
- **Smaller footprint**: ~1.6 GB (Q4) vs ~2.2 GB for phi3.5:mini - leaves an extra 600 MB free for the OS and dashboard on a 4 GB Pi 5.
- **Better instruction following**: Gemma 2 (Google DeepMind, 2024) outperforms Phi-3.5 Mini on MMLU, HellaSwag, and instruction-following benchmarks at the 2B parameter class.
- **Faster inference on Pi 5**: smaller weight count reduces per-token latency from ~5-10 s to ~4-8 s on the Pi 5's Cortex-A76 cores.
- **Comfortable RAM headroom**: 1.6 GB model + ~700 MB OS + ~300 MB dashboard = ~2.6 GB total, well within 4 GB with no swap pressure.

To pull the model on your Pi: `ollama pull gemma2:2b`

---

## Earlier development

Pre-release development history is tracked in git commit messages.
