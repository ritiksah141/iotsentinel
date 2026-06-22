# IoTSentinel - Test Suite Documentation

## Overview

| Metric | Value |
|---|---|
| Total tests | **1117 passing**, 9 skipped, 0 failing |
| Test files | 44 |
| Core-module coverage | db_manager 72% - feature_extractor 81% - zeek_parser 68% - name_resolver 79% - email_notifier 73% - alert_service 78% - config_manager 69% - alert_explainer 100% - ai_health 100% - weekly_story 94% - device_personality 88% - ai_assistant 83% |
| Dash callbacks coverage | 0% (by design - require a live browser; tested manually) |
| CI | `test.yml` runs the suite on Python 3.11 + 3.12 (plus an app-boot smoke test); `pi-deps.yml` checks the Pi requirement set installs on ARM64; `lint.yml` (ruff) and `security.yml` (bandit + pip-audit) gate every push to `main` |

Run the full suite:

```bash
pytest tests/                          # all 1117
pytest tests/ -x                       # stop at first failure
pytest tests/ -k "db"                  # run only db-related tests
./scripts/run_tests.sh report          # with HTML coverage report
```

---

## Design principles

**1. Real database, no mocking.**
Every test that touches storage uses a real in-memory SQLite instance via `DatabaseManager(":memory:")`. Mocking the DB was ruled out after a prior incident where mocked tests passed but the production migration failed - the mock/prod divergence masked the bug. See `test_database.py` and `test_db_coverage.py`.

**2. Unit-test the pure logic, integration-test the pipelines.**
Dash callbacks are large state machines that require a running browser to exercise properly. The callback tests (`test_setup_wizard.py::TestNavigateSteps`, `test_padlock.py`) extract the pure Python logic into module-level functions (`_navigate_steps_logic`, lock-state helpers) and test those directly. The Dash wiring itself is verified by a layout-structure check (required IDs present) and manual testing.

**3. Security and correctness before coverage.**
The test suite prioritises the paths where bugs have real consequences - default credentials, password validation, DB migrations, plaintext PII in logs. These paths have explicit regression tests named for the incident they prevent (e.g. `TestCoalesceGuard`, `TestMigrationV5`).

**4. Pi-realistic conditions.**
`test_pi_integration.py` and `test_db_scalability.py` simulate real Pi workloads - concurrent writes from multiple threads, long-running retention cleanup, and batch ingestion under load - to surface issues that only appear after days of continuous operation.

---

## Test files

### Core data pipeline

#### `test_database.py` - 26 tests
**Covers:** `database/db_manager.py` - CRUD operations for all five core entity types.

**Why it exists:** The database is the single source of truth for every dashboard view. This file establishes the correctness baseline: create/read/update/delete round-trips for devices, connections, alerts, ML predictions, and audit log entries. Transaction integrity tests verify that a mid-write failure leaves the DB in a clean state rather than partially committed.

| Class | What it validates |
|---|---|
| `TestDeviceOperations` | add, get, update, block/unblock, deduplication via upsert |
| `TestConnectionOperations` | single and batch insert, `last_seen` update on re-seen device |
| `TestAlertOperations` | create, acknowledge, suppress, severity filtering |
| `TestMLPredictionOperations` | store prediction, retrieve by IP, anomaly flag |
| `TestErrorHandling` | malformed input, duplicate primary key, FK violation |
| `TestTransactionIntegrity` | mid-transaction crash leaves no partial rows |

---

#### `test_db_coverage.py` - 88 tests
**Covers:** `database/db_manager.py` - all 40+ methods not covered by `test_database.py`.

**Why it exists:** `db_manager` is the widest module in the codebase (998 lines). `test_database.py` covers the five core entities; this file covers every other method so regressions surface at the function level rather than only at the integration level.

| Class | What it validates |
|---|---|
| `TestValidators` | input sanitisation helpers reject bad IPs/MACs |
| `TestDeviceMetadata` | custom name, notes, manufacturer, firmware fields |
| `TestDeviceGroups` | add/remove devices from groups, group membership query |
| `TestConnectionCount` | per-device and per-protocol aggregation |
| `TestModelPerformance` | store River ML epoch metrics, retrieve latest |
| `TestTrustBlock` | trust/block flag read-write, batch block |
| `TestBandwidthStats` | hourly bucket aggregation |
| `TestMaliciousIPs` | threat-intel feed ingestion and lookup |
| `TestAlertQueries` | unacknowledged count, time-range filter, device-scoped |
| `TestCleanup` | `cleanup_old_data` removes rows older than threshold |
| `TestConnectionProcessing` | `process_connection_data` wires parser output to DB |
| `TestSchemaVersion` | `get_schema_version` returns int; sentinel row present |
| `TestAddDeviceValidation` | missing IP, MAC, device_type rejected |
| `TestAddConnectionValidation` | missing required fields rejected |
| `TestAddConnectionsBatch` | executemany path; `last_seen` bulk update |
| `TestCreateIndexes` | indexes created without error; idempotent |
| `TestOptimizeDatabase` | `ANALYZE` + WAL checkpoint; no crash |
| `TestGetDatabaseStats` | row counts, file size, schema version |
| `TestHealthCheck` | connection alive; WAL size within bounds |
| `TestBackupDatabase` | `.db` copy created with correct name |
| `TestCleanupOldBackups` | keeps N most-recent, deletes older |
| `TestEnsureConnection` | reconnects transparently after connection drop |
| `TestMigrationV5` | `must_change_password`, `smart_home_rooms`, `smart_home_automations` created on fresh DB; idempotent; old schema drop+recreate guard |

---

#### `test_db_scalability.py` - 14 tests
**Covers:** `database/db_manager.py` - long-run stability (batch ingestion, retention, thread safety, WAL).

**Why it exists:** IoTSentinel runs 24/7 on a Pi 4. Issues like WAL bloat, lock contention, and unchecked table growth only manifest after days or weeks of operation. These tests simulate sustained load to surface those issues in CI rather than in production.

| Class | What it validates |
|---|---|
| `TestBatchIngestion` | 1 000 connections via `add_connections_batch`; correct row count; no FK errors |
| `TestTieredRetention` | 15 tables pruned at their configured thresholds; compliance tables kept longer |
| `TestThreadSafety` | 10 concurrent threads each inserting 50 rows; final count exact; no data corruption |
| `TestWalAndVacuum` | WAL checkpoint runs; VACUUM skipped above `vacuum_threshold_mb`; VACUUM runs below it |

---

#### `test_capture.py` - 11 tests
**Covers:** `capture/zeek_log_parser.py` - Zeek conn.log parsing.

**Why it exists:** Every byte of network data enters the system through this parser. An off-by-one on a field index or a silent failure on a malformed log line corrupts all downstream ML and alerting. Tests cover normal rows, missing optional fields, malformed timestamps, and empty files.

---

#### `test_capture_coverage.py` - 25 tests
**Covers:** `capture/zeek_log_parser.py` - protocol-specific log formats.

**Why it exists:** Zeek emits separate log files for each protocol (DHCP, HTTP, DNS). Each has a different field layout. These tests verify the per-protocol parsers independently so a change to one doesn't silently break another.

| Class | What it validates |
|---|---|
| `TestParseDhcpLog` | hostname extraction, IP/MAC binding, lease timestamps |
| `TestParseHttpLog` | URI, method, host, status code extraction |
| `TestParseDnsLog` | query name, response type, TTL |
| `TestIsMonitoringPaused` | pause flag respected during high-CPU conditions |
| `TestParseOnce` | single-file parse returns correct connection count |

---

### Machine learning

#### `test_ml.py` - 59 tests
**Covers:** `ml/feature_extractor.py`, `ml/attack_classifier.py`, `ml/predictive_analytics.py`.

**Why it exists:** ML correctness is the core value proposition of IoTSentinel. This is the largest module-level test file. It covers both the numeric pipeline (features must be finite, consistent shape, correct scale) and the semantic layer (threat levels must map to correct severity categories).

| Class | What it validates |
|---|---|
| `TestFeatureExtraction` | 14-dimensional vector from a connection row; each feature bounded |
| `TestMissingValueHandling` | zero bytes, None duration, missing protocol - no NaN in output |
| `TestScalerOperations` | MinMax normalisation; fit/transform consistency; saved scaler reloads correctly |
| `TestEdgeCases` | empty dataframe, single row, all-zero traffic |
| `TestFeaturePersistence` | scaler saved to disk; reloaded state matches original |
| `TestFeatureInterpretability` | feature names present; order stable across calls |
| `TestPerformance` | 10 000 rows processed in < 2 s (Pi-realistic budget) |
| `TestClassifyEvent` | `LOW` / `MEDIUM` / `HIGH` / `CRITICAL` returned for synthetic inputs |
| `TestThreatLevel` | score-to-level mapping boundaries (0-25 LOW, 26-50 MEDIUM, etc.) |
| `TestAttackSequences` | port-scan pattern detected; lateral movement flag set |
| `TestDeviceRiskScore` | composite score increases with more anomalies |
| `TestPredictDeviceFailure` | high-risk prediction stored; severity correct |
| `TestSaveLoadPaths` | model file paths resolve correctly on Pi directory layout |

---

#### `test_river_ml.py` - 23 tests
**Covers:** `ml/river_engine.py` - River ML incremental engine (HalfSpaceTrees + HoeffdingAdaptive).

**Why it exists:** River ML is the anomaly detection engine. Unlike batch models it updates on every connection - a bug in the update path would silently degrade detection accuracy over time. Tests verify that the model initialises correctly, scores connections, classifies threat levels, persists state across restarts, and integrates with the DB prediction store.

| Class | What it validates |
|---|---|
| `TestRiverEngineInitialization` | both models initialised; scoring callable immediately |
| `TestConnectionAnalysis` | anomaly score increases for synthetic attack traffic |
| `TestFeatureExtraction` | 14-feature vector from connection dict; matches `feature_extractor` output |
| `TestThreatClassification` | score thresholds → severity labels (LOW/MEDIUM/HIGH/CRITICAL) |
| `TestModelPersistence` | save/load preserves model state; predictions consistent |
| `TestStatistics` | accuracy, false-positive rate, total-processed counters updated |
| `TestEdgeCases` | zero-byte connection, unknown protocol, None fields |
| `TestIntegrationWithDatabase` | prediction stored in `ml_predictions`; retrievable by IP |

---

### Security and authentication

#### `test_must_change_password.py` - 20 tests
**Covers:** `utils/auth.py`, `config/init_database.py` - forced first-login password change.

**Why it exists:** Running IoTSentinel with the default `admin/admin` password is a critical security risk. The `must_change_password` flag was added to block dashboard access until the password is changed. These are explicit regression tests for that security control - verifying the flag is set, the gate blocks the dashboard, and the flag clears on password change.

| Class | What it validates |
|---|---|
| `TestUserClass` | `must_change_password` defaults False; True when set; other Flask-Login attrs unaffected |
| `TestVerifyUser` | flag False for normal user; True when default `admin/admin` password in DB |
| `TestGetUserById` | flag correctly loaded from DB; None for missing user |
| `TestChangePasswordClearsFlag` | flag set to 0 after change; new password authenticates; old rejected |
| `TestInitDatabaseFlag` | init with `admin/admin` sets flag=1; real password sets flag=0 |
| `TestCoalesceGuard` | old DB without the column doesn't crash (`COALESCE(must_change_password, 0)`) |

---

#### `test_log_sanitization.py` - 6 tests
**Covers:** Log output - PII redaction.

**Why it exists:** Security requirement. IP addresses, MAC addresses, and device names must be sanitised before appearing in log files to prevent PII leakage. Failure here could expose home network topology in log aggregators or crash reports.

---

### Setup wizard

#### `test_setup_wizard.py` - 110 tests
**Covers:** `dashboard/layouts/setup_wizard.py`, `dashboard/callbacks/callbacks_setup.py`, `config/config_manager.py`.

**Why it exists:** The wizard is the first thing every user sees on a fresh Pi install. A broken step-progression or a silent config-write failure would leave every new install broken. This is the most comprehensive callback test file - the `navigate_steps` logic was extracted to a module-level function specifically to make it testable without a running browser.

| Class | What it validates |
|---|---|
| `TestWriteEnv` | `.env` created; upsert replaces existing key; multiple keys; comment lines preserved; permission error → False |
| `TestSetupWizardLayout` | layout imports cleanly; all required component IDs present; vendor links correct; `xs=12` responsive columns present |
| `TestSetupGate` | gate inactive when `.env` exists; active when absent |
| `TestSaveConfig` | email keys written; Groq key written; `is_configured=True` set; `write_env` always called |
| `TestValidationHelpers` | short/empty Groq key fails; 200 → verified; 401 → rejected; AbuseIPDB: empty fails, 200 passes, timeout handled |
| `TestInterfaceDetection` | psutil returns interfaces; options have `label`/`value`; default prefers non-loopback; fallback on psutil failure |
| `TestNavigateSteps` (30 tests) | Next step 1-5 (all valid and error paths); Back from 2-5; Skip; all 6 progress bar values (17/33/50/67/83/100%); unknown trigger → `PreventUpdate` |
| `TestShowStep6` | step 6 shows container; steps 1-5 hide it; None data defaults hidden |
| `TestToggleTailscalePanel` | True shows panel; False/None/empty hides panel |
| `TestWizardFinalePanel` | `setup-done-btn` present; step 6 container present; `_STEPS` has 6 entries; `_step_header(n)` renders badge |

#### `test_wifi_manager.py` - 14 tests
**Covers:** `utils/wifi_manager.py` - the shared nmcli/reachability helpers used by the setup wizard, the post-setup **Settings → Network → Change WiFi** control, and the `iotsentinel-connectivity` recovery watchdog.

**Why it exists:** WiFi switching is how a headless, non-technical user stays in control of the Pi - in the wizard, when moving the Pi to a new network, and when the connectivity timer re-opens the setup hotspot after an outage. All three paths run the same `nmcli` calls, so the parsing and the "treat a connect timeout as a soft success" behaviour (the network drops the request that switches it) are pinned here once. Every helper degrades gracefully on a host without `nmcli`.

| What it validates |
|---|
| `nmcli_available` true/false by PATH; `scan_wifi_networks` parses SSIDs, dedupes, hides the setup hotspot, locks secured networks, and swallows errors → `[]` |
| `current_wifi` returns the active SSID, ignores the setup hotspot, and is `None` without nmcli |
| `connect_wifi` requires an SSID, builds the password command, surfaces stderr on failure, and treats a timeout as a soft success |
| `get_reachable_addresses` shape (`mdns`/`ip`/`port`); `get_local_ip` skips loopback |

---

### Dashboard features and UI

#### `test_asset_build.py` - 25 tests
**Covers:** Boot-time CSS minification (`dashboard/asset_build.py`).

**Why it exists:** `app.py` serves `<name>.min.css` instead of the readable sources, so a minifier bug would silently break every page's styling. These tests pin the safety guarantees (string literals untouched, `calc()` and descendant-pseudo selector semantics preserved) and run the minifier over the real shipped stylesheets to assert brace-count parity.

| Class | What it validates |
|---|---|
| `TestMinifyCss` | comment stripping, whitespace collapse, selector/string/calc safety |
| `TestRealStylesheets` | minified `custom.css` / `mobile-responsive.css` / `skeleton.css` keep every rule |
| `TestEnsureMinifiedCss` | stale regeneration, fresh-skip, missing-source fallback, ignore-regex anchoring |

---

#### `test_pwa.py` - 18 tests
**Covers:** Progressive Web App support, `/sw.js` and `/manifest.webmanifest` routes, the manifest, icon generation, and the service-worker caching guards.

**Why it exists:** the dashboard installs as a native-feeling app over the Tailscale Funnel HTTPS URL. That relies on a valid manifest, a root-scoped service worker, and the right `<head>` tags, and the service worker must never cache an authenticated or dynamic request. These tests pin install support and the network-only safety guards so a refactor can't silently break install or cache a login.

| Class | What it validates |
|---|---|
| `TestManifestFile` / `TestServiceWorkerFile` / `TestOfflineFallback` | manifest validity, icon files exist, service-worker network-only guards + versioned cache, offline page |
| `TestIconGeneration` | committed icons are square/correct size; `ensure_pwa_icons` idempotent and crash-safe |
| `TestPwaRoutes` | routes return correct status/content-type, `Service-Worker-Allowed: /`, unauthenticated, index tags |

---

#### `test_pi_scripts.py` - 7 tests
**Covers:** the Raspberry Pi ops scripts in `config/` (`optimize_pi.sh`, `zeek_monitor.sh`, `zeek_cleanup.sh`).

**Why it exists:** `scripts/setup_pi.sh` wires these into the shipped image behind `[ -f ]` guards; when they were missing the image silently lost Pi tuning, the Zeek watchdog, and log rotation. These tests pin that the files exist, are executable, pass `bash -n`, and that every path `setup_pi.sh` references resolves.

---

#### `test_image_build.py` - 22 tests
**Covers:** `scripts/build_pi_image.sh` (the Raspberry Pi image build) and the files it bundles.

**Why it exists:** A real ARM image takes ~40 min to build in CI, and broken builds shipped *silently* — images that "built successfully" but had no IoTSentinel installed (setup ran via `su` and aborted under qemu), an unsubstituted `__WIFI_COUNTRY__` placeholder, or files that were never committed so `git archive` left them out. This file dry-runs the build with a stubbed qemu/pi-gen in **~0.5 s** and asserts the generated stage tree is correct, so those failures surface locally and **block the expensive build** (the suite gates `build-pi-image` via `needs: [test]`).

| What it validates |
|---|
| `STAGE_LIST` runs the custom stage last; `prerun.sh` (copy_previous) + `EXPORT_IMAGE` present |
| deps install runs in the ARM chroot (not the host arch); installs `iw`/`rfkill`/NetworkManager |
| setup_pi.sh is invoked **as root** (`IOTSENTINEL_TARGET_USER`), never via `su` (the shipped-broken bug) |
| no `__WIFI_COUNTRY__` placeholders remain; `IOTSENTINEL_WIFI_COUNTRY=US` bakes US in |
| all 7 systemd units copied + the right ones enabled; repo tarball staged into the chroot |
| every referenced service/script exists; ExecStart targets exist; units have required sections |
| all critical files are committed (`git ls-files`) so they ship in the image |
| the post-build rootfs assertion (services/sudoers/venv) stays in `build_pi_image.sh` |

---

#### `test_traffic_light.py` - 22 tests
**Covers:** Security score system - score-to-colour mapping, Simple mode layout, email bridge, CSS.

**Why it exists:** The traffic-light score (red/amber/green) is the primary trust signal for non-technical users. It's the first thing they see on the Overview page. Tests verify score thresholds map to correct colour bands and that the Simple mode renders it correctly.

| Class | What it validates |
|---|---|
| `TestTrafficLightScoreMapping` | 0-39 → red, 40-69 → amber, 70-100 → green |
| `TestSimpleLayoutCallback` | traffic-light component present in Simple layout |
| `TestEmailBridgeCallbacks` | email alert toggle wires to SMTP config correctly |
| `TestTrafficLightCSSPresent` | CSS classes `traffic-light-*` defined in `custom.css` |

---

#### `test_view_toggle.py` - 12 tests
**Covers:** Simple / Advanced mode tier system (`dashboard/shared.py`).

**Why it exists:** The tier toggle controls which of the 24 dashboard cards are visible. Getting this wrong either blocks users from features they've enabled or exposes premium cards to users who haven't set up the integration. Legacy alias tests are specifically for the 2026-05-15 rename (`home_user` → `simple`, `security_admin` → `advanced`) - existing user preferences in the DB must still work.

| Class | What it validates |
|---|---|
| `TestSimpleTemplate` | `simple` tier shows correct card subset; premium cards hidden |
| `TestAdvancedTemplate` | `advanced` tier shows all cards |
| `TestLegacyAliases` | `home_user` → `simple`; `security_admin` → `advanced` (backwards compat) |
| `TestRegistrationDefault` | new user registration defaults to `simple` |

---

#### `test_padlock.py` - 16 tests
**Covers:** `dashboard/callbacks/callbacks_padlock.py` - feature lock/unlock UI.

**Why it exists:** The padlock overlay controls premium feature access (threat intelligence, global threat map). The lock-state helpers and save-API-key logic are tested directly without a running browser, using the same extracted-function pattern as the wizard.

| Class | What it validates |
|---|---|
| `TestPadlockOverlayComponent` | overlay renders with correct IDs and disable prop |
| `TestLockStateHelpers` | lock state computed correctly from API key presence |
| `TestSaveApiKeyImpl` | key written to `.env`; integration enabled in DB |
| `TestHandlePadlockClickLogic` | click routes to correct modal for each feature |

---

#### `test_dashboard_features.py` - 30 tests
**Covers:** Feature module initialization - IoT intelligence, protocol analyser, threat feed, sustainability, topology, predictive analytics.

**Why it exists:** Each of these modules has complex initialisation that touches the DB and config at import time. Tests verify clean initialisation, basic method contracts, and that feature data returns a consistent schema (no KeyError on dashboard render).

---

#### `test_dashboard_api_integration.py` - 15 tests
**Covers:** `alerts/integration.py` - API integration hub configuration and connectivity.

**Why it exists:** Third-party API integrations (AbuseIPDB, Shodan, PagerDuty) are the most likely source of runtime failures because they depend on external services. Tests verify configuration loading, credential handling, and that connectivity failures are surfaced as user-visible alerts rather than silent exceptions.

---

### Alerts and notifications

#### `test_alerts.py` - 29 tests
**Covers:** `alerts/email_notifier.py`, `alerts/alert_service.py` - email alerts, rate limiting, report generation.

**Why it exists:** Email is the primary alerting channel for non-technical home users. Rate limiting prevents alert storms from flooding a user's inbox during a network incident.

| Class | What it validates |
|---|---|
| `TestEmailNotifierInitialization` | SMTP config loaded from env; graceful no-config |
| `TestEmailSending` | send path; SMTP mock; attachment included |
| `TestReportSending` | daily report formatted correctly; schedule respected |
| `TestEmailFormatting` | HTML template renders severity colours; no raw Python in output |
| `TestSeverityHelpers` | `CRITICAL`/`HIGH`/`MEDIUM`/`LOW` → correct CSS class |
| `TestAlertCreation` | alert stored; `create_alert` returns ID |
| `TestRateLimiter` | burst of alerts for same device collapsed to one notification per window |
| `TestAlertFingerprint` | dedup fingerprint: attack-type aware, score-stripped, immune to the shared River preamble |
| `TestReportGeneration` | PDF-style summary includes all sections |

---

#### `test_email_coverage.py` - 23 tests
**Covers:** `alerts/email_notifier.py` - additional formatting and error paths.

**Why it exists:** Complements `test_alerts.py` with detailed formatting tests and error-path coverage. The `parse_bool` helper is used across the email configuration - a wrong implementation would silently disable email alerts for users who set `EMAIL_ENABLED=true` (string, not bool).

| Class | What it validates |
|---|---|
| `TestParseBool` | `"true"`, `"1"`, `"yes"` → True; `"false"`, `"0"`, `"no"` → False |
| `TestFormatReportSubject` | subject includes date and site name |
| `TestFormatReportText` | plain-text body contains all alert counts |
| `TestFormatReportHtml` | HTML body valid; severity sections present |
| `TestSendWithAttachmentDisabled` | attachment skipped when `REPORT_ATTACH=false` |
| `TestSendWithRetryError` | SMTP timeout retried 3× then fails gracefully |
| `TestSendReportWithAttachmentNotConfigured` | report sent without attachment when SMTP partially configured |

---

#### `test_push_notifiers.py` - 41 tests
**Covers:** `alerts/push_notifiers.py` - the ntfy / Telegram / Discord / webhook notifiers, the dispatcher fan-out, and the weekly-report digest formatter.

**Why it exists:** push notifications are the mobile alerting path that complements email. Each provider has a different request shape (ntfy headers, Telegram bot API, Discord embeds, generic webhook JSON), and a silent failure in any one would drop alerts for everyone using that channel. These tests stub the HTTP layer to pin each provider's payload, verify the dispatcher fans out to all enabled channels, and check that the weekly story / report text degrades to real stats rather than printing `?`.

| Class | What it validates |
|---|---|
| `TestNtfyNotifier` / `TestTelegramNotifier` / `TestDiscordNotifier` / `TestWebhookNotifier` | each provider builds the correct request, handles disabled/missing-config, and surfaces HTTP errors without raising |
| `TestDispatcherFanOut` | enabled channels all receive the alert; disabled channels skipped; one failing channel doesn't block the others |
| `TestFormatReportText` | digest prefers the weekly story → AI narrative → real summary stats; truncated to fit Telegram/Discord caps |

---

#### `test_plain_explanation.py` - 15 tests
**Covers:** `alerts/alert_service.py`, `database/db_manager.py` - plain-English alert explanations (AI-powered).

**Why it exists:** The "Explain in plain English" button is a flagship feature for non-technical users. Tests verify the LLM prompt is constructed correctly, the no-API-key fallback returns a reasonable message (not an error), and explanations are stored and retrieved correctly from the DB.

| Class | What it validates |
|---|---|
| `TestGeneratePlainExplanation` | Groq API called with correct prompt; response stored |
| `TestAlertDataclass` | alert fields present; severity maps to English label |
| `TestDbManagerPlainExplanation` | explanation stored and retrieved by alert ID |
| `TestAlertServicePassthrough` | `explain_alert` passes alert data to LLM helper correctly |

---

#### `test_alert_explainer.py` - 60 tests
**Covers:** `utils/alert_explainer.py`, all 9 exported functions: `clean_ai_text`, `source_label`, `source_badge_class`, `source_icon`, `build_prompt`, `parse_ai_text`, `rewrite_alert`, `persist`, `build_followup_prompt`.

**Why it exists:** `alert_explainer.py` is the single source of truth for AI provider labels, badge CSS, icon classes, prompt construction, response parsing, DB persistence, and ask-why chat grounding. These helpers are imported by five callback modules; a regression in any of them degrades the AI feature layer across the entire dashboard without an obvious error. This file gives every function 100% line coverage and tests the six boundary cases that have previously caused silent failures (None AI assistant, empty LLM text, exception mid-call, em-dash stripping, 500-char DB truncation, `source == 'rules'` fallback routing).

| Class | What it validates |
|---|---|
| `TestCleanAiText` | em-dash, en-dash, bold-marker stripping; None and empty-string safety |
| `TestSourceHelpers` | all 5 known keys → correct label/color/icon; unknown keys → fallback; None/empty safe |
| `TestBuildPrompt` | WHAT HAPPENED / WORRY LEVEL / TOP ACTION markers present; device/severity interpolated; `recs` sliced to 3 with `int(confidence*100)%` |
| `TestParseAiText` | all three section prefixes; worry-level `.`, `,`, ` - ` separators; fallback to tech_explanation; em-dashes stripped |
| `TestRewriteAlert` | None AI → None; empty text → None; exception → None; success → sections dict + `_source` |
| `TestPersist` | UPDATE writes `plain_explanation`, sets `plain_explanation_ai=1`, records `ai_source`; 500-char truncation; returns False on DB error |
| `TestBuildFollowupPrompt` | context contains device/severity/trigger; destinations and recs conditional; history bounded to last 4 non-system turns; question in prompt |

---

#### `test_ai_assistant.py` - 85 tests
**Covers:** `utils/ai_assistant.py`, the `HybridAIAssistant` 6-tier fallback engine: provider ordering, config-driven model names, per-provider health tracking, the TTL response cache, and the Anthropic/Gemini providers.

**Why it exists:** This module routes every AI request in the product and previously had zero coverage, which is how a decommissioned Groq model (`llama3-8b-8192`) silently killed the free cloud tier for weeks. These tests pin the default model IDs (a regression guard asserts the dead model can never return), the exact fallback order in both standard and privacy mode, and the failure-surfacing contract (WARNING once per provider per 10 minutes, health recorded for the admin panel). All providers are stubbed; no network calls.

| Class | What it validates |
|---|---|
| `TestAsBool` | string/bool/None parsing for env-coerced config values |
| `TestConstruction` | default models; `from_config` defaults, env precedence, broken-config safety |
| `TestModelNames` | configured model strings reach the OpenAI/Groq SDK calls |
| `TestAnthropicProvider` | `system=` param (never a system-role message); non-text blocks skipped; failure health |
| `TestGeminiProvider` | REST body shape; key in header never URL; safety-block and 429 fallthrough |
| `TestFallbackOrder` | full 6-tier order; privacy mode Ollama-first; rules last resort |
| `TestProviderHealth` | success/error recording; rate-limited WARNING; quiet Ollama ConnectionError |
| `TestStatusLevel` | ok / degraded / local-only matrix; recovery; stale errors ignored |
| `TestResponseCache` | hit/miss/TTL/eviction; history and rules never cached; thread-safety smoke |
| `TestStats` | cache_hits surfaced; reset; status message primary provider |

---

#### `test_ai_health.py` - 19 tests
**Covers:** `utils/ai_health.py`, the pure helpers behind the admin "AI Engine Health" card.

**Why it exists:** The health card is the user-facing window into provider failures (the fix for AI degrading silently to templates). The row-building logic is extracted from the Dash callback into a pure module precisely so these states, off / untested / ok / failing / recovered, can be unit-tested without a browser.

| Class | What it validates |
|---|---|
| `TestRelativeAge` | epoch → "just now"/"N minutes ago" buckets; future clamped |
| `TestBuildHealthRows` | provider ordering; all five states; error tooltips; rules row always ok |
| `TestBuildUsageLine` | request distribution sentence; cache-hit mention only when non-zero |

---

#### `test_cold_start.py` - 26 tests
**Covers:** `ml/inference_engine.py`, cold-start severity damping and baseline std-deviation sigma sentences.

**Why it exists:** New devices score against the global baseline and generate false positives until ~100 connections are learned, the worst first impression a security product can make. Damping lowers ML severities one level during the learning window (with a plain-English "still learning" note) while the threat-intel path is explicitly tested to never be damped. Sigma sentences ground spike claims in the device's learned variance instead of bare ratios.

| Class | What it validates |
|---|---|
| `TestIsLearningPeriod` | connection-count gate; first_seen gate; 10-min TTL cache; DB-error safety |
| `TestSeverityDamping` | damp map; learning note appended (no em dashes); malicious-IP alerts stay critical |
| `TestSigmaSentence` | 2-sigma threshold; zero-std guard; absolute deviation |
| `TestBaselineStats` | reads `device_behavior_baselines`; zero-std rows excluded; missing table safe |
| `TestSignalFiveSigma` | end-to-end sigma note on the bytes-spike sentence; absent without baseline or within range |

---

#### `test_device_baselines.py` - 8 tests
**Covers:** `get_device_baseline()` in `dashboard/shared.py` - reading the `device_behavior_baselines` table.

**Why it exists:** the baseline lookup feeds the cold-start sigma sentences and the device personality profiles. It must return `None` cleanly for a fresh device (no rows / insufficient data) and a correctly-mapped dict once rows exist - a wrong key mapping or an unhandled empty result would either crash the device view or invent baseline numbers.

| Class | What it validates |
|---|---|
| `TestGetDeviceBaseline` | `None` when no baseline rows exist; dict with `has_baseline=True` and correctly mapped keys when rows exist |

---

#### `test_weekly_story.py` - 33 tests
**Covers:** `utils/weekly_story.py`, `_facts_to_text`, `_template_fallback`, `generate_story`, `build_facts`.

**Why it exists:** The weekly story is one of the highest-value AI differentiators in the product. It had zero test coverage. Tests guard the mood-threshold logic, plural/singular grammar, bandwidth percentage maths, and the four LLM fallback paths, the last of which (source == 'rules' passthrough returning raw rule-based chat copy) was a subtle bug that tests would have caught immediately.

| Class | What it validates |
|---|---|
| `TestFactsToText` | bandwidth % calculation; conditional ai_exp / auto / busiest lines; MB format |
| `TestTemplateFallback` | mood thresholds (`<3` quiet, `<10` moderate, `≥10` busy); critical count note; new-device singular/plural; auto-actions and bandwidth paragraphs; closing monitoring sentence |
| `TestGenerateStory` | None / no-provider / source==rules / empty text / exception → template fallback; success path strips em-dashes and bold; always returns non-empty text |
| `TestBuildFacts` | alert counts with real DB rows; new_devices counter; graceful zero-default when `agent_actions` / `incidents` tables absent |

---

#### `test_device_personality.py` - 34 tests
**Covers:** `utils/device_personality.py`, the new Device Personality Profiles AI feature (2026-06-10). `_facts_to_text`, `_template_fallback`, `generate_personality`, `build_profile_facts`, `PERSONALITY_TTL`.

**Why it exists:** Device Personality Profiles is the v1.0.0 novel AI feature ("industry first"). The module follows the weekly-story pattern and has the same failure modes. Tests cover the complete fallback chain, em-dash/bold stripping, graceful DB degradation (missing baseline table, missing device row, no connections), and the TTL constant sanity check.

| Class | What it validates |
|---|---|
| `TestFactsToText` | device name / type / peak-hour range / today connections; no-baseline note; absent peak_hour_range omits the line; alert count formatting |
| `TestTemplateFallback` | device name/type included; zero-alert message; alert count; peak hours; typical destinations; monitoring sentence always present |
| `TestGeneratePersonality` | None / no-provider / source==rules / empty text / exception → template; success returns LLM text + source; em-dash and bold stripped; always returns something; `PERSONALITY_TTL > 0` |
| `TestBuildProfileFacts` | device_ip always set; device_name populated from DB; unknown IP falls back to IP string; has_baseline False with no rows / True with rows + correct `avg_connections`; today_connections counted; peak_hour_range None with no data / formatted string with data |

---

### Device intelligence and network

#### `test_ip_geolocator.py` - 14 tests
**Covers:** `utils/ip_geolocator.py` - batched, cached IP geolocation for the threat map and country-stats cards.

**Why it exists:** This module replaced 40 sequential ip-api.com requests per refresh (which hit the 45 req/min free-tier cap and produced read-timeout warnings) with one cached batch call. A caching bug would either re-introduce the rate-limit timeouts or silently serve stale geo data.

| Class | What it validates |
|---|---|
| `TestGeolocateIps` | one POST for N IPs, 24h success cache, 10min negative cache, timeout/HTTP-error/bad-JSON fallbacks, input de-dupe, 100-IP batch cap, expiry refetch |
| `TestGeolocateIp` | single-IP wrapper returns dict or None |

---

#### `test_name_resolver.py` - 30 tests
**Covers:** `utils/name_resolver.py` - 3-tier device name resolution (DNS → NetBIOS → manufacturer).

**Why it exists:** Device name resolution is the user-visible label for every device in the dashboard. Wrong names or crashes in resolution would show raw IPs or placeholder names. The three tiers need independent tests because each uses a different protocol.

| Class | What it validates |
|---|---|
| `TestIsSynthetic` | `None`, `""`, `Device-XXXXXX`, raw IPs → True; real names → False |
| `TestReverseDns` | PTR lookup returns hostname; timeout returns None; `.local` suffix stripped |
| `TestNetBiosResolve` | UDP reply parsed; group names ignored; timeout returns None |
| `TestManufacturerFallback` | `"Samsung Electronics"` + `smart_tv` → `"Samsung TV"`; 40+ brand/type pairs |
| `TestResolveName` | tier priority: DNS wins over NetBIOS; NetBIOS wins over manufacturer; all-miss returns synthetic |
| `TestCache` | second call returns cached result; cache respects TTL |

---

#### `test_smart_context.py` - 26 tests
**Covers:** `database/db_manager.py` - Smart Context rooms and automations tables.

**Why it exists:** `smart_home_rooms`, `device_room_assignments`, and `smart_home_automations` were added as new tables in 2026-06-02. New tables need full CRUD coverage from day one so regressions in the schema or query layer surface immediately.

| Class | What it validates |
|---|---|
| `TestRooms` | add, get (empty/populated/device-count), delete (row + cascade), duplicate name, nonexistent |
| `TestDeviceRoomAssignments` | add device to room, idempotent re-add, remove, get devices, get empty room |
| `TestAutomations` | save (returns ID, after insert, multiple, optional condition), delete (one/nonexistent/one-of-many), toggle (disable/re-enable) |
| `TestSchemaIdempotency` | double `CREATE TABLE IF NOT EXISTS` is safe; existing rows preserved across re-init |

---

### Integration and system tests

#### `test_integeration.py` - 9 tests
**Covers:** End-to-end data pipeline - Zeek → DB → ML → alerts.

**Why it exists:** Unit tests confirm each component works in isolation. Integration tests confirm they work together. The pipeline has three hand-offs where data format mismatches can occur silently: parser output → DB insert, DB record → feature extractor, prediction → alert creation.

| Class | What it validates |
|---|---|
| `TestZeekToDatabase` | parsed log row written to DB with correct fields |
| `TestDatabaseToMLPipeline` | DB connection row → feature vector → prediction stored |
| `TestEndToEndPipeline` | Zeek log → DB → ML → alert created (no data loss) |
| `TestPerformanceIntegration` | 100 connections processed in < 5 s |
| `TestDataConsistency` | connection and prediction IDs match across tables |
| `TestErrorRecovery` | malformed row at position N doesn't drop rows N+1 to end |

---

#### `test_pi_integration.py` - 14 tests
**Covers:** Pi-specific dependencies and performance targets.

**Why it exists:** The Pi is the target platform, but CI runs on x86. These tests verify Pi-specific assumptions - scapy packet handling, River ML memory usage, idle CPU target - so Pi-specific regressions surface in CI before reaching hardware.

| Class | What it validates |
|---|---|
| `TestPiRequirements` | all required packages importable; no version conflicts |
| `TestScapyIntegration` | scapy packet construction works; no root required for unit path |
| `TestRiverMLIntegration` | River HalfSpaceTrees fits in < 50 MB RSS |
| `TestDatabaseIntegration` | 1 000 rows written + queried in < 1 s on slow storage |
| `TestPerformance` | single-connection inference < 10 ms (Pi CPU budget) |
| `TestEndToEnd` | packet → feature → prediction round-trip completes |

---

#### `test_integration_tiering.py` - 15 tests
**Covers:** Integration tier system - which integrations are available at each tier.

**Why it exists:** Household users should not see enterprise integrations (Jira, PagerDuty, Splunk) and business users should not be blocked from them. The tier filter is applied at render time and at the API level.

| Class | What it validates |
|---|---|
| `TestIntegrationTierField` | every integration record has a `tier` field |
| `TestTierMembership` | household integrations are a strict subset of business |
| `TestTierFilteringLogic` | filter function returns correct set for each tier |
| `TestSetupWizardEssentialsOnly` | wizard step 3 shows only essentials (email, Groq, AbuseIPDB), never enterprise integrations |

---

#### `test_exports.py` - 2 tests
**Covers:** Data export smoke tests.

**Why it exists:** Smoke tests confirm the export endpoint initialises without error. Full export testing requires a browser session and is covered by manual testing.

---

### Capture mode and gateway (v1.0.0)

#### `test_mitre_helpers.py` - 10 tests
**Covers:** `dashboard/shared.py` `mitre_stage_from_tactic` and `mitre_tactic_from_explanation`.

**Why it exists:** the Attack Path Sankey was blank because alerts were matched against a tiny keyword map that never hit. These helpers reduce a persisted MITRE tactic (or one recovered from a legacy explanation) to a clean kill-chain stage, so the chart groups real stages. The tests cover every known tactic, the empty and unknown cases, and the helper composition.

#### `test_capture_mode_p1.py` - 17 tests
**Covers:** the capture-mode config, the Zeek interface-resolution precedence, `utils/network_monitor.uplink_ok`, and the orchestrator connectivity watchdog with auto-rollback.

**Why it exists:** gateway mode must never break the home Wi-Fi. These tests pin the passive default, the interface precedence (monitor over ap over home), the uplink probe (including the 0 percent loss regression that previously read as down), and the watchdog rolling the access point back when the uplink drops.

#### `test_gateway_ap_p2.py` - 17 tests
**Covers:** `config/configure_ap.sh`, `utils/ap_manager.py`, the orchestrator access-point wiring, and the gateway-aware firewall failsafe.

**Why it exists:** the access-point script must only start in gateway mode with a strong password and never touch the home Wi-Fi; the firewall must keep IoT devices blockable while protecting the access-point gateway. The tests prove the script safety, the manager start and stop paths, the immediate uplink check after bring-up, and that the failsafe whitelist makes the IoT subnet enforceable.

#### `test_gateway_hardening_p3.py` - 10 tests
**Covers:** the wizard access-point picker, `scripts/validate_gateway.sh`, the privileged nft and iptables wrapper, the sudoers grants, and systemd ordering.

**Why it exists:** inline enforcement runs as a non-root service, so nft and iptables must be elevated. These tests pin the sudo wrapper (and the no-sudo-as-root path), the validation script checks, the dongle picker persistence, and the provisioning and service-ordering guarantees.

## Coverage notes

The 25% overall coverage figure is misleading in isolation. The 13 Dash callback files (`dashboard/callbacks/callbacks_*.py`) account for ~10,250 lines and show 0% coverage - not because they're untested, but because they are Dash callback functions that register handlers at import time and execute only in response to browser events. They cannot be exercised by pytest without a running Dash server and browser automation.

The coverage that matters is on the importable, pure-Python modules:

| Module | Coverage | Notes |
|---|---|---|
| `utils/alert_explainer.py` | **100%** | AI provider labels, prompt build, parse, persist, ask-why grounding |
| `utils/ai_health.py` | **100%** | health-row builder behind the admin AI Engine Health card |
| `utils/weekly_story.py` | **94%** | Uncovered: a couple of LLM-error branches |
| `utils/device_personality.py` | **88%** | Uncovered: rare DB-degradation branches |
| `utils/ai_assistant.py` | **83%** | Uncovered: live-network provider calls (all stubbed in tests) |
| `ml/feature_extractor.py` | **81%** | Uncovered: Plotly figure helper (render-only, no logic) |
| `utils/name_resolver.py` | **79%** | Uncovered: socket timeout edge cases on unusual OS configs |
| `alerts/alert_service.py` | **78%** | Uncovered: LLM streaming path (requires live API key) |
| `alerts/email_notifier.py` | **73%** | Uncovered: full SMTP TLS session (requires live SMTP server) |
| `database/db_manager.py` | **72%** | Uncovered: connection pool teardown, vacuum on very large DBs |
| `config/config_manager.py` | **69%** | Uncovered: env-var fallback chain for absent `.env` |
| `capture/zeek_log_parser.py` | **68%** | Uncovered lines: rare error paths in malformed binary headers |

The Dash callbacks are verified through:
1. **Layout structure tests** - required component IDs are present (prevents wiring bugs)
2. **Extracted logic tests** - pure-Python functions extracted from callbacks are unit-tested
3. **Manual browser testing** - wizard, login, dashboard flows tested via Playwright screenshots
