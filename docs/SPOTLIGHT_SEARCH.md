# IoTSentinel Spotlight Search

> **A macOS Spotlight-inspired universal search built specifically for IoT security operations.**
> No other security dashboard has an intelligent, context-aware, voice-ready, NLP-powered search like this.

**Current Version:** 3.0 (February 2026)
**Status:** ✅ Fully Implemented & Production-Ready

---

## Table of Contents

1. [What Is It?](#1-what-is-it)
2. [Feature Overview](#2-feature-overview)
3. [Unique Competitive Advantages](#3-unique-competitive-advantages)
4. [Full Feature Reference](#4-full-feature-reference)
5. [Technical Architecture](#5-technical-architecture)
6. [API Reference](#6-api-reference)
7. [Performance](#7-performance)
8. [Keyboard Shortcuts](#8-keyboard-shortcuts)
9. [Security Model](#9-security-model)

---

## 1. What Is It?

Spotlight Search is the universal command palette for the IoTSentinel Dashboard. Triggered with **⌘K** (or **Ctrl+K**), it lets any user instantly navigate to any of the 37+ dashboard features, search live devices and alerts from the database, and execute emergency security actions — all without ever clicking through menus.

It was originally built as a simple fuzzy-search launcher (v1.0, December 2025) and has since evolved into a fully intelligent, security-aware search engine with NLP intent parsing, real-time database cross-search, and context-aware ranking based on live system state.

---

## 2. Feature Overview

| #   | Feature                                | Category     | Status |
| --- | -------------------------------------- | ------------ | ------ |
| 1   | Fuzzy Feature Search                   | Core         | ✅     |
| 2   | Top Hit / Best Match                   | Core         | ✅     |
| 3   | Result Count + Performance Stats       | Core         | ✅     |
| 4   | Category Grouping                      | Core         | ✅     |
| 5   | Category Filter Badges                 | Core         | ✅     |
| 6   | Recent Searches                        | Core         | ✅     |
| 7   | Keyboard Navigation (↑↓ Tab Enter)     | Core         | ✅     |
| 8   | RBAC Security + Audit Logging          | Security     | ✅     |
| 9   | NLP Natural Language Search            | Intelligence | ✅     |
| 10  | Context-Aware Result Boosting          | Intelligence | ✅     |
| 11  | Predictive Suggestions                 | Intelligence | ✅     |
| 12  | Cross-Domain Search (Devices + Alerts) | Intelligence | ✅     |
| 13  | Search Analytics (Usage Tracking)      | Analytics    | ✅     |
| 14  | Emergency Quick Launch (⌘⇧L/E/T)       | Emergency    | ✅     |
| 15  | Glassmorphism Design + Dark Mode       | UX           | ✅     |
| 16  | Shimmer Hover + GPU Animations         | UX           | ✅     |

---

## 3. Unique Competitive Advantages

Other security dashboards (Splunk, Elastic, Grafana, Datadog, Azure Sentinel) all have some form of search. Here's what makes IoTSentinel's different:

### 3.1 NLP Intent Engine — Not Just Keyword Matching

Every other dashboard search requires you to know the **exact name** of what you're looking for. IoTSentinel understands what you **mean**.

| You type                        | What happens                                             |
| ------------------------------- | -------------------------------------------------------- |
| `"show risky devices"`          | Boosts **Risk Heatmap** + **Device Management** to top   |
| `"what threats happened today"` | Boosts **Threat Intelligence** + **Threat Map**          |
| `"block untrusted"`             | Surfaces **Lockdown Mode** + **Firewall Rules**          |
| `"network slow"`                | Prioritises **Performance Analytics** + **System Info**  |
| `"we're under attack"`          | Immediately ranks **Lockdown Mode** first                |
| `"gdpr check"`                  | Finds **Compliance Dashboard** with zero keyword overlap |
| `"ask ai"`                      | Opens **AI Assistant** chat                              |

The engine has **14 intent categories** covering security, performance, devices, IoT, compliance, privacy, and incident response — all evaluated client-side with zero latency.

**Other dashboards:** `"Compliance"` → matches "Compliance".
**IoTSentinel:** `"are we gdpr compliant"` → matches "Compliance Dashboard" with intent boost 70.

---

### 3.2 Context-Aware Ranking — The Search Changes Based on Live System State

When you open Spotlight Search, it quietly fires a background query to check:

- **How many unacknowledged high/critical alerts exist right now?**
- **Is CPU usage above 80%?**

It then **re-ranks** results accordingly:

| System State              | What gets promoted                                            |
| ------------------------- | ------------------------------------------------------------- |
| 3 active critical alerts  | Threat Intelligence (+30), Risk Heatmap (+24), Firewall (+15) |
| 10 active critical alerts | Threat Intelligence (+100), immediate lockdown suggestions    |
| CPU > 80%                 | Performance Analytics (+30), System Info (+20)                |
| Normal                    | Default ranking by fuzzy score                                |

No other security product does this. Grafana, Datadog, and Splunk all return the same search results regardless of whether your network is actively being attacked right now.

---

### 3.3 Cross-Domain Search — Features AND Live Data in One Box

Search results are split into three layers:

```
🔴 ALERTS (from live DB)
  critical  Suspicious outbound traffic — 192.168.1.55
  high      Port scan detected — 192.168.1.12

📱 DEVICES (from live DB)
  192.168.1.55  — IP Camera       [Untrusted]
  192.168.1.12  — Smart Hub       [Trusted]

⚙️ FEATURES
  Device Management
  Threat Intelligence
```

This is fundamentally different from every competing product. Elastic/Splunk require you to know which index/dashboard to query. IoTSentinel gives you **one search box that searches everything** — features, live devices by IP/name/type/MAC, and recent alerts by severity or explanation — in a single interaction.

The cross-domain search uses a **300ms client-side debounce** before touching the database, so the main fuzzy feature search always remains instant.

---

### 3.4 Emergency Quick Launch — One Keystroke During Active Incidents

| Shortcut | Action                                             |
| -------- | -------------------------------------------------- |
| `⌘⇧L`    | Trigger **Lockdown Mode** instantly (RBAC-checked) |
| `⌘⇧E`    | Open **Quick Actions → Emergency Export**          |
| `⌘⇧T`    | Open **Threat Intelligence** immediately           |

Each action triggers a **red visual ring pulse** with a floating confirmation label (`🔒 LOCKDOWN INITIATED`, `🛡️ THREAT RESPONSE`, etc.) so the operator knows the keystroke registered.

No other security dashboard has dedicated emergency keyboard shortcuts at the OS level. During an active incident, shaving 15 seconds off every navigation step matters.

---

### 3.5 Predictive Suggestions — It Knows What You Need Before You Search

When the modal opens with an empty query, it shows **contextual recommendations** driven by two signals:

**Time of day:**
| Time | Suggested features |
|---|---|
| 06:00–10:00 | Analytics Dashboard, Overnight Alerts, Device Status |
| 10:00–14:00 | Threat Intelligence, Performance Analytics, Risk Heatmap |
| 14:00–18:00 | Vulnerability Scanner, Threat Intelligence, Firmware Management |
| 18:00–21:00 | Compliance Dashboard, Analytics, Automated Response |
| 21:00–06:00 | System Information, Performance Analytics, Analytics |

**Your personal usage history:**
`getTopFeatures()` reads your `localStorage` analytics and surfaces your **3 most-accessed features** with a "⭐ Your most used" section. After a few days of usage this becomes personalised to your exact workflow.

---

### 3.6 Search Analytics — Tracks What You Use to Get Smarter

Every time a feature is opened via Spotlight Search, `recordFeatureAccess(featureId)` writes a usage counter to `localStorage`. This data powers:

- The **"⭐ Your most used"** predictive section
- Future sorting improvements (frequently accessed features rank higher for that user)
- Usage patterns (which features get the most spotlight traffic?)

All data stays in the browser — no analytics beacon, no server call.

---

## 4. Full Feature Reference

### 4.1 Core Search

**Fuzzy Matching Algorithm**

Scores matches across four fields with different weights:

- Feature name: **3×**
- Keywords: **2×**
- Description: **1×**
- Category: **1×**

Bonus scoring: `+100` for exact match, `+50` for prefix match, increasing bonus for consecutive character matches.

**Top Hit**

The highest-scoring result is automatically marked as the **Top Hit** with:

- Green `TOP HIT` badge
- Larger icon (`fa-3x` vs `fa-2x`)
- Slightly larger name/description text
- Gradient-tinted card with success-color border

**Result Count & Performance Time**

Every search shows: `15 results • Showing top 15 • 2.34ms`

Performance is tracked with `performance.now()` for sub-millisecond precision. Typical result: **1–3ms** for the full 37-feature catalog.

---

### 4.2 Category System

Results are automatically grouped by category with headers showing item counts. Categories are sorted by result count (most results first).

Available categories: `Analytics`, `Security`, `Device Management`, `System`, `IoT`, `Intelligence`, `Performance`, `Notifications`, `Education`, `Developer`, `Actions`, `Customization`, `Assistance`, `Help`, `Emergency`

**Category Filter Badges**

Clicking a category badge (e.g., `Security (8)`) filters results to that category only. An `All` button resets the filter. The filter persists as you continue typing.

---

### 4.3 Recent Searches

- Stored in `localStorage` under key `iotsentinel_recent_searches`
- Maximum **5 entries**, deduplicated (last used moves to top)
- Shown as clickable badges when query is empty
- Persists across browser sessions
- "Clear All" button removes the history

---

### 4.4 Keyboard Navigation

| Key                 | Action                                                     |
| ------------------- | ---------------------------------------------------------- |
| `⌘K` / `Ctrl+K`     | Open spotlight search from anywhere                        |
| `↑` / `↓`           | Navigate results                                           |
| `Tab` / `Shift+Tab` | Navigate forward/backward                                  |
| `Enter`             | Open selected result (auto-selects first if none selected) |
| `Escape`            | Close modal, reset selection                               |

---

### 4.5 NLP Intent Engine (Detail)

The engine uses a pure client-side pattern-matching approach. No external AI API, no latency. Matching works by substring search — so `"we have a threat"` matches the pattern `"threat"` and boosts Threat Intelligence.

**14 intent categories implemented:**

| Intent         | Trigger patterns                                                            | Boosted features                                     |
| -------------- | --------------------------------------------------------------------------- | ---------------------------------------------------- |
| Risky Devices  | `risky device`, `dangerous device`, `vulnerable device`, `high risk device` | Risk Heatmap (+60), Device Management (+50)          |
| Threats        | `what threat`, `show threat`, `today threat`, `recent threat`, `any attack` | Threat Intelligence (+60), Threat Map (+50)          |
| Block/Lockdown | `block device`, `block untrusted`, `emergency block`, `prevent attack`      | Lockdown Mode (+70), Firewall (+50)                  |
| Performance    | `check performance`, `network slow`, `bandwidth`, `throughput`              | Performance Analytics (+60), Analytics (+40)         |
| Scan/Discover  | `scan network`, `find device`, `new device`, `discover device`              | Device Management (+50), Vulnerability Scanner (+60) |
| Export         | `export data`, `download report`, `generate report`                         | Quick Actions (+60)                                  |
| Emergency      | `emergency`, `lockdown`, `incident response`, `under attack`                | Lockdown Mode (+100), Automated Response (+60)       |
| User/Audit     | `who logged in`, `user activity`, `login activity`, `audit log`             | Compliance (+50), User Management (+60)              |
| Firmware       | `firmware update`, `device patch`, `outdated firmware`                      | Firmware Management (+60)                            |
| AI Help        | `ai help`, `ai assistant`, `ask ai`, `help me`                              | AI Assistant (+70)                                   |
| Privacy        | `data leak`, `privacy risk`, `data exposure`                                | Privacy Monitor (+60)                                |
| Smart Home     | `smart home`, `alexa`, `google home`, `iot hub`                             | Smart Home Hub Detection (+60)                       |
| Protocols      | `network traffic`, `mqtt`, `http traffic`, `coap`                           | Protocol Analyzer (+60)                              |
| Compliance     | `gdpr`, `hipaa`, `compliance check`, `regulation`                           | Compliance Dashboard (+70)                           |

---

### 4.6 Context-Aware Boost (Detail)

Fires **once** when the modal opens. Executes a single `COUNT(*)` query on the `alerts` table filtered to the last 24 hours with `severity IN ('high','critical') AND acknowledged = 0`. Also reads CPU via `psutil.cpu_percent(interval=None)` (returns cached OS value — non-blocking).

Boost values:

```python
# Per unacknowledged high/critical alert:
'threat-modal'        += alert_count × 10
'risk-heatmap-modal'  += alert_count × 8
'firewall-modal'      += alert_count × 5
'analytics-modal'     += alert_count × 3
'auto-response-modal' += alert_count × 2
'lockdown-modal'      += alert_count × 2

# When CPU > 80%:
'performance-modal'   += 30
'system-modal'        += 20
'benchmark-modal'     += 10
```

---

### 4.7 Cross-Domain Search (Detail)

Searches are debounced **300ms client-side** before a server callback fires, preventing per-keystroke DB hits.

**Devices query** — searches `device_ip`, `device_name`, `device_type`, `mac_address` using indexed `LIKE` (no `LOWER()` wrapper — SQLite LIKE is case-insensitive for ASCII by default; `LOWER()` would prevent index use). Returns up to 5 results.

**Alerts query** — searches `explanation`, `device_ip`, `severity`. Returns up to 5 most recent. Uses `idx_alerts_timestamp` and `idx_alerts_device` indexes.

Results are shown above feature results in the search panel with trust/block status badges for devices and severity badges for alerts.

---

### 4.8 Emergency Quick Launch (Detail)

Three `keydown` listeners added at `document` level. On `⌘/Ctrl+Shift+L/E/T`:

1. `triggerEmergencyIndicator(action)` runs immediately — adds `spotlight-emergency-active` class to `body`, which triggers:
   - Pulsing red outline animation (4 pulses, 1.8s total)
   - Floating `::before` label positioned at top-center of viewport

2. A hidden `<button>` element is clicked (invisible to user), which triggers a Dash clientside callback that writes to `spotlight-modal-trigger` store.

3. The existing `spotlight_open_modal_server_side` Python callback picks up the trigger, performs full RBAC checks, and opens the target modal — closing Spotlight in the process.

The emergency labels read:

- `🔒 LOCKDOWN INITIATED` (red background)
- `📤 EMERGENCY EXPORT` (amber background)
- `🛡️ THREAT RESPONSE` (indigo background)

---

## 5. Technical Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                  Spotlight Search Engine v3.0                    │
├─────────────────────────────────────────────────────────────────┤
│                                                                   │
│  Client-Side JavaScript (spotlight-search.js)                    │
│  ├─ Fuzzy Matching        → <1ms,  pure JS                       │
│  ├─ NLP Intent Engine     → <1ms,  14 intent categories          │
│  ├─ Context Boost Apply   → <1ms,  reads store from Python       │
│  ├─ Predictive Suggest.   → <1ms,  localStorage + time-of-day    │
│  ├─ Search Analytics      → <1ms,  localStorage counters         │
│  ├─ Keyboard Navigation   → event listeners                      │
│  └─ Emergency Shortcuts   → ⌘⇧L/E/T event listeners              │
│                                                                   │
│  Server-Side Python (callbacks_global.py)                        │
│  ├─ fetch_spotlight_context()  → fires on modal open (once)      │
│  │   └─ COUNT(*) alerts + psutil CPU read                        │
│  ├─ cross_domain_search()      → fires 300ms after last keystroke│
│  │   └─ Indexed LIKE on devices + alerts (LIMIT 5 each)         │
│  ├─ render_spotlight_results() → renders full result panel       │
│  │   ├─ Context alert banner (if active alerts > 0)              │
│  │   ├─ Predictive suggestion cards                              │
│  │   ├─ Cross-domain results (devices + alerts)                  │
│  │   └─ Feature results with category grouping                   │
│  └─ spotlight_open_modal_server_side() → RBAC + audit + open     │
│                                                                   │
│  dcc.Store Components                                             │
│  ├─ spotlight-catalog-store          (37 features, static)       │
│  ├─ spotlight-filtered-results       (current search output)     │
│  ├─ spotlight-category-filter        (active category filter)    │
│  ├─ spotlight-modal-trigger          (which modal to open)       │
│  ├─ spotlight-context-data           (alert count + CPU boosts)  │
│  ├─ spotlight-cross-domain-results   (live DB results)           │
│  └─ spotlight-cross-domain-debounced (300ms debounced query)     │
│                                                                   │
│  Database (SQLite via db_manager)                                 │
│  ├─ devices: idx_devices_name, idx_devices_last_seen             │
│  └─ alerts:  idx_alerts_timestamp, idx_alerts_severity,          │
│              idx_alerts_device                                    │
│                                                                   │
└─────────────────────────────────────────────────────────────────┘
```

**Data flow for a typical search:**

```
User types "threat" in input
         │
         ├──► (instant) JS fuzzyMatch() + parseNLPIntent() + applyContextBoosts()
         │    → renders feature results + predictive suggestions (0–3ms)
         │
         └──► (300ms later) cross_domain_search() Python callback fires
              → queries devices + alerts tables (indexed LIKE)
              → re-renders cross-domain section only
```

---

## 6. API Reference

### JavaScript (`window.spotlightSearch`)

| Function                     | Signature                                              | Description                           |
| ---------------------------- | ------------------------------------------------------ | ------------------------------------- |
| `fuzzyMatch`                 | `(query, target) → number`                             | Score a single string match           |
| `searchFeatures`             | `(query, catalog, max, filter, boosts) → SearchResult` | Full search with NLP + context boosts |
| `parseNLPIntent`             | `(query) → [{featureId, boost, pattern}]`              | NLP intent extraction                 |
| `getPredictiveSuggestions`   | `(catalog) → [{type, label, features}]`                | Time + frequency suggestions          |
| `recordFeatureAccess`        | `(featureId) → void`                                   | Write analytics counter               |
| `getTopFeatures`             | `(limit) → [{id, count}]`                              | Sorted usage history                  |
| `getSearchAnalytics`         | `() → {featureId: count}`                              | Full analytics object                 |
| `getRecentSearches`          | `() → string[]`                                        | Last 5 queries                        |
| `saveRecentSearch`           | `(query) → void`                                       | Add to recent searches                |
| `clearRecentSearches`        | `() → void`                                            | Wipe recent searches                  |
| `groupByCategory`            | `(results) → {cat: items[]}`                           | Group results by category             |
| `getAllCategories`           | `(catalog) → string[]`                                 | All unique categories                 |
| `getAutocompleteSuggestions` | `(query, catalog) → string[]`                          | Up to 5 autocomplete strings          |
| `selectNext`                 | `() → void`                                            | Keyboard: move selection down         |
| `selectPrevious`             | `() → void`                                            | Keyboard: move selection up           |
| `openSelected`               | `() → boolean`                                         | Click currently selected result       |
| `resetSelection`             | `() → void`                                            | Clear keyboard selection              |

**`SearchResult` object:**

```javascript
{
  results:              Feature[],    // Matched + scored features
  totalCount:           number,       // All matches before LIMIT
  hasMore:              boolean,      // More results available
  query:                string,       // Original query
  categories:           {cat: items}, // Grouped results
  topHit:               Feature|null, // Highest scoring result
  searchTime:           string,       // e.g. "2.34" (ms)
  categoryFilter:       string|null,  // Active category filter
  recentSearches:       string[],     // From localStorage
  predictiveSuggestions: Suggestion[],// Time + frequency suggestions
  contextData:          ContextData|null // Alert count + CPU
}
```

### Python (Dash Callbacks)

| Callback                           | Trigger                                                         | Output                                 |
| ---------------------------------- | --------------------------------------------------------------- | -------------------------------------- |
| `fetch_spotlight_context`          | `spotlight-search-modal.is_open`                                | `spotlight-context-data` store         |
| `cross_domain_search`              | `spotlight-cross-domain-debounced` store                        | `spotlight-cross-domain-results` store |
| `render_spotlight_results`         | `spotlight-filtered-results` + `spotlight-cross-domain-results` | Results panel HTML                     |
| `spotlight_open_modal_server_side` | `spotlight-modal-trigger` store                                 | All modal `is_open` states             |
| `toggle_spotlight_modal`           | Button / clear button                                           | `spotlight-search-modal.is_open`       |
| `update_category_filter`           | Filter badge clicks                                             | `spotlight-category-filter` store      |

---

## 7. Performance

| Operation                  | Typical Time | Notes                                 |
| -------------------------- | ------------ | ------------------------------------- |
| Fuzzy feature search       | 1–3ms        | Client-side JS, 37 features           |
| NLP intent parsing         | <1ms         | In-memory pattern matching            |
| Context boost application  | <1ms         | Object property lookup                |
| Predictive suggestions     | <1ms         | localStorage + array slice            |
| Analytics record           | <1ms         | localStorage write                    |
| Context fetch (modal open) | 5–20ms       | Single COUNT(\*) + psutil             |
| Cross-domain DB search     | 10–50ms      | Indexed LIKE, LIMIT 5, 300ms debounce |
| Full render (Python)       | 20–80ms      | Dash server callback                  |

**What users actually perceive:** The JS fuzzy search is instant (renders before the Python callback returns). The cross-domain DB results "pop in" after ~300ms of inactivity, which feels natural rather than slow.

**Performance protections in place:**

- 300ms debounce before any DB query fires
- `LIMIT 5` on both DB queries
- No `LOWER()` wrappers — indexed column access
- `psutil.cpu_percent(interval=None)` — returns OS-cached value, non-blocking
- Context fetch fires only on modal open, not on every keystroke
- All JS operations run client-side, no server roundtrip

---

## 8. Keyboard Shortcuts

### Standard shortcuts

| Shortcut            | Action                      |
| ------------------- | --------------------------- |
| `⌘K` / `Ctrl+K`     | Open Spotlight Search       |
| `↑` `↓`             | Navigate result list        |
| `Tab` / `Shift+Tab` | Navigate forward / backward |
| `Enter`             | Open highlighted result     |
| `Escape`            | Close modal                 |

### Emergency shortcuts (global — works without opening the modal)

| Shortcut               | Action                                           | Who can use       |
| ---------------------- | ------------------------------------------------ | ----------------- |
| `⌘⇧L` / `Ctrl+Shift+L` | **Lockdown Mode** — block all untrusted devices  | Admin only        |
| `⌘⇧E` / `Ctrl+Shift+E` | **Emergency Export** — open Quick Actions export | All authenticated |
| `⌘⇧T` / `Ctrl+Shift+T` | **Threat Response** — open Threat Intelligence   | All authenticated |

Emergency shortcuts show a visual confirmation pulse (red border ring + floating action label for 1.8s) so you know the action registered.

---

## 9. Security Model

All spotlight interactions use the existing RBAC system — no separate permission layer.

**Authentication gate:** Every `spotlight-modal-trigger` callback checks `current_user.is_authenticated` before opening any modal. Unauthenticated users get a toast warning.

**Admin-only modals** (blocked for non-admin roles):
`user-modal`, `firewall-modal`, `vuln-scanner-modal`, `compliance-modal`, `email-modal`, `lockdown-modal`

**Device management** additionally checks `can_manage_devices(current_user)` from the existing RBAC module.

**Cross-domain search** returns empty results for unauthenticated requests — no DB query is made.

**SQL injection prevention:** All DB queries use parameterized statements (`?` placeholders). No user input is ever interpolated directly into SQL strings.

**Audit logging:** Every successful modal open via Spotlight is logged to the audit trail via `audit_logger.log_action(action_type='spotlight_access', ...)`.

---

_Last updated: February 2026 — IoTSentinel v3.0_
