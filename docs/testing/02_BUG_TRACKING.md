# Bug Tracking Log - IoTSentinel

**Project**: IoTSentinel Network Security Monitor
**Purpose**: Document defects found during development and testing
**Last Updated**: December 2024

---

## Bug Summary Statistics

| Status    | Count  |
| --------- | ------ |
| Fixed     | 12     |
| Open      | 0      |
| Won't Fix | 0      |
| **Total** | **12** |

---

## Critical Bugs (Severity: High/Critical)

### BUG-001: Database Foreign Key Constraint Violation

- **Severity**: Critical
- **Status**: Fixed
- **Found By**: Integration testing (TC-INT-008)
- **Date Found**: November 2024
- **Component**: database/db_manager.py

**Description**: When adding a connection for a non-existent device, the system crashed with SQLite foreign key constraint error.

**Expected Behavior**: System should auto-create device record if it doesn't exist.

**Actual Behavior**:

```
sqlite3.IntegrityError: FOREIGN KEY constraint failed
```

**Root Cause**: `add_connection()` method didn't check for device existence before insertion.

**Fix Applied**:

```python
# Before (database/db_manager.py:215)
cursor.execute('INSERT INTO connections ...')

# After (database/db_manager.py:215)
# Auto-create device if it doesn't exist
self.add_device(device_ip=device_ip, device_name=f"Unknown ({device_ip})")
cursor.execute('INSERT INTO connections ...')
```

**Test Case Added**: TC-DB-008 (`test_add_connection_creates_device`)

**Verification**: ✅ Fixed and verified by test suite

---

### BUG-002: ML Model File Not Found Crash

- **Severity**: High
- **Status**: Fixed
- **Found By**: Error scenario testing (TC-ERR-003)
- **Date Found**: November 2024
- **Component**: ml/inference_engine.py

**Description**: Inference engine crashed on startup when ML model files were missing.

**Expected Behavior**: Gracefully handle missing models, log warning, continue without ML inference.

**Actual Behavior**:

```
FileNotFoundError: [Errno 2] No such file or directory: 'data/models/river_engine.pkl'
```

> **Resolution**: Migrate to River ML - model created automatically on first run

````

**Root Cause**: No file existence check before loading models.

**Fix Applied**:
```python
# ml/inference_engine.py:45
try:
    self.if_model = joblib.load(if_model_path)
except FileNotFoundError:
    self.logger.warning(f"Model not found: {if_model_path}. Running without ML.")
    self.if_model = None
````

**Test Case Added**: TC-INT-010 (`test_inference_handles_missing_model_gracefully`)

**Verification**: ✅ Fixed and verified

---

### BUG-003: AbuseIPDB API Key Environment Variable Mismatch

- **Severity**: High
- **Status**: Fixed
- **Found By**: API integration testing (TC-API-001)
- **Date Found**: December 2024
- **Component**: dashboard/app.py

**Description**: API Integration Hub showed AbuseIPDB as "Not Configured" despite valid API key in .env file.

**Expected Behavior**: Detect API key from `THREAT_INTELLIGENCE_ABUSEIPDB_API_KEY` environment variable.

**Actual Behavior**: Dashboard looked for wrong variable name, showed "Not Configured".

**Root Cause**: Code checked `config.get('threat_intel', 'abuseipdb_key')` instead of `os.getenv('THREAT_INTELLIGENCE_ABUSEIPDB_API_KEY')`.

**Fix Applied**:

```python
# dashboard/app.py:9820
# Before
abuseipdb_key = config.get('threat_intel', 'abuseipdb_key')

# After
abuseipdb_key = os.getenv('THREAT_INTELLIGENCE_ABUSEIPDB_API_KEY') or os.getenv('ABUSEIPDB_API_KEY')
```

**Test Case Added**: TC-API-001 (`test_abuseipdb_configured`)

**Verification**: ✅ Fixed and verified

---

## Medium Severity Bugs

### BUG-004: Zeek Log Parser Crashes on Corrupt JSON

- **Severity**: Medium
- **Status**: Fixed
- **Found By**: Capture module testing (TC-CAP-003)
- **Date Found**: November 2024
- **Component**: capture/zeek_log_parser.py

**Description**: Parser crashed when encountering malformed JSON in Zeek logs.

**Expected Behavior**: Skip corrupt entries, continue parsing valid entries, log warning.

**Actual Behavior**: Entire parsing process halted with `json.JSONDecodeError`.

**Root Cause**: No try-catch around JSON parsing.

**Fix Applied**:

```python
# capture/zeek_log_parser.py:87
try:
    conn_data = json.loads(line)
except json.JSONDecodeError:
    logger.warning(f"Skipping corrupt log entry: {line[:100]}")
    continue
```

**Test Case Added**: TC-CAP-003 (`test_handle_corrupt_log_entry`)

**Verification**: ✅ Fixed and verified

---

### BUG-005: Division by Zero in Feature Extraction

- **Severity**: Medium
- **Status**: Fixed
- **Found By**: ML testing (TC-ML-018)
- **Date Found**: November 2024
- **Component**: ml/feature_extractor.py

**Description**: Feature extractor crashed when connection duration was 0.

**Expected Behavior**: Handle zero duration gracefully, use default value.

**Actual Behavior**: `ZeroDivisionError` when calculating bytes_per_second.

**Root Cause**: `bytes_per_second = total_bytes / duration` without zero check.

**Fix Applied**:

```python
# ml/feature_extractor.py:125
bytes_per_second = total_bytes / duration if duration > 0 else 0
```

**Test Case Added**: TC-ML-018 (`test_zero_duration_connection`)

**Verification**: ✅ Fixed and verified

---

### BUG-006: Alert Severity Validation Missing

- **Severity**: Medium
- **Status**: Fixed
- **Found By**: Database testing (TC-DB-015)
- **Date Found**: November 2024
- **Component**: database/db_manager.py

**Description**: System accepted invalid alert severity levels (e.g., "ultra-high").

**Expected Behavior**: Only accept ['low', 'medium', 'high', 'critical'].

**Actual Behavior**: Any string accepted, causing display issues.

**Root Cause**: No severity validation before database insertion.

**Fix Applied**:

```python
# database/db_manager.py:185
VALID_SEVERITIES = ['low', 'medium', 'high', 'critical']
if severity not in VALID_SEVERITIES:
    raise ValueError(f"Invalid severity: {severity}")
```

**Test Case Added**: TC-DB-015 (`test_create_alert_with_invalid_severity_fails`)

**Verification**: ✅ Fixed and verified

---

### BUG-007: Memory Leak in Long-Running Inference

- **Severity**: Medium
- **Status**: Fixed
- **Found By**: System testing (manual)
- **Date Found**: December 2024
- **Component**: ml/inference_engine.py

**Description**: Memory usage grew unbounded during continuous operation.

**Expected Behavior**: Stable memory usage over time.

**Actual Behavior**: Memory increased 500MB over 24 hours.

**Root Cause**: Processed connection IDs stored in memory without cleanup.

**Fix Applied**:

```python
# ml/inference_engine.py:180
# Clear old processed IDs (keep only last 1000)
if len(self.processed_ids) > 1000:
    self.processed_ids = self.processed_ids[-1000:]
```

**Test Case Added**: Manual long-running test (documented in TEST_PLAN.md)

**Verification**: ✅ Fixed, memory stable after 48-hour test

---

## Low Severity Bugs

### BUG-008: Dashboard Theme Not Persisting

- **Severity**: Low
- **Status**: Fixed
- **Found By**: User testing
- **Date Found**: December 2024
- **Component**: dashboard/assets/theme-toggle.js

**Description**: Dark mode preference not saved between sessions.

**Expected Behavior**: Theme choice persists in localStorage.

**Actual Behavior**: Always reverted to light mode on page reload.

**Root Cause**: localStorage key mismatch (`theme` vs `iotsentinel-theme`).

**Fix Applied**:

```javascript
// dashboard/assets/theme-toggle.js:10
const savedTheme = localStorage.getItem("iotsentinel-theme") || "light";
```

**Test Case Added**: Manual testing (dashboard feature tested in TC-DASH-025)

**Verification**: ✅ Fixed and verified

---

### BUG-009: AlienVault OTX API Endpoint 403 Error

- **Severity**: Low
- **Status**: Fixed
- **Found By**: API integration testing (TC-API-005)
- **Date Found**: December 2024
- **Component**: dashboard/app.py

**Description**: AlienVault OTX showed as "Connection Failed" with valid API key.

**Expected Behavior**: Show "Connected" with valid API key.

**Actual Behavior**: 403 Forbidden error from API endpoint.

**Root Cause**: API endpoint `/api/v1/pulses/subscribed` doesn't work for new accounts without subscriptions.

**Fix Applied**:

```python
# dashboard/app.py:9890
# Changed endpoint from:
url = 'https://otx.alienvault.com/api/v1/pulses/subscribed'
# To:
url = 'https://otx.alienvault.com/api/v1/indicators/IPv4/8.8.8.8/general'
```

**Test Case Added**: TC-API-INT-002 (`test_otx_real_connection`)

**Verification**: ✅ Fixed and verified

---

### BUG-010: Customizable Widget Dashboard Not Applying Changes

- **Severity**: Low
- **Status**: Fixed
- **Found By**: Dashboard testing (TC-DASH-021)
- **Date Found**: December 2024
- **Component**: dashboard/app.py

**Description**: Widget visibility preferences saved but not applied without page refresh.

**Expected Behavior**: Changes apply immediately without page refresh.

**Actual Behavior**: Required manual page refresh to see changes.

**Root Cause**: Server-side callback updating dcc.Store but no clientside callback applying changes.

**Fix Applied**:

```python
# dashboard/app.py:6437
# Added clientside callback to apply preferences immediately
app.clientside_callback(
    """
    function(prefs) {
        // Apply visibility changes to DOM
        document.getElementById('metrics-section').style.display = prefs.metrics ? 'block' : 'none';
        // ...
    }
    """,
    Output('widget-visibility-dummy', 'children'),
    Input('widget-preferences', 'data')
)
```

**Test Case Added**: TC-DASH-021 (`test_widget_visibility_preferences`)

**Verification**: ✅ Fixed and verified

---

### BUG-011: Toast Message Incorrect for Widget Preferences

- **Severity**: Low
- **Status**: Fixed
- **Found By**: Dashboard testing
- **Date Found**: December 2024
- **Component**: dashboard/app.py

**Description**: Toast message said "refresh page to apply" even though changes applied immediately.

**Expected Behavior**: Toast should reflect immediate application.

**Actual Behavior**: Confusing message suggesting refresh needed.

**Root Cause**: Outdated toast message text.

**Fix Applied**:

```python
# dashboard/app.py:10796
# Before
message = f"Layout preferences saved! Refresh page to apply."

# After
message = f"Layout preferences saved! {enabled_count}/3 sections enabled and applied."
```

**Verification**: ✅ Fixed

---

### BUG-012: Email Alert SMTP Authentication Retry Loop

- **Severity**: Low
- **Status**: Fixed
- **Found By**: Alert testing (TC-ALERT-006)
- **Date Found**: November 2024
- **Component**: alerts/email_notifier.py

**Description**: Failed SMTP authentication retried infinitely.

**Expected Behavior**: Retry 3 times, then give up.

**Actual Behavior**: Infinite retry loop.

**Root Cause**: Retry logic missing maximum attempt counter.

**Fix Applied**:

```python
# alerts/email_notifier.py:89
max_retries = 3
for attempt in range(max_retries):
    try:
        # Send email
        break
    except Exception as e:
        if attempt == max_retries - 1:
            logger.error(f"Email failed after {max_retries} attempts")
```

**Test Case Added**: TC-ALERT-006 (`test_send_alert_email_retry`)

**Verification**: ✅ Fixed and verified

---

## Lessons Learned

1. **Foreign Key Integrity**: Always check related records exist before insertion
2. **Graceful Degradation**: Services should continue operating when optional components fail
3. **Input Validation**: Validate all inputs at boundaries (API, database, user input)
4. **Error Handling**: Wrap external operations (file I/O, API calls) in try-catch blocks
5. **Environment Variables**: Document all required environment variables clearly
6. **Memory Management**: Implement cleanup for long-running processes
7. **Testing Coverage**: Integration tests caught most critical bugs before production

---

## Testing Impact

**Bugs Found During Testing**: 12/12 (100%)

- Unit Tests: 6 bugs
- Integration Tests: 4 bugs
- System Tests: 1 bug
- User Testing: 1 bug

**Bugs Found in Production**: 0

This demonstrates the effectiveness of the comprehensive testing strategy.

---

**For AT4 Submission**: This bug tracking log demonstrates:

- Systematic defect tracking and resolution
- Test-driven development approach
- Professional debugging methodology
- Learning from mistakes and improving code quality
