# Risk Register for IoTSentinel

**Project**: IoTSentinel - Network Security Monitor  
**Created**: November 2025  
**Last Updated**: November 2025  
**Owner**: Project Team

---

## Risk Assessment Matrix

| Likelihood                | Impact           | Severity Score | Classification |
| ------------------------- | ---------------- | -------------- | -------------- |
| 1 = Rare (<10%)           | 1 = Negligible   | 1-4            | LOW            |
| 2 = Unlikely (10-30%)     | 2 = Minor        | 5-9            | MEDIUM         |
| 3 = Possible (30-50%)     | 3 = Moderate     | 10-14          | HIGH           |
| 4 = Likely (50-70%)       | 4 = Major        | 15-19          | CRITICAL       |
| 5 = Almost Certain (>70%) | 5 = Catastrophic | 20-25          | CRITICAL       |

---

## TECHNICAL RISKS (5)

### R-001: Raspberry Pi CPU Bottleneck ⚠️ CRITICAL

**Category**: Technical - Performance  
**Description**: Zeek + Python ML inference may exceed Pi 5's CPU capacity, preventing real-time analysis

**Likelihood**: 4 (Likely - Pi 5 has limited CPU)  
**Impact**: 4 (Major - System unusable if >30min lag)  
**Severity**: 16 (CRITICAL)

**Indicators**:

- CPU usage consistently >80%
- Processing lag >30 minutes
- Connection queue growing faster than processing

**Preventive Measures**:

1. **Architecture Decision**: Use Zeek (C++) instead of Python-only (Scapy) for packet capture
   - **Rationale**: Zeek processes 100+ Mbps vs. Scapy ~30 Mbps
   - **Evidence**: Performance benchmarking in Week 5
2. **Batch Processing**: ML inference processes 100 connections at a time
3. **Database Indexing**: Indexes on `timestamp`, `device_ip`, `processed`

**Detective Measures**:

- `TC-PERF-001`: CPU monitoring test (psutil)
- Metrics collector logs CPU every 60 seconds

**Corrective Measures**:

- If CPU >80% sustained: Increase inference interval from 5min to 10min
- If lag >1 hour: Upgrade to Pi 5 with 8GB RAM
- Emergency: Disable Autoencoder, use only Isolation Forest (lighter)

**Residual Risk After Mitigation**: Severity 6 (MEDIUM)  
**Owner**: Technical Lead  
**Status**: ✅ Mitigated (current avg CPU: 28%)

---

### R-002: Zeek Compilation Failure on Pi OS ⚠️ HIGH

**Category**: Technical - Deployment  
**Description**: Zeek may fail to compile on Raspberry Pi OS due to dependency conflicts

**Likelihood**: 2 (Unlikely - but documented cases exist)  
**Impact**: 5 (Catastrophic - No Zeek = No project)  
**Severity**: 10 (HIGH)

**Indicators**:

- Compilation errors during `make install`
- Missing system libraries (libpcap, cmake)

**Preventive Measures**:

1. **Use Pre-built Binaries**: Install Zeek from official repository, not source
   ```bash
   sudo apt-get install zeek
   ```
2. **Document Dependencies**: Comprehensive setup script (`scripts/setup_pi.sh`)
3. **Test on Clean Pi**: Verify installation on fresh Pi OS image

**Detective Measures**:

- `TC-SYS-003`: Installation test on Pi 5

**Corrective Measures**:

- Fallback: Use Suricata (lighter IDS) if Zeek fails
- Document workaround: Compile on Ubuntu VM, copy binaries

**Residual Risk**: Severity 4 (LOW)  
**Owner**: DevOps  
**Status**: ✅ Mitigated (pre-built binaries work)

---

### R-003: SQLite Database Locking ⚠️ MEDIUM

**Category**: Technical - Concurrency  
**Description**: Concurrent writes (Zeek parser + ML inference + Dashboard) may cause SQLite lock errors

**Likelihood**: 3 (Possible - SQLite not designed for high concurrency)  
**Impact**: 3 (Moderate - Causes intermittent failures)  
**Severity**: 9 (MEDIUM)

**Indicators**:

- "database is locked" errors in logs
- Dashboard shows stale data

**Preventive Measures**:

1. **WAL Mode**: Enable Write-Ahead Logging for better concurrency
   ```python
   conn.execute("PRAGMA journal_mode = WAL")
   ```
2. **Connection Pooling**: Reuse connections, don't create per-query
3. **Retry Logic**: Automatic retry with exponential backoff

**Detective Measures**:

- `TC-DB-020`: Transaction rollback test
- Error logging in `db_manager.py`

**Corrective Measures**:

- If locks frequent: Increase `timeout` parameter to 30 seconds
- Long-term: Migrate to PostgreSQL (out of scope for v1.0)

**Residual Risk**: Severity 6 (MEDIUM)  
**Owner**: Database Admin  
**Status**: ⚠️ In Progress (WAL enabled, monitoring)

---

### R-004: ML Inference Latency >30 Seconds ⚠️ HIGH

**Category**: Technical - Performance  
**Description**: Autoencoder inference may be too slow on Pi, causing alert delays

**Likelihood**: 3 (Possible - Neural networks are compute-intensive)  
**Impact**: 4 (Major - Violates NFR-001: real-time requirement)  
**Severity**: 12 (HIGH)

**Indicators**:

- Inference time per batch >30 seconds
- Alert generation lag >5 minutes

**Preventive Measures**:

1. **Model Optimization**: Small Autoencoder (10 encoding dimensions)
2. **Batch Processing**: Process 100 connections at once (not one-by-one)
3. **Dual-Model Strategy**: Use fast Isolation Forest as primary, Autoencoder for validation

**Detective Measures**:

- `TC-PERF-002`: Inference latency benchmark
- Metrics collector tracks processing time

**Corrective Measures**:

- If >30s: Reduce batch size to 50
- If still slow: Disable Autoencoder, use only Isolation Forest

**Residual Risk**: Severity 6 (MEDIUM)  
**Owner**: ML Engineer  
**Status**: ✅ Mitigated (avg inference: 24s per 100 connections)

---

### R-005: Dashboard Crashes with 50+ Concurrent Connections ⚠️ MEDIUM

**Category**: Technical - UI Performance  
**Description**: Dash app may become unresponsive when rendering large datasets

**Likelihood**: 2 (Unlikely - tested up to 30 devices)  
**Impact**: 3 (Moderate - Degrades UX)  
**Severity**: 6 (MEDIUM)

**Indicators**:

- Browser tab becomes unresponsive
- Dashboard load time >5 seconds

**Preventive Measures**:

1. **Pagination**: Limit tables to 20 rows per page
2. **Lazy Loading**: Load charts only when tab is active
3. **Efficient Queries**: Use SQL `LIMIT` clauses

**Detective Measures**:

- `TC-DASH-009`: Load test with 100 simulated devices

**Corrective Measures**:

- Add "Show More" buttons instead of infinite scroll
- Implement caching for expensive queries

**Residual Risk**: Severity 4 (LOW)  
**Owner**: Frontend Developer  
**Status**: ⚠️ Monitoring (tested 30 devices, no issues)

---

## PROJECT RISKS (4)

### R-006: Scope Creep ⚠️ CRITICAL

**Category**: Project Management  
**Description**: Attempting to match Bitdefender/Firewalla features leads to incomplete MVP

**Likelihood**: 4 (Likely - Feature requests are common)  
**Impact**: 5 (Catastrophic - Project fails to deliver on time)  
**Severity**: 20 (CRITICAL)

**Indicators**:

- Weekly features added exceed 2
- Implementation time exceeds initial estimates by >50%
- Core features (US-01 to US-08) not 100% complete

**Preventive Measures**:

1. **Strict MoSCoW**: Only MUST HAVE features for v1.0
2. **Feature Freeze**: Week 8 - no new features after this
3. **Definition of Done**: All MUST HAVE stories pass acceptance criteria

**Detective Measures**:

- Weekly sprint reviews
- Burndown chart tracking

**Corrective Measures**:

- If behind schedule: Move SHOULD HAVE to v2.0
- Emergency: Cut Autoencoder, use only Isolation Forest

**Residual Risk**: Severity 8 (MEDIUM)  
**Owner**: Project Manager  
**Status**: ⚠️ Active Risk (monitoring weekly)

---

### R-007: Underestimating UX Design Effort ⚠️ HIGH

**Category**: Project Management  
**Description**: "Educational transparency" UX is complex; may take longer than planned

**Likelihood**: 3 (Possible - UX design is iterative)  
**Impact**: 4 (Major - Poor UX defeats project purpose)  
**Severity**: 12 (HIGH)

**Indicators**:

- Usability test participants confused by alerts (>20% comprehension failure)
- More than 3 design iterations needed
- Time spent on UI exceeds 20% of total hours

**Preventive Measures**:

1. **Early Usability Testing**: Test with 5 users in Week 6
2. **Wireframes First**: Validate design before coding
3. **Persona Alignment**: Every UI decision references Sarah/David/Margaret

**Detective Measures**:

- `TC-VAL-002`: Alert comprehension test (target: 80%+ understand)
- User feedback sessions

**Corrective Measures**:

- If comprehension <80%: Simplify language further
- Use analogies (e.g., "like your car using 10x more fuel than usual")

**Residual Risk**: Severity 6 (MEDIUM)  
**Owner**: UX Designer  
**Status**: ⚠️ Testing Phase

---

### R-008: Baseline Data Collection Delayed ⚠️ MEDIUM

**Category**: Project Management  
**Description**: 7-day baseline collection delayed due to network inactivity or technical issues

**Likelihood**: 3 (Possible - Depends on network usage)  
**Impact**: 3 (Moderate - Delays ML training)  
**Severity**: 9 (MEDIUM)

**Indicators**:

- Less than 50 connections/hour during baseline
- Zeek process crashed during collection

**Preventive Measures**:

1. **User Instructions**: Emphasize "use network normally" during baseline
2. **Automated Restart**: Systemd service auto-restarts Zeek on crash
3. **Progress Monitoring**: Daily check of connection count

**Detective Measures**:

- `baseline_collector.py` status command
- Alert if <20 connections/hour

**Corrective Measures**:

- If insufficient data: Extend baseline to 10 days
- Generate synthetic "normal" data for testing (not production)

**Residual Risk**: Severity 6 (MEDIUM)  
**Owner**: Data Engineer  
**Status**: ⚠️ Monitoring (Day 3 of 7)

---

### R-009: Mentor Unavailable During Critical Phase ⚠️ LOW

**Category**: Project Management  
**Description**: Mentor unavailable when urgent technical guidance needed

**Likelihood**: 2 (Unlikely - Mentors scheduled regularly)  
**Impact**: 2 (Minor - Can self-research)  
**Severity**: 4 (LOW)

**Indicators**:

- Mentor doesn't respond within 48 hours
- Mentor unavailable for scheduled meetings

**Preventive Measures**:

1. **Regular Check-ins**: Biweekly Peer Support Group meetings
2. **Document Questions**: Prepare specific questions in advance
3. **Self-Research**: Consult Zeek documentation, StackOverflow

**Detective Measures**:

- Track mentor response times

**Corrective Measures**:

- Escalate to Module Coordinator if >72 hours without response

**Residual Risk**: Severity 2 (LOW)  
**Owner**: Student  
**Status**: ✅ No Issues

---

## DATA RISKS (4)

### R-010: Baseline Contaminated with Attack Traffic ⚠️ CRITICAL

**Category**: Data Quality  
**Description**: If network is compromised during baseline, ML learns "attacks are normal"

**Likelihood**: 2 (Unlikely - Home networks rarely targeted during specific week)  
**Impact**: 5 (Catastrophic - Model becomes useless)  
**Severity**: 10 (HIGH)

**Indicators**:

- Abnormally high connection counts during baseline
- Known malicious IPs in connection logs

**Preventive Measures**:

1. **User Warning**: Instruct user "report any suspicious activity during baseline"
2. **Manual Review**: Spot-check connection logs for obvious anomalies
3. **Baseline Restart**: Ability to discard and restart if contaminated

**Detective Measures**:

- Visual inspection of top 10 destination IPs
- Check against threat intelligence feeds (if available)

**Corrective Measures**:

- If contaminated: Delete data, restart 7-day collection
- Post-deployment: User can re-train model anytime

**Residual Risk**: Severity 4 (LOW)  
**Owner**: Security Analyst  
**Status**: ⚠️ Monitoring

---

### R-011: Insufficient Training Data (<500 Connections) ⚠️ HIGH

**Category**: Data Quality  
**Description**: Network too quiet during baseline; not enough data to train ML models

**Likelihood**: 3 (Possible - Elderly users may have minimal traffic)  
**Impact**: 4 (Major - Models won't train properly)  
**Severity**: 12 (HIGH)

**Indicators**:

- Connection count <500 after 7 days
- Only 1-2 devices active

**Preventive Measures**:

1. **Minimum Threshold Check**: Script validates ≥500 connections before training
2. **User Guidance**: "Ensure multiple devices are active during baseline"
3. **Extended Collection**: Automatically extend to 10 or 14 days if needed

**Detective Measures**:

- `baseline_collector.py status` shows connection count

**Corrective Measures**:

- If <500 connections: Extend baseline period automatically
- Provide warning: "Limited data may reduce detection accuracy"

**Residual Risk**: Severity 6 (MEDIUM)  
**Owner**: Data Engineer  
**Status**: ⚠️ Monitoring

---

### R-012: Zeek Log Rotation Deletes Active Data ⚠️ MEDIUM

**Category**: Data Loss  
**Description**: Zeek's log rotation may delete logs before parser processes them

**Likelihood**: 2 (Unlikely - Parser runs every 60 seconds)  
**Impact**: 3 (Moderate - Data loss)  
**Severity**: 6 (MEDIUM)

**Indicators**:

- Gaps in connection timestamps
- Parser reports "file not found"

**Preventive Measures**:

1. **Frequent Parsing**: Parse logs every 60 seconds (not hourly)
2. **Archive Before Rotation**: Copy logs to archive before deletion
3. **Zeek Configuration**: Increase rotation interval to 24 hours

**Detective Measures**:

- Monitor for timestamp gaps in database

**Corrective Measures**:

- Reduce parser interval to 30 seconds
- Disable automatic rotation, manual cleanup weekly

**Residual Risk**: Severity 3 (LOW)  
**Owner**: DevOps  
**Status**: ✅ Mitigated (hourly archiving)

---

### R-013: Privacy Violation (Accidental Payload Capture) ⚠️ CRITICAL

**Category**: Legal/Ethical  
**Description**: System accidentally captures packet payloads (not just metadata)

**Likelihood**: 1 (Rare - Zeek default is metadata-only)  
**Impact**: 5 (Catastrophic - Legal/ethical violation)  
**Severity**: 5 (MEDIUM)

**Indicators**:

- Zeek logs contain HTTP body content
- Database contains URLs with query parameters

**Preventive Measures**:

1. **Zeek Configuration**: Explicitly disable payload capture
   ```zeek
   redef Log::enable_http_payloads = F;
   ```
2. **Data Minimization**: Only log metadata (IP, port, bytes, duration)
3. **Privacy Statement**: Clearly document what is/isn't captured

**Detective Measures**:

- `TC-SEC-001`: Privacy audit test
- Manual review of Zeek logs

**Corrective Measures**:

- If payloads found: Immediately purge database, reconfigure Zeek

**Residual Risk**: Severity 2 (LOW)  
**Owner**: Privacy Officer  
**Status**: ✅ Verified (metadata only)

---

## INTEGRATION RISKS (3)

### R-014: Zeek Version Incompatibility ⚠️ MEDIUM

**Category**: Integration  
**Description**: IoTSentinel code written for Zeek 6.x breaks on Zeek 5.x or 7.x

**Likelihood**: 2 (Unlikely - Zeek is stable)  
**Impact**: 4 (Major - Parser fails)  
**Severity**: 8 (MEDIUM)

**Indicators**:

- Parser cannot read Zeek logs
- Log format changes (JSON structure)

**Preventive Measures**:

1. **Version Pinning**: Document exact Zeek version tested (6.0.3)
2. **Compatibility Testing**: Test on multiple Zeek versions
3. **Graceful Degradation**: Warn if unsupported version detected

**Detective Measures**:

- Startup script checks Zeek version

**Corrective Measures**:

- Provide migration guide for version upgrades
- Maintain compatibility layer for common Zeek versions

**Residual Risk**: Severity 4 (LOW)  
**Owner**: DevOps  
**Status**: ⚠️ Monitoring

---

### R-015: Dash/Plotly Version Conflict ⚠️ LOW

**Category**: Integration  
**Description**: Dash or Plotly library update breaks dashboard

**Likelihood**: 2 (Unlikely - Libraries are stable)  
**Impact**: 2 (Minor - Temporary UI issues)  
**Severity**: 4 (LOW)

**Indicators**:

- Dashboard fails to load
- Charts not rendering

**Preventive Measures**:

1. **Requirements Pinning**: Pin exact versions in `requirements.txt`
   ```
   dash==2.14.0
   plotly==5.18.0
   ```
2. **Virtual Environment**: Isolate dependencies

**Detective Measures**:

- Automated tests for dashboard rendering

**Corrective Measures**:

- Rollback to known-good versions
- Update code for new API if beneficial

**Residual Risk**: Severity 2 (LOW)  
**Owner**: Frontend Developer  
**Status**: ✅ Mitigated (versions pinned)

---

### R-016: Browser Compatibility Issues ⚠️ LOW

**Category**: Integration  
**Description**: Dashboard works on Chrome but breaks on Safari/Firefox

**Likelihood**: 2 (Unlikely - Dash is cross-browser)  
**Impact**: 2 (Minor - Affects some users)  
**Severity**: 4 (LOW)

**Indicators**:

- JavaScript errors in browser console
- Charts not interactive on specific browsers

**Preventive Measures**:

1. **Cross-Browser Testing**: Test on Chrome, Firefox, Safari
2. **Standard Web Technologies**: Dash uses React (well-supported)

**Detective Measures**:

- Browser compatibility matrix in test plan

**Corrective Measures**:

- Document browser requirements (Chrome 90+, Firefox 88+)

**Residual Risk**: Severity 2 (LOW)  
**Owner**: QA Engineer  
**Status**: ✅ Tested (3 browsers)

---

## ETHICAL/LEGAL RISKS (4)

### R-017: Monitoring Without Household Consent ⚠️ HIGH

**Category**: Ethical  
**Description**: Primary user monitors family members without their knowledge/consent

**Likelihood**: 3 (Possible - Common in parental control scenarios)  
**Impact**: 4 (Major - Ethical violation, family conflict)  
**Severity**: 12 (HIGH)

**Indicators**:

- User asks about "stealth mode"
- Device owner unaware of monitoring

**Preventive Measures**:

1. **Informed Consent Requirement**: Setup wizard requires user to confirm household consent
2. **Transparency**: Dashboard shows "Monitoring Active" banner
3. **User Guide**: Section on ethical use and consent

**Detective Measures**:

- Ethical framework documented in AT3

**Corrective Measures**:

- Provide "Pause Monitoring" button
- Documentation on ethical considerations

**Residual Risk**: Severity 6 (MEDIUM)  
**Owner**: Ethics Advisor  
**Status**: ⚠️ Documented (user responsibility)

---

### R-018: GDPR Compliance Issues ⚠️ MEDIUM

**Category**: Legal  
**Description**: System may violate GDPR if used in EU household without proper data handling

**Likelihood**: 2 (Unlikely - Home use, not business)  
**Impact**: 4 (Major - Legal liability)  
**Severity**: 8 (MEDIUM)

**Indicators**:

- Personal data stored without consent
- No data deletion mechanism

**Preventive Measures**:

1. **Local Processing**: All data stays on Pi (no cloud transfer)
2. **Data Minimization**: Only collect necessary metadata
3. **User Control**: Ability to delete all data

**Detective Measures**:

- Legal review of data practices

**Corrective Measures**:

- Provide "Delete All Data" button
- Privacy policy template for users

**Residual Risk**: Severity 4 (LOW)  
**Owner**: Legal Advisor  
**Status**: ✅ Compliant (home use exemption likely applies)

---

### R-019: ML Model Bias (False Positives) ⚠️ MEDIUM

**Category**: Ethical - AI  
**Description**: Model may unfairly flag certain types of legitimate traffic as anomalous

**Likelihood**: 3 (Possible - ML models can exhibit bias)  
**Impact**: 3 (Moderate - User frustration, distrust)  
**Severity**: 9 (MEDIUM)

**Indicators**:

- Consistent false positives for specific device types (e.g., smart TVs)
- Disproportionate alerts for certain protocols

**Preventive Measures**:

1. **Diverse Training Data**: 7-day baseline captures various usage patterns
2. **Dual-Model Validation**: Alert only if BOTH models agree (reduces FP)
3. **User Feedback**: Allow users to mark false positives

**Detective Measures**:

- `TC-ML-016`: Bias detection test
- Monitor FP rate by device type

**Corrective Measures**:

- If FP >10% for a device: Add to whitelist
- Re-train model with corrected labels

**Residual Risk**: Severity 6 (MEDIUM)  
**Owner**: ML Ethicist  
**Status**: ⚠️ Monitoring (current FP rate: 6.2%)

---

### R-020: Data Breach (Pi Compromised) ⚠️ HIGH

**Category**: Security  
**Description**: Attacker gains access to Raspberry Pi and exfiltrates network logs

**Likelihood**: 2 (Unlikely - Pi not publicly accessible)  
**Impact**: 5 (Catastrophic - Network topology exposed)  
**Severity**: 10 (HIGH)

**Indicators**:

- Unauthorized SSH logins
- Unusual outbound traffic from Pi

**Preventive Measures**:

1. **Strong Credentials**: Enforce strong passwords during setup
2. **Firewall Rules**: Block incoming connections except dashboard port
3. **Database Encryption**: Encrypt SQLite database at rest (optional)

**Detective Measures**:

- Monitor SSH logs for failed login attempts
- Alert on unusual Pi outbound traffic

**Corrective Measures**:

- If compromised: Immediately disconnect Pi from network
- Wipe SD card and reinstall

**Residual Risk**: Severity 4 (LOW)  
**Owner**: Security Engineer  
**Status**: ✅ Mitigated (localhost-only dashboard)

---

## Risk Summary Statistics

| Classification | Count  | Percentage |
| -------------- | ------ | ---------- |
| 🔴 CRITICAL    | 3      | 15%        |
| 🟠 HIGH        | 5      | 25%        |
| 🟡 MEDIUM      | 10     | 50%        |
| 🟢 LOW         | 2      | 10%        |
| **TOTAL**      | **20** | **100%**   |

### Risks by Category

| Category           | Count |
| ------------------ | ----- |
| Technical          | 5     |
| Project Management | 4     |
| Data Quality       | 4     |
| Integration        | 3     |
| Ethical/Legal      | 4     |

### Mitigation Status

| Status         | Count |
| -------------- | ----- |
| ✅ Mitigated   | 8     |
| ⚠️ Monitoring  | 10    |
| ❌ Unmitigated | 2     |

---

## Top 5 Risks Requiring Immediate Attention

1. **R-006: Scope Creep** (Severity 20) - Weekly sprint reviews mandatory
2. **R-001: CPU Bottleneck** (Severity 16, Mitigated to 6) - Continue performance monitoring
3. **R-004: ML Inference Latency** (Severity 12, Mitigated to 6) - Validate <30s requirement
4. **R-007: UX Design Effort** (Severity 12) - Usability testing Week 6
5. **R-017: Monitoring Without Consent** (Severity 12) - Document ethical framework in AT3

---

## Risk Review Schedule

- **Weekly**: Sprint reviews (R-006 scope creep)
- **Biweekly**: Performance metrics review (R-001, R-004)
- **Month 2**: Usability testing (R-007)
- **Pre-submission**: Final risk audit for AT3

---
