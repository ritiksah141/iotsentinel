# Requirements Traceability Matrix (RTM) - Aligned

| Req ID  | User Story (Parent Epic)                | Feature Description                                 | Code Files (approx. lines)                                                                           | Test Cases                                    | Status                 |
| :------ | :-------------------------------------- | :-------------------------------------------------- | :--------------------------------------------------------------------------------------------------- | :-------------------------------------------- | :--------------------- |
| FR-001  | US-001: Network Visibility              | Device Discovery                                    | `capture/zeek_log_parser.py:67-151`<br>`database/db_manager.py:45-122`<br>`dashboard/app.py:823-913` | TC-CAP-001, TC-DB-001, TC-INT-001, TC-VAL-001 | ✅ Implemented         |
| FR-002  | US-002: Real-Time Network Monitoring    | Real-Time Connection Monitoring                     | `dashboard/app.py:580-650`<br>`database/db_manager.py:150-168`                                       | TC-DB-010, TC-SYS-002, TC-VAL-003             | ✅ Implemented         |
| FR-003  | US-003: Anomaly Detection & Alerting    | Anomaly Alert Generation                            | `ml/inference_engine.py:100-200`<br>`database/db_manager.py:246-269`<br>`dashboard/app.py:710-820`   | TC-ML-012, TC-DB-014, TC-INT-005, TC-VAL-004  | ✅ Implemented         |
| FR-004  | US-004: Educational Alert Explanation   | Educational Alert Explanation                       | `dashboard/app.py:710-820`<br>`ml/inference_engine.py:208-220`                                       | TC-VAL-002                                    | ✅ Implemented         |
| FR-005  | US-005: 7-Day Baseline Training Period  | ~~7-Day Baseline Training~~ (Deprecated - River ML) | ~~`scripts/baseline_collector.py`~~ → `ml/river_engine.py` (Incremental learning)                    | TC-ML-001, TC-ML-002                          | ✅ Evolved to River ML |
| FR-006  | US-001: Network Visibility              | Device Activity Heatmap                             | `dashboard/app.py:916-963`                                                                           | TC-VAL-005                                    | ✅ Implemented         |
| FR-007  | US-003: Anomaly Detection & Alerting    | Alert Timeline (7 Days)                             | `dashboard/app.py:969-1021`                                                                          | TC-VAL-006                                    | ✅ Implemented         |
| NFR-001 | US-002: Real-Time Network Monitoring    | Dashboard Performance (<3s)                         | `database/db_manager.py:39`<br>`dashboard/app.py`                                                    | TC-DB-022, TC-INT-006, TC-SYS-003             | ✅ Implemented         |
| FR-008  | US-003: Anomaly Detection & Alerting    | Alert Filtering by Severity                         | `dashboard/app.py:710-843`                                                                           | TC-VAL-007                                    | ✅ Implemented         |
| FR-009  | US-010: Model Accuracy Metrics Display  | Model Accuracy Metrics                              | `dashboard/app.py:389-432`<br>`ml/inference_engine.py:233-258`                                       | TC-ML-023, TC-VAL-008                         | ✅ Implemented         |
| NFR-002 | US-006: Privacy & Security Controls     | Privacy Controls (Pause)                            | `dashboard/app.py:167-207`<br>`ml/inference_engine.py:260-272`                                       | TC-SEC-002                                    | ✅ Implemented         |
| NFR-003 | US-007: System Health Monitoring        | System Health Monitoring                            | `utils/metrics_collector.py:21-401`                                                                  | TC-SYS-004                                    | ✅ Implemented         |
| FR-010  | US-013: Data Export (CSV) & Reporting   | Data Export (CSV)                                   | `dashboard/app.py:155-158`, `434-449`                                                                | TC-VAL-009                                    | ✅ Implemented         |
| FR-011  | US-003: Anomaly Detection & Alerting    | Alert Acknowledgment                                | `database/db_manager.py:404-417`<br>`dashboard/app.py:710-820`                                       | TC-DB-016, TC-VAL-010                         | ✅ Implemented         |
| FR-012  | US-001: Network Visibility              | Device Trust/Block                                  | `scripts/firewall_manager.py:1-97`<br>`database/db_manager.py:497-518`<br>`dashboard/app.py:888-905` | TC-SEC-004                                    | ✅ Implemented         |
| FR-013  | US-003: Anomaly Detection & Alerting    | Email Alerts                                        | `alerts/email_notifier.py:1-86`<br>`ml/inference_engine.py:184-193`                                  | TC-INT-011                                    | ✅ Implemented         |
| NFR-004 | US-008: User Experience & Accessibility | Mobile Responsive                                   | `dashboard/assets/custom.css:1-22`                                                                   | TC-VAL-011                                    | ✅ Implemented         |
| FR-014  | US-008: User Experience & Accessibility | Onboarding Wizard                                   | `dashboard/app.py:142-207`                                                                           | TC-VAL-012                                    | ✅ Implemented         |
| FR-015  | US-007: System Health Monitoring        | System Orchestrator                                 | `orchestrator.py:1-122`                                                                              | TC-SYS-005                                    | ✅ Implemented         |
| FR-016  | US-012: Advanced Threat Intelligence    | Threat Intelligence Feed                            | `scripts/update_threat_feeds.py:1-52`<br>`ml/inference_engine.py:130-143`                            | TC-SEC-003                                    | ✅ Implemented         |
| FR-017  | US-010: Model Accuracy Metrics Display  | Model Performance Comparison                        | `scripts/compare_models.py:1-160`<br>`dashboard/app.py:1015-1036`                                    | TC-ML-024, TC-VAL-013                         | ✅ Implemented         |
| FR-018  | US-006: Privacy & Security Controls     | Firewall Lockdown Mode                              | `scripts/firewall_manager.py:1-97`<br>`dashboard/app.py:1104-1145`                                   | TC-SEC-004                                    | ✅ Implemented         |
| FR-019  | US-003: Anomaly Detection & Alerting    | Email Alert Notifications (Redundant)               | _See FR-013_                                                                                         | TC-INT-011                                    | ✅ Implemented         |
| FR-020  | US-013: Data Export (CSV) & Reporting   | Weekly Report Generation                            | `scripts/generate_report.py:1-103`                                                                   | TC-VAL-014                                    | ✅ Implemented         |
| FR-021  | US-006: Privacy & Security Controls     | Monitoring Pause/Resume (Redundant)                 | _See NFR-002_                                                                                        | TC-SEC-002                                    | ✅ Implemented         |
| NFR-005 | US-008: User Experience & Accessibility | Mobile Responsive (Redundant)                       | _See NFR-004_                                                                                        | TC-VAL-011                                    | ✅ Implemented         |
| N/A     | US-013: Deep Packet Inspection          | Excluded Feature                                    | N/A                                                                                                  | N/A                                           | ⚫ WON'T HAVE          |
| N/A     | US-014: Multi-Network Support           | Excluded Feature                                    | N/A                                                                                                  | N/A                                           | ⚫ WON'T HAVE          |
| FR-022  | US-015: IoT Device Classification       | Device Type Detection & Icons                       | `utils/device_classifier.py`<br>`database/db_manager.py:48-118`<br>`dashboard/app.py:372-389`        | TC-IOT-001                                    | ✅ Implemented         |
| FR-023  | US-016: Device Management               | Custom Names, Grouping, Notes                       | `database/db_manager.py:380-469`<br>`dashboard/app.py:1887-1899,4138-4220`                           | TC-IOT-002                                    | ✅ Implemented         |
| FR-024  | US-017: Dashboard Preferences           | Settings Customization                              | `dashboard/app.py` (Settings callbacks & device metadata management)                                 | TC-UX-003                                     | ✅ Implemented         |
| FR-025  | US-018: IoT Security Assessment         | Security Widget & Checks                            | `utils/iot_security_checker.py`<br>`dashboard/app.py:1660-1673,4290-4368`                            | TC-SEC-006                                    | ✅ Implemented         |
| FR-026  | US-019: Login Rate Limiting             | Brute Force Protection                              | `utils/rate_limiter.py`<br>`dashboard/app.py:43,66,3653-3694`                                        | TC-SEC-005                                    | ✅ Implemented         |
| FR-027  | US-020: Educational Chart Tooltips      | In-App Help System                                  | `dashboard/app.py:1439-1451,1511-1542,1586-1628`                                                     | TC-UX-002                                     | ✅ Implemented         |
| FR-028  | US-021: Health Check Endpoint           | /health API Monitoring                              | `dashboard/app.py:88-155`                                                                            | TC-SYS-006                                    | ✅ Implemented         |
| FR-029  | US-022: Enhanced Deployment             | Backup, Rollback, Clean Install                     | `scripts/deploy_to_pi.sh`<br>`.env.template`                                                         | TC-DEP-001                                    | ✅ Implemented         |

---

## Summary Statistics

| Category                          | Count  | Status                                  |
| --------------------------------- | ------ | --------------------------------------- |
| Functional Requirements (FR)      | 29     | ✅ 26 Implemented, 3 Redundant pointers |
| Non-Functional Requirements (NFR) | 5      | ✅ 4 Implemented, 1 Redundant pointer   |
| WON'T HAVE Features               | 2      | ⚫ Excluded by design                   |
| **Total Requirements**            | **34** | **30 Unique (100% complete)**           |

### MoSCoW Alignment

All requirements map to user stories following MoSCoW prioritization:

- 🔴 **MUST HAVE**: 8 user stories → 100% implemented
- 🟡 **SHOULD HAVE**: 6 user stories → 100% implemented
- 🟢 **COULD HAVE**: 4 user stories → 100% implemented
- ⚫ **WON'T HAVE**: 2 items → Properly excluded

### Test Coverage

All implemented requirements have associated test cases:

- Unit Tests: TC-DB-_, TC-ML-_, TC-CAP-\*
- Integration Tests: TC-INT-\*
- System Tests: TC-SYS-\*
- Validation Tests: TC-VAL-\*
- Security Tests: TC-SEC-\*
- **Total**: 194 tests collected (exceeds target)
