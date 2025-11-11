# IoTSentinel Test Plan

**Project**: IoTSentinel - Network Security Monitor  
**Version**: 1.0  
**Author**: Project Team  
**Last Updated**: November 2025

---

## 1. Test Strategy

This document outlines the comprehensive testing strategy for the IoTSentinel project, designed to ensure reliability, robustness, and correctness across all system components. Our approach is structured around a multi-level testing pyramid, emphasizing a strong foundation of unit tests, supported by broader integration and system-level tests.

### 1.1. Test Levels

- **Unit Tests**: Fine-grained tests that validate individual functions and classes in isolation. These form the majority of our test suite and are designed to be fast and specific.
- **Integration Tests**: Tests that verify the interaction between different components of the system (e.g., Zeek log parser and the database, or the database and the ML engine).
- **System Tests**: High-level tests that validate the end-to-end functionality of the system, including performance under load and long-term stability.
- **Validation Tests**: Tests mapped directly to user stories and requirements to ensure the software meets user expectations.

### 1.2. Coverage Target

Our goal is to achieve a **minimum of 85% line coverage** across all critical modules. This ensures that the most important parts of the codebase are thoroughly tested.

### 1.3. Tools

- **Test Runner**: `pytest`
- **Code Coverage**: `pytest-cov`
- **Mocking**: `unittest.mock`

---

## 2. Unit Tests (59 Tests)

### 2.1. Database Module (`database/`) - 22 Tests

This suite validates the integrity, correctness, and performance of all database operations managed by `DatabaseManager`.

- **TC-DB-001 to TC-DB-006**: Device CRUD Operations
  - `test_add_device_success`: Verifies successful device insertion.
  - `test_add_device_duplicate_updates`: Ensures that adding a duplicate device updates the existing record.
  - `test_add_device_updates_last_seen`: Confirms that the `last_seen` timestamp is updated on re-insertion.
  - `test_update_device_name`: Validates the renaming of a device.
  - `test_get_active_devices`: Checks that recently seen devices are correctly identified as active.
  - `test_get_active_devices_excludes_old`: Ensures that devices not seen recently are excluded from the active list.

- **TC-DB-007 to TC-DB-013**: Connection & Data Integrity
  - `test_add_connection_success`: Verifies successful insertion of a network connection record.
  - `test_add_connection_creates_device`: Ensures that adding a connection for a new device automatically creates a corresponding device record.
  - `test_add_connection_with_invalid_foreign_key_fails`: Validates that the foreign key constraint between `connections` and `devices` is enforced.
  - `test_get_unprocessed_connections`: Checks retrieval of connections that have not yet been processed by the ML engine.
  - `test_mark_connections_processed`: Verifies that connections can be successfully flagged as processed.
  - `test_get_connection_count`: Validates the total connection count over a given period.
  - `test_get_device_stats`: Ensures that device-specific statistics (e.g., data usage) are calculated correctly.

- **TC-DB-014 to TC-DB-017**: Alert Management
  - `test_create_alert_success`: Verifies successful creation of a security alert.
  - `test_create_alert_with_invalid_severity_fails`: Ensures that an alert with an invalid severity level cannot be created.
  - `test_acknowledge_alert`: Validates the acknowledgment of an alert.
  - `test_get_recent_alerts`: Checks the retrieval of recent alerts.

- **TC-DB-018 to TC-DB-019**: ML Prediction Storage
  - `test_store_prediction_success`: Verifies that an ML prediction can be successfully stored.
  - `test_store_multiple_predictions`: Ensures that multiple predictions (e.g., from different models) can be stored for the same connection.

- **TC-DB-020 to TC-DB-022**: Error Handling & Transactions
  - `test_database_connection_failure`: Simulates a connection failure to ensure graceful error handling.
  - `test_add_connection_with_none_values`: Checks that `None` values are handled correctly during insertion.
  - `test_rollback_on_error`: Verifies that database transactions are rolled back in case of an error, ensuring data integrity.

### 2.2. Machine Learning Module (`ml/`) - 23 Tests

This suite validates the feature extraction and data processing pipeline, ensuring that data is correctly prepared for the ML models.

- **TC-ML-001 to TC-ML-008**: Feature Extraction & Calculation
  - `test_extract_basic_features`: Verifies the extraction of all basic features from a connection.
  - `test_total_bytes_calculation`: Checks the correctness of the `total_bytes` feature.
  - `test_bytes_ratio_calculation`: Validates the `bytes_ratio` (sent vs. received) calculation.
  - `test_bytes_per_second_calculation`: Ensures the `bytes_per_second` calculation is correct.
  - `test_temporal_features`: Verifies the correct extraction of time-based features like `hour_of_day` and `is_weekend`.
  - `test_protocol_one_hot_encoding`: Checks that protocols (e.g., TCP, UDP) are correctly one-hot encoded.
  - `test_connection_state_encoding`: Validates the one-hot encoding of connection states (e.g., SF, S0).
  - `test_port_normalization`: Ensures that destination ports are correctly normalized to a 0-1 scale.

- **TC-ML-009 to TC-ML-010**: Missing Value Handling
  - `test_missing_duration_handled`: Verifies that connections with a missing `duration` are handled without errors.
  - `test_missing_bytes_handled`: Ensures that missing `bytes_sent` or `bytes_received` values are correctly imputed.

- **TC-ML-011 to TC-ML-014**: Feature Scaling
  - `test_fit_scaler`: Verifies that the feature scaler can be fitted to a dataset.
  - `test_transform_standardization`: Checks that the scaler correctly standardizes features to have a mean of ~0 and a standard deviation of ~1.
  - `test_fit_transform`: Ensures the `fit_transform` method works as expected.
  - `test_transform_without_fit_warns`: Confirms that using `transform` before `fit` is handled gracefully.

- **TC-ML-015 to TC-ML-018**: Edge Cases
  - `test_empty_dataframe`: Ensures the extractor handles an empty input DataFrame without crashing.
  - `test_single_connection`: Verifies correct processing of a single connection.
  - `test_zero_duration_connection`: Checks for correct handling of connections with zero duration to prevent division-by-zero errors.
  - `test_extreme_values`: Ensures that extreme or large values in features do not cause errors.

- **TC-ML-019 to TC-ML-020**: Persistence
  - `test_save_and_load`: Verifies that the feature extractor's state (including the scaler) can be saved and loaded correctly.
  - `test_loaded_extractor_produces_same_output`: Ensures that a loaded extractor produces the exact same output as the original.

- **TC-ML-021 to TC-ML-023**: Interpretability & Performance
  - `test_feature_names_are_descriptive`: Checks that feature names are clear and follow a consistent format.
  - `test_feature_count_consistency`: Ensures the number of features extracted is always consistent.
  - `test_large_batch_performance`: Benchmarks the extractor's performance, ensuring it can process 1000 connections in under a second.

### 2.3. Capture Module (`capture/`) - 4 Tests

This suite fills a critical gap by testing the `ZeekLogParser`, which is the entry point for all network data into the system.

- **TC-CAP-001**: `test_parse_conn_log`
  - **Description**: Verifies that a standard, well-formed Zeek `conn.log` file is parsed correctly and that the expected number of records are inserted into the database.
  - **Rationale**: Confirms the core functionality of the parser.

- **TC-CAP-002**: `test_parse_gzipped_log`
  - **Description**: Ensures that the parser can correctly read and process gzipped log files (`.log.gz`), which is a common format for rotated logs.
  - **Rationale**: Guarantees that the system can handle log rotation and archival.

- **TC-CAP-003**: `test_handle_corrupt_log_entry`
  - **Description**: Tests the parser's resilience by feeding it a log file containing a corrupted or invalid JSON entry. The test verifies that the parser skips the corrupt line and continues processing the valid entries.
  - **Rationale**: Ensures the robustness of the data pipeline; a single bad log entry should not halt the entire system.

- **TC-CAP-004**: `test_data_extraction`
  - **Description**: Verifies that the data extracted from a log entry (e.g., IP addresses, port, protocol) is correctly mapped to the corresponding database fields.
  - **Rationale**: Ensures the accuracy and integrity of the data being stored.

---

## 3. Integration Tests (10 Tests)

This suite validates the data flow and interactions between different modules.

- **TC-INT-001**: `test_parse_zeek_conn_log_to_database`
  - **Flow**: Zeek Log File → `ZeekLogParser` → `DatabaseManager`
  - **Verifies**: That raw Zeek JSON logs are correctly parsed and stored as connection records in the database.

- **TC-INT-002**: `test_parser_creates_devices_automatically`
  - **Flow**: `ZeekLogParser` → `DatabaseManager`
  - **Verifies**: That when a connection from a previously unseen IP address is parsed, a new device record is automatically created in the `devices` table.

- **TC-INT-003**: `test_feature_extraction_from_database`
  - **Flow**: `DatabaseManager` → `FeatureExtractor`
  - **Verifies**: That connection data stored in the database can be successfully retrieved and transformed into a feature matrix by the `FeatureExtractor`.

- **TC-INT-004**: `test_ml_inference_with_isolation_forest`
  - **Flow**: `DatabaseManager` → `FeatureExtractor` → `IsolationForest` Model
  - **Verifies**: That the full pipeline from database records to ML prediction works as expected, and that a trained model can correctly identify synthetic anomalies.

- **TC-INT-005**: `test_full_pipeline_generates_alerts`
  - **Flow**: Zeek Log File → Parser → DB → Feature Extraction → ML Model → Alert Creation
  - **Verifies**: The complete end-to-end pipeline. It confirms that a raw log entry can trigger the creation of a security alert in the database.

- **TC-INT-006**: `test_throughput_1000_connections`
  - **Flow**: `DatabaseManager`
  - **Verifies**: The performance of the database by inserting 1,000 connection records in a single transaction, ensuring it completes within a performance threshold (<10 seconds).

- **TC-INT-007**: `test_connection_count_matches_predictions`
  - **Flow**: `DatabaseManager`
  - **Verifies**: Data consistency by ensuring that for a given set of connections, the number of ML predictions stored in the database matches the number of connections.

- **TC-INT-008**: `test_alert_device_foreign_key_integrity`
  - **Flow**: `DatabaseManager`
  - **Verifies**: The relational integrity of the database by confirming that an alert can be successfully joined with its corresponding device record.

- **TC-INT-009**: `test_parser_continues_after_corrupt_record`
  - **Flow**: `ZeekLogParser` → `DatabaseManager`
  - **Verifies**: The resilience of the parsing pipeline by ensuring it can recover from and skip over corrupted log entries.

- **TC-INT-010**: `test_inference_handles_missing_model_gracefully`
  - **Flow**: `InferenceEngine`
  - **Verifies**: That the inference engine starts and runs without crashing even if the trained model files are missing (though it will not generate alerts).

---

## 4. System & Validation Tests

### 4.1. System Tests (5 Tests)

These high-level tests assess the behavior of the entire system.

- **TC-SYS-001**: 24-Hour Soak Test
  - **Objective**: Verify system stability and resource usage (CPU, memory) over an extended period of normal operation.
- **TC-SYS-002**: Performance Under Load
  - **Objective**: Test system performance with a high volume of simulated network traffic to identify bottlenecks.
- **TC-SYS-003**: Recovery After Failure
  - **Objective**: Ensure the system can gracefully recover and resume operation after a simulated crash or restart of a key component (e.g., the Zeek parser).
- **TC-SYS-004**: Dashboard Responsiveness
  - **Objective**: Validate that the web dashboard remains responsive and loads data within acceptable time limits (<3 seconds) even with a large database.
- **TC-SYS-005**: Long-Term Operation (7 Days)
  - **Objective**: Run the system for a full week to check for memory leaks, log rotation issues, and database growth problems.

### 4.2. Validation Tests (11 Tests)

These tests are mapped directly to user stories to validate that the system meets the specified requirements.

- **TC-VAL-001**: Corresponds to **US-001 (Device Discovery)**.
- **TC-VAL-002**: Corresponds to **US-005 (Alert Comprehension)**.
- **TC-VAL-003**: Corresponds to **US-002 (Real-Time Monitoring)**.
- **TC-VAL-004**: Corresponds to **US-003 (Anomaly Alert Generation)**.
- **TC-VAL-005**: Corresponds to **US-006 (Device Activity Heatmap)**.
- **TC-VAL-006**: Corresponds to **US-007 (Alert Timeline)**.
- **TC-VAL-007**: Corresponds to **US-009 (Alert Filtering)**.
- **TC-VAL-008**: Corresponds to **US-010 (Model Accuracy Metrics)**.
- **TC-VAL-009**: Corresponds to **US-013 (Data Export)**.
- **TC-VAL-010**: Corresponds to **US-014 (Alert Acknowledgment)**.
- **TC-VAL-011**: Corresponds to **US-017 (Mobile Responsiveness)**.

---

**Success Criteria**: Complete test plan with **59** test cases documented, achieving >85% code coverage and demonstrating a robust, mature approach to quality assurance.
