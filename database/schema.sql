-- IoTSentinel Database Schema Documentation
-- This is for REFERENCE ONLY - actual schema is created by config/init_database.py
-- Last updated: 2026-06-01 (Added alert_suppressions, agent_actions, totp_secrets,
--   rate_limit_log, sustainability tables, API integration tables,
--   manufacturer_eol_database; synced devices + users column additions)

-- ====================================================================================
-- CORE TABLES
-- ====================================================================================

devices (
    device_ip PRIMARY KEY,
    device_name,
    device_type,
    mac_address,
    manufacturer,
    model,                          -- Device model
    firmware_version,               -- Firmware version
    first_seen TIMESTAMP,
    last_seen TIMESTAMP,
    last_activity TIMESTAMP,        -- Last network activity
    is_trusted BOOLEAN,
    is_blocked BOOLEAN,
    custom_name,                    -- User-defined name
    notes,                          -- User notes
    icon DEFAULT '❓',              -- Device icon emoji
    category DEFAULT 'other',       -- Device category
    confidence DEFAULT 'low',       -- Classification confidence
    total_connections DEFAULT 0,    -- Connection counter
    is_kids_device INTEGER DEFAULT 0,  -- Kids Protection toggle
    manufacturing_date DATE,        -- Device manufacture date
    hardware_eol_date DATE          -- Hardware end-of-life date
)

connections (
    id PRIMARY KEY,
    timestamp,
    device_ip → devices,
    dest_ip,
    dest_port,
    protocol,
    service,
    duration,
    bytes_sent,
    bytes_received,
    packets_sent,
    packets_received,
    conn_state,
    processed                       -- 0 = needs ML analysis
)

alerts (
    id PRIMARY KEY,
    timestamp,
    device_ip → devices,
    severity,                       -- low/medium/high/critical
    anomaly_score,
    explanation,                    -- technical string (shown in detail modal)
    top_features,                   -- JSON
    acknowledged BOOLEAN,
    acknowledged_at TIMESTAMP,
    plain_explanation TEXT          -- one plain-English sentence (shown on compact card)
)

alert_suppressions (
    id PRIMARY KEY,
    device_ip,                      -- Device whose alerts are suppressed
    expires_at TIMESTAMP,           -- NULL = suppress indefinitely
    created_by,                     -- Username who created suppression
    created_at TIMESTAMP,
    INDEX(device_ip, expires_at)
)

ml_predictions (
    id PRIMARY KEY,
    timestamp,
    connection_id → connections,
    is_anomaly BOOLEAN,
    anomaly_score,
    model_type,                     -- river (or legacy: autoencoder/isolation_forest)
    model_version
)

model_performance (
    id PRIMARY KEY,
    timestamp,
    model_type,
    precision,
    recall,
    f1_score
)

malicious_ips (
    ip PRIMARY KEY,
    source                          -- blocklist source
)

-- ====================================================================================
-- USER MANAGEMENT
-- ====================================================================================

users (
    id PRIMARY KEY,
    username UNIQUE,
    password_hash,
    email,                              -- User email address
    email_verified INTEGER DEFAULT 0,   -- Email verification status
    role,                               -- admin/viewer
    created_at TIMESTAMP,
    last_login TIMESTAMP,
    is_active BOOLEAN,
    must_change_password INTEGER DEFAULT 0  -- Force password change on first login (set for default admin)
)

user_preferences (
    id PRIMARY KEY,
    user_id → users,
    preference_key,
    preference_value,
    updated_at TIMESTAMP,
    UNIQUE(user_id, preference_key)
)

password_reset_tokens (
    id PRIMARY KEY,
    user_id → users,
    token UNIQUE,                       -- Secure reset token
    expires_at TIMESTAMP,               -- Token expiration (1 hour)
    used BOOLEAN DEFAULT 0,             -- One-time use flag
    created_at TIMESTAMP,
    INDEX(token),
    INDEX(expires_at, used)
)

email_verification_codes (
    id PRIMARY KEY,
    email,                              -- Email being verified
    code,                               -- 6-digit verification code
    expires_at TIMESTAMP,               -- Code expiration (10 minutes)
    verified BOOLEAN DEFAULT 0,         -- Verification status
    created_at TIMESTAMP,
    INDEX(email, verified),
    INDEX(expires_at, verified)
)

oauth_accounts (
    id PRIMARY KEY,
    user_id → users,
    provider,                           -- 'google', 'github', etc.
    provider_user_id,                   -- OAuth provider's user ID
    email,                              -- Email from OAuth provider
    access_token,                       -- OAuth access token
    refresh_token,                      -- OAuth refresh token
    token_expires_at TIMESTAMP,         -- Token expiration
    created_at TIMESTAMP,
    last_login TIMESTAMP,
    UNIQUE(provider, provider_user_id),
    INDEX(provider, provider_user_id),
    INDEX(user_id)
)

webauthn_credentials (
    id PRIMARY KEY,
    user_id → users,
    credential_id UNIQUE,               -- WebAuthn credential ID
    public_key,                         -- Public key for verification
    sign_count DEFAULT 0,               -- Signature counter
    aaguid,                             -- Authenticator GUID
    transports,                         -- JSON array: ['usb', 'nfc', 'ble', 'internal']
    device_name,                        -- User-friendly name: "iPhone Touch ID"
    created_at TIMESTAMP,
    last_used TIMESTAMP,
    INDEX(user_id),
    INDEX(credential_id)
)

user_login_history (
    id PRIMARY KEY,
    user_id → users,
    login_timestamp TIMESTAMP,
    ip_address,                         -- Login IP address
    user_agent,                         -- Browser/device info
    login_method,                       -- 'password', 'oauth_google', 'webauthn'
    success BOOLEAN DEFAULT 1,          -- Login success/failure
    INDEX(user_id, login_timestamp DESC)
)

template_change_audit (
    id PRIMARY KEY,
    user_id → users,                    -- User who changed template
    username,                           -- Username for quick reference
    old_template,                       -- Previous template
    new_template,                       -- New template selected
    change_timestamp TIMESTAMP,         -- When change occurred
    ip_address,                         -- Client IP (metadata only)
    user_agent,                         -- Browser info (metadata only)
    INDEX(user_id, change_timestamp DESC)
)

emergency_mode_log (
    id PRIMARY KEY,
    triggered_by_user_id → users,       -- User who activated emergency mode
    triggered_by_username,              -- Username for quick reference
    trigger_timestamp TIMESTAMP,        -- When activated
    trigger_reason,                     -- User-provided reason
    actions_taken,                      -- Description of actions (e.g., "Blocked 6 devices")
    devices_blocked INTEGER DEFAULT 0,  -- Number of devices blocked
    deactivated_timestamp TIMESTAMP,    -- When deactivated
    deactivated_by_user_id → users,     -- User who deactivated
    deactivated_by_username,            -- Username for quick reference
    ip_address,                         -- Client IP (metadata only)
    is_active BOOLEAN DEFAULT 1,        -- Currently active flag
    INDEX(is_active, trigger_timestamp DESC)
)

rate_limit_log (
    id PRIMARY KEY,
    identifier,                         -- Username or IP being rate-limited
    action_type,                        -- 'login', 'api_call', etc.
    timestamp TIMESTAMP,
    ip_address,
    success BOOLEAN DEFAULT 1,
    INDEX(identifier, action_type, timestamp),
    INDEX(timestamp)                    -- For TTL cleanup queries
)

totp_secrets (
    id PRIMARY KEY,
    user_id UNIQUE → users,
    secret,                             -- TOTP secret (encrypted)
    enabled BOOLEAN DEFAULT 0,          -- Whether 2FA is active
    backup_codes,                       -- JSON: one-time recovery codes
    created_at TIMESTAMP,
    verified_at TIMESTAMP,              -- When user first verified the TOTP code
    INDEX(user_id, enabled)
)

audit_log (
    id PRIMARY KEY,
    timestamp TIMESTAMP,
    user_id → users,
    username TEXT NOT NULL,             -- Username for quick reference
    action_type TEXT NOT NULL,          -- Type of action performed
    action_description TEXT,            -- Human-readable description
    target_resource TEXT,               -- Resource affected
    ip_address TEXT,                    -- Client IP address
    user_agent TEXT,                    -- Browser/client info
    success BOOLEAN DEFAULT 1,          -- Action success/failure
    error_message TEXT,                 -- Error details if failed
    INDEX(user_id, timestamp DESC),
    INDEX(action_type, timestamp DESC),
    INDEX(timestamp DESC)
)

security_audit_log (
    id PRIMARY KEY,
    timestamp TEXT NOT NULL,            -- Event timestamp
    user_id → users,                    -- User who performed action
    username TEXT,                      -- Username for quick reference
    event_type TEXT NOT NULL,           -- Event type (login_success, permission_denied, etc.)
    event_category TEXT,                -- Event category grouping
    severity TEXT DEFAULT 'info',       -- Severity: info, warning, error, critical
    ip_address TEXT,                    -- Client IP address
    user_agent TEXT,                    -- Browser/client info
    resource_type TEXT,                 -- Type of resource (device, user, settings, etc.)
    resource_id TEXT,                   -- Specific resource identifier
    details TEXT,                       -- JSON with additional details
    result TEXT,                        -- Result: success, failure
    failure_reason TEXT,                -- Reason for failure if applicable
    session_id TEXT,                    -- Session identifier
    request_id TEXT,                    -- Request tracking ID
    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
    INDEX(timestamp DESC),
    INDEX(user_id, timestamp DESC),
    INDEX(event_type, timestamp DESC),
    INDEX(severity, timestamp DESC)
)
-- NOTE: audit_log is for general user actions (legacy)
-- NOTE: security_audit_log is for RBAC security events (comprehensive)

-- ====================================================================================
-- ALERT RULES & DEVICE GROUPS
-- ====================================================================================

alert_rules (
    id PRIMARY KEY,
    name,
    description,
    rule_type,                      -- data_volume, connection_count, port_activity, etc.
    condition_operator,             -- gt, lt, eq, contains, in_range
    threshold_value,
    threshold_value_2,
    time_window_hours,
    severity,
    device_filter,
    port_filter,
    protocol_filter,
    time_filter,
    is_enabled BOOLEAN,
    created_at TIMESTAMP,
    created_by → users,
    last_triggered TIMESTAMP,
    trigger_count
)

device_groups (
    id PRIMARY KEY,
    name UNIQUE,
    description,
    color,
    icon,
    created_at TIMESTAMP,
    created_by → users
)

device_group_members (
    id PRIMARY KEY,
    device_ip → devices,
    group_id → device_groups,
    added_at TIMESTAMP,
    added_by → users,
    UNIQUE(device_ip, group_id)
)

-- ====================================================================================
-- IOT DEVICE INTELLIGENCE
-- ====================================================================================

device_fingerprints (
    device_ip PRIMARY KEY,
    os_detected,
    os_version,
    os_confidence,
    device_family,
    hardware_model,
    open_ports,                     -- JSON array
    services_detected,              -- JSON array
    http_user_agent,
    dhcp_fingerprint,
    mdns_services,                  -- JSON array
    upnp_services,                  -- JSON array
    tls_fingerprint,                -- JA3/JA3S fingerprint
    behavior_profile,               -- JSON
    last_fingerprint_update TIMESTAMP
)

iot_vulnerabilities (
    id PRIMARY KEY,
    cve_id UNIQUE,
    title,
    description,
    severity,                       -- low/medium/high/critical
    cvss_score,
    affected_vendors,               -- JSON array
    affected_models,                -- JSON array
    affected_firmware,              -- JSON array
    exploit_available BOOLEAN,
    patch_available BOOLEAN,
    workaround,
    reference_urls,                 -- JSON array
    discovered_date DATE,
    published_date DATE,
    last_updated TIMESTAMP
)

device_vulnerabilities_detected (
    id PRIMARY KEY,
    device_ip → devices,
    cve_id → iot_vulnerabilities,
    detected_date TIMESTAMP,
    status,                         -- active/patched/mitigated/false_positive
    risk_score,
    auto_detected BOOLEAN,
    notes,
    last_checked TIMESTAMP,
    UNIQUE(device_ip, cve_id)
)

-- ====================================================================================
-- IOT PROTOCOL AWARENESS
-- ====================================================================================

mqtt_traffic (
    id PRIMARY KEY,
    timestamp,
    device_ip → devices,
    broker_ip,
    broker_port DEFAULT 1883,
    client_id,
    topic,
    message_type,                   -- PUBLISH, SUBSCRIBE, CONNECT, etc.
    qos,                            -- Quality of Service (0, 1, 2)
    payload_size,
    payload_preview,
    retain_flag BOOLEAN,
    is_encrypted BOOLEAN,
    username
)

coap_traffic (
    id PRIMARY KEY,
    timestamp,
    device_ip → devices,
    dest_ip,
    dest_port DEFAULT 5683,
    method,                         -- GET, POST, PUT, DELETE
    uri_path,
    message_type,                   -- CON, NON, ACK, RST
    payload_size,
    response_code,
    is_dtls BOOLEAN
)

zigbee_traffic (
    id PRIMARY KEY,
    timestamp,
    device_ip,                      -- Gateway/hub IP
    zigbee_address,                 -- 64-bit IEEE address
    short_address,                  -- 16-bit network address
    device_type,                    -- Router, End Device, Coordinator
    cluster_id,
    command,
    manufacturer_code,
    rssi,                           -- Signal strength
    lqi                             -- Link Quality Indicator
)

iot_protocols (
    device_ip → devices,
    protocol,                       -- mqtt, coap, zigbee, http, etc.
    first_seen TIMESTAMP,
    last_seen TIMESTAMP,
    total_messages DEFAULT 0,
    total_bytes DEFAULT 0,
    encryption_used BOOLEAN,
    authentication_used BOOLEAN,
    PRIMARY KEY (device_ip, protocol)
)

-- ====================================================================================
-- IOT THREAT DETECTION
-- ====================================================================================

botnet_signatures (
    id PRIMARY KEY,
    botnet_name UNIQUE,             -- Mirai, Gafgyt, Bashlite, etc.
    family,
    description,
    command_patterns,               -- JSON: regex patterns for C&C
    port_scan_patterns,             -- JSON: typical port scan sequences
    exploit_targets,                -- JSON: commonly exploited ports/services
    default_credentials,            -- JSON: username/password combinations
    ddos_signatures,                -- JSON: DDoS attack patterns
    propagation_methods,            -- JSON: spread techniques
    ioc_domains,                    -- JSON: known C&C domains
    ioc_ips,                        -- JSON: known C&C IPs
    user_agents,                    -- JSON: characteristic user agents
    severity DEFAULT 'critical',
    active BOOLEAN,
    last_updated TIMESTAMP
)

botnet_detections (
    id PRIMARY KEY,
    timestamp,
    device_ip → devices,
    botnet_name,
    detection_method,               -- signature, behavior, ml
    confidence_score,
    indicators,                     -- JSON: detected indicators
    severity,
    status,                         -- active/investigating/confirmed/false_positive/remediated
    remediation_steps,
    notes
)

ddos_activity (
    id PRIMARY KEY,
    timestamp,
    device_ip → devices,
    attack_type,                    -- SYN flood, UDP flood, HTTP flood, etc.
    target_ip,
    target_port,
    packet_count,
    bytes_sent,
    duration_seconds,
    packets_per_second,
    confidence_score,
    is_victim BOOLEAN,              -- TRUE if device is target, FALSE if participant
    mitigation_action
)

default_credentials (
    id PRIMARY KEY,
    device_type,                    -- Type of device (IP Camera, Router, etc.)
    manufacturer,                   -- Device manufacturer
    model,                          -- Specific model
    username,                       -- Default username
    password,                       -- Default password
    service,                        -- web, telnet, ssh, general, etc.
    severity,                       -- low/medium/high/critical
    notes,                          -- Additional context
    source,                         -- Where this credential is documented (Mirai, Vendor, etc.)
    last_updated TIMESTAMP,
    UNIQUE(device_type, manufacturer, username, password)
)

-- ====================================================================================
-- SMART HOME CONTEXT
-- ====================================================================================

smart_home_hubs (
    device_ip PRIMARY KEY,
    hub_type,                       -- SmartThings, Home Assistant, Hubitat, etc.
    hub_name,
    firmware_version,
    supported_protocols,            -- JSON: zigbee, zwave, wifi, thread, matter
    connected_devices_count,
    cloud_connected BOOLEAN,
    cloud_service,                  -- AWS, Google Cloud, Azure, etc.
    local_api_available BOOLEAN,
    last_discovered TIMESTAMP
)

smart_home_rooms (
    id PRIMARY KEY,
    room_name UNIQUE,
    room_type,                      -- living_room, bedroom, kitchen, etc.
    floor_level,
    icon,
    created_at TIMESTAMP
)

device_room_assignments (
    device_ip → devices,
    room_id → smart_home_rooms ON DELETE CASCADE,
    assigned_at TIMESTAMP,
    PRIMARY KEY (device_ip, room_id)
)

smart_home_automations (
    id PRIMARY KEY,
    name,                            -- Human-readable automation name
    trigger_type,                    -- time / device / location / sensor
    condition_text,                  -- Plain-English condition (optional)
    action_text,                     -- Plain-English action to perform
    is_enabled INTEGER DEFAULT 1,   -- 1 = active, 0 = disabled
    created_at TIMESTAMP,
    updated_at TIMESTAMP
)

device_ecosystems (
    device_ip → devices,
    ecosystem,                      -- Google Home, Amazon Alexa, Apple HomeKit, etc.
    integration_type,               -- native, cloud-to-cloud, local
    authenticated BOOLEAN,
    last_interaction TIMESTAMP,
    PRIMARY KEY (device_ip, ecosystem)
)

-- ====================================================================================
-- PRIVACY & DATA EXFILTRATION
-- ====================================================================================

cloud_connections (
    id PRIMARY KEY,
    device_ip → devices,
    cloud_domain,
    cloud_ip,
    cloud_provider,                 -- AWS, Google Cloud, Azure, Alibaba, etc.
    first_seen TIMESTAMP,
    last_seen TIMESTAMP,
    connection_count,
    total_bytes_uploaded,
    total_bytes_downloaded,
    uses_encryption BOOLEAN,
    certificate_valid BOOLEAN,
    privacy_concern_level           -- low/medium/high/critical
)

third_party_trackers (
    id PRIMARY KEY,
    device_ip → devices,
    tracker_domain,
    tracker_company,
    tracker_category,               -- analytics, advertising, social, etc.
    first_detected TIMESTAMP,
    last_detected TIMESTAMP,
    connection_count,
    data_sent_bytes,
    privacy_impact_score            -- 0-10 scale
)

data_exfiltration_events (
    id PRIMARY KEY,
    timestamp,
    device_ip → devices,
    destination_ip,
    destination_domain,
    destination_country,
    protocol,
    bytes_transferred,
    transfer_duration_seconds,
    anomaly_score,
    sensitivity_level,              -- low/medium/high/critical
    file_types_detected,            -- JSON: array of detected file types
    encryption_used BOOLEAN,
    status,                         -- investigating/confirmed/false_positive
    notes
)

-- ====================================================================================
-- NETWORK SEGMENTATION
-- ====================================================================================

network_segments (
    id PRIMARY KEY,
    segment_name UNIQUE,
    vlan_id UNIQUE,
    subnet,                         -- CIDR notation
    gateway,
    purpose,                        -- iot, trusted, guest, isolated, etc.
    security_level,                 -- low/medium/high/critical
    isolation_enabled BOOLEAN,
    firewall_rules,                 -- JSON: array of firewall rules
    recommended BOOLEAN,            -- AI-recommended segment
    created_at TIMESTAMP
)

device_segments (
    device_ip → devices,
    segment_id → network_segments,
    current_segment BOOLEAN,        -- FALSE if this is recommended, not actual
    recommended_by,                 -- system/user/ai
    reason,
    assigned_at TIMESTAMP,
    PRIMARY KEY (device_ip, segment_id)
)

segmentation_violations (
    id PRIMARY KEY,
    timestamp,
    source_device_ip → devices,
    source_segment_id,
    dest_device_ip,
    dest_segment_id,
    violation_type,                 -- unauthorized_access, cross_segment, etc.
    severity,
    blocked BOOLEAN
)

-- ====================================================================================
-- FIRMWARE & LIFECYCLE MANAGEMENT
-- ====================================================================================

firmware_database (
    id PRIMARY KEY,
    vendor,
    model,
    firmware_version,
    release_date DATE,
    is_latest BOOLEAN,
    is_eol BOOLEAN,                 -- End of life
    eol_date DATE,
    security_fixes,                 -- JSON: array of CVEs fixed
    download_url,
    release_notes_url,
    mandatory_update BOOLEAN,
    last_updated TIMESTAMP,
    UNIQUE(vendor, model, firmware_version)
)

device_firmware_status (
    device_ip PRIMARY KEY,
    current_firmware,
    latest_firmware,
    firmware_age_days,
    update_available BOOLEAN,
    is_eol BOOLEAN,
    last_update_check TIMESTAMP,
    auto_update_enabled BOOLEAN,
    update_notification_sent BOOLEAN
)

firmware_update_history (
    id PRIMARY KEY,
    device_ip → devices,
    old_version,
    new_version,
    update_method,                  -- auto, manual, ota
    update_status,                  -- pending/in_progress/success/failed
    initiated_by,                   -- user_id or 'system'
    initiated_at TIMESTAMP,
    completed_at TIMESTAMP,
    error_message
)

device_provisioning (
    id PRIMARY KEY,
    device_ip → devices,
    mac_address,
    provisioning_status,            -- discovered/identified/configured/tested/approved/rejected
    discovered_at TIMESTAMP,
    provisioning_steps,             -- JSON: array of completed steps
    assigned_segment_id,
    assigned_vlan,
    security_baseline_applied BOOLEAN,
    approved_by,                    -- user_id
    approved_at TIMESTAMP,
    notes
)

manufacturer_eol_database (
    id PRIMARY KEY,
    manufacturer,
    model,
    device_type,
    release_date DATE,
    eol_date DATE,                  -- End-of-life date
    support_end_date DATE,          -- Extended support end date
    replacement_model,              -- Suggested successor model
    recycling_info,                 -- E-waste/recycling guidance
    notes,
    created_at TIMESTAMP,
    UNIQUE(manufacturer, model)
)

-- ====================================================================================
-- EDUCATIONAL CONTENT & THREAT LIBRARY
-- ====================================================================================

threat_scenarios (
    id PRIMARY KEY,
    scenario_name UNIQUE,
    category,                       -- botnet, privacy, vulnerability, attack, etc.
    severity,                       -- low/medium/high/critical
    description,
    technical_details,
    real_world_example,
    affected_device_types,          -- JSON: array of device types
    indicators,                     -- JSON: what to look for
    mitigation_steps,               -- JSON: ordered list of steps
    prevention_tips,                -- JSON: best practices
    cve_reference_list,             -- JSON: related CVEs
    external_links,                 -- JSON: reference URLs
    difficulty_level,               -- beginner/intermediate/advanced
    created_at TIMESTAMP,
    last_updated TIMESTAMP
)

security_tips (
    id PRIMARY KEY,
    tip_category,                   -- setup, maintenance, monitoring, response
    device_type,                    -- specific device type or 'general'
    tip_title,
    tip_content,
    importance,                     -- low/medium/high/critical
    difficulty,                     -- easy/moderate/advanced
    time_required,                  -- e.g., "5 minutes", "1 hour"
    prerequisites,
    step_by_step,                   -- JSON: ordered steps
    screenshots_available BOOLEAN,
    related_scenarios,              -- JSON: array of related threat_scenarios.id
    tags,                           -- JSON: searchable tags
    created_at TIMESTAMP
)

user_security_knowledge (
    user_id → users,
    scenario_id → threat_scenarios,
    status,                         -- unread/read/understood/implemented
    first_viewed TIMESTAMP,
    last_viewed TIMESTAMP,
    implementation_date TIMESTAMP,
    notes,
    PRIMARY KEY (user_id, scenario_id)
)

-- ====================================================================================
-- ADVANCED ANALYTICS
-- ====================================================================================

network_health_metrics (
    id PRIMARY KEY,
    timestamp,
    total_iot_devices,
    vulnerable_devices,
    unpatched_devices,
    isolated_devices,
    encrypted_connections_pct,
    overall_security_score,         -- 0-100
    privacy_score,                  -- 0-100
    segmentation_score,             -- 0-100
    compliance_score,               -- 0-100
    recommendation_count
)

device_behavior_baselines (
    device_ip → devices,
    metric_name,                    -- e.g., 'hourly_data_upload', 'connections_per_hour'
    baseline_value,
    std_deviation,
    min_value,
    max_value,
    sample_count,
    last_updated TIMESTAMP,
    PRIMARY KEY (device_ip, metric_name)
)

schema_migrations (
    id PRIMARY KEY,
    migration_name UNIQUE,
    executed_at TIMESTAMP,
    version
)

-- ====================================================================================
-- TOAST SYSTEM ENHANCEMENTS
-- ====================================================================================

toast_history (
    id PRIMARY KEY,
    toast_id UNIQUE,                    -- Unique identifier for each toast
    timestamp TIMESTAMP,
    toast_type,                         -- success/error/danger/warning/info
    category DEFAULT 'general',         -- general/security/network/device/user/system/export/scan
    header,                             -- Toast header text
    message,                            -- Main toast message
    detail_message,                     -- Detailed message (for "View Details")
    user_id → users,                    -- User who received the toast
    session_id,                         -- Session identifier
    dismissed BOOLEAN DEFAULT 0,        -- Whether toast was manually dismissed
    dismissed_at TIMESTAMP,             -- When toast was dismissed
    duration,                           -- Display duration in milliseconds
    action_taken,                       -- Action button clicked (if any)
    metadata,                           -- JSON: additional context
    INDEX(timestamp DESC),
    INDEX(user_id, timestamp DESC),
    INDEX(category, timestamp DESC),
    INDEX(toast_type, timestamp DESC)
)

toast_categories (
    id PRIMARY KEY,
    category_name UNIQUE,               -- Internal category identifier
    display_name,                       -- User-friendly name
    icon,                               -- FontAwesome icon class
    color,                              -- Category color (hex)
    description,                        -- Category description
    priority DEFAULT 0,                 -- Display priority (higher = more important)
    enabled BOOLEAN DEFAULT 1,          -- Whether category is active
    created_at TIMESTAMP
)

user_toast_preferences (
    user_id PRIMARY KEY → users,
    history_enabled BOOLEAN DEFAULT 1,  -- Enable toast history
    history_retention_days DEFAULT 30,  -- How long to keep history
    categories_filter,                  -- JSON: array of enabled categories
    show_persistent_toasts DEFAULT 1,   -- Show persistent toasts
    queue_enabled DEFAULT 1,            -- Enable toast queue
    max_simultaneous_toasts DEFAULT 3,  -- Max toasts shown at once
    default_duration DEFAULT 'medium',  -- short/medium/long
    sound_enabled DEFAULT 0,            -- Play sound for toasts
    updated_at TIMESTAMP
)

-- ====================================================================================
-- ML MODEL MANAGEMENT
-- ====================================================================================

model_versions (
    id PRIMARY KEY,
    model_type,                         -- river, halfspacetrees, hoeffdingadaptive, snarimax
    version,                            -- Model version string
    file_path,                          -- Path to saved model file
    training_samples,                   -- Number of samples used for training
    validation_loss,                    -- Validation loss metric
    metadata_json,                      -- JSON: additional metadata
    is_active BOOLEAN DEFAULT 0,        -- Whether this is the active version
    created_at TIMESTAMP,
    UNIQUE(model_type, version)
)

model_drift_history (
    id PRIMARY KEY,
    model_type,                         -- Type of model being monitored
    drift_score,                        -- Drift score metric
    metric_type,                        -- Type of metric (accuracy, loss, etc.)
    baseline_value,                     -- Original baseline value
    current_value,                      -- Current measured value
    alert_triggered BOOLEAN DEFAULT 0,  -- Whether drift alert was triggered
    timestamp TIMESTAMP
)

-- ====================================================================================
-- SECURITY SCORING
-- ====================================================================================

security_score_history (
    id PRIMARY KEY,
    overall_score,                      -- Overall network security score (0-100)
    device_health_score,                -- Device health component score
    vulnerabilities_score,              -- Vulnerabilities component score
    encryption_score,                   -- Encryption usage score
    segmentation_score,                 -- Network segmentation score
    device_count,                       -- Number of devices evaluated
    timestamp TIMESTAMP,
    INDEX(timestamp DESC)
)

-- ====================================================================================
-- AUTO-DISCOVERY & PROVISIONING
-- ====================================================================================

discovery_events (
    id PRIMARY KEY,
    device_ip,                          -- Discovered device IP
    discovery_method,                   -- arp, mdns, upnp, passive, etc.
    device_info_json,                   -- JSON: discovered device information
    timestamp TIMESTAMP
)

scheduled_tasks (
    id PRIMARY KEY,
    task_type,                          -- auto_provision, firmware_check, scan, etc.
    device_ip,                          -- Target device (if applicable)
    scheduled_at TIMESTAMP,             -- When task should run
    completed BOOLEAN DEFAULT 0,        -- Whether task has completed
    created_at TIMESTAMP
)

-- ====================================================================================
-- SUSTAINABILITY & GREEN METRICS
-- ====================================================================================

sustainability_metrics (
    id PRIMARY KEY,
    timestamp TIMESTAMP,
    period_start TIMESTAMP,
    period_end TIMESTAMP,
    total_data_gb REAL DEFAULT 0,
    estimated_energy_kwh REAL DEFAULT 0,
    carbon_footprint_kg REAL DEFAULT 0,
    device_count INTEGER DEFAULT 0,
    active_device_hours REAL DEFAULT 0,
    notes
)

device_energy_estimates (
    id PRIMARY KEY,
    device_ip → devices,
    device_type,
    date DATE,
    estimated_power_watts REAL DEFAULT 0,
    active_hours REAL DEFAULT 0,
    estimated_energy_kwh REAL DEFAULT 0,
    data_transferred_gb REAL DEFAULT 0,
    UNIQUE(device_ip, date)
)

-- ====================================================================================
-- API INTEGRATION HUB
-- ====================================================================================

api_integrations (
    id PRIMARY KEY,
    integration_name UNIQUE,
    integration_type,
    category,                           -- threat_intel/geolocation/notifications/ticketing/webhooks
    priority,                           -- high/medium/low
    is_enabled BOOLEAN DEFAULT 0,
    api_key_encrypted,
    api_secret_encrypted,
    config_json,                        -- JSON: integration-specific settings
    rate_limit_per_day INTEGER,
    rate_limit_per_month INTEGER,
    last_used TIMESTAMP,
    total_requests INTEGER DEFAULT 0,
    successful_requests INTEGER DEFAULT 0,
    failed_requests INTEGER DEFAULT 0,
    last_error,
    last_health_check TIMESTAMP,
    health_status,                      -- healthy/degraded/error/untested
    created_at TIMESTAMP,
    updated_at TIMESTAMP,
    INDEX(category, is_enabled),
    INDEX(health_status, is_enabled)
)

api_integration_logs (
    id PRIMARY KEY,
    integration_id → api_integrations,
    timestamp TIMESTAMP,
    request_type,
    request_params,
    response_status INTEGER,
    response_time_ms INTEGER,
    success BOOLEAN DEFAULT 1,
    error_message,
    INDEX(integration_id, timestamp),
    INDEX(success, timestamp)
)

-- ====================================================================================
-- AI AGENT ACTIONS
-- ====================================================================================

agent_actions (
    id PRIMARY KEY,
    alert_id → alerts,                  -- Alert that triggered this action (nullable)
    device_ip,
    action_type,                        -- e.g., 'block_device', 'notify', 'quarantine'
    params,                             -- JSON: action parameters
    risk_level DEFAULT 'low',           -- low/medium/high/critical
    rationale,                          -- Technical justification
    plain_report,                       -- Plain-English summary shown in UI
    status DEFAULT 'pending',           -- pending/approved/rejected/executed/failed
    created_at TIMESTAMP,
    resolved_at TIMESTAMP,
    resolved_by,                        -- Username or 'auto'
    INDEX(status, created_at DESC),
    INDEX(device_ip, created_at DESC)
)

-- ====================================================================================
-- NOTES:
-- - This schema is for documentation only
-- - Actual tables are created by: config/init_database.py
-- - Runtime migrations (system_settings, etc.) are applied by: database/db_manager.py
-- - Total tables: 70
--     7 core (devices, connections, alerts, alert_suppressions, ml_predictions,
--             model_performance, malicious_ips)
--     13 user management (users, user_preferences, password_reset_tokens,
--                         email_verification_codes, oauth_accounts, webauthn_credentials,
--                         user_login_history, template_change_audit, emergency_mode_log,
--                         rate_limit_log, totp_secrets, audit_log, security_audit_log)
--     3  alert rules & device groups (alert_rules, device_groups, device_group_members)
--     3  IoT device intelligence
--     4  IoT protocol awareness
--     4  IoT threat detection
--     4  smart home context
--     3  privacy & data exfiltration
--     3  network segmentation
--     5  firmware & lifecycle (firmware_database, device_firmware_status,
--                              firmware_update_history, device_provisioning,
--                              manufacturer_eol_database)
--     3  educational content
--     3  advanced analytics (network_health_metrics, device_behavior_baselines,
--                            schema_migrations)
--     3  toast system
--     2  ML model management
--     1  security scoring
--     2  auto-discovery
--     2  sustainability & green metrics
--     2  API integration hub
--     1  AI agent actions
-- - Audit Tables:
--   * audit_log: Legacy general action logging
--   * security_audit_log: RBAC security events (comprehensive)
--   * template_change_audit: Dashboard template changes
-- - Last updated: 2026-06-01 (synced with init_database.py)
-- ====================================================================================
