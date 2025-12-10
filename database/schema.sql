-- IoTSentinel Database Schema Documentation
-- This is for REFERENCE ONLY - actual schema is created by config/init_database.py
-- Last updated: 2025-12-09

-- ====================================================================================
-- CORE TABLES
-- ====================================================================================

devices (
    device_ip PRIMARY KEY,
    device_name,
    device_type,
    mac_address,
    manufacturer,
    model,                          -- NEW: Device model
    firmware_version,               -- NEW: Firmware version
    first_seen TIMESTAMP,
    last_seen TIMESTAMP,
    last_activity TIMESTAMP,        -- NEW: Last network activity
    is_trusted BOOLEAN,
    is_blocked BOOLEAN,
    custom_name,                    -- NEW: User-defined name
    notes,                          -- NEW: User notes
    icon DEFAULT '❓',              -- NEW: Device icon emoji
    category DEFAULT 'other',       -- NEW: Device category
    confidence DEFAULT 'low',       -- NEW: Classification confidence
    total_connections DEFAULT 0     -- NEW: Connection counter
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
    explanation,
    top_features,                   -- JSON
    acknowledged BOOLEAN,
    acknowledged_at TIMESTAMP
)

ml_predictions (
    id PRIMARY KEY,
    timestamp,
    connection_id → connections,
    is_anomaly BOOLEAN,
    anomaly_score,
    model_type,                     -- autoencoder/isolation_forest
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
    email,                          -- User email address
    role,                           -- admin/viewer
    created_at TIMESTAMP,
    last_login TIMESTAMP,
    is_active BOOLEAN
)

user_preferences (
    id PRIMARY KEY,
    user_id → users,
    preference_key,
    preference_value,
    updated_at TIMESTAMP,
    UNIQUE(user_id, preference_key)
)

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
    room_id → smart_home_rooms,
    assigned_at TIMESTAMP,
    PRIMARY KEY (device_ip, room_id)
)

smart_home_automations (
    id PRIMARY KEY,
    automation_name,
    trigger_device_ip → devices,
    trigger_event,                  -- motion_detected, door_opened, etc.
    action_devices,                 -- JSON: array of affected device IPs
    action_description,
    execution_time TIMESTAMP,
    success BOOLEAN
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
-- NOTES:
-- - This schema is for documentation only
-- - Actual tables are created by: config/init_database.py
-- - Total tables: 50+ (10 core + 40 IoT security features)
-- - Last updated: December 9, 2025
-- ====================================================================================
