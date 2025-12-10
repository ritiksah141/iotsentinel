#!/usr/bin/env python3
"""
Database Initialization for IoTSentinel

Creates all required tables with proper schema.
Run this once during setup.
"""

import sqlite3
import sys
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from config.config_manager import config


def init_database():
    """Create all necessary tables."""

    db_path = config.get('database', 'path')

    print(f"Initializing database: {db_path}")

    # Create parent directory
    Path(db_path).parent.mkdir(parents=True, exist_ok=True)

    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    # Devices table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS devices (
            device_ip TEXT PRIMARY KEY,
            device_name TEXT,
            device_type TEXT,
            mac_address TEXT,
            manufacturer TEXT,
            model TEXT,
            firmware_version TEXT,
            first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_activity TIMESTAMP,
            is_trusted INTEGER DEFAULT 0,
            is_blocked INTEGER DEFAULT 0,
            custom_name TEXT,
            notes TEXT,
            icon TEXT DEFAULT "❓",
            category TEXT DEFAULT "other",
            confidence TEXT DEFAULT "low",
            total_connections INTEGER DEFAULT 0
        )
    ''')

    # Connections table (from Zeek)
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS connections (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            device_ip TEXT NOT NULL,
            dest_ip TEXT,
            dest_port INTEGER,
            protocol TEXT,
            service TEXT,
            duration REAL,
            bytes_sent INTEGER DEFAULT 0,
            bytes_received INTEGER DEFAULT 0,
            packets_sent INTEGER DEFAULT 0,
            packets_received INTEGER DEFAULT 0,
            conn_state TEXT,
            processed INTEGER DEFAULT 0,
            FOREIGN KEY (device_ip) REFERENCES devices(device_ip)
        )
    ''')

    # Indexes
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_conn_timestamp ON connections(timestamp)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_conn_device ON connections(device_ip)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_conn_processed ON connections(processed)')

    # Alerts table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            device_ip TEXT NOT NULL,
            severity TEXT CHECK(severity IN ('low', 'medium', 'high', 'critical')),
            anomaly_score REAL,
            explanation TEXT,
            top_features TEXT,
            acknowledged INTEGER DEFAULT 0,
            acknowledged_at TIMESTAMP,
            FOREIGN KEY (device_ip) REFERENCES devices(device_ip)
        )
    ''')

    # ML predictions
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS ml_predictions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            connection_id INTEGER,
            is_anomaly INTEGER,
            anomaly_score REAL,
            model_type TEXT,
            model_version TEXT,
            FOREIGN KEY (connection_id) REFERENCES connections(id)
        )
    ''')

    # Model performance metrics
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS model_performance (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            model_type TEXT,
            precision REAL,
            recall REAL,
            f1_score REAL
        )
    ''')

    # Malicious IPs table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS malicious_ips (
            ip TEXT PRIMARY KEY,
            source TEXT
        )
    ''')

    # Users table for authentication
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            email TEXT,
            role TEXT CHECK(role IN ('admin', 'viewer')) DEFAULT 'viewer',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_login TIMESTAMP,
            is_active INTEGER DEFAULT 1
        )
    ''')

    # Create default admin user (password: from env var or fallback to 'admin')
    # Password hash for 'admin' using bcrypt
    import bcrypt
    import os
    default_password = os.environ.get("IOTSENTINEL_ADMIN_PASSWORD", "admin")  # pragma: allowlist secret

    if default_password == "admin": # pragma: allowlist secret
        print("  ⚠️  Using default admin password. For production, set the IOTSENTINEL_ADMIN_PASSWORD environment variable.")

    password_hash = bcrypt.hashpw(default_password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

    cursor.execute('''
        INSERT OR IGNORE INTO users (username, password_hash, role)
        VALUES (?, ?, ?)
    ''', ('admin', password_hash, 'admin'))

    # User Preferences table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS user_preferences (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            preference_key TEXT NOT NULL,
            preference_value TEXT,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
            UNIQUE(user_id, preference_key)
        )
    ''')

    # Alert Rules table for custom user-defined rules
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS alert_rules (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            description TEXT,
            rule_type TEXT CHECK(rule_type IN ('data_volume', 'connection_count', 'port_activity', 'time_based', 'destination_ip', 'protocol')) NOT NULL,
            condition_operator TEXT CHECK(condition_operator IN ('gt', 'lt', 'eq', 'gte', 'lte', 'contains', 'in_range')) NOT NULL,
            threshold_value REAL,
            threshold_value_2 REAL,
            time_window_hours INTEGER DEFAULT 1,
            severity TEXT CHECK(severity IN ('low', 'medium', 'high', 'critical')) DEFAULT 'medium',
            device_filter TEXT,
            port_filter TEXT,
            protocol_filter TEXT,
            time_filter TEXT,
            is_enabled INTEGER DEFAULT 1,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            created_by INTEGER,
            last_triggered TIMESTAMP,
            trigger_count INTEGER DEFAULT 0,
            FOREIGN KEY (created_by) REFERENCES users(id)
        )
    ''')

    # Create default alert rules
    default_rules = [
        # High data volume rule
        ('High Data Transfer', 'Alert when device sends more than 1 GB in 1 hour', 'data_volume', 'gt', 1000.0, None, 1, 'high', None, None, None, None, 1),
        # Excessive connections
        ('Excessive Connections', 'Alert when device makes more than 500 connections in 1 hour', 'connection_count', 'gt', 500.0, None, 1, 'medium', None, None, None, None, 1),
        # Unusual port activity
        ('Suspicious Port Activity', 'Alert on connections to commonly exploited ports', 'port_activity', 'contains', None, None, 1, 'high', None, '22,23,3389,445,135', None, None, 1),
        # After-hours activity
        ('After-Hours Activity', 'Alert on network activity during unusual hours (11 PM - 6 AM)', 'time_based', 'in_range', 23.0, 6.0, 1, 'low', None, None, None, '23:00-06:00', 1),
    ]

    cursor.executemany('''
        INSERT OR IGNORE INTO alert_rules (
            name, description, rule_type, condition_operator, threshold_value, threshold_value_2,
            time_window_hours, severity, device_filter, port_filter, protocol_filter, time_filter, is_enabled
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    ''', default_rules)

    # Device Groups table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS device_groups (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT UNIQUE NOT NULL,
            description TEXT,
            color TEXT DEFAULT '#0dcaf0',
            icon TEXT DEFAULT 'fa-folder',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            created_by INTEGER,
            FOREIGN KEY (created_by) REFERENCES users(id)
        )
    ''')

    # Device-Group mapping table (many-to-many relationship)
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS device_group_members (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            device_ip TEXT NOT NULL,
            group_id INTEGER NOT NULL,
            added_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            added_by INTEGER,
            FOREIGN KEY (device_ip) REFERENCES devices(device_ip) ON DELETE CASCADE,
            FOREIGN KEY (group_id) REFERENCES device_groups(id) ON DELETE CASCADE,
            FOREIGN KEY (added_by) REFERENCES users(id),
            UNIQUE(device_ip, group_id)
        )
    ''')

    # Create default device groups
    default_groups = [
        ('IoT Devices', 'Smart home devices and IoT sensors', '#17a2b8', 'fa-lightbulb'),
        ('Computers', 'Laptops, desktops, and workstations', '#007bff', 'fa-laptop'),
        ('Mobile Devices', 'Smartphones and tablets', '#28a745', 'fa-mobile-alt'),
        ('Network Infrastructure', 'Routers, switches, and access points', '#6c757d', 'fa-network-wired'),
        ('Security Devices', 'Cameras, sensors, and security systems', '#dc3545', 'fa-shield-alt'),
        ('Media Devices', 'TVs, streaming devices, and speakers', '#fd7e14', 'fa-tv'),
        ('Printers & Peripherals', 'Printers, scanners, and other peripherals', '#6f42c1', 'fa-print'),
        ('Unknown Devices', 'Uncategorized or unidentified devices', '#6c757d', 'fa-question-circle'),
    ]

    cursor.executemany('''
        INSERT OR IGNORE INTO device_groups (name, description, color, icon)
        VALUES (?, ?, ?, ?)
    ''', default_groups)

    # =============================================================================
    # IOT-SPECIFIC FEATURES - All tables created inline
    # =============================================================================

    print("\n📡 Initializing IoT-specific features...")

    # Execute embedded IoT features migration
    cursor.executescript("""
    -- IoT Device Fingerprinting
    CREATE TABLE IF NOT EXISTS device_fingerprints (
        device_ip TEXT PRIMARY KEY, os_detected TEXT, os_version TEXT, os_confidence REAL DEFAULT 0,
        device_family TEXT, hardware_model TEXT, open_ports TEXT, services_detected TEXT,
        http_user_agent TEXT, dhcp_fingerprint TEXT, mdns_services TEXT, upnp_services TEXT,
        tls_fingerprint TEXT, behavior_profile TEXT, last_fingerprint_update TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS iot_vulnerabilities (
        id INTEGER PRIMARY KEY AUTOINCREMENT, cve_id TEXT UNIQUE, title TEXT NOT NULL, description TEXT,
        severity TEXT CHECK(severity IN ('low', 'medium', 'high', 'critical')), cvss_score REAL,
        affected_vendors TEXT, affected_models TEXT, affected_firmware TEXT,
        exploit_available BOOLEAN DEFAULT 0, patch_available BOOLEAN DEFAULT 0, workaround TEXT,
        reference_urls TEXT, discovered_date DATE, published_date DATE, last_updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS device_vulnerabilities_detected (
        id INTEGER PRIMARY KEY AUTOINCREMENT, device_ip TEXT NOT NULL, cve_id TEXT NOT NULL,
        detected_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        status TEXT DEFAULT 'active' CHECK(status IN ('active', 'patched', 'mitigated', 'false_positive')),
        risk_score REAL, auto_detected BOOLEAN DEFAULT 1, notes TEXT,
        last_checked TIMESTAMP DEFAULT CURRENT_TIMESTAMP, UNIQUE(device_ip, cve_id)
    );

    -- IoT Protocol Traffic
    CREATE TABLE IF NOT EXISTS mqtt_traffic (
        id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        device_ip TEXT NOT NULL, broker_ip TEXT, broker_port INTEGER DEFAULT 1883, client_id TEXT,
        topic TEXT, message_type TEXT, qos INTEGER, payload_size INTEGER, payload_preview TEXT,
        retain_flag BOOLEAN, is_encrypted BOOLEAN DEFAULT 0, username TEXT
    );
    CREATE INDEX IF NOT EXISTS idx_mqtt_device ON mqtt_traffic(device_ip);
    CREATE INDEX IF NOT EXISTS idx_mqtt_timestamp ON mqtt_traffic(timestamp);

    CREATE TABLE IF NOT EXISTS coap_traffic (
        id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        device_ip TEXT NOT NULL, dest_ip TEXT, dest_port INTEGER DEFAULT 5683,
        method TEXT, uri_path TEXT, message_type TEXT, payload_size INTEGER,
        response_code INTEGER, is_dtls BOOLEAN DEFAULT 0
    );
    CREATE INDEX IF NOT EXISTS idx_coap_device ON coap_traffic(device_ip);

    CREATE TABLE IF NOT EXISTS zigbee_traffic (
        id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        device_ip TEXT, zigbee_address TEXT, short_address TEXT, device_type TEXT,
        cluster_id TEXT, command TEXT, manufacturer_code TEXT, rssi INTEGER, lqi INTEGER
    );

    CREATE TABLE IF NOT EXISTS iot_protocols (
        device_ip TEXT, protocol TEXT, first_seen TIMESTAMP, last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        total_messages INTEGER DEFAULT 0, total_bytes INTEGER DEFAULT 0,
        encryption_used BOOLEAN DEFAULT 0, authentication_used BOOLEAN DEFAULT 0,
        PRIMARY KEY (device_ip, protocol)
    );

    -- IoT Threat Detection
    CREATE TABLE IF NOT EXISTS botnet_signatures (
        id INTEGER PRIMARY KEY AUTOINCREMENT, botnet_name TEXT UNIQUE, family TEXT, description TEXT,
        command_patterns TEXT, port_scan_patterns TEXT, exploit_targets TEXT, default_credentials TEXT,
        ddos_signatures TEXT, propagation_methods TEXT, ioc_domains TEXT, ioc_ips TEXT, user_agents TEXT,
        severity TEXT DEFAULT 'critical', active BOOLEAN DEFAULT 1, last_updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS botnet_detections (
        id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        device_ip TEXT NOT NULL, botnet_name TEXT, detection_method TEXT, confidence_score REAL,
        indicators TEXT, severity TEXT DEFAULT 'critical',
        status TEXT DEFAULT 'active' CHECK(status IN ('active', 'investigating', 'confirmed', 'false_positive', 'remediated')),
        remediation_steps TEXT, notes TEXT
    );
    CREATE INDEX IF NOT EXISTS idx_botnet_device ON botnet_detections(device_ip);

    CREATE TABLE IF NOT EXISTS ddos_activity (
        id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        device_ip TEXT NOT NULL, attack_type TEXT, target_ip TEXT, target_port INTEGER,
        packet_count INTEGER, bytes_sent INTEGER, duration_seconds INTEGER, packets_per_second REAL,
        confidence_score REAL, is_victim BOOLEAN DEFAULT 0, mitigation_action TEXT
    );
    CREATE INDEX IF NOT EXISTS idx_ddos_device ON ddos_activity(device_ip);

    -- Default Credentials Database (for credential-based threat detection)
    CREATE TABLE IF NOT EXISTS default_credentials (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        device_type TEXT NOT NULL,
        manufacturer TEXT,
        model TEXT,
        username TEXT NOT NULL,
        password TEXT NOT NULL,
        service TEXT DEFAULT 'general',
        severity TEXT DEFAULT 'critical' CHECK(severity IN ('low', 'medium', 'high', 'critical')),
        notes TEXT,
        source TEXT,
        last_updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        UNIQUE(device_type, manufacturer, username, password)
    );
    CREATE INDEX IF NOT EXISTS idx_default_creds_type ON default_credentials(device_type);
    CREATE INDEX IF NOT EXISTS idx_default_creds_mfr ON default_credentials(manufacturer);

    -- Smart Home Features
    CREATE TABLE IF NOT EXISTS smart_home_hubs (
        device_ip TEXT PRIMARY KEY, hub_type TEXT, hub_name TEXT, firmware_version TEXT,
        supported_protocols TEXT, connected_devices_count INTEGER DEFAULT 0,
        cloud_connected BOOLEAN DEFAULT 0, cloud_service TEXT, local_api_available BOOLEAN DEFAULT 0,
        last_discovered TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS smart_home_rooms (
        id INTEGER PRIMARY KEY AUTOINCREMENT, room_name TEXT UNIQUE NOT NULL, room_type TEXT,
        floor_level INTEGER, icon TEXT, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS device_room_assignments (
        device_ip TEXT, room_id INTEGER, assigned_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        PRIMARY KEY (device_ip, room_id)
    );

    CREATE TABLE IF NOT EXISTS device_ecosystems (
        device_ip TEXT, ecosystem TEXT, integration_type TEXT, authenticated BOOLEAN DEFAULT 0,
        last_interaction TIMESTAMP, PRIMARY KEY (device_ip, ecosystem)
    );

    -- Privacy Monitoring
    CREATE TABLE IF NOT EXISTS cloud_connections (
        id INTEGER PRIMARY KEY AUTOINCREMENT, device_ip TEXT NOT NULL, cloud_domain TEXT NOT NULL,
        cloud_ip TEXT, cloud_provider TEXT, first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP, connection_count INTEGER DEFAULT 1,
        total_bytes_uploaded INTEGER DEFAULT 0, total_bytes_downloaded INTEGER DEFAULT 0,
        uses_encryption BOOLEAN DEFAULT 0, certificate_valid BOOLEAN DEFAULT 1,
        privacy_concern_level TEXT CHECK(privacy_concern_level IN ('low', 'medium', 'high', 'critical'))
    );
    CREATE INDEX IF NOT EXISTS idx_cloud_device ON cloud_connections(device_ip);
    CREATE INDEX IF NOT EXISTS idx_cloud_privacy ON cloud_connections(privacy_concern_level);

    CREATE TABLE IF NOT EXISTS third_party_trackers (
        id INTEGER PRIMARY KEY AUTOINCREMENT, device_ip TEXT NOT NULL, tracker_domain TEXT NOT NULL,
        tracker_company TEXT, tracker_category TEXT, first_detected TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        last_detected TIMESTAMP DEFAULT CURRENT_TIMESTAMP, connection_count INTEGER DEFAULT 1,
        data_sent_bytes INTEGER DEFAULT 0, privacy_impact_score REAL
    );
    CREATE INDEX IF NOT EXISTS idx_tracker_device ON third_party_trackers(device_ip);

    CREATE TABLE IF NOT EXISTS data_exfiltration_events (
        id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        device_ip TEXT NOT NULL, destination_ip TEXT, destination_domain TEXT, destination_country TEXT,
        protocol TEXT, bytes_transferred INTEGER, transfer_duration_seconds INTEGER, anomaly_score REAL,
        sensitivity_level TEXT CHECK(sensitivity_level IN ('low', 'medium', 'high', 'critical')),
        file_types_detected TEXT, encryption_used BOOLEAN DEFAULT 0, status TEXT DEFAULT 'investigating', notes TEXT
    );
    CREATE INDEX IF NOT EXISTS idx_exfiltration_device ON data_exfiltration_events(device_ip);

    -- Network Segmentation
    CREATE TABLE IF NOT EXISTS network_segments (
        id INTEGER PRIMARY KEY AUTOINCREMENT, segment_name TEXT UNIQUE NOT NULL, vlan_id INTEGER UNIQUE,
        subnet TEXT, gateway TEXT, purpose TEXT,
        security_level TEXT CHECK(security_level IN ('low', 'medium', 'high', 'critical')),
        isolation_enabled BOOLEAN DEFAULT 0, firewall_rules TEXT, recommended BOOLEAN DEFAULT 0,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS device_segments (
        device_ip TEXT, segment_id INTEGER, current_segment BOOLEAN DEFAULT 1,
        recommended_by TEXT, reason TEXT, assigned_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        PRIMARY KEY (device_ip, segment_id)
    );

    CREATE TABLE IF NOT EXISTS segmentation_violations (
        id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        source_device_ip TEXT NOT NULL, source_segment_id INTEGER, dest_device_ip TEXT,
        dest_segment_id INTEGER, violation_type TEXT, severity TEXT, blocked BOOLEAN DEFAULT 0
    );

    -- Firmware Management
    CREATE TABLE IF NOT EXISTS firmware_database (
        id INTEGER PRIMARY KEY AUTOINCREMENT, vendor TEXT NOT NULL, model TEXT NOT NULL,
        firmware_version TEXT NOT NULL, release_date DATE, is_latest BOOLEAN DEFAULT 0,
        is_eol BOOLEAN DEFAULT 0, eol_date DATE, security_fixes TEXT,
        download_url TEXT, release_notes_url TEXT, mandatory_update BOOLEAN DEFAULT 0,
        last_updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP, UNIQUE(vendor, model, firmware_version)
    );
    CREATE INDEX IF NOT EXISTS idx_firmware_vendor_model ON firmware_database(vendor, model);

    CREATE TABLE IF NOT EXISTS device_firmware_status (
        device_ip TEXT PRIMARY KEY, current_firmware TEXT, latest_firmware TEXT,
        firmware_age_days INTEGER, update_available BOOLEAN DEFAULT 0, is_eol BOOLEAN DEFAULT 0,
        last_update_check TIMESTAMP, auto_update_enabled BOOLEAN DEFAULT 0, update_notification_sent BOOLEAN DEFAULT 0
    );

    CREATE TABLE IF NOT EXISTS firmware_update_history (
        id INTEGER PRIMARY KEY AUTOINCREMENT, device_ip TEXT NOT NULL, old_version TEXT, new_version TEXT,
        update_method TEXT, update_status TEXT DEFAULT 'pending' CHECK(update_status IN ('pending', 'in_progress', 'success', 'failed')),
        initiated_by TEXT, initiated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, completed_at TIMESTAMP, error_message TEXT
    );

    CREATE TABLE IF NOT EXISTS device_provisioning (
        id INTEGER PRIMARY KEY AUTOINCREMENT, device_ip TEXT NOT NULL, mac_address TEXT,
        provisioning_status TEXT DEFAULT 'discovered' CHECK(provisioning_status IN ('discovered', 'identified', 'configured', 'tested', 'approved', 'rejected')),
        discovered_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, provisioning_steps TEXT,
        assigned_segment_id INTEGER, assigned_vlan INTEGER, security_baseline_applied BOOLEAN DEFAULT 0,
        approved_by TEXT, approved_at TIMESTAMP, notes TEXT
    );

    -- Educational Content
    CREATE TABLE IF NOT EXISTS threat_scenarios (
        id INTEGER PRIMARY KEY AUTOINCREMENT, scenario_name TEXT UNIQUE NOT NULL, category TEXT,
        severity TEXT CHECK(severity IN ('low', 'medium', 'high', 'critical')), description TEXT NOT NULL,
        technical_details TEXT, real_world_example TEXT, affected_device_types TEXT, indicators TEXT,
        mitigation_steps TEXT, prevention_tips TEXT, cve_reference_list TEXT, external_links TEXT,
        difficulty_level TEXT CHECK(difficulty_level IN ('beginner', 'intermediate', 'advanced')),
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, last_updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    CREATE INDEX IF NOT EXISTS idx_scenario_category ON threat_scenarios(category);
    CREATE INDEX IF NOT EXISTS idx_scenario_severity ON threat_scenarios(severity);

    CREATE TABLE IF NOT EXISTS security_tips (
        id INTEGER PRIMARY KEY AUTOINCREMENT, tip_category TEXT, device_type TEXT,
        tip_title TEXT NOT NULL, tip_content TEXT NOT NULL,
        importance TEXT CHECK(importance IN ('low', 'medium', 'high', 'critical')),
        difficulty TEXT CHECK(difficulty IN ('easy', 'moderate', 'advanced')),
        time_required TEXT, prerequisites TEXT, step_by_step TEXT, screenshots_available BOOLEAN DEFAULT 0,
        related_scenarios TEXT, tags TEXT, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS user_security_knowledge (
        user_id INTEGER, scenario_id INTEGER,
        status TEXT DEFAULT 'unread' CHECK(status IN ('unread', 'read', 'understood', 'implemented')),
        first_viewed TIMESTAMP, last_viewed TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        implementation_date TIMESTAMP, notes TEXT, PRIMARY KEY (user_id, scenario_id)
    );

    -- Network Health Metrics
    CREATE TABLE IF NOT EXISTS network_health_metrics (
        id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        total_iot_devices INTEGER, vulnerable_devices INTEGER, unpatched_devices INTEGER, isolated_devices INTEGER,
        encrypted_connections_pct REAL, overall_security_score REAL, privacy_score REAL,
        segmentation_score REAL, compliance_score REAL, recommendation_count INTEGER
    );

    CREATE TABLE IF NOT EXISTS device_behavior_baselines (
        device_ip TEXT, metric_name TEXT, baseline_value REAL, std_deviation REAL,
        min_value REAL, max_value REAL, sample_count INTEGER,
        last_updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP, PRIMARY KEY (device_ip, metric_name)
    );

    CREATE TABLE IF NOT EXISTS schema_migrations (
        id INTEGER PRIMARY KEY AUTOINCREMENT, migration_name TEXT UNIQUE NOT NULL,
        executed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, version TEXT
    );

    INSERT OR IGNORE INTO schema_migrations (migration_name, version) VALUES ('iot_features_migration', '2.0.0');

    -- Initialize sample data
    INSERT OR IGNORE INTO botnet_signatures (botnet_name, family, description, exploit_targets, severity)
    VALUES
    ('Mirai', 'Mirai', 'Infamous IoT botnet using default credentials', '["23", "2323", "80", "8080"]', 'critical'),
    ('Gafgyt', 'Gafgyt/Bashlite', 'IoT botnet targeting weak telnet passwords', '["23", "22", "80"]', 'critical');

    -- Common IoT Default Credentials (used by Mirai and other botnets)
    INSERT OR IGNORE INTO default_credentials (device_type, manufacturer, username, password, service, severity, notes, source)
    VALUES
    ('IP Camera', 'Generic', 'admin', 'admin', 'web/telnet', 'critical', 'Most common default', 'Mirai'),
    ('IP Camera', 'Generic', 'admin', '12345', 'web/telnet', 'critical', 'Common numeric password', 'Mirai'),
    ('IP Camera', 'Generic', 'admin', 'password', 'web/telnet', 'critical', 'Default password', 'Common'),
    ('IP Camera', 'Generic', 'root', 'root', 'telnet', 'critical', 'Root access default', 'Mirai'),
    ('IP Camera', 'Generic', 'root', '12345', 'telnet', 'critical', 'Numeric root password', 'Mirai'),
    ('IP Camera', 'Generic', 'root', 'pass', 'telnet', 'critical', 'Short password', 'Mirai'),
    ('IP Camera', 'Generic', 'admin', '', 'web/telnet', 'critical', 'Empty password', 'Mirai'),
    ('IP Camera', 'Generic', 'root', '', 'telnet', 'critical', 'Empty root password', 'Mirai'),
    ('DVR/NVR', 'Generic', 'admin', 'admin', 'web/telnet', 'critical', 'Default DVR credentials', 'Mirai'),
    ('DVR/NVR', 'Generic', 'admin', '12345', 'web/telnet', 'critical', 'Common DVR password', 'Mirai'),
    ('DVR/NVR', 'Generic', 'root', 'root', 'telnet', 'critical', 'Root DVR access', 'Mirai'),
    ('DVR/NVR', 'Generic', 'admin', '1234', 'web/telnet', 'critical', '4-digit password', 'Common'),
    ('Router', 'Generic', 'admin', 'admin', 'web/telnet', 'critical', 'Default router login', 'Mirai'),
    ('Router', 'Generic', 'admin', 'password', 'web', 'critical', 'Common router password', 'Common'),
    ('Router', 'Generic', 'root', 'root', 'telnet', 'critical', 'Root router access', 'Mirai'),
    ('Router', 'TP-Link', 'admin', 'admin', 'web', 'critical', 'TP-Link default', 'Vendor'),
    ('Router', 'Linksys', 'admin', 'admin', 'web', 'critical', 'Linksys default', 'Vendor'),
    ('Router', 'Netgear', 'admin', 'password', 'web', 'critical', 'Netgear default', 'Vendor'),
    ('Router', 'D-Link', 'admin', 'admin', 'web', 'critical', 'D-Link default', 'Vendor'),
    ('Router', 'ASUS', 'admin', 'admin', 'web', 'critical', 'ASUS default', 'Vendor'),
    ('Smart Speaker', 'Generic', 'admin', 'admin', 'web', 'high', 'Smart speaker default', 'Common'),
    ('Smart Hub', 'Generic', 'admin', 'admin', 'web', 'critical', 'Hub default login', 'Common'),
    ('Smart Lock', 'Generic', 'admin', '0000', 'app', 'critical', 'Numeric PIN default', 'Common'),
    ('Smart Lock', 'Generic', 'admin', '1234', 'app', 'critical', '4-digit PIN', 'Common'),
    ('Printer', 'Generic', 'admin', 'admin', 'web', 'medium', 'Printer default', 'Common'),
    ('Printer', 'HP', 'admin', '', 'web', 'medium', 'HP empty password', 'Vendor'),
    ('Thermostat', 'Generic', 'admin', 'admin', 'web', 'high', 'Smart thermostat', 'Common'),
    ('Security System', 'Generic', 'admin', '1234', 'app/web', 'critical', 'Security panel PIN', 'Common'),
    ('Security System', 'Generic', 'admin', '0000', 'app/web', 'critical', 'Default security PIN', 'Common'),
    ('Generic', 'Generic', 'user', 'user', 'general', 'high', 'Generic user account', 'Mirai'),
    ('Generic', 'Generic', 'support', 'support', 'telnet', 'high', 'Support account default', 'Mirai'),
    ('Generic', 'Generic', 'admin', '888888', 'telnet', 'critical', 'Repeated digit password', 'Mirai'),
    ('Generic', 'Generic', 'admin', '123456', 'telnet', 'critical', '6-digit sequential', 'Mirai'),
    ('Generic', 'Generic', 'root', '123456', 'telnet', 'critical', 'Root sequential password', 'Mirai'),
    ('Generic', 'Generic', 'default', 'default', 'general', 'high', 'Default/default combo', 'Common'),
    ('Generic', 'Generic', 'guest', 'guest', 'general', 'medium', 'Guest account', 'Common');

    INSERT OR IGNORE INTO network_segments (segment_name, vlan_id, purpose, security_level, recommended)
    VALUES
    ('IoT Isolated', 20, 'iot', 'medium', 1),
    ('Smart Home', 30, 'iot', 'medium', 1),
    ('Critical IoT', 40, 'iot', 'high', 1),
    ('Guest/Untrusted', 99, 'guest', 'low', 1);

    -- Educational threat scenarios
    INSERT OR IGNORE INTO threat_scenarios (scenario_name, category, severity, description, technical_details, real_world_example, affected_device_types, indicators, mitigation_steps, prevention_tips, cve_reference_list, difficulty_level)
    VALUES
    ('Mirai Botnet Infection', 'botnet', 'critical',
     'IoT device becomes part of the Mirai botnet through credential brute-forcing.',
     'Mirai is a self-propagating botnet that targets IoT devices with default or weak credentials.',
     'In October 2016, Mirai infected over 600,000 IoT devices and launched the largest DDoS attack in history (1.2 Tbps) against DNS provider Dyn.',
     '["IP Camera", "DVR/NVR", "Router"]',
     '["Unusual outbound telnet connections", "High network traffic to port 23/2323"]',
     '["Disconnect device immediately", "Factory reset", "Change default credentials"]',
     '["Never use default credentials", "Disable telnet", "Segment IoT devices"]',
     '["CVE-2016-10372"]',
     'intermediate'),
    ('Unauthorized Cloud Data Upload', 'privacy', 'high',
     'Smart camera or voice assistant uploads data to cloud without user awareness.',
     'IoT devices often upload data to cloud servers for processing without explicit user consent.',
     'In 2019, Amazon employed thousands of workers to listen to Alexa voice recordings.',
     '["Smart Speaker", "IP Camera", "Smart Doorbell"]',
     '["Large upload traffic", "Connections to AWS/Google Cloud"]',
     '["Review device privacy settings", "Disable cloud features", "Use local recording"]',
     '["Choose devices with local storage", "Monitor network uploads"]',
     '[]',
     'beginner'),
    ('DDoS-for-Hire Botnet Participation', 'botnet', 'critical',
     'Compromised IoT device participates in DDoS attacks.',
     'Attackers rent out botnets to launch DDoS attacks using infected IoT devices.',
     'In 2018, the Memcashed DDoS reached 1.7 Tbps using 50,000 IoT devices.',
     '["Router", "IP Camera", "DVR"]',
     '["Extremely high outbound traffic", "Repetitive packet patterns"]',
     '["Contact ISP", "Factory reset all devices", "Update firmware"]',
     '["Implement egress filtering", "Monitor traffic spikes"]',
     '["CVE-2018-10561"]',
     'advanced'),
    ('Smart Home Automation Hijacking', 'attack', 'high',
     'Attacker gains control of smart home automation systems.',
     'Exploiting weak passwords or vulnerabilities to control smart home hubs.',
     'In 2019, Ring camera hacks allowed strangers to talk to children.',
     '["Smart Lock", "Smart Hub", "Smart Camera"]',
     '["Unexpected automation triggers", "Unknown users in app"]',
     '["Change all passwords", "Enable 2FA", "Update firmware"]',
     '["Always enable 2FA", "Use unique passwords"]',
     '["CVE-2019-9556"]',
     'intermediate'),
    ('Ransomware Attack on Smart Device', 'attack', 'high',
     'IoT device infected with ransomware that locks functionality.',
     'Ransomware targeting IoT devices locks users out until payment.',
     'In 2016, smart thermostat ransomware locked temperature at 99°F.',
     '["Smart TV", "Smart Thermostat", "Smart Lock"]',
     '["Device locked", "Ransom message displayed"]',
     '["DO NOT pay ransom", "Factory reset", "Disconnect from network"]',
     '["Regular backups", "Network segmentation"]',
     '[]',
     'intermediate');

    -- Security tips
    INSERT OR IGNORE INTO security_tips (tip_category, device_type, tip_title, tip_content, importance, difficulty, time_required, prerequisites, step_by_step, tags)
    VALUES
    ('setup', 'Camera', 'Change Default Camera Passwords',
     'Default passwords are the #1 cause of IoT compromises. Always change them immediately.',
     'critical', 'easy', '5 minutes', '',
     '["Access camera web interface", "Navigate to Settings > Security", "Change admin password to strong password (12+ chars)"]',
     '["password", "security", "camera"]'),
    ('network', 'All IoT', 'Create Separate IoT Network (VLAN)',
     'Isolate all IoT devices to prevent lateral movement if compromised.',
     'critical', 'advanced', '30 minutes', 'Router with VLAN support',
     '["Create new WiFi SSID", "Enable VLAN tagging", "Configure firewall rules"]',
     '["network", "vlan", "segmentation"]'),
    ('setup', 'Smart Lock', 'Enable Two-Factor Authentication',
     'Require both password and phone verification for smart lock access.',
     'critical', 'easy', '5 minutes', 'Smartphone',
     '["Open app", "Go to Security", "Enable 2FA", "Save backup codes"]',
     '["2fa", "authentication"]'),
    ('maintenance', 'IP Camera', 'Regular Firmware Updates',
     'Keep firmware updated to patch security vulnerabilities.',
     'high', 'easy', '10 minutes', 'Web access',
     '["Check version", "Download latest", "Upload firmware", "Verify"]',
     '["firmware", "update"]'),
    ('monitoring', 'All IoT', 'Monitor IoT Network Traffic',
     'Use network monitoring to detect suspicious behavior.',
     'high', 'moderate', '1 hour', 'Computer',
     '["Install monitoring tool", "Configure alerts", "Review daily"]',
     '["monitoring", "network"]'),
    ('setup', 'Router', 'Disable UPnP Protocol',
     'UPnP allows devices to open ports automatically, creating security holes.',
     'high', 'easy', '3 minutes', 'Router access',
     '["Access router", "Navigate to UPnP", "Disable", "Save"]',
     '["upnp", "router"]'),
    ('setup', 'Smart Speaker', 'Disable Always-Listening Mode',
     'Reduce privacy risks by using push-to-talk instead of always-on microphone.',
     'medium', 'easy', '2 minutes', 'Smartphone',
     '["Open app", "Settings > Wake Word", "Disable"]',
     '["privacy", "speaker"]');
    """)

    conn.commit()
    conn.close()

    print(f"\n✓ Database initialized: {db_path}")
    print("\nCore Tables:")
    print("  - devices (with IoT metadata: icon, category, model, firmware)")
    print("  - connections")
    print("  - alerts")
    print("  - ml_predictions")
    print("  - model_performance")
    print("  - malicious_ips")
    print("  - users")
    print("  - user_preferences")
    print("  - alert_rules")
    print("  - device_groups")
    print("  - device_group_members")
    print("\n✓ Default admin user created:")
    print("  Username: admin")
    if default_password == "admin": # pragma: allowlist secret
        print("  Password: admin")
        print("  ⚠️  CHANGE THIS PASSWORD AFTER FIRST LOGIN!")
    else:
        print("  Password: [set from IOTSENTINEL_ADMIN_PASSWORD environment variable]")
    print("\n✓ Default alert rules created:")
    print("  - High Data Transfer (1 GB/hour)")
    print("  - Excessive Connections (500/hour)")
    print("  - Suspicious Port Activity (common exploit ports)")
    print("  - After-Hours Activity (11 PM - 6 AM)")
    print("\n✓ Default device groups created:")
    print("  - IoT Devices")
    print("  - Computers")
    print("  - Mobile Devices")
    print("  - Network Infrastructure")
    print("  - Security Devices")
    print("  - Media Devices")
    print("  - Printers & Peripherals")
    print("  - Unknown Devices")

    print("\n📡 IoT Security Features:")
    print("  - Device Fingerprinting & Intelligence")
    print("  - IoT Protocol Awareness (MQTT, CoAP, Zigbee)")
    print("  - IoT-Specific Threat Detection")
    print("  - Smart Home Context & Ecosystem Detection")
    print("  - Privacy Monitoring & Cloud Tracking")
    print("  - Network Segmentation Recommendations")
    print("  - Firmware Lifecycle Management")
    print("  - Educational Content Library (5 threat scenarios, 7 security tips)")


if __name__ == "__main__":
    init_database()
