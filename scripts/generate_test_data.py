#!/usr/bin/env python3
"""
Create realistic test data for IoTSentinel dashboard testing.

Generates:
- 10 devices (mix of IoT devices, laptops, phones)
- 1000+ connections over 24 hours
- 20 alerts of varying severity
- ML predictions
"""

import sys
from pathlib import Path
import random
from datetime import datetime, timedelta
import json

sys.path.insert(0, str(Path(__file__).parent.parent))

from config.config_manager import config
from database.db_manager import DatabaseManager

# Initialize database
db = DatabaseManager(config.get('database', 'path'))

print("=" * 70)
print("IoTSentinel Test Data Generator")
print("=" * 70)

# ============================================================================
# 1. CREATE DEVICES
# ============================================================================

devices = [
    {
        'device_ip': '192.168.1.10',
        'device_name': 'Living Room TV',
        'device_type': 'Smart TV',
        'mac_address': 'AA:BB:CC:DD:EE:10',
        'manufacturer': 'Samsung'
    },
    {
        'device_ip': '192.168.1.20',
        'device_name': 'Kitchen Echo',
        'device_type': 'Smart Speaker',
        'mac_address': 'AA:BB:CC:DD:EE:20',
        'manufacturer': 'Amazon'
    },
    {
        'device_ip': '192.168.1.30',
        'device_name': 'Security Camera',
        'device_type': 'IoT Camera',
        'mac_address': 'AA:BB:CC:DD:EE:30',
        'manufacturer': 'Ring'
    },
    {
        'device_ip': '192.168.1.40',
        'device_name': 'Johns Laptop',
        'device_type': 'Laptop',
        'mac_address': 'AA:BB:CC:DD:EE:40',
        'manufacturer': 'Apple'
    },
    {
        'device_ip': '192.168.1.50',
        'device_name': 'Marias iPhone',
        'device_type': 'Smartphone',
        'mac_address': 'AA:BB:CC:DD:EE:50',
        'manufacturer': 'Apple'
    },
    {
        'device_ip': '192.168.1.60',
        'device_name': 'Smart Thermostat',
        'device_type': 'IoT Device',
        'mac_address': 'AA:BB:CC:DD:EE:60',
        'manufacturer': 'Nest'
    },
    {
        'device_ip': '192.168.1.70',
        'device_name': 'Xbox Console',
        'device_type': 'Gaming Console',
        'mac_address': 'AA:BB:CC:DD:EE:70',
        'manufacturer': 'Microsoft'
    },
    {
        'device_ip': '192.168.1.80',
        'device_name': 'Smart Fridge',
        'device_type': 'IoT Appliance',
        'mac_address': 'AA:BB:CC:DD:EE:80',
        'manufacturer': 'LG'
    },
    {
        'device_ip': '192.168.1.90',
        'device_name': 'Work Laptop',
        'device_type': 'Laptop',
        'mac_address': 'AA:BB:CC:DD:EE:90',
        'manufacturer': 'Dell'
    },
    {
        'device_ip': '192.168.1.100',
        'device_name': 'Guest Tablet',
        'device_type': 'Tablet',
        'mac_address': 'AA:BB:CC:DD:EE:A0',
        'manufacturer': 'Samsung'
    }
]

print("\n1. Creating devices...")
for device in devices:
    db.add_device(**device)
print(f"   ✓ Created {len(devices)} devices")

# ============================================================================
# 2. CREATE CONNECTIONS (REALISTIC PATTERNS)
# ============================================================================

print("\n2. Creating connections...")

# Common destinations
destinations = [
    ('8.8.8.8', 53, 'udp', 'dns'),           # Google DNS
    ('1.1.1.1', 53, 'udp', 'dns'),           # Cloudflare DNS
    ('142.250.80.46', 443, 'tcp', 'https'),  # Google
    ('157.240.22.35', 443, 'tcp', 'https'),  # Facebook
    ('13.107.42.14', 443, 'tcp', 'https'),   # Microsoft
    ('54.230.159.1', 443, 'tcp', 'https'),   # AWS/Netflix
    ('192.168.1.1', 80, 'tcp', 'http'),      # Router
]

connection_ids = []
now = datetime.now()

# Generate connections for last 24 hours
for hour_offset in range(24):
    connections_this_hour = random.randint(30, 80)

    for _ in range(connections_this_hour):
        # Random device
        device = random.choice(devices)

        # Random destination
        dest = random.choice(destinations)

        # Random timing within hour
        minutes = random.randint(0, 59)
        seconds = random.randint(0, 59)
        timestamp = now - timedelta(hours=hour_offset, minutes=minutes, seconds=seconds)

        # Realistic traffic patterns
        if device['device_type'] == 'Smart TV':
            bytes_sent = random.randint(1000, 50000)
            bytes_received = random.randint(500000, 5000000)  # Streaming
        elif device['device_type'] == 'IoT Camera':
            bytes_sent = random.randint(50000, 500000)  # Uploading video
            bytes_received = random.randint(1000, 10000)
        elif device['device_type'] == 'Laptop':
            bytes_sent = random.randint(10000, 100000)
            bytes_received = random.randint(10000, 500000)
        else:
            bytes_sent = random.randint(100, 10000)
            bytes_received = random.randint(100, 50000)

        conn_id = db.add_connection(
            device_ip=device['device_ip'],
            dest_ip=dest[0],
            dest_port=dest[1],
            protocol=dest[2],
            service=dest[3],
            duration=random.uniform(0.1, 30.0),
            bytes_sent=bytes_sent,
            bytes_received=bytes_received,
            packets_sent=random.randint(1, 100),
            packets_received=random.randint(1, 200),
            conn_state=random.choice(['SF', 'S0', 'REJ', 'RSTO'])
        )

        if conn_id:
            connection_ids.append(conn_id)

        # Manually set timestamp (SQLite default is now)
        cursor = db.conn.cursor()
        cursor.execute(
            "UPDATE connections SET timestamp = ? WHERE id = ?",
            (timestamp.isoformat(), conn_id)
        )

    db.conn.commit()

print(f"   ✓ Created {len(connection_ids)} connections over 24 hours")

# ============================================================================
# 3. CREATE ML PREDICTIONS
# ============================================================================

print("\n3. Creating ML predictions...")

prediction_count = 0
for conn_id in connection_ids:
    # 95% normal, 5% anomalous
    is_anomaly = random.random() < 0.05

    if is_anomaly:
        anomaly_score = random.uniform(-1.0, -0.3)  # River anomaly scores
    else:
        anomaly_score = random.uniform(0.3, 0.8)

    db.store_prediction(
        connection_id=conn_id,
        is_anomaly=is_anomaly,
        anomaly_score=anomaly_score,
        model_type='river'
    )
    prediction_count += 1

print(f"   ✓ Created {prediction_count} ML predictions")

# ============================================================================
# 4. CREATE ALERTS (VARIOUS SEVERITIES)
# ============================================================================

print("\n4. Creating security alerts...")

alert_templates = [
    {
        'severity': 'critical',
        'explanation': 'Device is communicating with known command & control server. Possible botnet infection.',
        'features': {'bytes_sent': 0.95, 'dest_ip_reputation': 0.89, 'unusual_port': 0.82}
    },
    {
        'severity': 'high',
        'explanation': 'Unusual data upload detected. Device sent 500MB in 1 hour (normal: 5MB/hour).',
        'features': {'bytes_sent': 0.88, 'bytes_per_second': 0.75, 'duration': 0.65}
    },
    {
        'severity': 'medium',
        'explanation': 'Device contacted 50 unique IPs in last hour (normal: 5 IPs/hour).',
        'features': {'unique_destinations': 0.72, 'connection_frequency': 0.68, 'protocol_diversity': 0.55}
    },
    {
        'severity': 'low',
        'explanation': 'Device active at unusual time. Typically offline between 2am-6am.',
        'features': {'hour_of_day': 0.45, 'day_of_week': 0.38, 'is_weekend': 0.32}
    }
]

alert_count = 0
for i in range(20):  # Create 20 alerts
    device = random.choice(devices)
    template = random.choice(alert_templates)

    # Spread alerts over last 7 days
    hours_ago = random.randint(1, 168)
    timestamp = now - timedelta(hours=hours_ago)

    alert_id = db.create_alert(
        device_ip=device['device_ip'],
        severity=template['severity'],
        anomaly_score=random.uniform(-1.0, -0.2),
        explanation=f"{device['device_name']}: {template['explanation']}",
        top_features=json.dumps(template['features'])
    )

    if alert_id:
        # Set custom timestamp
        cursor = db.conn.cursor()
        cursor.execute(
            "UPDATE alerts SET timestamp = ? WHERE id = ?",
            (timestamp.isoformat(), alert_id)
        )

        # 30% chance alert is acknowledged
        if random.random() < 0.3:
            cursor.execute(
                "UPDATE alerts SET acknowledged = 1, acknowledged_at = ? WHERE id = ?",
                (timestamp + timedelta(hours=random.randint(1, 24)), alert_id)
            )

        alert_count += 1

db.conn.commit()
print(f"   ✓ Created {alert_count} alerts (critical/high/medium/low)")

# ============================================================================
# SUMMARY
# ============================================================================

print("\n" + "=" * 70)
print("Test Data Summary:")
print("=" * 70)
print(f"  Devices:       {len(devices)}")
print(f"  Connections:   {len(connection_ids)}")
print(f"  Predictions:   {prediction_count}")
print(f"  Alerts:        {alert_count}")
print("=" * 70)
print(f"\nDatabase: {db.db_path}")
print("✓ Test data generation complete!")
print("\nYou can now run the dashboard:\n")
print("  python3 dashboard/app.py")
print("=" * 70)

db.close()
