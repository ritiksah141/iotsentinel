devices (
    device_ip PRIMARY KEY,
    device_name,
    mac_address,
    first_seen,
    last_seen,
    is_trusted
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
    conn_state,
    processed  -- 0 = needs ML analysis
)

alerts (
    id PRIMARY KEY,
    timestamp,
    device_ip → devices,
    severity,  -- low/medium/high/critical
    anomaly_score,
    explanation,
    top_features  -- JSON
)

ml_predictions (
    id PRIMARY KEY,
    connection_id → connections,
    is_anomaly,
    anomaly_score,
    model_type  -- autoencoder/isolation_forest
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
    ip TEXT PRIMARY KEY,
    source TEXT
)