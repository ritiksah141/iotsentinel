"""
Shared export data layer for IoTSentinel report generation.

Provides a single source of truth for the three core export datasets
(devices, alerts, connections). Each function executes the canonical
SELECT and returns sqlite3.Row rows — the same dict-style objects the
format-specific exporters (CSV / PDF / Excel) already use.

Eliminates the three near-identical query copies that previously existed
across report_generator.py, pdf_exporter.py, and excel_exporter.py.
"""

import sqlite3
import logging
from datetime import datetime, timedelta
from typing import List, Optional

logger = logging.getLogger(__name__)


def devices_dataset(db_manager) -> List[sqlite3.Row]:
    """
    Return all devices ordered by last-seen descending.

    Columns: device_ip, device_name, device_type, mac_address,
             manufacturer, first_seen, last_seen, is_trusted, is_blocked
    """
    try:
        cursor = db_manager.conn.cursor()
        cursor.execute("""
            SELECT
                device_ip,
                device_name,
                device_type,
                mac_address,
                manufacturer,
                first_seen,
                last_seen,
                is_trusted,
                is_blocked
            FROM devices
            ORDER BY last_seen DESC
        """)
        return cursor.fetchall()
    except sqlite3.Error as e:
        logger.error(f"report_datasets: error fetching devices: {e}")
        return []


def alerts_dataset(db_manager, days: int = 7) -> List[sqlite3.Row]:
    """
    Return alerts (with device_name join) from the last ``days`` days,
    ordered newest-first.

    Columns: id, timestamp, device_ip, device_name, severity,
             anomaly_score, explanation, acknowledged
    """
    try:
        cursor = db_manager.conn.cursor()
        cutoff = (datetime.now() - timedelta(days=days)).isoformat()
        cursor.execute("""
            SELECT
                a.id,
                a.timestamp,
                a.device_ip,
                d.device_name,
                a.severity,
                a.anomaly_score,
                a.explanation,
                a.acknowledged
            FROM alerts a
            LEFT JOIN devices d ON a.device_ip = d.device_ip
            WHERE a.timestamp > ?
            ORDER BY a.timestamp DESC
        """, (cutoff,))
        return cursor.fetchall()
    except sqlite3.Error as e:
        logger.error(f"report_datasets: error fetching alerts: {e}")
        return []


def connections_dataset(
    db_manager,
    device_ip: Optional[str] = None,
    hours: int = 24,
    limit: Optional[int] = None,
) -> List[sqlite3.Row]:
    """
    Return connection rows from the last ``hours`` hours.

    Columns (superset used by all formatters):
        timestamp, device_ip, dest_ip, dest_port, protocol, service,
        duration, bytes_sent, bytes_received, packets_sent,
        packets_received, conn_state

    Args:
        device_ip: Filter to a single source device; None = all devices.
        hours: Look-back window (default 24).
        limit: Row cap applied in SQL. None = no cap (CSV path).
               Pass 500 for PDF, 5000 for Excel to match original limits.
    """
    try:
        cursor = db_manager.conn.cursor()
        cutoff = (datetime.now() - timedelta(hours=hours)).isoformat()

        base = """
            SELECT
                timestamp,
                device_ip,
                dest_ip,
                dest_port,
                protocol,
                service,
                duration,
                bytes_sent,
                bytes_received,
                packets_sent,
                packets_received,
                conn_state
            FROM connections
        """
        if device_ip:
            sql = base + "WHERE device_ip = ? AND timestamp > ? ORDER BY timestamp DESC"
            params: tuple = (device_ip, cutoff)
        else:
            sql = base + "WHERE timestamp > ? ORDER BY timestamp DESC"
            params = (cutoff,)

        if limit is not None:
            sql += f" LIMIT {int(limit)}"

        cursor.execute(sql, params)
        return cursor.fetchall()
    except sqlite3.Error as e:
        logger.error(f"report_datasets: error fetching connections: {e}")
        return []
