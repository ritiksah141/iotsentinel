#!/usr/bin/env python3
"""
Database Query Optimizer for IoTSentinel

Provides query optimization strategies for large datasets including:
- Index management
- Query result caching
- Batch operations
- Efficient query patterns
"""

import sqlite3
import logging
from typing import Dict, List, Any, Optional, Tuple
from datetime import datetime, timedelta
from contextlib import contextmanager

logger = logging.getLogger(__name__)


class QueryOptimizer:
    """
    Optimizes database queries for better performance with large datasets.
    """

    def __init__(self, db_path: str):
        """
        Initialize query optimizer.

        Args:
            db_path: Path to SQLite database
        """
        self.db_path = db_path
        self._initialize_indexes()
        self._optimize_database_settings()

    def _get_connection(self) -> sqlite3.Connection:
        """Get database connection with optimized settings."""
        conn = sqlite3.connect(
            self.db_path,
            check_same_thread=False,
            timeout=30.0
        )
        conn.row_factory = sqlite3.Row
        return conn

    @contextmanager
    def get_connection(self):
        """
        Context manager for database connections.

        Usage:
            with optimizer.get_connection() as conn:
                cursor = conn.cursor()
                ...
        """
        conn = self._get_connection()
        try:
            yield conn
            conn.commit()
        except Exception as e:
            conn.rollback()
            logger.error(f"Database error: {e}")
            raise
        finally:
            conn.close()

    def _initialize_indexes(self):
        """Create optimized indexes for frequently queried columns."""
        indexes = [
            # Alerts table indexes
            ("idx_alerts_timestamp", "CREATE INDEX IF NOT EXISTS idx_alerts_timestamp ON alerts(timestamp DESC)"),
            ("idx_alerts_severity", "CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts(severity)"),
            ("idx_alerts_device", "CREATE INDEX IF NOT EXISTS idx_alerts_device_ip ON alerts(device_ip)"),
            ("idx_alerts_composite", "CREATE INDEX IF NOT EXISTS idx_alerts_composite ON alerts(timestamp DESC, severity, device_ip)"),

            # Connections table indexes
            ("idx_connections_timestamp", "CREATE INDEX IF NOT EXISTS idx_connections_timestamp ON connections(timestamp DESC)"),
            ("idx_connections_device", "CREATE INDEX IF NOT EXISTS idx_connections_device_ip ON connections(device_ip)"),
            ("idx_connections_dest", "CREATE INDEX IF NOT EXISTS idx_connections_dest_ip ON connections(dest_ip)"),
            ("idx_connections_port", "CREATE INDEX IF NOT EXISTS idx_connections_dest_port ON connections(dest_port)"),
            ("idx_connections_composite", "CREATE INDEX IF NOT EXISTS idx_connections_composite ON connections(device_ip, timestamp DESC)"),

            # Devices table indexes
            ("idx_devices_last_seen", "CREATE INDEX IF NOT EXISTS idx_devices_last_seen ON devices(last_seen DESC)"),
            ("idx_devices_first_seen", "CREATE INDEX IF NOT EXISTS idx_devices_first_seen ON devices(first_seen)"),
            ("idx_devices_status", "CREATE INDEX IF NOT EXISTS idx_devices_status ON devices(is_blocked, is_trusted)"),
            ("idx_devices_type", "CREATE INDEX IF NOT EXISTS idx_devices_type ON devices(device_type)"),
        ]

        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()

                for index_name, create_sql in indexes:
                    try:
                        cursor.execute(create_sql)
                        logger.debug(f"Created/verified index: {index_name}")
                    except sqlite3.Error as e:
                        logger.warning(f"Could not create index {index_name}: {e}")

                logger.info(f"Database indexes initialized ({len(indexes)} indexes)")

        except Exception as e:
            logger.error(f"Error initializing indexes: {e}")

    def _optimize_database_settings(self):
        """Apply database-level optimizations."""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()

                # Enable WAL mode for better concurrency
                cursor.execute("PRAGMA journal_mode = WAL")

                # Increase cache size (10MB)
                cursor.execute("PRAGMA cache_size = -10000")

                # Optimize for read-heavy workloads
                cursor.execute("PRAGMA temp_store = MEMORY")

                # Reduce fsync calls
                cursor.execute("PRAGMA synchronous = NORMAL")

                logger.info("Database optimization settings applied")

        except Exception as e:
            logger.error(f"Error applying database optimizations: {e}")

    def get_alerts_optimized(
        self,
        limit: int = 1000,
        offset: int = 0,
        filters: Optional[Dict[str, Any]] = None
    ) -> List[Dict[str, Any]]:
        """
        Get alerts with optimized query and pagination.

        Args:
            limit: Maximum number of results
            offset: Result offset for pagination
            filters: Optional filters (severity, device_ip, start_date, end_date)

        Returns:
            List of alert dictionaries
        """
        filters = filters or {}

        # Build query with indexed columns
        where_clauses = []
        params = []

        if 'severity' in filters:
            where_clauses.append("severity = ?")
            params.append(filters['severity'])

        if 'device_ip' in filters:
            where_clauses.append("device_ip = ?")
            params.append(filters['device_ip'])

        if 'start_date' in filters:
            where_clauses.append("timestamp >= ?")
            params.append(filters['start_date'])

        if 'end_date' in filters:
            where_clauses.append("timestamp <= ?")
            params.append(filters['end_date'])

        where_sql = " AND ".join(where_clauses) if where_clauses else "1=1"

        # Use covering index by selecting only necessary columns
        query = f"""
            SELECT id, timestamp, severity, device_ip,
                   anomaly_score, details
            FROM alerts
            WHERE {where_sql}
            ORDER BY timestamp DESC
            LIMIT ? OFFSET ?
        """

        params.extend([limit, offset])

        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute(query, params)

                alerts = []
                for row in cursor.fetchall():
                    alerts.append(dict(row))

                return alerts

        except Exception as e:
            logger.error(f"Error fetching alerts: {e}")
            return []

    def get_connections_optimized(
        self,
        limit: int = 1000,
        offset: int = 0,
        filters: Optional[Dict[str, Any]] = None
    ) -> List[Dict[str, Any]]:
        """
        Get connections with optimized query and pagination.

        Args:
            limit: Maximum number of results
            offset: Result offset for pagination
            filters: Optional filters (device_ip, dest_port, start_date, end_date)

        Returns:
            List of connection dictionaries
        """
        filters = filters or {}

        where_clauses = []
        params = []

        if 'device_ip' in filters:
            where_clauses.append("device_ip = ?")
            params.append(filters['device_ip'])

        if 'dest_port' in filters:
            where_clauses.append("dest_port = ?")
            params.append(filters['dest_port'])

        if 'start_date' in filters:
            where_clauses.append("timestamp >= ?")
            params.append(filters['start_date'])

        if 'end_date' in filters:
            where_clauses.append("timestamp <= ?")
            params.append(filters['end_date'])

        where_sql = " AND ".join(where_clauses) if where_clauses else "1=1"

        query = f"""
            SELECT id, timestamp, device_ip, dest_ip, dest_port,
                   protocol, bytes_sent, bytes_received
            FROM connections
            WHERE {where_sql}
            ORDER BY timestamp DESC
            LIMIT ? OFFSET ?
        """

        params.extend([limit, offset])

        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute(query, params)

                connections = []
                for row in cursor.fetchall():
                    connections.append(dict(row))

                return connections

        except Exception as e:
            logger.error(f"Error fetching connections: {e}")
            return []

    def get_aggregated_alerts(
        self,
        days: int = 30,
        granularity: str = 'daily'
    ) -> List[Tuple[str, int, str]]:
        """
        Get aggregated alert counts using optimized grouping.

        Args:
            days: Number of days to analyze
            granularity: 'hourly', 'daily', or 'weekly'

        Returns:
            List of (time_bucket, count, severity) tuples
        """
        cutoff = datetime.now() - timedelta(days=days)
        cutoff_str = cutoff.strftime('%Y-%m-%d %H:%M:%S')

        if granularity == 'hourly':
            time_format = '%Y-%m-%d %H:00:00'
        elif granularity == 'weekly':
            time_format = '%Y-W%W'
        else:
            time_format = '%Y-%m-%d'

        # Optimized query using indexed timestamp column
        query = """
            SELECT
                strftime(?, timestamp) as time_bucket,
                COUNT(*) as alert_count,
                severity
            FROM alerts
            WHERE timestamp >= ?
            GROUP BY time_bucket, severity
            ORDER BY time_bucket
        """

        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute(query, (time_format, cutoff_str))
                return cursor.fetchall()

        except Exception as e:
            logger.error(f"Error getting aggregated alerts: {e}")
            return []

    def get_top_devices_by_activity(
        self,
        days: int = 7,
        limit: int = 10
    ) -> List[Tuple[str, int]]:
        """
        Get most active devices using optimized query.

        Args:
            days: Number of days to analyze
            limit: Maximum number of devices to return

        Returns:
            List of (device_ip, connection_count) tuples
        """
        cutoff = datetime.now() - timedelta(days=days)
        cutoff_str = cutoff.strftime('%Y-%m-%d %H:%M:%S')

        # Use indexed device_ip and timestamp columns
        query = """
            SELECT device_ip, COUNT(*) as conn_count
            FROM connections
            WHERE timestamp >= ?
            GROUP BY device_ip
            ORDER BY conn_count DESC
            LIMIT ?
        """

        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute(query, (cutoff_str, limit))
                return cursor.fetchall()

        except Exception as e:
            logger.error(f"Error getting top devices: {e}")
            return []

    def analyze_query_performance(self, query: str, params: Tuple = ()) -> Dict[str, Any]:
        """
        Analyze query performance using EXPLAIN QUERY PLAN.

        Args:
            query: SQL query to analyze
            params: Query parameters

        Returns:
            Dictionary with performance analysis
        """
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()

                # Get query plan
                cursor.execute(f"EXPLAIN QUERY PLAN {query}", params)
                query_plan = cursor.fetchall()

                # Execute query and measure time
                import time
                start_time = time.time()
                cursor.execute(query, params)
                cursor.fetchall()
                execution_time = time.time() - start_time

                return {
                    'query_plan': [dict(row) for row in query_plan],
                    'execution_time_seconds': execution_time,
                    'uses_index': any('USING INDEX' in str(row) for row in query_plan)
                }

        except Exception as e:
            logger.error(f"Error analyzing query: {e}")
            return {'error': str(e)}

    def vacuum_database(self):
        """Optimize database file by running VACUUM."""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                logger.info("Running VACUUM to optimize database...")
                cursor.execute("VACUUM")
                logger.info("Database optimization complete")

        except Exception as e:
            logger.error(f"Error running VACUUM: {e}")

    def get_database_stats(self) -> Dict[str, Any]:
        """
        Get database statistics.

        Returns:
            Dictionary with database statistics
        """
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()

                # Get table sizes
                cursor.execute("""
                    SELECT name, COUNT(*) as row_count
                    FROM (
                        SELECT 'alerts' as name FROM alerts
                        UNION ALL
                        SELECT 'connections' as name FROM connections
                        UNION ALL
                        SELECT 'devices' as name FROM devices
                    )
                    GROUP BY name
                """)
                table_counts = {row['name']: row['row_count'] for row in cursor.fetchall()}

                # Get database page stats
                cursor.execute("PRAGMA page_count")
                page_count = cursor.fetchone()[0]

                cursor.execute("PRAGMA page_size")
                page_size = cursor.fetchone()[0]

                # Get index list
                cursor.execute("""
                    SELECT name, tbl_name
                    FROM sqlite_master
                    WHERE type = 'index'
                    AND name LIKE 'idx_%'
                """)
                indexes = [dict(row) for row in cursor.fetchall()]

                db_size_mb = (page_count * page_size) / (1024 * 1024)

                return {
                    'table_counts': table_counts,
                    'database_size_mb': round(db_size_mb, 2),
                    'indexes': indexes,
                    'page_count': page_count,
                    'page_size': page_size
                }

        except Exception as e:
            logger.error(f"Error getting database stats: {e}")
            return {}
