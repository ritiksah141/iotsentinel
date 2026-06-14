#!/usr/bin/env python3
"""
Natural Language to SQL Query Generator
Enhances HybridAI with database schema awareness and safe SQL generation
"""

import logging
import re
from typing import Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)


class NLtoSQLGenerator:
    """
    Converts natural language queries to safe SQL with injection prevention.

    Features:
    - Schema-aware query generation
    - SQL injection prevention
    - Query validation and sanitization
    - Support for common IoT security queries
    """

    # Database schema (IoTSentinel)
    SCHEMA = {
        'devices': {
            'columns': ['device_ip', 'mac_address', 'device_type', 'manufacturer', 'first_seen',
                       'last_seen', 'trust_level', 'risk_score', 'is_trusted'],
            'description': 'Network devices and their properties'
        },
        'connections': {
            'columns': ['id', 'device_ip', 'dest_ip', 'dest_port', 'protocol', 'bytes_sent',
                       'bytes_received', 'duration', 'timestamp'],
            'description': 'Network connections and traffic data'
        },
        'alerts': {
            'columns': ['id', 'device_ip', 'severity', 'explanation', 'anomaly_score',
                       'timestamp', 'acknowledged', 'details'],
            'description': 'Security alerts and anomalies'
        },
        'threat_intel': {
            'columns': ['ip_address', 'abuse_confidence_score', 'country', 'is_malicious',
                       'last_checked', 'reports_count'],
            'description': 'Threat intelligence data for external IPs'
        }
    }

    # Query templates (safe parameterized queries)
    QUERY_TEMPLATES = {
        'high_risk_devices': {
            'pattern': r'(high|critical|dangerous|risky) ?(risk|threat)? ?(devices|iot)',
            'sql': "SELECT device_ip, device_type, risk_score, trust_level FROM devices WHERE risk_score > 70 ORDER BY risk_score DESC LIMIT 10",
            'description': 'Find high-risk devices'
        },
        'recent_alerts': {
            'pattern': r'(recent|latest|new) ?(alerts|warnings|threats)',
            'sql': "SELECT device_ip, severity, explanation, timestamp FROM alerts WHERE timestamp >= datetime('now', '-24 hours') ORDER BY timestamp DESC LIMIT 20",
            'description': 'Show recent security alerts'
        },
        'untrusted_devices': {
            'pattern': r'(untrusted|unknown|unverified) ?(devices)',
            'sql': "SELECT device_ip, device_type, manufacturer, last_seen FROM devices WHERE is_trusted = 0 ORDER BY last_seen DESC LIMIT 20",
            'description': 'List untrusted devices'
        },
        'top_talkers': {
            'pattern': r'(top|highest|most) ?(traffic|bandwidth|data|talkers)',
            'sql': "SELECT device_ip, SUM(bytes_sent + bytes_received) as total_bytes, COUNT(*) as connection_count FROM connections WHERE timestamp >= datetime('now', '-24 hours') GROUP BY device_ip ORDER BY total_bytes DESC LIMIT 10",
            'description': 'Find devices with highest traffic'
        },
        'external_connections': {
            'pattern': r'(external|outside|internet) ?(connections|traffic)',
            'sql': "SELECT device_ip, dest_ip, dest_port, protocol, COUNT(*) as count FROM connections WHERE dest_ip NOT LIKE '192.168.%' AND dest_ip NOT LIKE '10.%' AND timestamp >= datetime('now', '-1 hour') GROUP BY device_ip, dest_ip ORDER BY count DESC LIMIT 20",
            'description': 'Show external connections'
        },
        'malicious_ips': {
            'pattern': r'(malicious|bad|threat|dangerous) ?(ips|addresses|connections)',
            'sql': "SELECT c.device_ip, c.dest_ip, t.abuse_confidence_score, t.country, COUNT(*) as attempts FROM connections c JOIN threat_intel t ON c.dest_ip = t.ip_address WHERE t.is_malicious = 1 AND c.timestamp >= datetime('now', '-24 hours') GROUP BY c.device_ip, c.dest_ip ORDER BY attempts DESC LIMIT 15",
            'description': 'Show connections to known malicious IPs'
        },
        'device_count': {
            'pattern': r'how many ?(devices|iot)',
            'sql': "SELECT COUNT(*) as total_devices, COUNT(CASE WHEN is_trusted = 1 THEN 1 END) as trusted, COUNT(CASE WHEN is_trusted = 0 THEN 1 END) as untrusted FROM devices",
            'description': 'Count total devices'
        },
        'alert_summary': {
            'pattern': r'(alert|security) ?(summary|stats|statistics)',
            'sql': "SELECT severity, COUNT(*) as count FROM alerts WHERE timestamp >= datetime('now', '-24 hours') GROUP BY severity ORDER BY CASE severity WHEN 'critical' THEN 1 WHEN 'high' THEN 2 WHEN 'medium' THEN 3 ELSE 4 END",
            'description': 'Alert statistics by severity'
        },
        'port_scan_attempts': {
            'pattern': r'(port|scan|scanning) ?(attempts|activity)',
            'sql': "SELECT device_ip, COUNT(DISTINCT dest_port) as unique_ports, COUNT(*) as attempts FROM connections WHERE timestamp >= datetime('now', '-1 hour') GROUP BY device_ip HAVING unique_ports > 10 ORDER BY unique_ports DESC LIMIT 10",
            'description': 'Detect potential port scanning'
        },
        'device_details': {
            'pattern': r'(show|get|display) ?(device|details|info)',
            'sql': "SELECT device_ip, device_type, manufacturer, trust_level, risk_score, first_seen, last_seen FROM devices ORDER BY last_seen DESC LIMIT 20",
            'description': 'Show device details'
        },
        'traffic_by_protocol': {
            'pattern': r'(traffic|connections) ?(by|per) ?(protocol)',
            'sql': "SELECT protocol, COUNT(*) as count, SUM(bytes_sent + bytes_received) as total_bytes FROM connections WHERE timestamp >= datetime('now', '-24 hours') GROUP BY protocol ORDER BY total_bytes DESC",
            'description': 'Traffic breakdown by protocol'
        },
        'devices_by_type': {
            'pattern': r'(devices|count) ?(by|per) ?(type|category)',
            'sql': "SELECT device_type, COUNT(*) as count, AVG(risk_score) as avg_risk FROM devices GROUP BY device_type ORDER BY count DESC",
            'description': 'Device count by type'
        }
    }

    # Dangerous SQL keywords (for injection prevention)
    BLOCKED_KEYWORDS = [
        'DROP', 'DELETE', 'INSERT', 'UPDATE', 'ALTER', 'CREATE', 'TRUNCATE',
        'EXEC', 'EXECUTE', 'GRANT', 'REVOKE', '--', ';--', '/*', '*/'
    ]

    def __init__(self, db_manager=None, ai_assistant=None):
        """
        Initialize NL to SQL generator.

        Args:
            db_manager: DatabaseManager instance for query execution
            ai_assistant: Optional HybridAIAssistant for LLM-powered SQL generation
        """
        self.db = db_manager
        self.ai = ai_assistant
        logger.info("NLtoSQLGenerator initialized with IoTSentinel schema")

    def parse_query(self, natural_query: str) -> Dict:
        """
        Parse natural language query and generate SQL.

        Args:
            natural_query: User's natural language question

        Returns:
            Dict with SQL query, description, and safety status
        """
        query_lower = natural_query.lower().strip()

        # Check for blocked keywords (SQL injection prevention)
        if self._contains_blocked_keywords(query_lower):
            return {
                'status': 'blocked',
                'reason': 'Query contains potentially dangerous SQL keywords',
                'sql': None
            }

        # Try matching against templates
        for template_name, template_data in self.QUERY_TEMPLATES.items():
            pattern = template_data['pattern']
            if re.search(pattern, query_lower):
                return {
                    'status': 'success',
                    'sql': template_data['sql'],
                    'description': template_data['description'],
                    'template': template_name,
                    'safe': True
                }

        # Check for IP address queries
        ip_match = self._extract_ip_address(query_lower)
        if ip_match:
            return self._generate_ip_query(ip_match)

        # Check for time-based queries
        time_query = self._parse_time_query(query_lower)
        if time_query:
            return time_query

        # No match found
        return {
            'status': 'no_match',
            'reason': 'Could not understand query. Try asking about: high-risk devices, recent alerts, traffic stats, or specific IP addresses.',
            'sql': None,
            'suggestions': [
                'Show me high-risk devices',
                'What are the recent alerts?',
                'Show top traffic talkers',
                'List untrusted devices',
                'Show external connections'
            ]
        }

    # ------------------------------------------------------------------
    # LLM-powered SQL generation with strict read-only guardrails
    # ------------------------------------------------------------------

    def validate_sql(self, sql: str) -> Tuple[bool, str]:
        """
        Validate that a SQL string is safe to execute (SELECT-only, no injection).

        Returns (True, cleaned_sql) or (False, reason_string).
        """
        if not sql or not sql.strip():
            return False, "Empty SQL"

        cleaned = sql.strip().rstrip(';')

        # Must start with SELECT
        if not cleaned.upper().startswith('SELECT'):
            return False, "Only SELECT queries are allowed"

        # Must be a single statement (no semicolons mid-query)
        if ';' in cleaned:
            return False, "Multi-statement queries are not allowed"

        upper = cleaned.upper()

        # Blocked write/admin keywords
        for kw in self.BLOCKED_KEYWORDS:
            if kw in upper:
                return False, f"Blocked keyword detected: {kw}"

        # All referenced tables must be in the known schema
        table_words = re.findall(
            r'\b(?:FROM|JOIN)\s+([a-zA-Z_][a-zA-Z0-9_]*)', cleaned, re.IGNORECASE
        )
        known_tables = set(self.SCHEMA.keys())
        for tbl in table_words:
            if tbl.lower() not in known_tables:
                return False, f"Unknown table referenced: {tbl}"

        # Force LIMIT if missing (safety cap)
        if 'LIMIT' not in upper:
            cleaned += ' LIMIT 100'

        return True, cleaned

    def generate_sql_llm(self, natural_query: str) -> Optional[str]:
        """
        Use the AI assistant to generate a safe SELECT query.
        Returns the validated SQL string, or None if unavailable/invalid.
        """
        if self.ai is None:
            return None

        schema_summary = '\n'.join(
            f"  {tbl}({', '.join(info['columns'])})"
            for tbl, info in self.SCHEMA.items()
        )

        prompt = (
            f"Convert the following question into a single SQLite SELECT query.\n"
            f"Rules:\n"
            f"  1. Output ONLY the SQL query, nothing else - no explanation, no markdown.\n"
            f"  2. Use only SELECT (no INSERT, UPDATE, DELETE, DROP, etc.).\n"
            f"  3. Only reference these tables:\n{schema_summary}\n"
            f"  4. Always include LIMIT 50 unless the user asks for more.\n"
            f"  5. Use datetime('now', '-N hours/days') for time filters.\n\n"
            f"Question: {natural_query}"
        )
        try:
            sql_raw, _ = self.ai.get_response(
                prompt=prompt, max_tokens=150, temperature=0.1
            )
        except Exception as e:
            logger.warning(f"LLM SQL generation failed: {e}")
            return None

        if not sql_raw:
            return None

        # Strip any markdown code fences the LLM might have added
        sql_clean = re.sub(r'```(?:sql)?', '', sql_raw, flags=re.IGNORECASE).strip().strip('`')
        # Take only the first line that starts with SELECT (discard explanation text)
        for line in sql_clean.splitlines():
            if line.strip().upper().startswith('SELECT'):
                sql_clean = line.strip()
                break

        valid, result = self.validate_sql(sql_clean)
        if valid:
            return result
        logger.debug(f"LLM SQL failed validation ({result}): {sql_clean}")
        return None

    def answer_in_plain_english(self, natural_query: str, results: Dict) -> str:
        """
        Given a NL query and the DB results, produce a 1-2 sentence plain-English answer.
        Falls back to the structured table format if AI unavailable or fails.
        No em dashes, no markdown bold.
        """
        if self.ai is None or results.get('status') != 'success':
            return ""

        rows = results.get('results', [])
        row_count = results.get('row_count', 0)
        description = results.get('description', '')

        # Compact representation for the prompt
        if rows:
            sample = rows[:5]
            row_text = '; '.join(
                ', '.join(f"{k}={v}" for k, v in row.items() if v is not None)
                for row in sample
            )
            if row_count > 5:
                row_text += f' ... ({row_count} total rows)'
        else:
            row_text = 'No results found.'

        prompt = (
            f"Answer this home network question in 1-2 plain sentences using the data below.\n"
            f"No em dashes, no markdown, no jargon.\n\n"
            f"Question: {natural_query}\n"
            f"Data ({description}): {row_text}"
        )
        try:
            answer, _ = self.ai.get_response(prompt=prompt, max_tokens=80, temperature=0.3)
            if answer:
                return answer.replace('—', '-').replace('–', '-').replace('**', '')
        except Exception:
            pass
        return ""

    def execute_query(self, natural_query: str, max_results: int = 100) -> Dict:
        """
        Parse and execute natural language query.

        Args:
            natural_query: User's question
            max_results: Maximum rows to return

        Returns:
            Query results dict
        """
        if not self.db:
            return {
                'status': 'error',
                'error': 'Database manager not configured'
            }

        # 1. Try LLM-powered SQL first (falls back to regex templates if unavailable)
        llm_sql = self.generate_sql_llm(natural_query)
        if llm_sql:
            try:
                cursor = self.db.conn.cursor()
                cursor.execute(llm_sql)
                rows = cursor.fetchall()
                columns = self._extract_column_names(llm_sql)
                results = [
                    {col: (row[i] if i < len(row) else None) for i, col in enumerate(columns)}
                    for row in rows[:max_results]
                ]
                return {
                    'status': 'success',
                    'query': natural_query,
                    'sql': llm_sql,
                    'description': f"Results for: {natural_query}",
                    'results': results,
                    'row_count': len(results),
                    'columns': columns,
                    'source': 'llm',
                }
            except Exception as e:
                logger.debug(f"LLM SQL execution failed, falling back to templates: {e}")

        # 2. Fall back to regex template matcher
        parsed = self.parse_query(natural_query)

        if parsed['status'] != 'success':
            return parsed

        # Execute SQL
        try:
            sql = parsed['sql']

            # Add LIMIT if not present (safety measure)
            if 'LIMIT' not in sql.upper():
                sql += f" LIMIT {max_results}"

            cursor = self.db.conn.cursor()
            cursor.execute(sql)
            results = cursor.fetchall()

            # Get column names (extract from SQL or use default)
            columns = self._extract_column_names(sql)

            # Format results
            formatted_results = []
            for row in results[:max_results]:
                row_dict = {}
                for i, col in enumerate(columns):
                    row_dict[col] = row[i] if i < len(row) else None
                formatted_results.append(row_dict)

            return {
                'status': 'success',
                'query': natural_query,
                'sql': sql,
                'description': parsed.get('description', ''),
                'results': formatted_results,
                'row_count': len(formatted_results),
                'columns': columns
            }

        except Exception as e:
            logger.error(f"Error executing NL query: {e}")
            return {
                'status': 'error',
                'error': str(e),
                'sql': parsed['sql']
            }

    def _contains_blocked_keywords(self, query: str) -> bool:
        """Check if query contains dangerous SQL keywords."""
        query_upper = query.upper()
        return any(keyword in query_upper for keyword in self.BLOCKED_KEYWORDS)

    def _extract_ip_address(self, query: str) -> Optional[str]:
        """Extract IP address from query."""
        ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
        match = re.search(ip_pattern, query)
        return match.group(0) if match else None

    def _generate_ip_query(self, ip_address: str) -> Dict:
        """Generate query for specific IP address."""
        # Sanitize IP (prevent injection)
        if not re.match(r'^(\d{1,3}\.){3}\d{1,3}$', ip_address):
            return {
                'status': 'error',
                'reason': 'Invalid IP address format'
            }

        sql = f"""
        SELECT
            d.device_ip, d.device_type, d.manufacturer, d.trust_level, d.risk_score,
            COUNT(c.id) as connection_count,
            SUM(c.bytes_sent + c.bytes_received) as total_bytes,
            MAX(c.timestamp) as last_connection
        FROM devices d
        LEFT JOIN connections c ON d.device_ip = c.device_ip
        WHERE d.device_ip = '{ip_address}'
        GROUP BY d.device_ip
        """

        return {
            'status': 'success',
            'sql': sql,
            'description': f'Information about device {ip_address}',
            'safe': True
        }

    def _parse_time_query(self, query: str) -> Optional[Dict]:
        """Parse time-based queries (last hour, today, etc.)."""
        time_patterns = {
            r'last ?(hour|1h)': '-1 hour',
            r'last ?(day|24h)': '-24 hours',
            r'last ?(week|7d)': '-7 days',
            r'today': '-1 day',
            r'this ?(week)': '-7 days'
        }

        for pattern, time_offset in time_patterns.items():
            if re.search(pattern, query):
                # Check what data they want
                if 'alert' in query:
                    sql = f"SELECT device_ip, severity, explanation, timestamp FROM alerts WHERE timestamp >= datetime('now', '{time_offset}') ORDER BY timestamp DESC LIMIT 50"
                    desc = f"Alerts from {time_offset}"
                elif 'connection' in query or 'traffic' in query:
                    sql = f"SELECT device_ip, dest_ip, protocol, bytes_sent, bytes_received, timestamp FROM connections WHERE timestamp >= datetime('now', '{time_offset}') ORDER BY timestamp DESC LIMIT 50"
                    desc = f"Connections from {time_offset}"
                else:
                    continue

                return {
                    'status': 'success',
                    'sql': sql,
                    'description': desc,
                    'safe': True
                }

        return None

    def _extract_column_names(self, sql: str) -> List[str]:
        """Extract column names from SELECT statement."""
        try:
            # Simple regex to extract SELECT columns
            select_match = re.search(r'SELECT\s+(.*?)\s+FROM', sql, re.IGNORECASE | re.DOTALL)
            if select_match:
                columns_str = select_match.group(1)
                # Split by comma, extract column names/aliases
                columns = []
                for col in columns_str.split(','):
                    col = col.strip()
                    # Check for AS alias
                    if ' as ' in col.lower():
                        alias = col.split(' as ')[-1].strip()
                        columns.append(alias)
                    # Check for table.column notation
                    elif '.' in col:
                        columns.append(col.split('.')[-1].strip())
                    else:
                        # Remove functions like COUNT(*), SUM(), etc.
                        col = re.sub(r'^\w+\(', '', col)
                        col = re.sub(r'\)$', '', col)
                        columns.append(col.strip())
                return columns
        except Exception as e:
            logger.error(f"Error extracting columns: {e}")

        # Default fallback
        return ['col1', 'col2', 'col3', 'col4', 'col5']

    def get_schema_info(self) -> Dict:
        """Get database schema information for AI context."""
        return {
            'tables': self.SCHEMA,
            'available_queries': list(self.QUERY_TEMPLATES.keys()),
            'example_questions': [
                'Show me high-risk devices',
                'What are the recent alerts?',
                'Show top traffic talkers in the last 24 hours',
                'List all untrusted devices',
                'Show connections to external IPs',
                'Show me alert statistics',
                'What devices are scanning ports?'
            ]
        }

    def format_results_as_text(self, results: Dict) -> str:
        """
        Format query results as human-readable text.

        Args:
            results: Query execution results

        Returns:
            Formatted text string
        """
        if results['status'] != 'success':
            if 'suggestions' in results:
                return f"❌ {results['reason']}\n\n💡 Try asking:\n" + "\n".join(f"  • {s}" for s in results['suggestions'])
            return f"❌ {results.get('reason', results.get('error', 'Unknown error'))}"

        output = []
        output.append(f"📊 **{results['description']}**")
        output.append(f"Found {results['row_count']} result(s):\n")

        # Format as table
        if results['results']:
            columns = results['columns']

            # Header
            output.append(" | ".join(columns))
            output.append("-" * (len(" | ".join(columns)) + 10))

            # Rows (limit to 10 for readability)
            for row in results['results'][:10]:
                row_values = [str(row.get(col, ''))[:30] for col in columns]  # Truncate long values
                output.append(" | ".join(row_values))

            if len(results['results']) > 10:
                output.append(f"\n... and {len(results['results']) - 10} more row(s)")

        return "\n".join(output)
