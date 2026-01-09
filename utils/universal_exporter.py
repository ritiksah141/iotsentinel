#!/usr/bin/env python3
"""
Universal Exporter for IoTSentinel

Provides a unified interface for exporting data in multiple formats:
CSV, JSON, PDF, and Excel. All data is fetched fresh from the database.
"""

import json
import logging
from datetime import datetime
from typing import Dict, Any, Optional, Literal
from pathlib import Path

from .report_generator import ReportGenerator
from .pdf_exporter import PDFExporter
from .excel_exporter import ExcelExporter

logger = logging.getLogger(__name__)

ExportFormat = Literal['csv', 'json', 'pdf', 'excel']
ExportType = Literal['devices', 'alerts', 'connections', 'alert_rules', 'security_summary']


class UniversalExporter:
    """
    Universal export handler supporting multiple formats and data types.

    Provides a single interface for all export operations with consistent
    data fetching from the database.
    """

    def __init__(self, db_path: str = None, db_manager=None):
        """
        Initialize universal exporter.

        Args:
            db_path: Path to SQLite database (legacy)
            db_manager: DatabaseManager instance (preferred)
        """
        if db_manager is not None:
            self.db_manager = db_manager
            self.db_path = None
        else:
            from database.db_manager import DatabaseManager
            self.db_manager = DatabaseManager(db_path=db_path)
            self.db_path = db_path

        self.report_gen = ReportGenerator(db_manager=self.db_manager)

        # Initialize format-specific exporters lazily
        self._pdf_exporter = None
        self._excel_exporter = None

    @property
    def pdf_exporter(self) -> PDFExporter:
        """Get PDF exporter instance (lazy initialization)."""
        if self._pdf_exporter is None:
            self._pdf_exporter = PDFExporter(db_manager=self.db_manager)
        return self._pdf_exporter

    @property
    def excel_exporter(self) -> ExcelExporter:
        """Get Excel exporter instance (lazy initialization)."""
        if self._excel_exporter is None:
            self._excel_exporter = ExcelExporter(db_manager=self.db_manager)
        return self._excel_exporter

    def export_devices(
        self,
        format: ExportFormat = 'csv',
        include_metadata: bool = True
    ) -> Dict[str, Any]:
        """
        Export device inventory in specified format.

        Args:
            format: Export format ('csv', 'json', 'pdf', 'excel')
            include_metadata: Include metadata in export

        Returns:
            Dictionary with 'content', 'filename', and 'mimetype'
        """
        try:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')

            if format == 'csv':
                content = self.report_gen.export_devices_csv()
                return {
                    'content': content,
                    'filename': f'devices_{timestamp}.csv',
                    'mimetype': 'text/csv'
                }

            elif format == 'json':
                # Get devices and convert to JSON
                import sqlite3
                conn = self.db_manager.conn

                cursor = conn.cursor()

                cursor.execute("""
                    SELECT
                        device_ip, device_name, device_type, mac_address,
                        manufacturer, first_seen, last_seen, is_trusted, is_blocked
                    FROM devices
                    ORDER BY last_seen DESC
                """)

                devices = [dict(row) for row in cursor.fetchall()]

                export_data = {
                    'export_type': 'devices',
                    'generated_at': datetime.now().isoformat(),
                    'total_count': len(devices),
                    'devices': devices
                } if include_metadata else devices

                content = json.dumps(export_data, indent=2, default=str)
                return {
                    'content': content,
                    'filename': f'devices_{timestamp}.json',
                    'mimetype': 'application/json'
                }

            elif format == 'pdf':
                content = self.pdf_exporter.export_devices_pdf()
                return {
                    'content': content,
                    'filename': f'devices_{timestamp}.pdf',
                    'mimetype': 'application/pdf'
                }

            elif format == 'excel':
                content = self.excel_exporter.export_devices_excel()
                return {
                    'content': content,
                    'filename': f'devices_{timestamp}.xlsx',
                    'mimetype': 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
                }

            else:
                raise ValueError(f"Unsupported format: {format}")

        except Exception as e:
            logger.error(f"Error exporting devices as {format}: {e}")
            return {
                'content': '',
                'filename': f'error_{timestamp}.txt',
                'mimetype': 'text/plain'
            }

    def export_alerts(
        self,
        format: ExportFormat = 'csv',
        days: int = 7,
        include_metadata: bool = True
    ) -> Dict[str, Any]:
        """
        Export security alerts in specified format.

        Args:
            format: Export format ('csv', 'json', 'pdf', 'excel')
            days: Number of days to include
            include_metadata: Include metadata in export

        Returns:
            Dictionary with 'content', 'filename', and 'mimetype'
        """
        try:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')

            if format == 'csv':
                content = self.report_gen.export_alerts_csv(days=days)
                return {
                    'content': content,
                    'filename': f'alerts_{days}d_{timestamp}.csv',
                    'mimetype': 'text/csv'
                }

            elif format == 'json':
                # Get alerts and convert to JSON
                import sqlite3
                from datetime import timedelta
                conn = self.db_manager.conn

                cursor = conn.cursor()

                cutoff_date = datetime.now() - timedelta(days=days)

                cursor.execute("""
                    SELECT
                        a.id, a.timestamp, a.device_ip, d.device_name,
                        a.severity, a.anomaly_score, a.explanation, a.acknowledged
                    FROM alerts a
                    LEFT JOIN devices d ON a.device_ip = d.device_ip
                    WHERE a.timestamp > ?
                    ORDER BY a.timestamp DESC
                """, (cutoff_date.isoformat(),))

                alerts = [dict(row) for row in cursor.fetchall()]

                export_data = {
                    'export_type': 'alerts',
                    'generated_at': datetime.now().isoformat(),
                    'period_days': days,
                    'total_count': len(alerts),
                    'alerts': alerts
                } if include_metadata else alerts

                content = json.dumps(export_data, indent=2, default=str)
                return {
                    'content': content,
                    'filename': f'alerts_{days}d_{timestamp}.json',
                    'mimetype': 'application/json'
                }

            elif format == 'pdf':
                content = self.pdf_exporter.export_alerts_pdf(days=days)
                return {
                    'content': content,
                    'filename': f'alerts_{days}d_{timestamp}.pdf',
                    'mimetype': 'application/pdf'
                }

            elif format == 'excel':
                content = self.excel_exporter.export_alerts_excel(days=days)
                return {
                    'content': content,
                    'filename': f'alerts_{days}d_{timestamp}.xlsx',
                    'mimetype': 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
                }

            else:
                raise ValueError(f"Unsupported format: {format}")

        except Exception as e:
            logger.error(f"Error exporting alerts as {format}: {e}")
            return {
                'content': '',
                'filename': f'error_{timestamp}.txt',
                'mimetype': 'text/plain'
            }

    def export_connections(
        self,
        format: ExportFormat = 'csv',
        device_ip: Optional[str] = None,
        hours: int = 24,
        include_metadata: bool = True
    ) -> Dict[str, Any]:
        """
        Export network connections in specified format.

        Args:
            format: Export format ('csv', 'json', 'pdf', 'excel')
            device_ip: Filter by specific device IP (optional)
            hours: Number of hours to include
            include_metadata: Include metadata in export

        Returns:
            Dictionary with 'content', 'filename', and 'mimetype'
        """
        try:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            device_suffix = f"_{device_ip}" if device_ip else ""

            if format == 'csv':
                content = self.report_gen.export_connections_csv(
                    device_ip=device_ip,
                    hours=hours
                )
                return {
                    'content': content,
                    'filename': f'connections{device_suffix}_{hours}h_{timestamp}.csv',
                    'mimetype': 'text/csv'
                }

            elif format == 'json':
                # Get connections and convert to JSON
                import sqlite3
                from datetime import timedelta
                conn = self.db_manager.conn

                cursor = conn.cursor()

                cutoff_time = datetime.now() - timedelta(hours=hours)

                if device_ip:
                    cursor.execute("""
                        SELECT * FROM connections
                        WHERE device_ip = ? AND timestamp > ?
                        ORDER BY timestamp DESC
                        LIMIT 10000
                    """, (device_ip, cutoff_time.isoformat()))
                else:
                    cursor.execute("""
                        SELECT * FROM connections
                        WHERE timestamp > ?
                        ORDER BY timestamp DESC
                        LIMIT 10000
                    """, (cutoff_time.isoformat(),))

                connections = [dict(row) for row in cursor.fetchall()]

                export_data = {
                    'export_type': 'connections',
                    'generated_at': datetime.now().isoformat(),
                    'device_ip': device_ip,
                    'period_hours': hours,
                    'total_count': len(connections),
                    'connections': connections
                } if include_metadata else connections

                content = json.dumps(export_data, indent=2, default=str)
                return {
                    'content': content,
                    'filename': f'connections{device_suffix}_{hours}h_{timestamp}.json',
                    'mimetype': 'application/json'
                }

            elif format == 'pdf':
                content = self.pdf_exporter.export_connections_pdf(
                    device_ip=device_ip,
                    hours=hours
                )
                return {
                    'content': content,
                    'filename': f'connections{device_suffix}_{hours}h_{timestamp}.pdf',
                    'mimetype': 'application/pdf'
                }

            elif format == 'excel':
                content = self.excel_exporter.export_connections_excel(
                    device_ip=device_ip,
                    hours=hours
                )
                return {
                    'content': content,
                    'filename': f'connections{device_suffix}_{hours}h_{timestamp}.xlsx',
                    'mimetype': 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
                }

            else:
                raise ValueError(f"Unsupported format: {format}")

        except Exception as e:
            logger.error(f"Error exporting connections as {format}: {e}")
            return {
                'content': '',
                'filename': f'error_{timestamp}.txt',
                'mimetype': 'text/plain'
            }

    def export_alert_rules(
        self,
        format: ExportFormat = 'csv',
        include_metadata: bool = True
    ) -> Dict[str, Any]:
        """
        Export alert rules in specified format.

        Args:
            format: Export format ('csv', 'json', 'pdf', 'excel')
            include_metadata: Include metadata in export

        Returns:
            Dictionary with 'content', 'filename', and 'mimetype'
        """
        try:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')

            if format == 'csv':
                content = self.report_gen.export_alert_rules_csv()
                return {
                    'content': content,
                    'filename': f'alert_rules_{timestamp}.csv',
                    'mimetype': 'text/csv'
                }

            elif format == 'json':
                # Get alert rules and convert to JSON
                import sqlite3
                conn = self.db_manager.conn

                cursor = conn.cursor()

                cursor.execute("""
                    SELECT * FROM alert_rules
                    ORDER BY severity DESC, name ASC
                """)

                rules = [dict(row) for row in cursor.fetchall()]

                export_data = {
                    'export_type': 'alert_rules',
                    'generated_at': datetime.now().isoformat(),
                    'total_count': len(rules),
                    'rules': rules
                } if include_metadata else rules

                content = json.dumps(export_data, indent=2, default=str)
                return {
                    'content': content,
                    'filename': f'alert_rules_{timestamp}.json',
                    'mimetype': 'application/json'
                }

            elif format in ['pdf', 'excel']:
                # For now, fallback to CSV for alert rules PDF/Excel
                # Can be enhanced later with dedicated formatters
                content = self.report_gen.export_alert_rules_csv()
                return {
                    'content': content,
                    'filename': f'alert_rules_{timestamp}.csv',
                    'mimetype': 'text/csv'
                }

            else:
                raise ValueError(f"Unsupported format: {format}")

        except Exception as e:
            logger.error(f"Error exporting alert rules as {format}: {e}")
            return {
                'content': '',
                'filename': f'error_{timestamp}.txt',
                'mimetype': 'text/plain'
            }

    def export_sustainability_report(
        self,
        format: ExportFormat = 'csv',
        carbon_data: dict = None,
        energy_data: dict = None
    ) -> Dict[str, Any]:
        """
        Export sustainability metrics in specified format.

        Args:
            format: Export format ('csv', 'json', 'pdf', 'excel')
            carbon_data: Carbon footprint metrics dictionary
            energy_data: Energy consumption metrics dictionary

        Returns:
            Dictionary with 'content', 'filename', and 'mimetype'
        """
        try:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')

            if not carbon_data or not energy_data:
                raise ValueError("Both carbon_data and energy_data are required")

            if format == 'csv':
                import io
                output = io.StringIO()
                output.write("IoTSentinel Sustainability Report\n")
                output.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")

                output.write("=== CARBON FOOTPRINT ===\n")
                output.write(f"Daily Carbon Footprint,{carbon_data.get('daily_carbon_kg', 0):.2f} kg CO2\n")
                output.write(f"Yearly Estimate,{carbon_data.get('yearly_carbon_kg', 0):.1f} kg CO2\n")
                output.write(f"Trees Needed to Offset,{carbon_data.get('equivalent_trees', 0):.1f}\n")
                output.write(f"Car Miles Equivalent,{carbon_data.get('equivalent_miles_driven', 0):.0f} miles\n\n")

                output.write("=== ENERGY CONSUMPTION ===\n")
                output.write(f"Today's Energy,{energy_data.get('total_energy_kwh', 0):.2f} kWh\n")
                output.write(f"Daily Cost,${energy_data.get('estimated_cost_usd', 0):.2f}\n")
                output.write(f"Monthly Estimate,${energy_data.get('monthly_estimate_cost', 0):.2f}\n")
                output.write(f"Yearly Estimate,${energy_data.get('yearly_estimate_cost', 0):.2f}\n\n")

                output.write("=== TOP ENERGY CONSUMERS ===\n")
                output.write("Device,Type,Energy (kWh),Carbon (kg CO2)\n")
                for device in energy_data.get('device_breakdown', [])[:10]:
                    output.write(f"{device.get('device_name', 'Unknown')},{device.get('device_type', 'Unknown')},")
                    output.write(f"{device.get('estimated_energy_kwh', 0):.2f},{device.get('carbon_kg', 0):.3f}\n")

                content = output.getvalue()
                return {
                    'content': content,
                    'filename': f'sustainability_report_{timestamp}.csv',
                    'mimetype': 'text/csv'
                }

            elif format == 'json':
                report_data = {
                    'generated_at': datetime.now().isoformat(),
                    'carbon_footprint': carbon_data,
                    'energy_consumption': energy_data
                }
                content = json.dumps(report_data, indent=2)
                return {
                    'content': content,
                    'filename': f'sustainability_report_{timestamp}.json',
                    'mimetype': 'application/json'
                }

            elif format == 'pdf':
                from reportlab.lib.pagesizes import letter
                from reportlab.lib import colors
                from reportlab.lib.styles import getSampleStyleSheet
                from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer
                import io

                buffer = io.BytesIO()
                doc = SimpleDocTemplate(buffer, pagesize=letter)
                styles = getSampleStyleSheet()
                elements = []

                title = Paragraph("<b>IoTSentinel Sustainability Report</b>", styles['Title'])
                elements.append(title)
                elements.append(Spacer(1, 12))

                timestamp_para = Paragraph(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", styles['Normal'])
                elements.append(timestamp_para)
                elements.append(Spacer(1, 20))

                # Carbon Footprint
                elements.append(Paragraph("<b>Carbon Footprint Metrics</b>", styles['Heading2']))
                elements.append(Spacer(1, 12))

                carbon_table = Table([
                    ['Metric', 'Value'],
                    ['Daily Carbon Footprint', f"{carbon_data.get('daily_carbon_kg', 0):.2f} kg CO₂"],
                    ['Monthly Estimate', f"{carbon_data.get('monthly_carbon_kg', 0):.2f} kg CO₂"],
                    ['Yearly Estimate', f"{carbon_data.get('yearly_carbon_kg', 0):.1f} kg CO₂"],
                    ['Trees to Offset', f"{carbon_data.get('equivalent_trees', 0):.1f} trees"],
                    ['Car Miles Equivalent', f"{carbon_data.get('equivalent_miles_driven', 0):.0f} miles"]
                ], colWidths=[250, 250])

                carbon_table.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (-1, 0), colors.green),
                    ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                    ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                    ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                    ('FONTSIZE', (0, 0), (-1, 0), 12),
                    ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                    ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
                    ('GRID', (0, 0), (-1, -1), 1, colors.black)
                ]))
                elements.append(carbon_table)
                elements.append(Spacer(1, 20))

                # Energy Consumption
                elements.append(Paragraph("<b>Energy Consumption Metrics</b>", styles['Heading2']))
                elements.append(Spacer(1, 12))

                energy_table = Table([
                    ['Metric', 'Value'],
                    ['Today\'s Energy', f"{energy_data.get('total_energy_kwh', 0):.2f} kWh"],
                    ['Daily Cost', f"${energy_data.get('estimated_cost_usd', 0):.2f}"],
                    ['Monthly Estimate', f"${energy_data.get('monthly_estimate_cost', 0):.2f}"],
                    ['Yearly Estimate', f"${energy_data.get('yearly_estimate_cost', 0):.2f}"]
                ], colWidths=[250, 250])

                energy_table.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (-1, 0), colors.orange),
                    ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                    ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                    ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                    ('FONTSIZE', (0, 0), (-1, 0), 12),
                    ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                    ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
                    ('GRID', (0, 0), (-1, -1), 1, colors.black)
                ]))
                elements.append(energy_table)
                elements.append(Spacer(1, 20))

                # Top Consumers
                if energy_data.get('device_breakdown'):
                    elements.append(Paragraph("<b>Top Energy Consumers</b>", styles['Heading2']))
                    elements.append(Spacer(1, 12))

                    device_data = [['Device', 'Type', 'Energy (kWh)', 'Carbon (kg CO₂)']]
                    for device in energy_data.get('device_breakdown', [])[:10]:
                        device_data.append([
                            device.get('device_name', 'Unknown')[:30],
                            device.get('device_type', 'Unknown'),
                            f"{device.get('estimated_energy_kwh', 0):.2f}",
                            f"{device.get('carbon_kg', 0):.3f}"
                        ])

                    device_table = Table(device_data, colWidths=[150, 100, 100, 100])
                    device_table.setStyle(TableStyle([
                        ('BACKGROUND', (0, 0), (-1, 0), colors.red),
                        ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                        ('FONTSIZE', (0, 0), (-1, 0), 10),
                        ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                        ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
                        ('GRID', (0, 0), (-1, -1), 1, colors.black)
                    ]))
                    elements.append(device_table)

                doc.build(elements)
                content = buffer.getvalue()
                buffer.close()

                return {
                    'content': content,
                    'filename': f'sustainability_report_{timestamp}.pdf',
                    'mimetype': 'application/pdf'
                }

            elif format == 'excel':
                import pandas as pd
                import io

                buffer = io.BytesIO()

                with pd.ExcelWriter(buffer, engine='openpyxl') as writer:
                    # Carbon Sheet
                    carbon_df = pd.DataFrame([
                        {'Metric': 'Daily Carbon Footprint', 'Value': f"{carbon_data.get('daily_carbon_kg', 0):.2f} kg CO₂"},
                        {'Metric': 'Monthly Estimate', 'Value': f"{carbon_data.get('monthly_carbon_kg', 0):.2f} kg CO₂"},
                        {'Metric': 'Yearly Estimate', 'Value': f"{carbon_data.get('yearly_carbon_kg', 0):.1f} kg CO₂"},
                        {'Metric': 'Trees to Offset', 'Value': f"{carbon_data.get('equivalent_trees', 0):.1f} trees"},
                        {'Metric': 'Car Miles Equivalent', 'Value': f"{carbon_data.get('equivalent_miles_driven', 0):.0f} miles"}
                    ])
                    carbon_df.to_excel(writer, sheet_name='Carbon Footprint', index=False)

                    # Energy Sheet
                    energy_df = pd.DataFrame([
                        {'Metric': 'Today\'s Energy', 'Value': f"{energy_data.get('total_energy_kwh', 0):.2f} kWh"},
                        {'Metric': 'Daily Cost', 'Value': f"${energy_data.get('estimated_cost_usd', 0):.2f}"},
                        {'Metric': 'Monthly Estimate', 'Value': f"${energy_data.get('monthly_estimate_cost', 0):.2f}"},
                        {'Metric': 'Yearly Estimate', 'Value': f"${energy_data.get('yearly_estimate_cost', 0):.2f}"}
                    ])
                    energy_df.to_excel(writer, sheet_name='Energy Consumption', index=False)

                    # Top Consumers Sheet
                    if energy_data.get('device_breakdown'):
                        devices_data = []
                        for device in energy_data.get('device_breakdown', [])[:10]:
                            devices_data.append({
                                'Device': device.get('device_name', 'Unknown'),
                                'Type': device.get('device_type', 'Unknown'),
                                'Energy (kWh)': f"{device.get('estimated_energy_kwh', 0):.2f}",
                                'Carbon (kg CO₂)': f"{device.get('carbon_kg', 0):.3f}"
                            })
                        devices_df = pd.DataFrame(devices_data)
                        devices_df.to_excel(writer, sheet_name='Top Consumers', index=False)

                content = buffer.getvalue()
                buffer.close()

                return {
                    'content': content,
                    'filename': f'sustainability_report_{timestamp}.xlsx',
                    'mimetype': 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
                }

            else:
                raise ValueError(f"Unsupported format: {format}")

        except Exception as e:
            logger.error(f"Error exporting sustainability report as {format}: {e}")
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            return {
                'content': '',
                'filename': f'error_{timestamp}.txt',
                'mimetype': 'text/plain'
            }

    def get_supported_formats(self, export_type: ExportType) -> list:
        """
        Get list of supported export formats for a given type.

        Args:
            export_type: Type of export

        Returns:
            List of supported format names
        """
        # All types support CSV and JSON
        base_formats = ['csv', 'json']

        # PDF and Excel support for major data types
        if export_type in ['devices', 'alerts', 'connections']:
            return base_formats + ['pdf', 'excel']

        return base_formats

    def generate_download_dict(
        self,
        export_type: ExportType,
        format: ExportFormat = 'csv',
        **kwargs
    ) -> Dict[str, Any]:
        """
        Generate download dictionary for Dash dcc.Download component.

        Args:
            export_type: Type of data to export
            format: Export format
            **kwargs: Additional arguments for specific export types

        Returns:
            Dictionary compatible with dcc.Download
        """
        export_map = {
            'devices': self.export_devices,
            'alerts': self.export_alerts,
            'connections': self.export_connections,
            'alert_rules': self.export_alert_rules
        }

        if export_type not in export_map:
            raise ValueError(f"Unsupported export type: {export_type}")

        result = export_map[export_type](format=format, **kwargs)

        # Return in Dash download format
        if isinstance(result['content'], bytes):
            return {
                'content': result['content'],
                'filename': result['filename'],
                'type': result['mimetype'],
                'base64': True
            }
        else:
            return {
                'content': result['content'],
                'filename': result['filename'],
                'type': result['mimetype']
            }
