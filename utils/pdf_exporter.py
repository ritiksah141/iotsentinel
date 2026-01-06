#!/usr/bin/env python3
"""
PDF Exporter for IoTSentinel

Generates professional PDF reports and exports from database data.
Supports tables, charts, and formatted text.
"""

import io
import sqlite3
import logging
from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional, Tuple
from pathlib import Path

try:
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import letter, A4
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import inch
    from reportlab.platypus import (
        SimpleDocTemplate, Table, TableStyle, Paragraph,
        Spacer, PageBreak, Image, KeepTogether
    )
    from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT
    from reportlab.pdfgen import canvas
    REPORTLAB_AVAILABLE = True
except ImportError:
    REPORTLAB_AVAILABLE = False

logger = logging.getLogger(__name__)


class PDFExporter:
    """
    Professional PDF export generator for IoTSentinel.

    Generates formatted PDF documents with tables, charts, and metadata
    directly from database queries.
    """

    def __init__(
        self,
        db_path: str,
        company_name: str = "IoTSentinel",
        logo_path: Optional[str] = None,
        primary_color: str = "#2c3e50",
        accent_color: str = "#3498db"
    ):
        """
        Initialize PDF exporter with custom branding.

        Args:
            db_path: Path to SQLite database
            company_name: Custom company name for branding
            logo_path: Path to company logo image (PNG/JPG)
            primary_color: Primary brand color (hex)
            accent_color: Accent brand color (hex)
        """
        if not REPORTLAB_AVAILABLE:
            raise ImportError(
                "ReportLab not installed. Install with: pip install reportlab"
            )

        self.db_path = db_path
        self.company_name = company_name
        self.logo_path = logo_path
        self.primary_color = colors.HexColor(primary_color) if primary_color else colors.HexColor('#2c3e50')
        self.accent_color = colors.HexColor(accent_color) if accent_color else colors.HexColor('#3498db')

        self.styles = getSampleStyleSheet()
        self._setup_custom_styles()

    def _setup_custom_styles(self):
        """Setup custom paragraph styles using branding colors."""
        # Title style - uses primary color
        self.styles.add(ParagraphStyle(
            name='CustomTitle',
            parent=self.styles['Heading1'],
            fontSize=24,
            textColor=self.primary_color,
            spaceAfter=30,
            alignment=TA_CENTER,
            fontName='Helvetica-Bold'
        ))

        # Heading style - uses primary color
        self.styles.add(ParagraphStyle(
            name='CustomHeading',
            parent=self.styles['Heading2'],
            fontSize=14,
            textColor=self.primary_color,
            spaceAfter=12,
            spaceBefore=12,
            fontName='Helvetica-Bold'
        ))

        # Accent heading style - uses accent color
        self.styles.add(ParagraphStyle(
            name='AccentHeading',
            parent=self.styles['Heading2'],
            fontSize=14,
            textColor=self.accent_color,
            spaceAfter=12,
            spaceBefore=12,
            fontName='Helvetica-Bold'
        ))

        # Metadata style
        self.styles.add(ParagraphStyle(
            name='Metadata',
            parent=self.styles['Normal'],
            fontSize=9,
            textColor=colors.grey,
            alignment=TA_RIGHT
        ))

    def _create_header_footer(self, canvas_obj, doc):
        """Add customized header and footer to each page with branding."""
        canvas_obj.saveState()

        # Header with custom branding
        header_y = letter[1] - 0.5*inch

        # Add logo if provided
        if self.logo_path and Path(self.logo_path).exists():
            try:
                from reportlab.platypus import Image
                logo = Image(self.logo_path, width=1.5*inch, height=0.6*inch)
                logo.drawOn(canvas_obj, inch, header_y - 0.3*inch)
                text_x = inch + 1.7*inch  # Position text after logo
            except Exception as e:
                logger.warning(f"Could not load logo: {e}")
                text_x = inch
        else:
            text_x = inch

        # Header text with company name
        canvas_obj.setFont('Helvetica-Bold', 10)
        canvas_obj.setFillColor(self.primary_color)
        canvas_obj.drawString(text_x, header_y, f"{self.company_name} Security Report")

        # Header line
        canvas_obj.setStrokeColor(self.accent_color)
        canvas_obj.setLineWidth(2)
        canvas_obj.line(inch, header_y - 0.15*inch, letter[0] - inch, header_y - 0.15*inch)

        # Footer
        canvas_obj.setFont('Helvetica', 8)
        canvas_obj.setFillColor(colors.grey)

        # Left footer - company name
        canvas_obj.drawString(
            inch,
            0.5*inch,
            f"{self.company_name}"
        )

        # Right footer - page and date
        canvas_obj.drawRightString(
            letter[0] - inch,
            0.5*inch,
            f"Page {doc.page} - Generated {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
        )

        canvas_obj.restoreState()

    def export_devices_pdf(self) -> bytes:
        """
        Export all devices to PDF format.

        Returns:
            PDF file content as bytes
        """
        try:
            # Query database
            conn = sqlite3.connect(self.db_path)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()

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

            devices = cursor.fetchall()
            conn.close()

            # Create PDF
            buffer = io.BytesIO()
            doc = SimpleDocTemplate(
                buffer,
                pagesize=letter,
                rightMargin=inch,
                leftMargin=inch,
                topMargin=1.2*inch,
                bottomMargin=inch
            )

            # Build content
            story = []

            # Title
            title = Paragraph("Device Inventory Report", self.styles['CustomTitle'])
            story.append(title)
            story.append(Spacer(1, 0.2*inch))

            # Metadata
            metadata = Paragraph(
                f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}<br/>"
                f"Total Devices: {len(devices)}",
                self.styles['Metadata']
            )
            story.append(metadata)
            story.append(Spacer(1, 0.3*inch))

            # Summary statistics
            active_count = sum(1 for d in devices if self._is_active(d['last_seen']))
            trusted_count = sum(1 for d in devices if d['is_trusted'])
            blocked_count = sum(1 for d in devices if d['is_blocked'])

            summary_data = [
                ['Metric', 'Count'],
                ['Total Devices', str(len(devices))],
                ['Active (24h)', str(active_count)],
                ['Trusted', str(trusted_count)],
                ['Blocked', str(blocked_count)]
            ]

            summary_table = Table(summary_data, colWidths=[3*inch, 2*inch])
            summary_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#3498db')),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, 0), 12),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
                ('GRID', (0, 0), (-1, -1), 1, colors.grey)
            ]))
            story.append(summary_table)
            story.append(Spacer(1, 0.4*inch))

            # Device list heading
            heading = Paragraph("Device Details", self.styles['CustomHeading'])
            story.append(heading)
            story.append(Spacer(1, 0.1*inch))

            # Device table
            table_data = [['IP Address', 'Name', 'Type', 'MAC', 'Manufacturer', 'Status', 'Last Seen']]

            for device in devices:
                status = 'Blocked' if device['is_blocked'] else 'Trusted' if device['is_trusted'] else 'Active'
                table_data.append([
                    device['device_ip'] or 'N/A',
                    device['device_name'] or 'Unknown',
                    device['device_type'] or 'Unknown',
                    device['mac_address'] or 'N/A',
                    device['manufacturer'] or 'Unknown',
                    status,
                    self._format_datetime(device['last_seen'])
                ])

            device_table = Table(
                table_data,
                colWidths=[1.1*inch, 1*inch, 0.9*inch, 1.2*inch, 1*inch, 0.7*inch, 1*inch]
            )
            device_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#2c3e50')),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, 0), 9),
                ('FONTSIZE', (0, 1), (-1, -1), 8),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                ('TOPPADDING', (0, 1), (-1, -1), 6),
                ('BOTTOMPADDING', (0, 1), (-1, -1), 6),
                ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
                ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.lightgrey])
            ]))
            story.append(device_table)

            # Build PDF
            doc.build(story, onFirstPage=self._create_header_footer,
                     onLaterPages=self._create_header_footer)

            pdf_data = buffer.getvalue()
            buffer.close()

            logger.info(f"Generated PDF with {len(devices)} devices")
            return pdf_data

        except sqlite3.Error as e:
            logger.error(f"Database error exporting devices PDF: {e}")
            return b""
        except Exception as e:
            logger.error(f"Error generating PDF: {e}")
            return b""

    def export_alerts_pdf(self, days: int = 7) -> bytes:
        """
        Export alerts to PDF format.

        Args:
            days: Number of days to export (default: 7)

        Returns:
            PDF file content as bytes
        """
        try:
            # Query database
            conn = sqlite3.connect(self.db_path)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()

            cutoff_date = datetime.now() - timedelta(days=days)

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
            """, (cutoff_date.isoformat(),))

            alerts = cursor.fetchall()
            conn.close()

            # Create PDF
            buffer = io.BytesIO()
            doc = SimpleDocTemplate(
                buffer,
                pagesize=letter,
                rightMargin=0.75*inch,
                leftMargin=0.75*inch,
                topMargin=1.2*inch,
                bottomMargin=inch
            )

            # Build content
            story = []

            # Title
            title = Paragraph("Security Alerts Report", self.styles['CustomTitle'])
            story.append(title)
            story.append(Spacer(1, 0.2*inch))

            # Metadata
            metadata = Paragraph(
                f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}<br/>"
                f"Period: Last {days} days<br/>"
                f"Total Alerts: {len(alerts)}",
                self.styles['Metadata']
            )
            story.append(metadata)
            story.append(Spacer(1, 0.3*inch))

            # Severity breakdown
            severity_counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
            for alert in alerts:
                sev = alert['severity'].lower()
                if sev in severity_counts:
                    severity_counts[sev] += 1

            summary_data = [
                ['Severity', 'Count', 'Percentage'],
                ['Critical', str(severity_counts['critical']),
                 f"{severity_counts['critical']/len(alerts)*100:.1f}%" if alerts else "0%"],
                ['High', str(severity_counts['high']),
                 f"{severity_counts['high']/len(alerts)*100:.1f}%" if alerts else "0%"],
                ['Medium', str(severity_counts['medium']),
                 f"{severity_counts['medium']/len(alerts)*100:.1f}%" if alerts else "0%"],
                ['Low', str(severity_counts['low']),
                 f"{severity_counts['low']/len(alerts)*100:.1f}%" if alerts else "0%"]
            ]

            summary_table = Table(summary_data, colWidths=[2*inch, 1.5*inch, 1.5*inch])
            summary_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#e74c3c')),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, 0), 12),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
                ('GRID', (0, 0), (-1, -1), 1, colors.grey)
            ]))
            story.append(summary_table)
            story.append(Spacer(1, 0.4*inch))

            # Alert details
            if alerts:
                heading = Paragraph("Alert Details", self.styles['CustomHeading'])
                story.append(heading)
                story.append(Spacer(1, 0.1*inch))

                table_data = [['Timestamp', 'Device', 'Severity', 'Score', 'Explanation']]

                for alert in alerts[:100]:  # Limit to 100 for PDF size
                    table_data.append([
                        self._format_datetime(alert['timestamp']),
                        f"{alert['device_name'] or 'Unknown'}\n{alert['device_ip']}",
                        alert['severity'].upper(),
                        f"{alert['anomaly_score']:.3f}" if alert['anomaly_score'] else 'N/A',
                        self._truncate_text(alert['explanation'] or '', 80)
                    ])

                alert_table = Table(
                    table_data,
                    colWidths=[1.2*inch, 1.3*inch, 0.8*inch, 0.7*inch, 2.5*inch]
                )
                alert_table.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#2c3e50')),
                    ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                    ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                    ('VALIGN', (0, 0), (-1, -1), 'TOP'),
                    ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                    ('FONTSIZE', (0, 0), (-1, 0), 9),
                    ('FONTSIZE', (0, 1), (-1, -1), 7),
                    ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                    ('TOPPADDING', (0, 1), (-1, -1), 4),
                    ('BOTTOMPADDING', (0, 1), (-1, -1), 4),
                    ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
                    ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.lightgrey])
                ]))
                story.append(alert_table)

                if len(alerts) > 100:
                    note = Paragraph(
                        f"<i>Note: Showing 100 of {len(alerts)} alerts. "
                        "Use filters to generate focused reports.</i>",
                        self.styles['Normal']
                    )
                    story.append(Spacer(1, 0.1*inch))
                    story.append(note)

            # Build PDF
            doc.build(story, onFirstPage=self._create_header_footer,
                     onLaterPages=self._create_header_footer)

            pdf_data = buffer.getvalue()
            buffer.close()

            logger.info(f"Generated alerts PDF with {len(alerts)} alerts")
            return pdf_data

        except sqlite3.Error as e:
            logger.error(f"Database error exporting alerts PDF: {e}")
            return b""
        except Exception as e:
            logger.error(f"Error generating alerts PDF: {e}")
            return b""

    def export_connections_pdf(self, device_ip: Optional[str] = None, hours: int = 24) -> bytes:
        """
        Export connection logs to PDF format.

        Args:
            device_ip: Filter by specific device IP (optional)
            hours: Number of hours to export (default: 24)

        Returns:
            PDF file content as bytes
        """
        try:
            # Query database
            conn = sqlite3.connect(self.db_path)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()

            cutoff_time = datetime.now() - timedelta(hours=hours)

            if device_ip:
                cursor.execute("""
                    SELECT
                        timestamp,
                        device_ip,
                        dest_ip,
                        dest_port,
                        protocol,
                        service,
                        bytes_sent,
                        bytes_received,
                        conn_state
                    FROM connections
                    WHERE device_ip = ? AND timestamp > ?
                    ORDER BY timestamp DESC
                    LIMIT 500
                """, (device_ip, cutoff_time.isoformat()))
            else:
                cursor.execute("""
                    SELECT
                        timestamp,
                        device_ip,
                        dest_ip,
                        dest_port,
                        protocol,
                        service,
                        bytes_sent,
                        bytes_received,
                        conn_state
                    FROM connections
                    WHERE timestamp > ?
                    ORDER BY timestamp DESC
                    LIMIT 500
                """, (cutoff_time.isoformat(),))

            connections = cursor.fetchall()
            conn.close()

            # Create PDF
            buffer = io.BytesIO()
            doc = SimpleDocTemplate(
                buffer,
                pagesize=letter,
                rightMargin=0.5*inch,
                leftMargin=0.5*inch,
                topMargin=1.2*inch,
                bottomMargin=inch
            )

            # Build content
            story = []

            # Title
            title_text = f"Network Connections Report"
            if device_ip:
                title_text += f" - {device_ip}"
            title = Paragraph(title_text, self.styles['CustomTitle'])
            story.append(title)
            story.append(Spacer(1, 0.2*inch))

            # Metadata
            metadata = Paragraph(
                f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}<br/>"
                f"Time Range: Last {hours} hours<br/>"
                f"Total Connections: {len(connections)}",
                self.styles['Metadata']
            )
            story.append(metadata)
            story.append(Spacer(1, 0.3*inch))

            # Connection details
            if connections:
                heading = Paragraph("Connection Details", self.styles['CustomHeading'])
                story.append(heading)
                story.append(Spacer(1, 0.1*inch))

                table_data = [['Time', 'Source', 'Destination', 'Port', 'Protocol', 'Bytes Sent', 'Bytes Recv']]

                for conn in connections[:200]:  # Limit for PDF size
                    table_data.append([
                        self._format_datetime(conn['timestamp'], short=True),
                        conn['device_ip'] or 'N/A',
                        conn['dest_ip'] or 'N/A',
                        str(conn['dest_port'] or 'N/A'),
                        conn['protocol'] or 'N/A',
                        self._format_bytes(conn['bytes_sent']),
                        self._format_bytes(conn['bytes_received'])
                    ])

                conn_table = Table(
                    table_data,
                    colWidths=[0.9*inch, 1*inch, 1*inch, 0.6*inch, 0.7*inch, 0.9*inch, 0.9*inch]
                )
                conn_table.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#27ae60')),
                    ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                    ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                    ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                    ('FONTSIZE', (0, 0), (-1, 0), 8),
                    ('FONTSIZE', (0, 1), (-1, -1), 7),
                    ('BOTTOMPADDING', (0, 0), (-1, 0), 8),
                    ('TOPPADDING', (0, 1), (-1, -1), 3),
                    ('BOTTOMPADDING', (0, 1), (-1, -1), 3),
                    ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
                    ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.lightgrey])
                ]))
                story.append(conn_table)

                if len(connections) > 200:
                    note = Paragraph(
                        f"<i>Note: Showing 200 of {len(connections)} connections.</i>",
                        self.styles['Normal']
                    )
                    story.append(Spacer(1, 0.1*inch))
                    story.append(note)

            # Build PDF
            doc.build(story, onFirstPage=self._create_header_footer,
                     onLaterPages=self._create_header_footer)

            pdf_data = buffer.getvalue()
            buffer.close()

            logger.info(f"Generated connections PDF with {len(connections)} connections")
            return pdf_data

        except sqlite3.Error as e:
            logger.error(f"Database error exporting connections PDF: {e}")
            return b""
        except Exception as e:
            logger.error(f"Error generating connections PDF: {e}")
            return b""

    # Helper methods

    def _is_active(self, last_seen: str, hours: int = 24) -> bool:
        """Check if device was active within specified hours."""
        if not last_seen:
            return False
        try:
            last_seen_dt = datetime.fromisoformat(last_seen)
            cutoff = datetime.now() - timedelta(hours=hours)
            return last_seen_dt > cutoff
        except:
            return False

    def _format_datetime(self, dt_str: str, short: bool = False) -> str:
        """Format datetime string for display."""
        if not dt_str:
            return 'N/A'
        try:
            dt = datetime.fromisoformat(dt_str)
            if short:
                return dt.strftime('%m/%d %H:%M')
            return dt.strftime('%Y-%m-%d %H:%M:%S')
        except:
            return dt_str

    def _format_bytes(self, bytes_val: Optional[int]) -> str:
        """Format bytes into human-readable string."""
        if bytes_val is None:
            return 'N/A'

        for unit in ['B', 'KB', 'MB', 'GB']:
            if bytes_val < 1024:
                return f"{bytes_val:.0f}{unit}"
            bytes_val /= 1024
        return f"{bytes_val:.0f}TB"

    def _truncate_text(self, text: str, max_length: int) -> str:
        """Truncate text to maximum length."""
        if len(text) <= max_length:
            return text
        return text[:max_length-3] + '...'
