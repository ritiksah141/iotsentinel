#!/usr/bin/env python3
"""
Report Templates System for IoTSentinel

Provides pre-defined report templates and custom template builder.
Templates define the structure, sections, and visualizations for reports.
"""

import logging
from typing import Dict, List, Any, Optional
from datetime import datetime
from dataclasses import dataclass, field
import json

logger = logging.getLogger(__name__)


@dataclass
class ReportSection:
    """Represents a section in a report template."""
    title: str
    section_type: str  # 'text', 'table', 'chart', 'metrics', 'list'
    data_source: str  # 'alerts', 'devices', 'connections', 'custom'
    config: Dict[str, Any] = field(default_factory=dict)
    order: int = 0


@dataclass
class ReportTemplate:
    """Represents a complete report template."""
    name: str
    description: str
    template_type: str  # 'executive', 'security', 'network', 'custom'
    sections: List[ReportSection] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    created_at: str = field(default_factory=lambda: datetime.now().isoformat())


class ReportTemplateManager:
    """
    Manages report templates.

    Provides pre-defined templates and allows creating custom templates.
    """

    def __init__(self):
        """Initialize template manager with predefined templates."""
        self.templates: Dict[str, ReportTemplate] = {}
        self._load_predefined_templates()

    def _load_predefined_templates(self):
        """Load all predefined report templates."""
        self.templates['executive_summary'] = self._create_executive_summary_template()
        self.templates['security_audit'] = self._create_security_audit_template()
        self.templates['network_activity'] = self._create_network_activity_template()
        self.templates['device_inventory'] = self._create_device_inventory_template()
        self.templates['threat_analysis'] = self._create_threat_analysis_template()

    def _create_executive_summary_template(self) -> ReportTemplate:
        """Create executive summary template."""
        template = ReportTemplate(
            name="Executive Summary",
            description="High-level overview for executives and stakeholders",
            template_type="executive"
        )

        template.sections = [
            ReportSection(
                title="Security Posture Overview",
                section_type="metrics",
                data_source="alerts",
                config={
                    'metrics': ['total_alerts', 'critical_alerts', 'alert_trend', 'percent_change'],
                    'time_period': 7
                },
                order=1
            ),
            ReportSection(
                title="Alert Trends",
                section_type="chart",
                data_source="alerts",
                config={
                    'chart_type': 'trend',
                    'show_moving_average': True,
                    'period_days': 30
                },
                order=2
            ),
            ReportSection(
                title="Network Activity Summary",
                section_type="metrics",
                data_source="connections",
                config={
                    'metrics': ['total_connections', 'unique_sources', 'suspicious_patterns'],
                    'time_period': 7
                },
                order=3
            ),
            ReportSection(
                title="Device Status",
                section_type="table",
                data_source="devices",
                config={
                    'columns': ['device_count', 'active_devices', 'new_devices', 'inactive_devices'],
                    'summary': True
                },
                order=4
            ),
            ReportSection(
                title="Top Concerns",
                section_type="list",
                data_source="custom",
                config={
                    'source': 'trend_analyzer.get_executive_summary',
                    'field': 'top_concerns'
                },
                order=5
            )
        ]

        template.metadata = {
            'format_options': ['pdf', 'excel', 'json'],
            'default_period_days': 7,
            'refresh_interval': '24h'
        }

        return template

    def _create_security_audit_template(self) -> ReportTemplate:
        """Create security audit template."""
        template = ReportTemplate(
            name="Security Audit Report",
            description="Comprehensive security analysis and compliance check",
            template_type="security"
        )

        template.sections = [
            ReportSection(
                title="Alert Summary by Severity",
                section_type="chart",
                data_source="alerts",
                config={
                    'chart_type': 'pie',
                    'group_by': 'severity',
                    'period_days': 30
                },
                order=1
            ),
            ReportSection(
                title="Security Alerts Timeline",
                section_type="chart",
                data_source="alerts",
                config={
                    'chart_type': 'area',
                    'period_days': 30,
                    'granularity': 'daily'
                },
                order=2
            ),
            ReportSection(
                title="Critical Alerts Detailed",
                section_type="table",
                data_source="alerts",
                config={
                    'filter': {'severity': 'critical'},
                    'columns': ['timestamp', 'device_ip', 'explanation', 'acknowledged'],
                    'limit': 50
                },
                order=3
            ),
            ReportSection(
                title="Anomaly Detection Results",
                section_type="table",
                data_source="custom",
                config={
                    'source': 'trend_analyzer.detect_anomalies',
                    'metric': 'alerts',
                    'days': 30
                },
                order=4
            ),
            ReportSection(
                title="Blocked Devices",
                section_type="table",
                data_source="devices",
                config={
                    'filter': {'is_blocked': True},
                    'columns': ['device_ip', 'device_name', 'manufacturer', 'blocked_reason']
                },
                order=5
            ),
            ReportSection(
                title="Security Recommendations",
                section_type="text",
                data_source="custom",
                config={
                    'content_type': 'recommendations',
                    'based_on': ['alerts', 'anomalies', 'blocked_devices']
                },
                order=6
            )
        ]

        template.metadata = {
            'format_options': ['pdf', 'excel'],
            'default_period_days': 30,
            'compliance_frameworks': ['NIST', 'ISO27001'],
            'refresh_interval': '7d'
        }

        return template

    def _create_network_activity_template(self) -> ReportTemplate:
        """Create network activity template."""
        template = ReportTemplate(
            name="Network Activity Report",
            description="Detailed network traffic and connection analysis",
            template_type="network"
        )

        template.sections = [
            ReportSection(
                title="Connection Overview",
                section_type="metrics",
                data_source="connections",
                config={
                    'metrics': ['total_connections', 'unique_sources', 'unique_destinations'],
                    'time_period': 24
                },
                order=1
            ),
            ReportSection(
                title="Top Active Devices",
                section_type="chart",
                data_source="devices",
                config={
                    'chart_type': 'bar',
                    'metric': 'connection_count',
                    'limit': 10,
                    'period_hours': 24
                },
                order=2
            ),
            ReportSection(
                title="Activity by Hour",
                section_type="chart",
                data_source="connections",
                config={
                    'chart_type': 'bar',
                    'group_by': 'hour',
                    'period_days': 7
                },
                order=3
            ),
            ReportSection(
                title="Top Protocols",
                section_type="table",
                data_source="connections",
                config={
                    'group_by': 'protocol',
                    'aggregation': 'count',
                    'limit': 10
                },
                order=4
            ),
            ReportSection(
                title="Top Destination Ports",
                section_type="chart",
                data_source="connections",
                config={
                    'chart_type': 'pie',
                    'group_by': 'dest_port',
                    'limit': 10,
                    'period_days': 7
                },
                order=5
            ),
            ReportSection(
                title="Suspicious Connections",
                section_type="table",
                data_source="connections",
                config={
                    'filter': {'suspicious': True},
                    'columns': ['timestamp', 'device_ip', 'dest_ip', 'dest_port', 'service'],
                    'limit': 100
                },
                order=6
            )
        ]

        template.metadata = {
            'format_options': ['pdf', 'excel', 'csv'],
            'default_period_hours': 24,
            'refresh_interval': '1h'
        }

        return template

    def _create_device_inventory_template(self) -> ReportTemplate:
        """Create device inventory template."""
        template = ReportTemplate(
            name="Device Inventory Report",
            description="Complete inventory of all network devices",
            template_type="custom"
        )

        template.sections = [
            ReportSection(
                title="Device Summary",
                section_type="metrics",
                data_source="devices",
                config={
                    'metrics': ['total_devices', 'active_devices', 'blocked_devices', 'trusted_devices']
                },
                order=1
            ),
            ReportSection(
                title="Devices by Type",
                section_type="chart",
                data_source="devices",
                config={
                    'chart_type': 'pie',
                    'group_by': 'device_type'
                },
                order=2
            ),
            ReportSection(
                title="Devices by Manufacturer",
                section_type="chart",
                data_source="devices",
                config={
                    'chart_type': 'bar',
                    'group_by': 'manufacturer',
                    'limit': 10
                },
                order=3
            ),
            ReportSection(
                title="All Devices",
                section_type="table",
                data_source="devices",
                config={
                    'columns': ['device_ip', 'device_name', 'device_type', 'manufacturer',
                               'last_seen', 'is_trusted', 'is_blocked'],
                    'sort_by': 'last_seen',
                    'sort_order': 'desc'
                },
                order=4
            ),
            ReportSection(
                title="Recently Added Devices",
                section_type="table",
                data_source="devices",
                config={
                    'filter': {'recently_added': True},
                    'period_days': 7,
                    'columns': ['device_ip', 'device_name', 'first_seen', 'manufacturer'],
                    'limit': 20
                },
                order=5
            )
        ]

        template.metadata = {
            'format_options': ['pdf', 'excel', 'csv'],
            'refresh_interval': '24h'
        }

        return template

    def _create_threat_analysis_template(self) -> ReportTemplate:
        """Create threat analysis template."""
        template = ReportTemplate(
            name="Threat Analysis Report",
            description="Advanced threat detection and analysis",
            template_type="security"
        )

        template.sections = [
            ReportSection(
                title="Threat Overview",
                section_type="metrics",
                data_source="alerts",
                config={
                    'metrics': ['total_threats', 'critical_threats', 'threat_trend'],
                    'period_days': 7
                },
                order=1
            ),
            ReportSection(
                title="Anomaly Detection Timeline",
                section_type="chart",
                data_source="custom",
                config={
                    'source': 'trend_analyzer.detect_anomalies',
                    'chart_type': 'scatter',
                    'metric': 'alerts',
                    'days': 30
                },
                order=2
            ),
            ReportSection(
                title="High Risk Alerts",
                section_type="table",
                data_source="alerts",
                config={
                    'filter': {'severity': ['critical', 'high']},
                    'columns': ['timestamp', 'device_ip', 'severity', 'explanation', 'anomaly_score'],
                    'sort_by': 'anomaly_score',
                    'sort_order': 'desc',
                    'limit': 50
                },
                order=3
            ),
            ReportSection(
                title="Devices Under Attack",
                section_type="table",
                data_source="custom",
                config={
                    'source': 'alerts_grouped_by_device',
                    'having': {'alert_count': {'gt': 5}},
                    'period_days': 7
                },
                order=4
            ),
            ReportSection(
                title="Attack Patterns",
                section_type="chart",
                data_source="alerts",
                config={
                    'chart_type': 'heatmap',
                    'x_axis': 'hour',
                    'y_axis': 'severity',
                    'period_days': 7
                },
                order=5
            )
        ]

        template.metadata = {
            'format_options': ['pdf', 'excel'],
            'default_period_days': 7,
            'severity_threshold': 'high',
            'refresh_interval': '1h'
        }

        return template

    def get_template(self, template_name: str) -> Optional[ReportTemplate]:
        """
        Get a template by name.

        Args:
            template_name: Name of the template

        Returns:
            ReportTemplate or None if not found
        """
        return self.templates.get(template_name)

    def list_templates(self) -> List[Dict[str, str]]:
        """
        List all available templates.

        Returns:
            List of template info dictionaries
        """
        return [
            {
                'name': template.name,
                'key': key,
                'description': template.description,
                'type': template.template_type
            }
            for key, template in self.templates.items()
        ]

    def create_custom_template(
        self,
        name: str,
        description: str,
        sections: List[Dict[str, Any]]
    ) -> ReportTemplate:
        """
        Create a custom report template.

        Args:
            name: Template name
            description: Template description
            sections: List of section configurations

        Returns:
            Created ReportTemplate
        """
        template = ReportTemplate(
            name=name,
            description=description,
            template_type="custom"
        )

        # Convert section dicts to ReportSection objects
        for i, section_config in enumerate(sections):
            section = ReportSection(
                title=section_config['title'],
                section_type=section_config['section_type'],
                data_source=section_config['data_source'],
                config=section_config.get('config', {}),
                order=section_config.get('order', i + 1)
            )
            template.sections.append(section)

        # Generate unique key
        template_key = name.lower().replace(' ', '_')
        self.templates[template_key] = template

        return template

    def save_template(self, template: ReportTemplate, filepath: str):
        """
        Save template to JSON file.

        Args:
            template: Template to save
            filepath: Path to save file
        """
        try:
            template_dict = {
                'name': template.name,
                'description': template.description,
                'template_type': template.template_type,
                'sections': [
                    {
                        'title': section.title,
                        'section_type': section.section_type,
                        'data_source': section.data_source,
                        'config': section.config,
                        'order': section.order
                    }
                    for section in template.sections
                ],
                'metadata': template.metadata,
                'created_at': template.created_at
            }

            with open(filepath, 'w') as f:
                json.dump(template_dict, f, indent=2)

            logger.info(f"Template saved to {filepath}")

        except Exception as e:
            logger.error(f"Error saving template: {e}")

    def load_template(self, filepath: str) -> Optional[ReportTemplate]:
        """
        Load template from JSON file.

        Args:
            filepath: Path to template file

        Returns:
            Loaded ReportTemplate or None on error
        """
        try:
            with open(filepath, 'r') as f:
                template_dict = json.load(f)

            template = ReportTemplate(
                name=template_dict['name'],
                description=template_dict['description'],
                template_type=template_dict['template_type'],
                metadata=template_dict.get('metadata', {}),
                created_at=template_dict.get('created_at', datetime.now().isoformat())
            )

            for section_dict in template_dict['sections']:
                section = ReportSection(
                    title=section_dict['title'],
                    section_type=section_dict['section_type'],
                    data_source=section_dict['data_source'],
                    config=section_dict.get('config', {}),
                    order=section_dict.get('order', 0)
                )
                template.sections.append(section)

            logger.info(f"Template loaded from {filepath}")
            return template

        except Exception as e:
            logger.error(f"Error loading template: {e}")
            return None

    def get_template_config(self, template_name: str) -> Optional[Dict[str, Any]]:
        """
        Get template configuration as dictionary.

        Args:
            template_name: Name of the template

        Returns:
            Template configuration dictionary
        """
        template = self.get_template(template_name)
        if not template:
            return None

        return {
            'name': template.name,
            'description': template.description,
            'type': template.template_type,
            'sections': [
                {
                    'title': section.title,
                    'type': section.section_type,
                    'source': section.data_source,
                    'config': section.config,
                    'order': section.order
                }
                for section in sorted(template.sections, key=lambda s: s.order)
            ],
            'metadata': template.metadata
        }
