#!/usr/bin/env python3
"""
Export Helpers for Dashboard Integration

Helper functions to integrate UniversalExporter with Dash callbacks.
Provides simplified interfaces for common export operations.
"""

import logging
from typing import Dict, Any, Optional
from .universal_exporter import UniversalExporter, ExportFormat

logger = logging.getLogger(__name__)


class DashExportHelper:
    """
    Helper class for integrating exports into Dash callbacks.

    Provides simple methods that return data in the format expected
    by dcc.Download components.
    """

    def __init__(self, db_path: str):
        """
        Initialize export helper.

        Args:
            db_path: Path to SQLite database
        """
        self.exporter = UniversalExporter(db_path)

    def export_devices(
        self,
        format: str = 'csv'
    ) -> Optional[Dict[str, Any]]:
        """
        Export devices in specified format.

        Args:
            format: One of 'csv', 'json', 'pdf', 'excel'

        Returns:
            Download dict for dcc.Download or None on error
        """
        try:
            result = self.exporter.export_devices(format=format)

            if not result or not result.get('content'):
                return None

            # Handle binary content (PDF, Excel)
            if isinstance(result['content'], bytes):
                import base64
                content_b64 = base64.b64encode(result['content']).decode()
                return {
                    'content': content_b64,
                    'filename': result['filename'],
                    'type': result['mimetype'],
                    'base64': True
                }
            else:
                # Text content (CSV, JSON)
                return {
                    'content': result['content'],
                    'filename': result['filename'],
                    'type': result['mimetype']
                }

        except Exception as e:
            logger.error(f"Error in export_devices: {e}")
            return None

    def export_alerts(
        self,
        format: str = 'csv',
        days: int = 7
    ) -> Optional[Dict[str, Any]]:
        """
        Export alerts in specified format.

        Args:
            format: One of 'csv', 'json', 'pdf', 'excel'
            days: Number of days to include

        Returns:
            Download dict for dcc.Download or None on error
        """
        try:
            result = self.exporter.export_alerts(format=format, days=days)

            if not result or not result.get('content'):
                return None

            # Handle binary content (PDF, Excel)
            if isinstance(result['content'], bytes):
                import base64
                content_b64 = base64.b64encode(result['content']).decode()
                return {
                    'content': content_b64,
                    'filename': result['filename'],
                    'type': result['mimetype'],
                    'base64': True
                }
            else:
                # Text content (CSV, JSON)
                return {
                    'content': result['content'],
                    'filename': result['filename'],
                    'type': result['mimetype']
                }

        except Exception as e:
            logger.error(f"Error in export_alerts: {e}")
            return None

    def export_connections(
        self,
        format: str = 'csv',
        device_ip: Optional[str] = None,
        hours: int = 24
    ) -> Optional[Dict[str, Any]]:
        """
        Export connections in specified format.

        Args:
            format: One of 'csv', 'json', 'pdf', 'excel'
            device_ip: Filter by device IP (optional)
            hours: Number of hours to include

        Returns:
            Download dict for dcc.Download or None on error
        """
        try:
            result = self.exporter.export_connections(
                format=format,
                device_ip=device_ip,
                hours=hours
            )

            if not result or not result.get('content'):
                return None

            # Handle binary content (PDF, Excel)
            if isinstance(result['content'], bytes):
                import base64
                content_b64 = base64.b64encode(result['content']).decode()
                return {
                    'content': content_b64,
                    'filename': result['filename'],
                    'type': result['mimetype'],
                    'base64': True
                }
            else:
                # Text content (CSV, JSON)
                return {
                    'content': result['content'],
                    'filename': result['filename'],
                    'type': result['mimetype']
                }

        except Exception as e:
            logger.error(f"Error in export_connections: {e}")
            return None


# Example Dash callback implementations
"""
EXAMPLE USAGE IN app.py:

1. Import the helper at the top of app.py:
   from utils.export_helpers import DashExportHelper

2. Initialize the helper (after DB_PATH is defined):
   export_helper = DashExportHelper(DB_PATH)

3. Create a universal export callback:

@app.callback(
    [Output('download-devices', 'data'),
     Output('devices-export-toast', 'children')],
    [Input('export-devices-btn', 'n_clicks')],
    [State('export-format-dropdown', 'value')]
)
def export_devices_universal(n_clicks, export_format):
    '''Export devices in selected format (CSV/JSON/PDF/Excel).'''
    if not n_clicks:
        raise dash.exceptions.PreventUpdate

    try:
        # Use the helper to generate export
        download_data = export_helper.export_devices(format=export_format)

        if download_data:
            toast = ToastManager.success(
                "Export Complete",
                detail_message=f"Devices exported as {export_format.upper()}"
            )
            return download_data, toast
        else:
            toast = ToastManager.error(
                "Export Failed",
                detail_message="Could not generate export file"
            )
            return None, toast

    except Exception as e:
        logger.error(f"Error exporting devices: {e}")
        toast = ToastManager.error(
            "Export Error",
            detail_message=str(e)
        )
        return None, toast


4. Add export format dropdown to your UI:

dbc.Select(
    id='export-format-dropdown',
    options=[
        {'label': 'CSV Format', 'value': 'csv'},
        {'label': 'JSON Format', 'value': 'json'},
        {'label': 'PDF Report', 'value': 'pdf'},
        {'label': 'Excel Workbook', 'value': 'excel'}
    ],
    value='csv',
    className='mb-2'
)

dbc.Button(
    "Export Devices",
    id='export-devices-btn',
    color="primary"
)

dcc.Download(id='download-devices')


5. For alerts export with time range:

@app.callback(
    [Output('download-alerts', 'data'),
     Output('alerts-export-toast', 'children')],
    [Input('export-alerts-btn', 'n_clicks')],
    [State('export-format-dropdown', 'value'),
     State('alert-days-input', 'value')]
)
def export_alerts_universal(n_clicks, export_format, days):
    '''Export alerts in selected format with time range.'''
    if not n_clicks:
        raise dash.exceptions.PreventUpdate

    try:
        days = int(days) if days else 7

        download_data = export_helper.export_alerts(
            format=export_format,
            days=days
        )

        if download_data:
            toast = ToastManager.success(
                "Export Complete",
                detail_message=f"Last {days} days of alerts exported as {export_format.upper()}"
            )
            return download_data, toast
        else:
            toast = ToastManager.error(
                "Export Failed",
                detail_message="Could not generate export file"
            )
            return None, toast

    except Exception as e:
        logger.error(f"Error exporting alerts: {e}")
        toast = ToastManager.error(
            "Export Error",
            detail_message=str(e)
        )
        return None, toast


6. For connections export with device filter:

@app.callback(
    [Output('download-connections', 'data'),
     Output('connections-export-toast', 'children')],
    [Input('export-connections-btn', 'n_clicks')],
    [State('export-format-dropdown', 'value'),
     State('device-selector', 'value'),
     State('hours-input', 'value')]
)
def export_connections_universal(n_clicks, export_format, device_ip, hours):
    '''Export connections in selected format with filters.'''
    if not n_clicks:
        raise dash.exceptions.PreventUpdate

    try:
        hours = int(hours) if hours else 24

        download_data = export_helper.export_connections(
            format=export_format,
            device_ip=device_ip,
            hours=hours
        )

        if download_data:
            toast = ToastManager.success(
                "Export Complete",
                detail_message=f"Connections exported as {export_format.upper()}"
            )
            return download_data, toast
        else:
            toast = ToastManager.error(
                "Export Failed",
                detail_message="Could not generate export file"
            )
            return None, toast

    except Exception as e:
        logger.error(f"Error exporting connections: {e}")
        toast = ToastManager.error(
            "Export Error",
            detail_message=str(e)
        )
        return None, toast
"""
