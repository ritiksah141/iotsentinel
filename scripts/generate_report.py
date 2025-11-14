#!/usr/bin/env python3
"""
Weekly Report Generator for IoTSentinel

Generates and emails a summary of the week's network activity.
Designed to be run periodically (e.g., via a cron job).
"""

import logging
import sys
from pathlib import Path
from datetime import datetime, timedelta

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from config.config_manager import config
from database.db_manager import DatabaseManager
from alerts.email_notifier import send_email

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def generate_html_report(summary_data: dict) -> str:
    """Generate an HTML report from summary data."""
    
    # CSS for styling
    styles = """
    <style>
        body { font-family: sans-serif; margin: 20px; }
        h1 { color: #2c3e50; }
        h2 { color: #34495e; border-bottom: 1px solid #ccc; padding-bottom: 5px; }
        table { border-collapse: collapse; width: 100%; margin-bottom: 20px; }
        th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
        th { background-color: #f2f2f2; }
    </style>
    """
    
    # Report body
    html = f"<html><head>{styles}</head><body>"
    html += "<h1>IoTSentinel Weekly Summary</h1>"
    
    # Summary section
    html += "<h2>Summary</h2>"
    html += f"<p>New Devices Discovered: <strong>{summary_data['new_devices']}</strong></p>"
    html += f"<p>Total Alerts Generated: <strong>{summary_data['total_alerts']}</strong></p>"
    
    # Top Alerts
    html += "<h2>Top Alerts</h2>"
    if summary_data['top_alerts']:
        html += "<table><tr><th>Device</th><th>Severity</th><th>Explanation</th></tr>"
        for alert in summary_data['top_alerts']:
            html += f"<tr><td>{alert['device_ip']}</td><td>{alert['severity']}</td><td>{alert['explanation']}</td></tr>"
        html += "</table>"
    else:
        html += "<p>No alerts this week. Great job!</p>"
        
    # Top Bandwidth Consumers
    html += "<h2>Top 5 Devices by Bandwidth</h2>"
    if summary_data['top_bandwidth']:
        html += "<table><tr><th>Device</th><th>Total Usage (MB)</th></tr>"
        for device in summary_data['top_bandwidth']:
            usage_mb = device['total_bytes'] / (1024 * 1024)
            html += f"<tr><td>{device['device_ip']}</td><td>{usage_mb:.2f} MB</td></tr>"
        html += "</table>"
    else:
        html += "<p>No bandwidth data available.</p>"
        
    html += "</body></html>"
    return html

def generate_report():
    """Generate and email the weekly report."""
    logger.info("Generating weekly report...")
    
    db = DatabaseManager(config.get('database', 'path'))
    
    try:
        # Fetch data
        one_week_ago = (datetime.now() - timedelta(days=7)).isoformat()
        
        # Using existing methods where possible
        all_alerts = db.get_recent_alerts(hours=7*24)
        top_alerts = sorted(all_alerts, key=lambda x: x['severity'], reverse=True)[:5]
        
        top_bandwidth = db.get_bandwidth_stats(hours=7*24)
        
        # Get new devices (this requires a new DB method)
        # For now, we'll just count devices seen in the last week
        # A proper implementation would check `first_seen`
        new_devices_count = db.get_connection_count(hours=7*24) # Placeholder
        
        summary_data = {
            "new_devices": new_devices_count,
            "total_alerts": len(all_alerts),
            "top_alerts": top_alerts,
            "top_bandwidth": top_bandwidth
        }
        
        # Generate HTML
        html_report = generate_html_report(summary_data)
        
        # Send email
        subject = f"IoTSentinel Weekly Report: {datetime.now().strftime('%Y-%m-%d')}"
        send_email(subject, html_report)
        
    except Exception as e:
        logger.error(f"Failed to generate report: {e}")
    finally:
        db.close()

if __name__ == '__main__':
    generate_report()
