#!/usr/bin/env python3
"""
Test Script for IoTSentinel Advanced Reporting System

Tests all report generation functionality with real database data.
"""

import os
import sys
import logging
from pathlib import Path
from datetime import datetime

# Setup paths
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Import report modules
from utils.report_builder import ReportBuilder
from utils.report_templates import ReportTemplateManager
from utils.trend_analyzer import TrendAnalyzer
from database.db_manager import DatabaseManager
from config.config_manager import config

# Database path
DB_PATH = project_root / 'data' / 'iot_monitor.db'

def check_database():
    """Check if database exists and has data."""
    logger.info("=" * 60)
    logger.info("CHECKING DATABASE")
    logger.info("=" * 60)

    if not os.path.exists(DB_PATH):
        logger.error(f"❌ Database not found at {DB_PATH}")
        return False

    logger.info(f"✅ Database found at {DB_PATH}")

    # Check for data
    db = DatabaseManager(DB_PATH)

    try:
        # Count alerts
        alerts_count = db.count_alerts()
        logger.info(f"   📊 Alerts: {alerts_count}")

        # Count devices
        devices = db.get_all_devices()
        logger.info(f"   📱 Devices: {len(devices)}")

        # Count connections
        conn = db.get_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM connections")
        connections_count = cursor.fetchone()[0]
        conn.close()
        logger.info(f"   🔌 Connections: {connections_count}")

        if alerts_count == 0 and len(devices) == 0 and connections_count == 0:
            logger.warning("⚠️  Database is empty - reports will have no data")
            return True  # Still return True to test report generation

        logger.info("✅ Database has data for testing")
        return True

    except Exception as e:
        logger.error(f"❌ Error checking database: {e}")
        return False

def test_trend_analyzer():
    """Test trend analysis functionality."""
    logger.info("\n" + "=" * 60)
    logger.info("TESTING TREND ANALYZER")
    logger.info("=" * 60)

    try:
        analyzer = TrendAnalyzer(DB_PATH)

        # Test alert trends
        logger.info("📈 Testing alert trends analysis...")
        alert_trends = analyzer.analyze_alert_trends(days=7, granularity='daily')
        logger.info(f"   Trend Direction: {alert_trends.get('trend_direction')}")
        logger.info(f"   Total Alerts: {alert_trends.get('total_alerts')}")
        logger.info(f"   Percent Change: {alert_trends.get('percent_change')}%")
        logger.info("   ✅ Alert trends analysis works")

        # Test device activity
        logger.info("\n📱 Testing device activity analysis...")
        device_activity = analyzer.analyze_device_activity(days=7)
        logger.info(f"   Most Active Devices: {len(device_activity.get('most_active_devices', []))}")
        logger.info(f"   New Devices: {device_activity.get('new_devices')}")
        logger.info(f"   Inactive Devices: {device_activity.get('inactive_devices')}")
        logger.info("   ✅ Device activity analysis works")

        # Test network traffic
        logger.info("\n🌐 Testing network traffic analysis...")
        network_traffic = analyzer.analyze_network_traffic(hours=24)
        logger.info(f"   Total Connections: {network_traffic.get('total_connections')}")
        logger.info(f"   Unique Sources: {network_traffic.get('unique_sources')}")
        logger.info(f"   Suspicious Patterns: {network_traffic.get('suspicious_patterns')}")
        logger.info("   ✅ Network traffic analysis works")

        # Test executive summary
        logger.info("\n📊 Testing executive summary...")
        summary = analyzer.get_executive_summary(days=7)
        logger.info(f"   Period: {summary.get('period', {}).get('days')} days")
        logger.info(f"   Security Posture: {summary.get('security_posture', {}).get('alert_trend')}")
        logger.info(f"   Device Count: {summary.get('device_status', {}).get('device_count')}")
        logger.info("   ✅ Executive summary works")

        # Test anomaly detection
        logger.info("\n🔍 Testing anomaly detection...")
        anomalies = analyzer.detect_anomalies(metric='alerts', days=30)
        logger.info(f"   Anomalies Found: {anomalies.get('anomaly_count', 0)}")
        logger.info("   ✅ Anomaly detection works")

        logger.info("\n✅ ALL TREND ANALYZER TESTS PASSED")
        return True

    except Exception as e:
        logger.error(f"❌ Trend analyzer test failed: {e}", exc_info=True)
        return False

def test_report_templates():
    """Test report template system."""
    logger.info("\n" + "=" * 60)
    logger.info("TESTING REPORT TEMPLATES")
    logger.info("=" * 60)

    try:
        manager = ReportTemplateManager()

        # List all templates
        templates = manager.list_templates()
        logger.info(f"📄 Found {len(templates)} templates:")
        for template in templates:
            logger.info(f"   - {template['name']} ({template['key']})")

        # Test each template
        for template in templates:
            template_obj = manager.get_template(template['key'])
            logger.info(f"\n   Testing template: {template['name']}")
            logger.info(f"      Sections: {len(template_obj.sections)}")
            logger.info(f"      Type: {template_obj.template_type}")

        logger.info("\n✅ ALL TEMPLATE TESTS PASSED")
        return True

    except Exception as e:
        logger.error(f"❌ Template test failed: {e}", exc_info=True)
        return False

def test_report_generation():
    """Test report generation in all formats."""
    logger.info("\n" + "=" * 60)
    logger.info("TESTING REPORT GENERATION")
    logger.info("=" * 60)

    # Create output directory
    output_dir = project_root / 'test_reports_output'
    output_dir.mkdir(exist_ok=True)
    logger.info(f"📁 Output directory: {output_dir}")

    try:
        builder = ReportBuilder(DB_PATH)
        manager = ReportTemplateManager()
        templates = manager.list_templates()

        results = []

        for template in templates:
            template_key = template['key']
            template_name = template['name']

            logger.info(f"\n📊 Generating reports for: {template_name}")

            # Test JSON format
            try:
                logger.info("   📄 Generating JSON report...")
                json_report = builder.build_report(
                    template_name=template_key,
                    format='json',
                    parameters={'days': 7}
                )
                if json_report:
                    filename = output_dir / json_report['filename']
                    with open(filename, 'w') as f:
                        f.write(json_report['content'])
                    logger.info(f"      ✅ JSON saved: {filename}")
                    results.append(('JSON', template_name, True))
                else:
                    logger.warning(f"      ⚠️  JSON generation returned None")
                    results.append(('JSON', template_name, False))
            except Exception as e:
                logger.error(f"      ❌ JSON failed: {e}")
                results.append(('JSON', template_name, False))

            # Test PDF format
            try:
                logger.info("   📑 Generating PDF report...")
                pdf_report = builder.build_report(
                    template_name=template_key,
                    format='pdf',
                    parameters={'days': 7}
                )
                if pdf_report:
                    filename = output_dir / pdf_report['filename']
                    with open(filename, 'wb') as f:
                        f.write(pdf_report['content'])
                    logger.info(f"      ✅ PDF saved: {filename}")
                    results.append(('PDF', template_name, True))
                else:
                    logger.warning(f"      ⚠️  PDF generation returned None")
                    results.append(('PDF', template_name, False))
            except Exception as e:
                logger.error(f"      ❌ PDF failed: {e}")
                results.append(('PDF', template_name, False))

            # Test Excel format
            try:
                logger.info("   📊 Generating Excel report...")
                excel_report = builder.build_report(
                    template_name=template_key,
                    format='excel',
                    parameters={'days': 7}
                )
                if excel_report:
                    filename = output_dir / excel_report['filename']
                    with open(filename, 'wb') as f:
                        f.write(excel_report['content'])
                    logger.info(f"      ✅ Excel saved: {filename}")
                    results.append(('Excel', template_name, True))
                else:
                    logger.warning(f"      ⚠️  Excel generation returned None")
                    results.append(('Excel', template_name, False))
            except Exception as e:
                logger.error(f"      ❌ Excel failed: {e}")
                results.append(('Excel', template_name, False))

        # Summary
        logger.info("\n" + "=" * 60)
        logger.info("REPORT GENERATION SUMMARY")
        logger.info("=" * 60)

        success_count = sum(1 for _, _, success in results if success)
        total_count = len(results)

        logger.info(f"Total Reports: {total_count}")
        logger.info(f"Successful: {success_count}")
        logger.info(f"Failed: {total_count - success_count}")

        if success_count == total_count:
            logger.info("✅ ALL REPORT GENERATION TESTS PASSED")
            return True
        else:
            logger.warning(f"⚠️  {total_count - success_count} reports failed")
            return False

    except Exception as e:
        logger.error(f"❌ Report generation test failed: {e}", exc_info=True)
        return False

def main():
    """Run all tests."""
    logger.info("🚀 Starting IoTSentinel Report Testing")
    logger.info(f"Timestamp: {datetime.now()}")

    results = {
        'database_check': check_database(),
        'trend_analyzer': test_trend_analyzer(),
        'report_templates': test_report_templates(),
        'report_generation': test_report_generation()
    }

    # Final summary
    logger.info("\n" + "=" * 60)
    logger.info("FINAL TEST SUMMARY")
    logger.info("=" * 60)

    for test_name, passed in results.items():
        status = "✅ PASSED" if passed else "❌ FAILED"
        logger.info(f"{test_name}: {status}")

    all_passed = all(results.values())

    if all_passed:
        logger.info("\n🎉 ALL TESTS PASSED!")
        logger.info("The advanced reporting system is working correctly.")
        return 0
    else:
        logger.warning("\n⚠️  SOME TESTS FAILED")
        logger.warning("Review the errors above for details.")
        return 1

if __name__ == '__main__':
    sys.exit(main())
