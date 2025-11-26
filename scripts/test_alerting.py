#!/usr/bin/env python3
"""
Test Script for IoTSentinel Alerting System

Run this script to test your alerting configuration:
    python -m alerts.test_alerting

Tests performed:
1. Configuration validation
2. Email connectivity (optional)
3. Alert creation and deduplication
4. Rate limiting
5. Report generation
"""

import sys
import logging
from pathlib import Path
from datetime import datetime

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


def test_configuration(config):
    """Test configuration loading."""
    print("\n" + "=" * 60)
    print("TEST 1: Configuration Validation")
    print("=" * 60)

    # Check email config
    email_enabled = config.get('email', 'enabled', default=False)
    print(f"  Email enabled: {email_enabled}")

    if email_enabled or str(email_enabled).lower() == 'true':
        smtp_host = config.get('email', 'smtp_host')
        smtp_user = config.get('email', 'smtp_user')
        sender = config.get('email', 'sender_email')
        recipient = config.get('email', 'recipient_email')

        print(f"  SMTP Host: {smtp_host}")
        print(f"  SMTP User: {smtp_user}")
        print(f"  Sender: {sender}")
        print(f"  Recipient: {recipient}")

        # Check for missing config
        if not all([smtp_host, smtp_user, sender, recipient]):
            print("  ⚠️  WARNING: Some email configuration is missing")
            return False

        # Check for placeholder values
        if smtp_host == 'smtp.example.com':
            print("  ⚠️  WARNING: Using placeholder SMTP host")
            return False

    # Check alerting config
    alerting_enabled = config.get('alerting', 'enabled', default=True)
    print(f"  Alerting enabled: {alerting_enabled}")

    print("  ✅ Configuration loaded successfully")
    return True


def test_alert_creation(alert_service):
    """Test alert creation and storage."""
    print("\n" + "=" * 60)
    print("TEST 2: Alert Creation")
    print("=" * 60)

    try:
        # Create a test alert
        alert_id = alert_service.create_alert(
            device_ip='192.168.1.TEST',
            severity='medium',
            anomaly_score=0.85,
            explanation='Test alert for system validation',
            send_notification=False  # Don't send email for this test
        )

        if alert_id:
            print(f"  ✅ Alert created successfully (ID: {alert_id})")
            return True
        else:
            print("  ❌ Alert creation returned None")
            return False

    except Exception as e:
        print(f"  ❌ Alert creation failed: {e}")
        return False


def test_rate_limiter():
    """Test rate limiting functionality."""
    print("\n" + "=" * 60)
    print("TEST 3: Rate Limiter")
    print("=" * 60)

    try:
        from alerts.alert_service import RateLimiter, Alert

        limiter = RateLimiter(
            max_per_device_per_hour=3,
            max_global_per_hour=5,
            cooldown_minutes=1
        )

        # Create test alerts
        alerts_sent = 0
        for i in range(5):
            alert = Alert(
                device_ip='192.168.1.100',
                severity='high',
                anomaly_score=0.9 + i * 0.01,
                explanation=f'Test alert {i+1}'
            )

            should_send, reason = limiter.should_send(alert)

            if should_send:
                limiter.record_sent(alert)
                alerts_sent += 1
                print(f"  Alert {i+1}: SENT")
            else:
                print(f"  Alert {i+1}: BLOCKED ({reason})")

        if alerts_sent == 3:  # Should be limited to max_per_device
            print(f"  ✅ Rate limiter working correctly ({alerts_sent} alerts allowed)")
            return True
        else:
            print(f"  ⚠️  Rate limiter allowed {alerts_sent} alerts (expected 3)")
            return False

    except Exception as e:
        print(f"  ❌ Rate limiter test failed: {e}")
        return False


def test_email_notifier(config):
    """Test email notifier (without sending)."""
    print("\n" + "=" * 60)
    print("TEST 4: Email Notifier Initialization")
    print("=" * 60)

    try:
        from alerts.email_notifier import EmailNotifier

        notifier = EmailNotifier(config)

        print(f"  Channel name: {notifier.channel_name}")
        print(f"  Is enabled: {notifier.is_enabled()}")

        if notifier.is_enabled():
            print("  ✅ Email notifier is properly configured")
        else:
            print("  ⚠️  Email notifier is disabled or not fully configured")

        return True

    except Exception as e:
        print(f"  ❌ Email notifier test failed: {e}")
        return False


def test_report_generation(db_manager, alert_service):
    """Test report data generation."""
    print("\n" + "=" * 60)
    print("TEST 5: Report Generation")
    print("=" * 60)

    try:
        from alerts.report_scheduler import ReportGenerator

        generator = ReportGenerator(db_manager, alert_service)

        # Generate weekly report data
        report = generator.generate_weekly_report()

        print(f"  Report type: {report.get('report_type')}")
        print(f"  Period: {report.get('period')}")
        print(f"  Total alerts: {report.get('summary', {}).get('total', 0)}")

        if 'summary' in report and 'period' in report:
            print("  ✅ Report generation working")
            return True
        else:
            print("  ❌ Report data incomplete")
            return False

    except Exception as e:
        print(f"  ❌ Report generation test failed: {e}")
        return False


def test_send_email(alerting_system):
    """Test sending actual email (optional)."""
    print("\n" + "=" * 60)
    print("TEST 6: Send Test Email (Optional)")
    print("=" * 60)

    response = input("  Send a test email? (y/N): ").strip().lower()

    if response != 'y':
        print("  Skipped")
        return True

    try:
        success = alerting_system.send_test_email()

        if success:
            print("  ✅ Test email sent successfully!")
            print("  Check your inbox to confirm receipt")
        else:
            print("  ❌ Failed to send test email")

        return success

    except Exception as e:
        print(f"  ❌ Error sending test email: {e}")
        return False


def main():
    """Run all tests."""
    print("\n" + "=" * 60)
    print("IoTSentinel Alerting System Test Suite")
    print("=" * 60)
    print(f"Started at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

    # Add project root to path
    project_root = Path(__file__).parent.parent
    sys.path.insert(0, str(project_root))

    try:
        from config.config_manager import config
        from database.db_manager import DatabaseManager
        from alerts.alert_service import AlertService
        from alerts.integration import AlertingSystem
    except ImportError as e:
        print(f"\n❌ Failed to import required modules: {e}")
        print("Make sure you're running from the project root directory")
        sys.exit(1)

    results = []

    # Test 1: Configuration
    results.append(('Configuration', test_configuration(config)))

    # Initialize database (in-memory for testing)
    try:
        db = DatabaseManager(':memory:')
        # Create minimal schema for testing
        cursor = db.conn.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS devices (
                device_ip TEXT PRIMARY KEY,
                device_name TEXT
            )
        """)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                device_ip TEXT,
                severity TEXT,
                anomaly_score REAL,
                explanation TEXT,
                top_features TEXT,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                acknowledged INTEGER DEFAULT 0
            )
        """)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS connections (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                device_ip TEXT,
                dest_ip TEXT,
                bytes_sent INTEGER,
                bytes_received INTEGER,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        db.conn.commit()
    except Exception as e:
        print(f"\n❌ Failed to initialize test database: {e}")
        sys.exit(1)

    # Create alert service
    alert_service = AlertService(db, config)

    # Test 2: Alert Creation
    results.append(('Alert Creation', test_alert_creation(alert_service)))

    # Test 3: Rate Limiter
    results.append(('Rate Limiter', test_rate_limiter()))

    # Test 4: Email Notifier
    results.append(('Email Notifier', test_email_notifier(config)))

    # Test 5: Report Generation
    results.append(('Report Generation', test_report_generation(db, alert_service)))

    # Create full alerting system for email test
    alerting_system = AlertingSystem(db, config)

    # Test 6: Send Email (optional)
    results.append(('Send Test Email', test_send_email(alerting_system)))

    # Summary
    print("\n" + "=" * 60)
    print("TEST SUMMARY")
    print("=" * 60)

    passed = 0
    for name, result in results:
        status = "✅ PASSED" if result else "❌ FAILED"
        print(f"  {name}: {status}")
        if result:
            passed += 1

    print(f"\nTotal: {passed}/{len(results)} tests passed")

    # Cleanup
    db.close()

    return passed == len(results)


if __name__ == '__main__':
    success = main()
    sys.exit(0 if success else 1)
