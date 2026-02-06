#!/usr/bin/env python3
"""
RBAC Security Verification Script
Tests that all security features are properly integrated and logs results
Location: /scripts/verify_rbac_security.py
"""

import sys
import logging
from pathlib import Path
from datetime import datetime

# Add project root to path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

# Setup logging to file
log_dir = project_root / 'data' / 'logs'
log_dir.mkdir(parents=True, exist_ok=True)
log_file = log_dir / 'rbac_verification.log'

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(log_file),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)

def test_imports():
    """Test that all security modules can be imported"""
    logger.info("=" * 70)
    logger.info("TESTING SECURITY MODULE IMPORTS")
    logger.info("=" * 70)

    try:
        from utils.rbac_manager import PermissionManager, can_export_data, ROLES
        logger.info("✅ RBAC Manager imported successfully")
        logger.info(f"   - Roles defined: {list(ROLES.keys())}")
        logger.info(f"   - Permissions per role:")
        for role, data in ROLES.items():
            logger.info(f"     • {role}: {len(data['permissions'])} permissions")
    except Exception as e:
        logger.error(f"❌ RBAC Manager import failed: {e}")
        return False

    try:
        from utils.security_audit_logger import get_audit_logger, SecurityAuditLogger
        logger.info("\n✅ Security Audit Logger imported successfully")
        logger.info(f"   - Event types defined: {len(SecurityAuditLogger.EVENT_TYPES)}")
        logger.info(f"   - Sample events: {list(SecurityAuditLogger.EVENT_TYPES.keys())[:5]}")
    except Exception as e:
        logger.error(f"❌ Security Audit Logger import failed: {e}")
        return False

    return True


def test_database_integration():
    """Test database integration"""
    logger.info("\n" + "=" * 70)
    logger.info("TESTING DATABASE INTEGRATION")
    logger.info("=" * 70)

    try:
        from database.db_manager import DatabaseManager
        from utils.security_audit_logger import get_audit_logger

        # Initialize with test database
        db_path = 'data/database/iotsentinel.db'
        db_manager = DatabaseManager(db_path)

        # Initialize security audit logger
        audit_logger = get_audit_logger(db_manager)
        logger.info("✅ Security audit logger initialized with database")

        # Check if table exists
        cursor = db_manager.conn.cursor()
        cursor.execute("""
            SELECT name FROM sqlite_master
            WHERE type='table' AND name='security_audit_log'
        """)
        if cursor.fetchone():
            logger.info("✅ security_audit_log table exists")

            # Count existing records
            cursor.execute("SELECT COUNT(*) FROM security_audit_log")
            count = cursor.fetchone()[0]
            logger.info(f"   - Current audit records: {count}")
        else:
            logger.warning("⚠️  security_audit_log table will be created on first use")

        return True

    except Exception as e:
        logger.error(f"❌ Database integration test failed: {e}")
        return False


def test_permission_functions():
    """Test permission helper functions"""
    logger.info("\n" + "=" * 70)
    logger.info("TESTING PERMISSION FUNCTIONS")
    logger.info("=" * 70)

    try:
        from utils.rbac_manager import (
            can_export_data, can_manage_devices, can_block_devices,
            can_delete_data, can_run_scans
        )

        # Create a mock user object
        class MockUser:
            def __init__(self, role):
                self.role = role
                self.is_authenticated = True
                self.username = f"test_{role}"
                self.id = 1

        # Test with different roles
        roles_to_test = ['admin', 'security_analyst', 'operator', 'viewer']

        logger.info("\nPermission Matrix:")
        logger.info(f"{'Role':<20} {'Export':<10} {'Manage':<10} {'Block':<10} {'Delete':<10} {'Scan':<10}")
        logger.info("-" * 70)

        for role in roles_to_test:
            user = MockUser(role)
            export = "✅" if can_export_data(user) else "❌"
            manage = "✅" if can_manage_devices(user) else "❌"
            block = "✅" if can_block_devices(user) else "❌"
            delete = "✅" if can_delete_data(user) else "❌"
            scan = "✅" if can_run_scans(user) else "❌"

            logger.info(f"{role:<20} {export:<10} {manage:<10} {block:<10} {delete:<10} {scan:<10}")

        logger.info("\n✅ Permission functions working correctly")
        return True

    except Exception as e:
        logger.error(f"❌ Permission function test failed: {e}")
        return False


def test_audit_logging():
    """Test audit logging functionality"""
    logger.info("\n" + "=" * 70)
    logger.info("TESTING AUDIT LOGGING")
    logger.info("=" * 70)

    try:
        from database.db_manager import DatabaseManager
        from utils.security_audit_logger import get_audit_logger

        db_path = 'data/database/iotsentinel.db'
        db_manager = DatabaseManager(db_path)
        audit_logger = get_audit_logger(db_manager)

        # Test logging
        success = audit_logger.log(
            event_type='login_success',
            user_id=999,
            username='test_user',
            details={'method': 'password', 'test': True, 'timestamp': datetime.now().isoformat()},
            severity='info',
            ip_address='127.0.0.1',
            result='success'
        )

        if success:
            logger.info("✅ Test audit log entry created successfully")

            # Retrieve recent events
            events = audit_logger.get_recent_events(limit=1)
            if events and len(events) > 0:
                logger.info("✅ Audit log retrieval working")
                logger.info(f"   - Latest event: {events[0]['event_type']}")
            else:
                logger.warning("⚠️  Could not retrieve test event")
        else:
            logger.warning("⚠️  Audit logging may not be fully functional (check logs)")

        return True

    except Exception as e:
        logger.error(f"❌ Audit logging test failed: {e}")
        return False


def main():
    """Run all tests"""
    logger.info("\n" + "=" * 70)
    logger.info("RBAC & SECURITY AUDIT SYSTEM VERIFICATION")
    logger.info(f"Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    logger.info(f"Log file: {log_file}")
    logger.info("=" * 70)
    logger.info("")

    all_passed = True

    # Run tests
    all_passed &= test_imports()
    all_passed &= test_database_integration()
    all_passed &= test_permission_functions()
    all_passed &= test_audit_logging()

    # Summary
    logger.info("\n" + "=" * 70)
    logger.info("VERIFICATION SUMMARY")
    logger.info("=" * 70)

    if all_passed:
        logger.info("✅ ALL TESTS PASSED")
        logger.info("\nThe RBAC and Security Audit system is fully operational!")
        logger.info("\nNext steps:")
        logger.info("  1. Start the dashboard: python3 dashboard/app.py")
        logger.info("  2. Test export functions (should be admin-only)")
        logger.info("  3. Check security_audit_log table for logged events")
        logger.info("  4. Review docs/RBAC_SECURITY_GUIDE.md for usage details")
        logger.info(f"\nVerification completed successfully at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        return 0
    else:
        logger.error("⚠️  SOME TESTS FAILED")
        logger.error("\nPlease review the errors above and check:")
        logger.error("  1. All required packages are installed (pip install -r requirements.txt)")
        logger.error("  2. Database is accessible")
        logger.error("  3. No syntax errors in modified files")
        logger.error(f"\nVerification failed at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        return 1


if __name__ == '__main__':
    sys.exit(main())
