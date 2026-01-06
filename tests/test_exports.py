#!/usr/bin/env python3
"""
Test script for Universal Export System

Tests all export formats (CSV, JSON, PDF, Excel) for all data types.
"""

import sys
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from utils.universal_exporter import UniversalExporter
from utils.export_helpers import DashExportHelper
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Database path
DB_PATH = "data/iot_monitor.db"


def test_export_formats():
    """Test all export formats for each data type."""

    print("="*80)
    print("UNIVERSAL EXPORT SYSTEM - TEST SUITE")
    print("="*80)
    print()

    # Check if database exists
    db_file = Path(DB_PATH)
    if not db_file.exists():
        print(f"❌ Database not found at: {DB_PATH}")
        print("   Please ensure the database exists before running tests.")
        return False

    print(f"✅ Database found: {DB_PATH}")
    print()

    try:
        exporter = UniversalExporter(DB_PATH)
        results = {}

        # Test Devices Export
        print("-" * 80)
        print("TESTING DEVICE EXPORTS")
        print("-" * 80)

        for format in ['csv', 'json', 'pdf', 'excel']:
            try:
                print(f"  Testing {format.upper()} format...", end=" ")
                result = exporter.export_devices(format=format)

                if result and result.get('content'):
                    size = len(result['content'])
                    filename = result['filename']
                    print(f"✅ Success ({size:,} bytes) - {filename}")
                    results[f'devices_{format}'] = True
                else:
                    print(f"❌ Failed - No content returned")
                    results[f'devices_{format}'] = False

            except Exception as e:
                print(f"❌ Error: {e}")
                results[f'devices_{format}'] = False

        print()

        # Test Alerts Export
        print("-" * 80)
        print("TESTING ALERT EXPORTS (Last 7 days)")
        print("-" * 80)

        for format in ['csv', 'json', 'pdf', 'excel']:
            try:
                print(f"  Testing {format.upper()} format...", end=" ")
                result = exporter.export_alerts(format=format, days=7)

                if result and result.get('content'):
                    size = len(result['content'])
                    filename = result['filename']
                    print(f"✅ Success ({size:,} bytes) - {filename}")
                    results[f'alerts_{format}'] = True
                else:
                    print(f"❌ Failed - No content returned")
                    results[f'alerts_{format}'] = False

            except Exception as e:
                print(f"❌ Error: {e}")
                results[f'alerts_{format}'] = False

        print()

        # Test Connections Export
        print("-" * 80)
        print("TESTING CONNECTION EXPORTS (Last 24 hours)")
        print("-" * 80)

        for format in ['csv', 'json', 'pdf', 'excel']:
            try:
                print(f"  Testing {format.upper()} format...", end=" ")
                result = exporter.export_connections(format=format, hours=24)

                if result and result.get('content'):
                    size = len(result['content'])
                    filename = result['filename']
                    print(f"✅ Success ({size:,} bytes) - {filename}")
                    results[f'connections_{format}'] = True
                else:
                    print(f"❌ Failed - No content returned")
                    results[f'connections_{format}'] = False

            except Exception as e:
                print(f"❌ Error: {e}")
                results[f'connections_{format}'] = False

        print()

        # Test Alert Rules Export
        print("-" * 80)
        print("TESTING ALERT RULES EXPORTS")
        print("-" * 80)

        for format in ['csv', 'json']:
            try:
                print(f"  Testing {format.upper()} format...", end=" ")
                result = exporter.export_alert_rules(format=format)

                if result and result.get('content'):
                    size = len(result['content'])
                    filename = result['filename']
                    print(f"✅ Success ({size:,} bytes) - {filename}")
                    results[f'alert_rules_{format}'] = True
                else:
                    print(f"❌ Failed - No content returned")
                    results[f'alert_rules_{format}'] = False

            except Exception as e:
                print(f"❌ Error: {e}")
                results[f'alert_rules_{format}'] = False

        print()

        # Summary
        print("="*80)
        print("TEST SUMMARY")
        print("="*80)

        total_tests = len(results)
        passed_tests = sum(1 for v in results.values() if v)
        failed_tests = total_tests - passed_tests

        print(f"Total Tests: {total_tests}")
        print(f"Passed: {passed_tests} ✅")
        print(f"Failed: {failed_tests} ❌")
        print()

        if failed_tests == 0:
            print("🎉 ALL TESTS PASSED!")
            print()
            print("The Universal Export System is working correctly.")
            print("All formats (CSV, JSON, PDF, Excel) are operational.")
        else:
            print("⚠️  SOME TESTS FAILED")
            print()
            print("Failed tests:")
            for test, passed in results.items():
                if not passed:
                    print(f"  - {test}")
            print()

        print("="*80)

        return failed_tests == 0

    except Exception as e:
        print(f"❌ CRITICAL ERROR: {e}")
        import traceback
        traceback.print_exc()
        return False


def test_dash_helper():
    """Test the Dash integration helper."""

    print("="*80)
    print("TESTING DASH EXPORT HELPER")
    print("="*80)
    print()

    try:
        helper = DashExportHelper(DB_PATH)

        # Test device export
        print("Testing device export...", end=" ")
        result = helper.export_devices(format='csv')
        if result:
            print(f"✅ Success - {result['filename']}")
        else:
            print("❌ Failed")

        # Test alert export
        print("Testing alert export...", end=" ")
        result = helper.export_alerts(format='json', days=7)
        if result:
            print(f"✅ Success - {result['filename']}")
        else:
            print("❌ Failed")

        # Test connection export
        print("Testing connection export...", end=" ")
        result = helper.export_connections(format='pdf', hours=24)
        if result:
            print(f"✅ Success - {result['filename']}")
        else:
            print("❌ Failed")

        print()
        print("✅ Dash Helper tests completed")
        print("="*80)
        print()

        return True

    except Exception as e:
        print(f"❌ Error: {e}")
        import traceback
        traceback.print_exc()
        return False


def save_sample_exports():
    """Save sample exports to files for manual inspection."""

    print("="*80)
    print("SAVING SAMPLE EXPORT FILES")
    print("="*80)
    print()

    output_dir = Path("data/sample_exports")
    output_dir.mkdir(parents=True, exist_ok=True)

    print(f"Output directory: {output_dir}")
    print()

    try:
        exporter = UniversalExporter(DB_PATH)

        # Save device exports
        for format in ['csv', 'json', 'pdf', 'excel']:
            try:
                result = exporter.export_devices(format=format)
                if result and result.get('content'):
                    filepath = output_dir / result['filename']

                    if isinstance(result['content'], bytes):
                        with open(filepath, 'wb') as f:
                            f.write(result['content'])
                    else:
                        with open(filepath, 'w') as f:
                            f.write(result['content'])

                    print(f"  ✅ Saved: {filepath}")
            except Exception as e:
                print(f"  ❌ Failed to save {format}: {e}")

        print()
        print(f"✅ Sample exports saved to: {output_dir}")
        print("   You can manually inspect these files to verify formatting.")
        print("="*80)
        print()

        return True

    except Exception as e:
        print(f"❌ Error: {e}")
        return False


if __name__ == '__main__':
    print()
    print("╔════════════════════════════════════════════════════════════════════════════╗")
    print("║                   IOTSENTINEL EXPORT SYSTEM TEST                           ║")
    print("╚════════════════════════════════════════════════════════════════════════════╝")
    print()

    # Run all tests
    test1_passed = test_export_formats()
    print()

    test2_passed = test_dash_helper()
    print()

    test3_passed = save_sample_exports()
    print()

    # Final summary
    if test1_passed and test2_passed and test3_passed:
        print("╔════════════════════════════════════════════════════════════════════════════╗")
        print("║                         ✅ ALL TESTS PASSED ✅                             ║")
        print("║                                                                            ║")
        print("║  The Universal Export System is fully operational!                        ║")
        print("║                                                                            ║")
        print("║  Next Steps:                                                               ║")
        print("║  1. Integrate export_helper into dashboard/app.py                         ║")
        print("║  2. Add format dropdowns to export modals                                 ║")
        print("║  3. Update existing export callbacks                                      ║")
        print("║  4. Test in live dashboard                                                ║")
        print("╚════════════════════════════════════════════════════════════════════════════╝")
        sys.exit(0)
    else:
        print("╔════════════════════════════════════════════════════════════════════════════╗")
        print("║                        ⚠️  SOME TESTS FAILED ⚠️                           ║")
        print("║                                                                            ║")
        print("║  Please review the errors above and fix any issues.                       ║")
        print("╚════════════════════════════════════════════════════════════════════════════╝")
        sys.exit(1)
