#!/usr/bin/env python3
"""
Database Device Reset Utility

Cleans up old devices and starts fresh with only currently connected devices.
"""

import sys
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from database.db_manager import DatabaseManager
from config.config_manager import config
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def reset_devices(keep_minutes: int = 5):
    """
    Reset device table to only keep currently active devices.

    Args:
        keep_minutes: Keep devices seen within this many minutes (default: 5)
    """
    db = DatabaseManager(config.get('database', 'path'))

    print("\n" + "=" * 70)
    print("IoTSentinel Device Database Reset")
    print("=" * 70)

    # Get current device count
    all_devices = db.get_all_devices()
    print(f"\nCurrent total devices in database: {len(all_devices)}")

    # Get active devices
    active_devices = db.get_active_devices(minutes=keep_minutes)
    print(f"Currently active devices (last {keep_minutes} min): {len(active_devices)}")

    if len(active_devices) == 0:
        print("\n⚠️  WARNING: No active devices found!")
        print("This might mean:")
        print("  1. No devices are currently generating traffic")
        print("  2. Zeek is not running")
        print("  3. The orchestrator hasn't parsed recent logs")
        print("\nRun ARP scan first or wait for traffic, then try again.")
        db.close()
        return

    print("\nActive devices that will be kept:")
    print("-" * 70)
    for device in active_devices:
        print(f"  {device['device_ip']:<16} {device['mac_address'] or 'No MAC':<20} {device['device_name'] or 'Unnamed':<20}")
    print("-" * 70)

    # Confirm deletion
    response = input(f"\n⚠️  Delete {len(all_devices) - len(active_devices)} old devices? (yes/no): ")

    if response.lower() != 'yes':
        print("\nOperation cancelled. No changes made.")
        db.close()
        return

    # Delete old devices
    try:
        cursor = db.conn.cursor()
        cursor.execute("""
            DELETE FROM devices
            WHERE last_seen < datetime('now', ? || ' minutes')
        """, (f'-{keep_minutes}',))

        deleted_count = cursor.rowcount
        db.conn.commit()

        print(f"\n✓ Successfully deleted {deleted_count} old devices")
        print(f"✓ {len(active_devices)} active devices retained")

    except Exception as e:
        print(f"\n✗ Error during cleanup: {e}")
        db.conn.rollback()

    db.close()
    print("\nDatabase reset complete!")
    print("=" * 70)


def delete_all_devices():
    """Delete ALL devices from database (nuclear option)."""
    db = DatabaseManager(config.get('database', 'path'))

    all_devices = db.get_all_devices()
    print("\n" + "=" * 70)
    print("⚠️  NUCLEAR OPTION: Delete ALL Devices")
    print("=" * 70)
    print(f"\nThis will delete ALL {len(all_devices)} devices from the database.")
    print("The ARP scanner and Zeek will repopulate with new devices.")

    response = input("\nAre you SURE? Type 'DELETE ALL' to confirm: ")

    if response != 'DELETE ALL':
        print("\nOperation cancelled. No changes made.")
        db.close()
        return

    try:
        cursor = db.conn.cursor()
        cursor.execute("DELETE FROM devices")
        deleted_count = cursor.rowcount
        db.conn.commit()

        print(f"\n✓ Deleted all {deleted_count} devices")
        print("\nRun ARP scan to repopulate:")
        print("  sudo python3 -m utils.arp_scanner --scan")

    except Exception as e:
        print(f"\n✗ Error: {e}")
        db.conn.rollback()

    db.close()


if __name__ == '__main__':
    import argparse

    parser = argparse.ArgumentParser(description='Reset IoTSentinel device database')
    parser.add_argument('--keep-minutes', type=int, default=5,
                       help='Keep devices seen within this many minutes (default: 5)')
    parser.add_argument('--delete-all', action='store_true',
                       help='Delete ALL devices (use with caution!)')

    args = parser.parse_args()

    if args.delete_all:
        delete_all_devices()
    else:
        reset_devices(keep_minutes=args.keep_minutes)
