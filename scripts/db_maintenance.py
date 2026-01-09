#!/usr/bin/env python3
"""
Database Maintenance Script for IoTSentinel

Automates:
- Daily backups
- Weekly optimization
- Health checks
- Old data cleanup
- Backup rotation

Usage:
    python scripts/db_maintenance.py --daily    # Run daily tasks
    python scripts/db_maintenance.py --weekly   # Run weekly tasks
    python scripts/db_maintenance.py --health   # Health check only
    python scripts/db_maintenance.py --backup   # Backup only
"""

import sys
import argparse
import logging
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from database.db_manager import DatabaseManager
from config.config_manager import config

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


def health_check(db: DatabaseManager) -> bool:
    """Run health check and report status."""
    logger.info("=" * 70)
    logger.info("DATABASE HEALTH CHECK")
    logger.info("=" * 70)

    health = db.health_check()

    print(f"\nStatus: {health['status'].upper()}")
    print(f"Timestamp: {health['timestamp']}")

    if 'metrics' in health:
        print("\nMetrics:")
        for key, value in health['metrics'].items():
            print(f"  {key}: {value}")

        print("\nConfiguration:")
        for key, value in health['configuration'].items():
            print(f"  {key}: {value}")

    if health.get('warnings'):
        print("\n⚠️  WARNINGS:")
        for warning in health['warnings']:
            print(f"  - {warning}")

    if 'error' in health:
        print(f"\n❌ ERROR: {health['error']}")
        return False

    print("\n" + "=" * 70)
    return health['status'] in ['healthy', 'warning']


def daily_maintenance(db: DatabaseManager):
    """Run daily maintenance tasks."""
    logger.info("=" * 70)
    logger.info("DAILY MAINTENANCE")
    logger.info("=" * 70)

    # 1. Health check
    logger.info("\n1. Running health check...")
    health_check(db)

    # 2. Create backup
    logger.info("\n2. Creating daily backup...")
    backup_file = db.backup_database()
    if backup_file:
        logger.info(f"✓ Backup created: {backup_file}")
    else:
        logger.error("✗ Backup failed!")

    # 3. Cleanup old backups (keep 7 days)
    logger.info("\n3. Cleaning up old backups...")
    deleted = db.cleanup_old_backups(keep_days=7)
    logger.info(f"✓ Removed {deleted} old backups")

    # 4. Cleanup old data (keep 90 days)
    logger.info("\n4. Cleaning up old data...")
    db.cleanup_old_data(days=90)

    # 5. Database stats
    logger.info("\n5. Database statistics:")
    stats = db.get_database_stats()
    if stats:
        print(f"\nStorage:")
        for key, value in stats['storage'].items():
            print(f"  {key}: {value}")

        print(f"\nTable Counts:")
        for table, count in stats['tables'].items():
            print(f"  {table}: {count:,}")

        print(f"\nRecent Activity:")
        for key, value in stats['activity'].items():
            print(f"  {key}: {value}")

    logger.info("\n" + "=" * 70)
    logger.info("✓ Daily maintenance complete")


def weekly_maintenance(db: DatabaseManager):
    """Run weekly maintenance tasks."""
    logger.info("=" * 70)
    logger.info("WEEKLY MAINTENANCE")
    logger.info("=" * 70)

    # 1. Create backup
    logger.info("\n1. Creating weekly backup...")
    backup_file = db.backup_database(backup_dir='data/backups/weekly')
    if backup_file:
        logger.info(f"✓ Backup created: {backup_file}")

    # 2. Optimize database
    logger.info("\n2. Optimizing database...")
    db.optimize_database()

    # 3. Verify indexes
    logger.info("\n3. Creating/verifying indexes...")
    db.create_indexes()

    # 4. Cleanup old weekly backups (keep 4 weeks)
    logger.info("\n4. Cleaning up old weekly backups...")
    deleted = db.cleanup_old_backups(backup_dir='data/backups/weekly', keep_days=28)
    logger.info(f"✓ Removed {deleted} old weekly backups")

    logger.info("\n" + "=" * 70)
    logger.info("✓ Weekly maintenance complete")


def backup_only(db: DatabaseManager):
    """Create a backup only."""
    logger.info("Creating database backup...")
    backup_file = db.backup_database()
    if backup_file:
        logger.info(f"✓ Backup created: {backup_file}")
    else:
        logger.error("✗ Backup failed!")


def main():
    parser = argparse.ArgumentParser(
        description='Database maintenance utility for IoTSentinel'
    )
    parser.add_argument(
        '--daily',
        action='store_true',
        help='Run daily maintenance tasks'
    )
    parser.add_argument(
        '--weekly',
        action='store_true',
        help='Run weekly maintenance tasks'
    )
    parser.add_argument(
        '--health',
        action='store_true',
        help='Run health check only'
    )
    parser.add_argument(
        '--backup',
        action='store_true',
        help='Create backup only'
    )
    parser.add_argument(
        '--stats',
        action='store_true',
        help='Show database statistics'
    )

    args = parser.parse_args()

    # Get database path from config
    db_path = config.get('database', 'path')
    logger.info(f"Connecting to database: {db_path}")

    db = DatabaseManager(db_path)

    try:
        if args.daily:
            daily_maintenance(db)
        elif args.weekly:
            weekly_maintenance(db)
        elif args.health:
            success = health_check(db)
            sys.exit(0 if success else 1)
        elif args.backup:
            backup_only(db)
        elif args.stats:
            stats = db.get_database_stats()
            print("\nDatabase Statistics:")
            print("=" * 70)

            print("\nStorage:")
            for key, value in stats['storage'].items():
                print(f"  {key}: {value}")

            print("\nTable Counts:")
            for table, count in stats['tables'].items():
                print(f"  {table}: {count:,}")

            print("\nRecent Activity:")
            for key, value in stats['activity'].items():
                print(f"  {key}: {value}")

            print("\n" + "=" * 70)
        else:
            parser.print_help()
            print("\nExample usage:")
            print("  python scripts/db_maintenance.py --daily")
            print("  python scripts/db_maintenance.py --health")
            print("  python scripts/db_maintenance.py --backup")

    except Exception as e:
        logger.error(f"Maintenance failed: {e}", exc_info=True)
        sys.exit(1)

    logger.info("Done!")


if __name__ == '__main__':
    main()
