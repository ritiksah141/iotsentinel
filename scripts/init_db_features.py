#!/usr/bin/env python3
"""
Initialize Database with Security and Performance Features

Runs once after database creation to:
- Create performance indexes
- Verify database integrity
- Set up security constraints
- Display configuration summary

Usage:
    python scripts/init_db_features.py
"""

import sys
import logging
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from database.db_manager import DatabaseManager
from config.config_manager import config

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


def main():
    print("=" * 70)
    print("IoTSentinel Database Initialization")
    print("=" * 70)

    db_path = config.get('database', 'path')
    logger.info(f"Initializing database: {db_path}")

    db = DatabaseManager(db_path)

    try:
        # 1. Create indexes
        print("\n1. Creating performance indexes...")
        db.create_indexes()

        # 2. Run health check
        print("\n2. Running health check...")
        health = db.health_check()

        if health['status'] == 'healthy':
            print("   ✓ Database is healthy")
        else:
            print(f"   ⚠️  Status: {health['status']}")
            if health.get('warnings'):
                for warning in health['warnings']:
                    print(f"      - {warning}")

        # 3. Display configuration
        print("\n3. Database Configuration:")
        if 'configuration' in health:
            for key, value in health['configuration'].items():
                print(f"   {key}: {value}")

        # 4. Display statistics
        print("\n4. Database Statistics:")
        stats = db.get_database_stats()
        if stats:
            print(f"   Database size: {stats['storage']['database_size_mb']} MB")
            print(f"   WAL size: {stats['storage']['wal_size_mb']} MB")

            print("\n   Table counts:")
            for table, count in sorted(stats['tables'].items()):
                if count > 0:
                    print(f"     {table}: {count:,}")

        # 5. Create initial backup
        print("\n5. Creating initial backup...")
        backup_file = db.backup_database()
        if backup_file:
            print(f"   ✓ Backup created: {backup_file}")

        print("\n" + "=" * 70)
        print("✓ Database initialization complete!")
        print("=" * 70)

        print("\nNext steps:")
        print("  1. Set up automated maintenance:")
        print("     bash scripts/setup_db_automation.sh")
        print("")
        print("  2. Run health checks:")
        print("     python scripts/db_maintenance.py --health")
        print("")
        print("  3. View statistics:")
        print("     python scripts/db_maintenance.py --stats")
        print("")

    except Exception as e:
        logger.error(f"Initialization failed: {e}", exc_info=True)
        sys.exit(1)


if __name__ == '__main__':
    main()
