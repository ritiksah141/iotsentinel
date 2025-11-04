#!/usr/bin/env python3
"""
Baseline Data Collection Manager for IoTSentinel

Orchestrates 7-day "normal" traffic capture for ML training.

Usage:
    python3 baseline_collector.py start    # Start collection
    python3 baseline_collector.py status   # Check progress
    python3 baseline_collector.py stop     # Finalize
"""

import sys
import time
import json
import subprocess
from datetime import datetime, timedelta
from pathlib import Path
import logging
import sqlite3

# Add project root
sys.path.insert(0, str(Path(__file__).parent.parent))

from config.config_manager import config

# Setup logging
log_dir = Path(config.get('logging', 'log_dir'))
log_dir.mkdir(parents=True, exist_ok=True)

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(log_dir / 'baseline.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)


class BaselineCollector:
    """Manages 7-day baseline collection."""
    
    def __init__(self, duration_days=7):
        self.duration_days = duration_days
        self.output_dir = Path('data/baseline')
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
        self.metadata_file = self.output_dir / 'metadata.json'
        self.db_path = config.get('database', 'path')
        self.start_time = None
        self.end_time = None
        
        # Load existing metadata if available
        if self.metadata_file.exists():
            with open(self.metadata_file, 'r') as f:
                metadata = json.load(f)
                if metadata.get('status') == 'active':
                    self.start_time = datetime.fromisoformat(metadata['start_time'])
                    self.end_time = datetime.fromisoformat(metadata['end_time'])
    
    def _check_zeek_status(self):
        """Check if Zeek is running."""
        try:
            result = subprocess.run(
                ['sudo', '/opt/zeek/bin/zeekctl', 'status'],
                capture_output=True,
                text=True,
                check=False
            )
            
            if 'running' in result.stdout:
                logger.info("✓ Zeek is running")
                return True
            else:
                logger.warning("⚠️  Zeek is not running!")
                return False
        except Exception as e:
            logger.error(f"Could not check Zeek status: {e}")
            return False
    
    def start_collection(self):
        """Begin baseline collection period."""
        if self.metadata_file.exists():
            with open(self.metadata_file, 'r') as f:
                metadata = json.load(f)
                if metadata.get('status') == 'active':
                    logger.error("Collection already in progress!")
                    return False
        
        self.start_time = datetime.now()
        self.end_time = self.start_time + timedelta(days=self.duration_days)
        
        logger.info("=" * 60)
        logger.info(f"Starting {self.duration_days}-day baseline collection")
        logger.info(f"Start: {self.start_time}")
        logger.info(f"End: {self.end_time}")
        logger.info("=" * 60)
        logger.info("")
        logger.info("IMPORTANT: For the next 7 days:")
        logger.info("  1. Use your network NORMALLY")
        logger.info("  2. Do NOT run security tests or port scans")
        logger.info("  3. Inform household members to use devices normally")
        logger.info("")
        
        # Ensure Zeek is running
        if not self._check_zeek_status():
            logger.info("Starting Zeek...")
            try:
                subprocess.run(
                    ['sudo', '/opt/zeek/bin/zeekctl', 'deploy'],
                    check=True
                )
                logger.info("✓ Zeek started")
            except Exception as e:
                logger.error(f"Failed to start Zeek: {e}")
                return False
        
        # Create collection metadata
        metadata = {
            'start_time': self.start_time.isoformat(),
            'end_time': self.end_time.isoformat(),
            'duration_days': self.duration_days,
            'status': 'active',
            'collection_type': 'baseline',
            'version': '1.0'
        }
        
        with open(self.metadata_file, 'w') as f:
            json.dump(metadata, f, indent=2)
        
        logger.info(f"✓ Metadata saved to {self.metadata_file}")
        logger.info("")
        logger.info("Collection started successfully!")
        logger.info("Check progress with: python3 scripts/baseline_collector.py status")
        
        return True
    
    def check_progress(self):
        """Check collection progress and data quality."""
        if not self.start_time:
            logger.error("No active collection found")
            return None
        
        now = datetime.now()
        elapsed = now - self.start_time
        remaining = self.end_time - now
        
        if remaining.total_seconds() < 0:
            remaining = timedelta(0)
        
        progress = min((elapsed.total_seconds() / 
                       (self.duration_days * 86400)) * 100, 100)
        
        logger.info("=" * 60)
        logger.info(f"BASELINE COLLECTION PROGRESS")
        logger.info("=" * 60)
        logger.info(f"Progress: {progress:.1f}%")
        logger.info(f"Elapsed: {elapsed}")
        logger.info(f"Remaining: {remaining}")
        logger.info("")
        
        # Check Zeek status
        self._check_zeek_status()
        
        # Check Zeek conn.log
        conn_log = Path('/opt/zeek/logs/current/conn.log')
        if conn_log.exists():
            try:
                with open(conn_log) as f:
                    line_count = sum(1 for line in f if not line.startswith('#'))
                
                logger.info(f"Zeek connection records: {line_count:,}")
                
                hours_elapsed = elapsed.total_seconds() / 3600
                if hours_elapsed > 0:
                    records_per_hour = line_count / hours_elapsed
                    logger.info(f"Average rate: {records_per_hour:.0f} records/hour")
                    
                    if records_per_hour < 50:
                        logger.warning("⚠️  Low data collection rate - ensure devices are active")
            
            except Exception as e:
                logger.error(f"Error reading Zeek logs: {e}")
        else:
            logger.warning("⚠️  Zeek conn.log not found!")
        
        # Check database
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute("SELECT COUNT(*) FROM connections")
            db_count = cursor.fetchone()[0]
            conn.close()
            logger.info(f"Database connection records: {db_count:,}")
        except Exception as e:
            logger.warning(f"Database check failed: {e}")
        
        logger.info("=" * 60)
        
        status_obj = {
            'progress_percent': progress,
            'elapsed': str(elapsed),
            'remaining': str(remaining),
            'status': 'complete' if progress >= 100 else 'active'
        }
        
        if progress >= 100:
            logger.info("")
            logger.info("✓ Collection period complete!")
            logger.info("Run: python3 scripts/baseline_collector.py stop")
        
        return status_obj
    
    def finalize_collection(self):
        """Finalize baseline collection."""
        logger.info("=" * 60)
        logger.info("FINALIZING BASELINE COLLECTION")
        logger.info("=" * 60)
        
        # Archive Zeek logs
        zeek_logs = Path('/opt/zeek/logs/current')
        archive_path = self.output_dir / 'zeek_logs'
        archive_path.mkdir(exist_ok=True)
        
        logger.info("Archiving Zeek logs...")
        try:
            for log_file in zeek_logs.glob('*.log'):
                import shutil
                dest_file = archive_path / log_file.name
                shutil.copy2(log_file, dest_file)
                logger.info(f"  ✓ Archived: {log_file.name}")
        except Exception as e:
            logger.error(f"Error archiving logs: {e}")
        
        # Update metadata
        with open(self.metadata_file, 'r') as f:
            metadata = json.load(f)
        
        metadata['status'] = 'complete'
        metadata['actual_end_time'] = datetime.now().isoformat()
        
        with open(self.metadata_file, 'w') as f:
            json.dump(metadata, f, indent=2)
        
        logger.info(f"✓ Baseline data saved to {self.output_dir}")
        logger.info("")
        logger.info("Next steps:")
        logger.info("  1. Train Autoencoder: python3 ml/train_autoencoder.py")
        logger.info("  2. Train Isolation Forest: python3 ml/train_isolation_forest.py")
        logger.info("  3. Start inference: python3 ml/inference_engine.py --continuous")
        logger.info("=" * 60)
        
        return True


def main():
    """CLI interface."""
    collector = BaselineCollector(duration_days=7)
    
    if len(sys.argv) < 2:
        print("Usage: python3 baseline_collector.py [start|status|stop]")
        sys.exit(1)
    
    command = sys.argv[1].lower()
    
    if command == 'start':
        collector.start_collection()
    elif command == 'status':
        collector.check_progress()
    elif command == 'stop':
        collector.finalize_collection()
    else:
        print(f"Unknown command: {command}")
        sys.exit(1)


if __name__ == '__main__':
    main()