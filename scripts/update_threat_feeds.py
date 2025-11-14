#!/usr/bin/env python3
"""
Threat Intelligence Feed Updater for IoTSentinel

Downloads a list of malicious IPs and updates the database.
Designed to be run periodically (e.g., via a cron job).
"""

import logging
import sys
from pathlib import Path
import requests

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from config.config_manager import config
from database.db_manager import DatabaseManager

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# CINS Army list - a free, reputable source of malicious IPs
CINS_ARMY_URL = "http://cinsscore.com/list/ci-badguys.txt"

def update_threat_feeds():
    """Download threat feeds and update the database."""
    logger.info("Updating threat intelligence feeds...")
    
    db = DatabaseManager(config.get('database', 'path'))
    
    try:
        response = requests.get(CINS_ARMY_URL, timeout=30)
        response.raise_for_status()
        
        ips = [line.strip() for line in response.text.splitlines() if line.strip()]
        
        if ips:
            db.add_malicious_ips(ips, "CINS Army")
            logger.info(f"Successfully updated {len(ips)} IPs from CINS Army.")
        else:
            logger.warning("Threat intelligence feed was empty.")
            
    except requests.RequestException as e:
        logger.error(f"Error downloading threat intelligence feed: {e}")
    finally:
        db.close()

if __name__ == '__main__':
    update_threat_feeds()
