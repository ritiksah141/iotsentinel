#!/bin/bash
# Database Maintenance Automation Setup for IoTSentinel
#
# This script sets up automated database maintenance tasks via cron
#
# Usage: bash scripts/setup_db_automation.sh

set -e

# Colors for output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo "=================================================="
echo "IoTSentinel Database Automation Setup"
echo "=================================================="

# Get the absolute path to the project directory
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
PROJECT_DIR="$( cd "$SCRIPT_DIR/.." && pwd )"
PYTHON_PATH=$(which python3)
MAINTENANCE_SCRIPT="$PROJECT_DIR/scripts/db_maintenance.py"

echo ""
echo "Project directory: $PROJECT_DIR"
echo "Python path: $PYTHON_PATH"
echo ""

# Check if maintenance script exists
if [ ! -f "$MAINTENANCE_SCRIPT" ]; then
    echo "❌ Error: Maintenance script not found at $MAINTENANCE_SCRIPT"
    exit 1
fi

# Make maintenance script executable
chmod +x "$MAINTENANCE_SCRIPT"
echo "✓ Made maintenance script executable"

# Create log directory
mkdir -p "$PROJECT_DIR/data/logs"
echo "✓ Created log directory"

# Create backup directories
mkdir -p "$PROJECT_DIR/data/backups"
mkdir -p "$PROJECT_DIR/data/backups/weekly"
echo "✓ Created backup directories"

# Create cron job entries
DAILY_JOB="0 2 * * * cd $PROJECT_DIR && $PYTHON_PATH $MAINTENANCE_SCRIPT --daily >> $PROJECT_DIR/data/logs/db_maintenance.log 2>&1"
WEEKLY_JOB="0 3 * * 0 cd $PROJECT_DIR && $PYTHON_PATH $MAINTENANCE_SCRIPT --weekly >> $PROJECT_DIR/data/logs/db_maintenance.log 2>&1"

echo ""
echo "Suggested cron jobs:"
echo "=================================================="
echo ""
echo "# Daily maintenance (runs at 2 AM)"
echo "$DAILY_JOB"
echo ""
echo "# Weekly maintenance (runs at 3 AM on Sundays)"
echo "$WEEKLY_JOB"
echo ""
echo "=================================================="
echo ""

# Ask user if they want to install cron jobs
read -p "Do you want to install these cron jobs now? (y/n) " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    # Backup existing crontab
    crontab -l > /tmp/crontab_backup_$(date +%Y%m%d_%H%M%S) 2>/dev/null || true

    # Add new cron jobs (avoiding duplicates)
    (crontab -l 2>/dev/null | grep -v "db_maintenance.py" || true; echo "$DAILY_JOB"; echo "$WEEKLY_JOB") | crontab -

    echo ""
    echo "${GREEN}✓ Cron jobs installed successfully!${NC}"
    echo ""
    echo "Current crontab:"
    crontab -l | grep db_maintenance
else
    echo ""
    echo "${YELLOW}⊘ Skipped cron installation${NC}"
    echo ""
    echo "To install manually, run:"
    echo "  crontab -e"
    echo ""
    echo "And add the lines above."
fi

echo ""
echo "=================================================="
echo "Manual Maintenance Commands"
echo "=================================================="
echo ""
echo "Run daily maintenance:"
echo "  python3 scripts/db_maintenance.py --daily"
echo ""
echo "Run weekly maintenance:"
echo "  python3 scripts/db_maintenance.py --weekly"
echo ""
echo "Health check:"
echo "  python3 scripts/db_maintenance.py --health"
echo ""
echo "Create backup:"
echo "  python3 scripts/db_maintenance.py --backup"
echo ""
echo "View statistics:"
echo "  python3 scripts/db_maintenance.py --stats"
echo ""
echo "View maintenance log:"
echo "  tail -f data/logs/db_maintenance.log"
echo ""
echo "=================================================="
echo "${GREEN}✓ Setup complete!${NC}"
echo "=================================================="
