#!/bin/bash
# Enhanced deployment script for IoTSentinel with backup and rollback support

set -e

# Configuration (can be overridden with environment variables or .deploy.env)
PI_USER="${PI_USER:-sentinel}"
PI_HOST="${PI_HOST:-iotsentinel.local}"
PI_PATH="${PI_PATH:-/home/sentinel/iotsentinel}"
BACKUP_DIR="${BACKUP_DIR:-$PI_PATH/backups}"

# Parse command line arguments
CLEAN_INSTALL=false
NO_BACKUP=false
DRY_RUN=false

while [[ $# -gt 0 ]]; do
    case $1 in
        --clean)
            CLEAN_INSTALL=true
            shift
            ;;
        --no-backup)
            NO_BACKUP=true
            shift
            ;;
        --dry-run)
            DRY_RUN=true
            shift
            ;;
        --help)
            echo "Usage: $0 [OPTIONS]"
            echo ""
            echo "Options:"
            echo "  --clean       Perform clean installation (removes data, starts from zero)"
            echo "  --no-backup   Skip automatic backup (not recommended)"
            echo "  --dry-run     Show what would be done without actually doing it"
            echo "  --help        Show this help message"
            echo ""
            echo "Environment variables:"
            echo "  PI_USER       Username for Pi (default: sentinel)"
            echo "  PI_HOST       Hostname or IP of Pi (default: iotsentinel.local)"
            echo "  PI_PATH       Installation path on Pi (default: /home/sentinel/iotsentinel)"
            echo ""
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            echo "Use --help for usage information"
            exit 1
            ;;
    esac
done

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

# Helper functions
log_info() {
    echo -e "${BLUE}ℹ${NC} $1"
}

log_success() {
    echo -e "${GREEN}✓${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}⚠${NC} $1"
}

log_error() {
    echo -e "${RED}✗${NC} $1"
}

log_header() {
    echo ""
    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${CYAN}  $1${NC}"
    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
}

# Start deployment
log_header "IoTSentinel Deployment (Enhanced)"

if [ "$DRY_RUN" = true ]; then
    log_warning "DRY RUN MODE - No changes will be made"
fi

if [ "$CLEAN_INSTALL" = true ]; then
    log_warning "CLEAN INSTALL MODE - All data will be removed!"
    echo ""
    read -p "Are you sure you want to continue? (yes/no): " -r
    if [[ ! $REPLY =~ ^[Yy]es$ ]]; then
        echo "Deployment cancelled."
        exit 0
    fi
fi

# Check .env file
log_header "Pre-deployment Checks"

if [ ! -f ".env" ]; then
    log_error ".env file not found!"
    log_info "Copy .env.template to .env and configure your settings:"
    log_info "  cp .env.template .env"
    log_info "  nano .env"
    exit 1
fi
log_success ".env file found"

# Validate .env contains required variables
if ! grep -q "FLASK_SECRET_KEY" .env; then
    log_error "FLASK_SECRET_KEY not found in .env"
    log_info "Please add FLASK_SECRET_KEY to your .env file"
    exit 1
fi

if grep -q "your-secret-key-change-this-in-production" .env; then
    log_warning "FLASK_SECRET_KEY is still using default value"
    log_info "Generate a secure key with: python3 -c \"import secrets; print(secrets.token_hex(32))\""
fi
log_success ".env configuration validated"

# Check Pi connectivity
log_header "Connectivity Check"

log_info "Checking connection to $PI_HOST..."
if ! ping -c 1 $PI_HOST > /dev/null 2>&1; then
    log_error "Cannot reach $PI_HOST"
    exit 1
fi
log_success "Pi is reachable at $PI_HOST"

# Test SSH connectivity
log_info "Testing SSH connection..."
if ! ssh -o ConnectTimeout=5 ${PI_USER}@${PI_HOST} "echo 'SSH OK'" > /dev/null 2>&1; then
    log_error "Cannot establish SSH connection to ${PI_USER}@${PI_HOST}"
    log_info "Ensure SSH keys are set up correctly"
    exit 1
fi
log_success "SSH connection established"

# Create backup (unless --no-backup or --clean)
if [ "$CLEAN_INSTALL" = false ] && [ "$NO_BACKUP" = false ]; then
    log_header "Backup Creation"

    TIMESTAMP=$(date +%Y%m%d_%H%M%S)
    BACKUP_NAME="iotsentinel_backup_${TIMESTAMP}"

    log_info "Creating backup: $BACKUP_NAME"

    if [ "$DRY_RUN" = false ]; then
        ssh ${PI_USER}@${PI_HOST} "bash -s" << ENDSSH
set -e
mkdir -p ${BACKUP_DIR}

# Create backup directory
BACKUP_PATH="${BACKUP_DIR}/${BACKUP_NAME}"
mkdir -p \$BACKUP_PATH

# Backup critical data
if [ -d "${PI_PATH}/data/database" ]; then
    echo "Backing up database..."
    cp -r ${PI_PATH}/data/database \$BACKUP_PATH/
fi

if [ -f "${PI_PATH}/.env" ]; then
    echo "Backing up .env file..."
    cp ${PI_PATH}/.env \$BACKUP_PATH/
fi

if [ -d "${PI_PATH}/data/baseline" ]; then
    echo "Backing up baseline data..."
    cp -r ${PI_PATH}/data/baseline \$BACKUP_PATH/
fi

# Create backup manifest
echo "Backup created: \$(date)" > \$BACKUP_PATH/manifest.txt
echo "Source: ${PI_PATH}" >> \$BACKUP_PATH/manifest.txt

# Compress backup
echo "Compressing backup..."
cd ${BACKUP_DIR}
tar -czf ${BACKUP_NAME}.tar.gz ${BACKUP_NAME}
rm -rf ${BACKUP_NAME}

# Keep only last 5 backups
ls -t ${BACKUP_DIR}/*.tar.gz | tail -n +6 | xargs -r rm

echo "Backup location: ${BACKUP_DIR}/${BACKUP_NAME}.tar.gz"
ENDSSH
        log_success "Backup created: ${BACKUP_NAME}.tar.gz"
        log_info "Backup location: ${BACKUP_DIR}/${BACKUP_NAME}.tar.gz"
        log_info "To restore: ssh ${PI_USER}@${PI_HOST} 'cd ${BACKUP_DIR} && tar -xzf ${BACKUP_NAME}.tar.gz'"
    else
        log_info "[DRY RUN] Would create backup: ${BACKUP_NAME}.tar.gz"
    fi
fi

# Sync code
log_header "Code Synchronization"

log_info "Syncing code to Pi..."

RSYNC_OPTS="-avz --progress"
RSYNC_EXCLUDE=(
    --exclude 'venv/'
    --exclude '.git/'
    --exclude '__pycache__/'
    --exclude '*.pyc'
    --exclude '.DS_Store'
    --exclude '*.log'
    --exclude '*.backup'
    --exclude '.pytest_cache/'
    --exclude 'backups/'
)

# Don't sync data directory if clean install
if [ "$CLEAN_INSTALL" = false ]; then
    RSYNC_EXCLUDE+=(--exclude 'data/')
fi

# Always exclude .env (will be copied separately)
RSYNC_EXCLUDE+=(--exclude '.env')

if [ "$DRY_RUN" = true ]; then
    RSYNC_OPTS="$RSYNC_OPTS --dry-run"
fi

rsync $RSYNC_OPTS "${RSYNC_EXCLUDE[@]}" ./ ${PI_USER}@${PI_HOST}:${PI_PATH}/

log_success "Code synchronized"

# Copy .env file separately
log_info "Copying .env file..."
if [ "$DRY_RUN" = false ]; then
    scp .env ${PI_USER}@${PI_HOST}:${PI_PATH}/.env
    log_success ".env file copied"
else
    log_info "[DRY RUN] Would copy .env file"
fi

# Run setup on Pi
log_header "Remote Setup"

if [ "$DRY_RUN" = true ]; then
    log_info "[DRY RUN] Would run setup on Pi"
    log_header "Deployment Complete (Dry Run)"
    exit 0
fi

ssh ${PI_USER}@${PI_HOST} "bash -s" << ENDSSH
set -e

cd ${PI_PATH}

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  IoTSentinel Setup"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

# Load environment variables
if [ -f .env ]; then
    export \$(cat .env | grep -v '^#' | xargs)
fi

# Clean install - remove data
if [ "$CLEAN_INSTALL" = true ]; then
    echo "🗑️  Removing old data (clean install)..."
    rm -rf data/database/*
    rm -rf data/baseline/*
    rm -rf data/logs/*
    rm -rf data/models/*
    echo "✓ Old data removed"
fi

# Create directory structure
echo "📁 Creating directory structure..."
mkdir -p data/{baseline,models,database,logs}
mkdir -p capture ml dashboard config services scripts utils

# Check Zeek installation
echo "🔍 Checking Zeek installation..."
if ! command -v /opt/zeek/bin/zeek &> /dev/null; then
    echo "❌ Zeek is not installed at /opt/zeek/bin/zeek"
    echo "Please install Zeek first!"
    exit 1
fi

ZEEK_VERSION=\$(/opt/zeek/bin/zeek --version | head -1)
echo "✓ Found Zeek: \$ZEEK_VERSION"

# Verify Zeek status
echo "📊 Checking Zeek status..."
ZEEK_STATUS=\$(sudo /opt/zeek/bin/zeekctl status 2>&1 || echo "not running")
if echo "\$ZEEK_STATUS" | grep -q "running"; then
    echo "✓ Zeek is running"
else
    echo "⚠️  Zeek is not running. Starting..."
    sudo /opt/zeek/bin/zeekctl deploy
    sleep 3
    sudo /opt/zeek/bin/zeekctl status
fi

# Python virtual environment
if [ ! -d "venv" ]; then
    echo "🐍 Creating Python virtual environment..."
    python3 -m venv venv
else
    echo "✓ Virtual environment exists"
fi

# Install dependencies
echo "📦 Installing Python dependencies..."
source venv/bin/activate
pip install --upgrade pip setuptools --quiet
pip install -r requirements-pi.txt --quiet
echo "✓ Python packages installed"

# Set permissions
echo "🔐 Setting permissions..."
chmod +x scripts/*.sh 2>/dev/null || true
chmod +x scripts/*.py 2>/dev/null || true
chmod +x capture/*.py 2>/dev/null || true
chmod 600 .env

# Initialize database
if [ ! -f "data/database/iotsentinel.db" ]; then
    echo "🗄️  Initializing database..."
    python3 config/init_database.py
    echo "✓ Database initialized"
else
    echo "✓ Database exists"

    # Run migrations if needed
    if [ -f "config/migrate_database.py" ]; then
        echo "🔄 Running database migrations..."
        python3 config/migrate_database.py || echo "⚠️  No migrations needed"
    fi
fi

# Install/update systemd services
echo "⚙️  Installing systemd services..."
if [ -f "services/iotsentinel-backend.service" ]; then
    sudo cp services/iotsentinel-backend.service /etc/systemd/system/
    sudo systemctl daemon-reload
    sudo systemctl enable iotsentinel-backend.service
    echo "✓ Backend service installed"
fi

if [ -f "services/iotsentinel-dashboard.service" ]; then
    sudo cp services/iotsentinel-dashboard.service /etc/systemd/system/
    sudo systemctl daemon-reload
    sudo systemctl enable iotsentinel-dashboard.service
    echo "✓ Dashboard service installed"
fi

# Restart services
echo "🔄 Restarting services..."
sudo systemctl restart iotsentinel-backend.service || echo "⚠️  Backend service not started"
sudo systemctl restart iotsentinel-dashboard.service || echo "⚠️  Dashboard service not started"

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  ✓ Setup Complete!"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
ENDSSH

log_success "Remote setup complete"

# Health check
log_header "Post-Deployment Health Check"

log_info "Waiting for services to start..."
sleep 5

log_info "Checking service status..."
ssh ${PI_USER}@${PI_HOST} "bash -s" << 'ENDSSH'
echo "Backend status:"
sudo systemctl status iotsentinel-backend.service --no-pager -l | head -10
echo ""
echo "Dashboard status:"
sudo systemctl status iotsentinel-dashboard.service --no-pager -l | head -10
ENDSSH

log_success "Health check complete"

# Validation
log_header "Post-Deployment Validation"

log_info "Running validation checks..."
ssh ${PI_USER}@${PI_HOST} "bash -s" << 'ENDSSH'
cd ${PI_PATH}
source venv/bin/activate

# Run validation script
if [ -f "scripts/validate_pi_deployment.sh" ]; then
    bash scripts/validate_pi_deployment.sh
else
    echo "⚠️  Validation script not found (skipping)"
fi
ENDSSH

VALIDATION_EXIT=$?

echo ""

# Summary
log_header "Deployment Summary"

echo ""

if [ $VALIDATION_EXIT -eq 0 ]; then
    log_success "✓ Deployment completed successfully - 100% ready!"
else
    log_warning "⚠ Deployment completed but validation found issues"
    log_info "Review validation output above and fix any critical errors"
fi

echo ""
log_info "Dashboard URL: http://${PI_HOST}:8050"
log_info "Default login: admin / admin"
log_warning "IMPORTANT: Change the default password immediately!"
echo ""

if [ "$CLEAN_INSTALL" = true ]; then
    log_info "Next steps for clean install:"
    echo "  1. SSH to Pi: ${CYAN}ssh ${PI_USER}@${PI_HOST}${NC}"
    echo "  2. Start baseline collection: ${CYAN}cd ~/iotsentinel && source venv/bin/activate${NC}"
    echo "     ${CYAN}python3 scripts/baseline_collector.py start${NC}"
    echo "  3. Wait 24 hours for baseline to establish"
else
    log_info "Next steps:"
    echo "  1. Access dashboard at: ${CYAN}http://${PI_HOST}:8050${NC}"
    echo "  2. Login and verify all services are running"
    echo "  3. Check logs if needed: ${CYAN}ssh ${PI_USER}@${PI_HOST} 'journalctl -u iotsentinel-dashboard -f'${NC}"
fi

echo ""
log_info "Backup location: ${BACKUP_DIR}/"
log_info "To rollback: ${CYAN}ssh ${PI_USER}@${PI_HOST} 'cd ${BACKUP_DIR} && tar -xzf iotsentinel_backup_*.tar.gz'${NC}"
log_info "Re-run validation: ${CYAN}ssh ${PI_USER}@${PI_HOST} 'cd ~/iotsentinel && bash scripts/validate_pi_deployment.sh'${NC}"
echo ""

log_header "Deployment Complete"
