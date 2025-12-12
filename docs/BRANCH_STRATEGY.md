# IoTSentinel Branch Strategy

## Overview

This project uses a **two-branch strategy** to separate production code from academic evidence/documentation.

## Branch Structure

### 🚀 `main` - Production Code (Clean)

**Purpose**: Production-ready IoTSentinel system

**Contains**:
- Core system components (capture, ML, alerts, dashboard)
- Production deployment code
- Essential documentation (README, deployment guides)
- Production dependencies only

**Does NOT contain**:
- Academic evidence modules
- BCS compliance documentation
- Requirements traceability matrices
- Risk registers
- Performance benchmarking reports
- Architecture diagram generators

**Use for**:
- Production deployment to Raspberry Pi
- Feature development
- Bug fixes
- System testing
- Real-world usage

### 📚 `academic` - Academic Documentation

**Purpose**: Academic evidence for AT2/AT3 submissions and BCS compliance

**Contains**:
- `academic/` - Complete academic evidence collection system
  - BCS Compliance Manager
  - Requirements Traceability Matrix Generator
  - Risk Register Manager
  - Performance Metrics Collector
  - C4 Architecture Diagram Generator
  - Dashboard Integration Components
- Academic integration guides
- Implementation documentation
- Test scripts for academic modules
- Generated evidence exports (JSON/CSV/diagrams)

**Use for**:
- Generating evidence for AT2 (Implementation Report)
- Generating evidence for AT3 (Final Report)
- BCS compliance documentation
- Screenshots for reports
- Exporting requirements traceability
- Creating architecture diagrams

## Working with Branches

### For Production Development

```bash
# Stay on main
git checkout main

# Make changes to production code
# Test, commit, deploy as normal

git add .
git commit -m "Your production feature/fix"
git push origin main
```

### For Academic Evidence/Reports

```bash
# Switch to academic branch
git checkout academic

# Now you have access to:
# - academic/ modules
# - Integration guides
# - Test scripts

# Run academic evidence dashboard
python dashboard/app.py  # With academic features integrated

# Generate evidence
python academic/test_academic_modules.py
# OR use the dashboard "Academic Evidence" modal

# Take screenshots, export data for reports
```

### Updating Academic Evidence

```bash
# Switch to academic branch
git checkout academic

# Make changes to academic modules
vim academic/bcs_compliance.py

# Test changes
python academic/test_academic_modules.py

# Commit
git add academic/
git commit -m "Update BCS compliance evidence"
git push origin academic
```

### Keeping Branches in Sync

When you make production changes on `main` that you want reflected in academic evidence:

```bash
# On academic branch
git checkout academic

# Merge latest main into academic
git merge main

# Resolve any conflicts
# Commit the merge
```

## Files by Branch

### `main` Branch Files

```
iotsentinel/
├── alerts/           # Alert management
├── capture/          # Packet capture
├── config/           # Configuration
├── dashboard/        # Web dashboard (production UI only)
├── database/         # Database management
├── ml/              # Machine learning models
├── scripts/         # Production scripts
├── services/        # Background services
├── tests/           # Unit tests
├── utils/           # Utilities
├── README.md        # Main documentation
├── requirements.txt # Production dependencies
└── orchestrator.py  # Main orchestrator
```

### `academic` Branch Additional Files

```
iotsentinel/
├── academic/                              # Academic evidence modules
│   ├── __init__.py
│   ├── bcs_compliance.py
│   ├── rtm_generator.py
│   ├── risk_register.py
│   ├── performance_metrics.py
│   ├── c4_generator.py
│   ├── dashboard_components.py
│   ├── test_academic_modules.py
│   └── README.md
├── ACADEMIC_EVIDENCE_INTEGRATION_GUIDE.md
├── IMPLEMENTATION_COMPLETE.md
├── BRANCH_STRATEGY.md (this file)
├── scripts/
│   └── integrate_academic_evidence.py
├── data/
│   ├── bcs_evidence_*.json
│   ├── rtm_*.csv
│   ├── risk_register_*.json
│   ├── performance_metrics_*.csv
│   ├── architecture_docs_*.json
│   └── diagrams/
└── requirements.txt (includes diagrams library)
```

## .gitignore Strategy

The `.gitignore` on `main` excludes all academic evidence files:

```gitignore
# Academic Evidence (lives on academic branch only)
academic/
ACADEMIC_EVIDENCE_INTEGRATION_GUIDE.md
IMPLEMENTATION_COMPLETE.md
scripts/integrate_academic_evidence.py
data/bcs_evidence_*.json
data/rtm_*.csv
data/risk_register_*.json
data/performance_metrics_*.csv
data/architecture_docs_*.json
data/diagrams/
```

This ensures academic files can't accidentally be committed to `main`.

## Deployment Strategy

### Production Deployment (Raspberry Pi)

**Use**: `main` branch

```bash
# On Raspberry Pi
git clone <repo-url>
git checkout main  # Ensure on main branch
pip install -r requirements.txt
python orchestrator.py
```

Benefits:
- Clean, minimal dependencies
- No academic overhead
- Faster deployment
- Production-focused

### Academic Evidence Generation (Development Machine)

**Use**: `academic` branch

```bash
# On development machine
git clone <repo-url>
git checkout academic
pip install -r requirements.txt  # Includes diagrams library
python dashboard/app.py  # With academic features
```

Benefits:
- Full academic evidence system
- Export capabilities
- Screenshot generation
- Report preparation

## Timeline Workflow

### During Development (Now - April 2025)

**Primary Branch**: `main`
- Develop features
- Fix bugs
- Test system
- Deploy to Raspberry Pi

**Switch to**: `academic`
- When writing reports
- To generate evidence
- To take screenshots
- To export data

### For AT2 Submission (April 10, 2025)

```bash
# Switch to academic
git checkout academic

# Generate all evidence
python academic/test_academic_modules.py

# Run dashboard, take screenshots
python dashboard/app.py

# Export everything
# - BCS Compliance → JSON
# - RTM → CSV
# - Risk Register → JSON
# - Performance Metrics → CSV
# - C4 Diagrams → PNG/TXT

# Include in report appendices
```

### For AT3 Submission (Later)

```bash
# Same process
git checkout academic

# Export final 24-hour performance metrics
# Generate complete evidence package
# Update any documentation
# Take final screenshots
```

### After Graduation

**Keep**: `main` branch
- Production system still works
- Can deploy to new devices
- Can maintain/enhance

**Archive**: `academic` branch
- Historical record of academic work
- Can reference for portfolio
- Demonstrates academic rigor

## Quick Reference

| Task | Branch | Command |
|------|--------|---------|
| Deploy to Pi | `main` | `git checkout main` |
| Develop features | `main` | `git checkout main` |
| Fix bugs | `main` | `git checkout main` |
| Write reports | `academic` | `git checkout academic` |
| Generate evidence | `academic` | `git checkout academic` |
| Take screenshots | `academic` | `git checkout academic` |
| Export RTM | `academic` | `git checkout academic` |
| Create diagrams | `academic` | `git checkout academic` |

## Benefits of This Strategy

### ✅ Clean Production Code
- `main` branch has no academic overhead
- Faster deployment
- Smaller dependency footprint
- Professional production environment

### ✅ Complete Academic Evidence
- `academic` has everything for submissions
- All evidence generation tools
- Export capabilities
- Integration guides

### ✅ No Conflicts
- Academic code can't pollute production
- .gitignore prevents accidents
- Clear separation of concerns

### ✅ Easy Switching
- One command to switch contexts
- All tools available when needed
- Nothing in the way when not needed

## Support

### Current Branch
```bash
git branch  # Shows current branch with *
```

### Switch Branches
```bash
git checkout main              # Production
git checkout academic # Academic
```

### List All Branches
```bash
git branch -a
```

### See What's Different Between Branches
```bash
git diff main..academic
```

## Summary

| | `main` | `academic` |
|---|---|---|
| **Purpose** | Production system | Academic documentation |
| **Deployment** | Raspberry Pi | Development only |
| **Dependencies** | Minimal | Includes diagrams, etc. |
| **Dashboard** | Production UI | + Academic Evidence modal |
| **Use for** | Real-world operation | AT2/AT3 submissions |
| **File count** | ~50 files | ~65 files (+academic) |
| **Lines of code** | ~6,500 | ~9,500 (+3,000 academic) |

---

**Created**: 2025-12-12
**Strategy**: Two-branch separation of production and academic code
**Benefit**: Clean production, complete academic evidence
