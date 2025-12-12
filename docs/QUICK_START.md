# IoTSentinel - Quick Start Guide

## 🎯 Two-Branch System

This project uses **two branches** for different purposes:

### 🚀 `main` - Production Code (You are here!)

**For**: Running IoTSentinel on your Raspberry Pi

```bash
git checkout main
python dashboard/app.py  # Production dashboard
python orchestrator.py   # Full system
```

### 📚 `academic-evidence` - Academic Documentation

**For**: Writing reports, generating evidence for AT2/AT3

```bash
git checkout academic-evidence
python dashboard/app.py  # Dashboard + Academic Evidence modal
```

---

## Quick Commands

### Production Use (stay on `main`)
```bash
# Start the system
python orchestrator.py

# Start dashboard only
python dashboard/app.py

# Run tests
pytest tests/

# Deploy to Raspberry Pi
# (uses main branch - clean production code)
```

### Academic Report Writing (switch to `academic-evidence`)
```bash
# Switch branches
git checkout academic-evidence

# Run academic evidence tests
python academic/test_academic_modules.py

# Start dashboard with academic features
python dashboard/app.py
# Click "Academic Evidence" button in dashboard

# Generate evidence exports
# Use the dashboard Export tab or:
python -c "
from academic.bcs_compliance import BCSComplianceManager
from academic.rtm_generator import RTMGenerator
bcs = BCSComplianceManager('data/iotsentinel.db')
bcs.export_to_json()
rtm = RTMGenerator('data/iotsentinel.db')
rtm.export_to_csv()
print('Evidence exported to data/')
"
```

---

## What's Different Between Branches?

| Feature | `main` | `academic-evidence` |
|---------|--------|---------------------|
| Production code | ✅ | ✅ |
| Academic modules | ❌ | ✅ |
| BCS compliance docs | ❌ | ✅ |
| RTM generator | ❌ | ✅ |
| Risk register | ❌ | ✅ |
| Performance benchmarks | ❌ | ✅ |
| C4 diagrams | ❌ | ✅ |
| Dependencies | Minimal | + diagrams |

---

## When to Use Which Branch?

### Use `main` for:
- ✅ Normal development
- ✅ Testing features
- ✅ Deploying to Raspberry Pi
- ✅ Running in production
- ✅ Demonstrating the system

### Use `academic-evidence` for:
- 📝 Writing AT2 implementation report
- 📝 Writing AT3 final report
- 📊 Generating BCS compliance evidence
- 📊 Exporting requirements traceability matrix
- 📊 Creating architecture diagrams
- 📸 Taking screenshots for reports

---

## Current Status

You are on: **`main`** branch

```bash
# Check current branch
git branch

# Switch to academic branch
git checkout academic-evidence

# Switch back to main
git checkout main
```

---

## For More Details

- **BRANCH_STRATEGY.md** - Complete branch strategy explanation
- **README.md** - Main project documentation
- On `academic-evidence` branch:
  - **ACADEMIC_EVIDENCE_INTEGRATION_GUIDE.md** - How to use academic features
  - **IMPLEMENTATION_COMPLETE.md** - What was implemented
  - **academic/README.md** - Academic module documentation

---

**Quick Tip**: Think of it like this:
- `main` = The actual IoT security system (production)
- `academic-evidence` = The report writing toolkit (documentation)

Both are based on the same core code, but `academic-evidence` adds tools
specifically for generating evidence for your university submissions.
