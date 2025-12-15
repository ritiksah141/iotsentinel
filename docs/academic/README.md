# Academic Documentation & Tools

This folder contains both **academic documentation** (Markdown files) and **Python modules** for generating academic evidence.

---

## 📁 Folder Contents

### Documentation Files (5 Markdown files)
Academic documentation for AT4 Project Review Report submission.

### Python Modules (9 Python files)
Tools for generating academic evidence, compliance data, and project artifacts.

---

## 📄 Documentation Index

### 1. USER_STORIES.md (15K)
**Purpose**: User stories and requirements specification
**For AT4**: Requirements analysis and user-centered design evidence
**Section**: Requirements Engineering

Key content:
- User personas and scenarios
- Functional and non-functional requirements
- Acceptance criteria for features

---

### 2. USER_PERSONAS.md (8.1K)
**Purpose**: Detailed user personas for design
**For AT4**: User research and target audience analysis
**Section**: Design and Requirements

Key content:
- Home user persona (Sarah)
- Small business owner persona
- Security professional persona
- Goals, pain points, and needs analysis

---

### 3. REQUIREMENTS_TRACEABILITY_MATRIX.md (10K)
**Purpose**: Trace requirements to implementation
**For AT4**: Evidence of systematic requirements tracking
**Section**: Requirements Management

Key content:
- Requirements mapped to features
- Implementation status tracking
- Test case linkage

---

### 4. RISK_REGISTER.md (26K)
**Purpose**: Risk identification and mitigation
**For AT4**: Project management and risk analysis
**Section**: Risk Management

Key content:
- 15+ risks identified
- Risk severity assessment
- Mitigation strategies
- Risk monitoring and control

---

### 5. C4_ARCHITECTURE.md (12K)
**Purpose**: System architecture documentation
**For AT4**: Architecture design and technical depth
**Section**: System Design

Key content:
- Context diagrams
- Container diagrams
- Component diagrams
- Deployment architecture

---

---

## For AT4 Report

### How to Use These Documents

**Requirements Section**:
- Reference USER_STORIES.md for requirements gathering
- Include USER_PERSONAS.md for user research
- Use REQUIREMENTS_TRACEABILITY_MATRIX.md to show requirements coverage

**Design Section**:
- Reference C4_ARCHITECTURE.md for architecture design
- Include /database/schema.sql for database schema
- Reference Python modules for technical implementation

**Project Management Section**:
- Reference RISK_REGISTER.md for risk management
- Show systematic approach to risk mitigation

### Suggested Appendices

**Appendix A**: Requirements Documentation
- USER_STORIES.md
- USER_PERSONAS.md
- REQUIREMENTS_TRACEABILITY_MATRIX.md

**Appendix B**: Design Documentation
- C4_ARCHITECTURE.md
- Database schema (/database/schema.sql)

**Appendix C**: Project Management
- RISK_REGISTER.md

---

## Related Documentation

**Testing Documentation**: `/docs/testing/`
- See testing folder for all test-related documentation (30% of AT4)

**User Documentation**: `/docs/`
- README.md - Documentation overview
- DEPLOYMENT_GUIDE.md - Deployment instructions
- SYSTEM_CONFIGURATION_MANUAL.md - Configuration reference

---

## 🐍 Python Modules

This folder also contains Python modules for generating academic evidence and documentation.

### Available Modules

**1. bcs_compliance.py**
- Generates BCS (British Computer Society) compliance evidence
- Exports compliance data to JSON
- Maps features to BCS competency requirements

**2. rtm_generator.py**
- Generates Requirements Traceability Matrix
- Links requirements to implementation and tests
- Exports to CSV and JSON formats

**3. risk_register.py**
- Manages project risk register
- Tracks risk severity, likelihood, and mitigation
- Exports risk data for reporting

**4. c4_generator.py**
- Generates C4 architecture diagrams
- Creates context, container, and component diagrams
- Exports diagrams in text and JSON formats

**5. performance_metrics.py**
- Collects system performance metrics
- Tracks database, ML inference, and API performance
- Exports metrics to CSV

**6. dashboard_components.py**
- Dash components for academic evidence visualization
- Modal dialogs and buttons for evidence display
- Dashboard integration helpers

**7. test_academic_modules.py**
- Test suite for all academic modules
- Verifies module functionality
- Run with: `python docs/academic/test_academic_modules.py`

**8. __init__.py**
- Python package initialization
- Allows imports like: `from docs.academic.rtm_generator import RTMGenerator`

### Usage

```python
# Import from docs.academic
from docs.academic.rtm_generator import RTMGenerator
from docs.academic.bcs_compliance import BCSComplianceManager

# Generate evidence
rtm = RTMGenerator(db_path)
rtm_data = rtm.generate_rtm()
rtm.export_to_csv("output.csv")
```

### Running Tests

```bash
# Test all academic modules
python docs/academic/test_academic_modules.py

# Or run specific tests
python -c "from docs.academic.bcs_compliance import BCSComplianceManager; print('OK')"
```

### Integration

See `/scripts/integrate_academic_evidence.py` for guided integration into the main dashboard.

---

**Last Updated**: December 15, 2024
**Purpose**: AT4 Project Review Report (30% of final grade)
**Status**: Complete - Ready for submission
**Contents**: 5 documentation files + 9 Python modules + 1 comprehensive README
