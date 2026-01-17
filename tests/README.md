# IoTSentinel Test Suite Documentation

Comprehensive testing suite for the IoTSentinel network security monitoring system.

## 📊 Test Coverage Overview

| Component               | Test File                           | Tests | Status |
| ----------------------- | ----------------------------------- | ----- | ------ |
| Database Operations     | `test_database.py`                  | 50+   | ✅     |
| Zeek Log Capture        | `test_capture.py`                   | 11    | ✅     |
| Email Alerts            | `test_alerts.py`                    | 15    | ✅     |
| ML Models               | `test_ml.py`                        | 20+   | ✅     |
| Inference Engine        | `test_inference_engine.py`          | 15+   | ✅     |
| Integration Pipeline    | `test_integeration.py`              | 25+   | ✅     |
| River ML Engine         | `test_ml.py`                        | 20+   | ✅     |
| ML Inference            | `test_integeration.py`              | 15+   | ✅     |
| Error Scenarios         | `test_error_scenarios.py`           | 12+   | ✅     |
| **Dashboard Features**  | `test_dashboard_features.py`        | 30    | ✅ NEW |
| **API Integration Hub** | `test_dashboard_api_integration.py` | 16    | ✅ NEW |

**Total Tests: 180+**

---

## 🚀 Quick Start

### Prerequisites

```bash
# Install testing dependencies
pip install -r requirements-dev.txt

# Or install core testing packages
pip install pytest pytest-cov pytest-mock
```

### Run All Tests

```bash
# Run all tests with coverage
pytest

# Run with verbose output
pytest -v

# Run with coverage report
pytest --cov=. --cov-report=html --cov-report=term-missing
```

### Run Specific Test Categories

```bash
# Unit tests only
pytest -m unit

# Integration tests only
pytest -m integration

# Dashboard tests
pytest -m dashboard

# API tests
pytest -m api

# ML model tests
pytest -m ml

# Database tests
pytest -m database

# Critical tests only
pytest -m critical
```

### Run Specific Test Files

```bash
# Test database operations
pytest tests/test_database.py -v

# Test dashboard features
pytest tests/test_dashboard_features.py -v

# Test API integration
pytest tests/test_dashboard_api_integration.py -v

# Test ML models
pytest tests/test_ml.py -v
```

---

## 📁 Test Structure

```
tests/
├── README.md                          # This file
├── conftest.py                        # Shared pytest fixtures
├── test_database.py                   # Database CRUD operations
├── test_capture.py                    # Zeek log parsing
├── test_alerts.py                     # Email alerting system
├── test_ml.py                         # ML model training/inference
├── test_inference_engine.py           # Real-time inference
├── test_integeration.py               # End-to-end pipeline
├── test_ml.py                         # River ML engine tests
├── test_integeration.py               # ML integration tests
├── test_error_scenarios.py            # Error handling
├── test_dashboard_features.py         # 16 competitive features
└── test_dashboard_api_integration.py  # Threat intelligence APIs
```

---

## 🧪 Test Categories

### Unit Tests (`-m unit`)

Test individual components in isolation:

- Database operations (CRUD)
- Feature extraction
- Data parsing
- Model predictions
- Alert generation

### Integration Tests (`-m integration`)

Test connected systems:

- Zeek logs → Parser → Database
- Database → Feature Extraction → ML Inference
- ML Predictions → Alert Generation
- Complete pipeline end-to-end

### API Tests (`-m api`)

Test external API integrations:

- AbuseIPDB connectivity
- VirusTotal connectivity
- Shodan connectivity
- AlienVault OTX connectivity
- GreyNoise connectivity
- IPinfo connectivity
- MITRE ATT&CK framework

### Dashboard Tests (`-m dashboard`)

Test all 16 competitive features:

1. ML Model Comparison Chart
2. Educational Tooltips
3. IoT Protocol Analyzer
4. Device Intelligence Panel
5. Live Threat Feed
6. Sustainability Widget
7. Network Topology Map
8. Attack Pattern Recognition
9. Device Behavior Profiling
10. Predictive Analytics
11. Customizable Widget Dashboard
12. API Integration Hub
13. Geographic Threat Map
14. Real-time Threat Intelligence
15. Advanced Alert Management
16. Dashboard Preferences

### Database Tests (`-m database`)

Test database operations:

- Device CRUD operations
- Connection logging
- Alert storage
- ML prediction storage
- Data integrity

### ML Tests (`-m ml`)

Test machine learning models:

- Isolation Forest training
- River ML incremental learning
- Feature extraction
- Model inference
- Anomaly detection

---

## 📈 Coverage Reports

### Generate HTML Coverage Report

```bash
# Generate coverage report
pytest --cov=. --cov-report=html

# Open the report
open htmlcov/index.html  # macOS
xdg-open htmlcov/index.html  # Linux
start htmlcov/index.html  # Windows
```

### Generate Terminal Coverage Report

```bash
# Show missing lines
pytest --cov=. --cov-report=term-missing

# Show only uncovered lines
pytest --cov=. --cov-report=term-missing:skip-covered
```

### Coverage Goals

- **Overall Coverage**: ≥ 80%
- **Critical Components**: ≥ 90%
  - Database operations
  - ML inference
  - Alert generation
- **Dashboard Components**: ≥ 70%
- **Utilities**: ≥ 60%

---

## 🎯 Test Markers

Tests are tagged with markers for easy filtering:

| Marker        | Description                             | Count |
| ------------- | --------------------------------------- | ----- |
| `unit`        | Unit tests for individual components    | 120+  |
| `integration` | Integration tests for connected systems | 30+   |
| `api`         | Tests requiring external API calls      | 16    |
| `database`    | Tests interacting with database         | 50+   |
| `dashboard`   | Tests for dashboard features            | 30    |
| `ml`          | Tests for ML models                     | 40+   |
| `slow`        | Tests taking > 5 seconds                | 20+   |
| `critical`    | Must-pass tests for production          | 50+   |

### Using Markers

```bash
# Run only critical tests (for CI/CD)
pytest -m critical

# Skip slow tests
pytest -m "not slow"

# Run dashboard and API tests
pytest -m "dashboard or api"

# Run everything except API tests (no external dependencies)
pytest -m "not api"
```

---

## 🔧 Configuration

### pytest.ini

The `pytest.ini` file at project root configures:

- Test discovery patterns
- Coverage settings
- Output formatting
- Test markers
- Timeout limits

### conftest.py

Shared fixtures defined in `tests/conftest.py`:

```python
@pytest.fixture
def db():
    """Create clean in-memory database for each test."""
    # Returns DatabaseManager instance with test schema
```

---

## 📝 Writing New Tests

### Test Naming Convention

```python
# Test files: test_<component>.py
test_database.py
test_capture.py

# Test classes: Test<Feature>
class TestDeviceOperations:
    pass

# Test functions: test_<what>_<expected>
def test_add_device_success(self, db):
    pass
```

### Test Case ID Convention

```python
def test_add_device_success(self, db):
    """TC-DB-001: Verify successful device insertion."""
    # TC-DB-001 = Test Case - Database - Test Number 001
```

### Example Test

```python
import pytest

@pytest.mark.unit
@pytest.mark.database
class TestDeviceOperations:
    """Test suite for device management."""

    def test_add_device_success(self, db):
        """TC-DB-001: Verify successful device insertion."""
        # Arrange
        device = {
            'device_ip': '192.168.1.100',
            'device_name': 'Test Laptop'
        }

        # Act
        result = db.add_device(**device)

        # Assert
        assert result is True
        devices = db.get_all_devices()
        assert len(devices) == 1
```

---

## 🐛 Debugging Failed Tests

### Verbose Output

```bash
# Show full test output
pytest -v

# Show full error tracebacks
pytest -vv

# Show print statements
pytest -s
```

### Run Single Test

```bash
# Run specific test function
pytest tests/test_database.py::TestDeviceOperations::test_add_device_success -v

# Run specific test class
pytest tests/test_database.py::TestDeviceOperations -v
```

### Debug with PDB

```python
# Add breakpoint in test
def test_something():
    import pdb; pdb.set_trace()
    # Test code
```

```bash
# Run with debugger
pytest --pdb
```

---

## 🔄 Continuous Integration

### Pre-commit Hook

```bash
# Run before committing
pytest -m critical --cov=. --cov-fail-under=80
```

### CI/CD Pipeline

```yaml
# Example GitHub Actions workflow
- name: Run Tests
  run: |
    pip install -r requirements-dev.txt
    pytest -m "critical and not slow" --cov=. --cov-report=xml

- name: Upload Coverage
  uses: codecov/codecov-action@v3
```

---

## 📊 Test Metrics (For AT3/AT4 Submission)

Current test metrics as of last run:

- **Total Tests**: 180+
- **Test Coverage**: ~75% (backend), ~30% (dashboard)
- **Passing Tests**: 148/148 (backend only)
- **Failed Tests**: 0
- **Skipped Tests**: Variable (based on API keys configured)
- **Average Test Duration**: 0.5s per test
- **Total Suite Duration**: ~90s

### Coverage by Component

| Component             | Coverage | Tests |
| --------------------- | -------- | ----- |
| Database Manager      | 95%      | 50+   |
| Zeek Parser           | 90%      | 11    |
| Email Alerts          | 85%      | 15    |
| ML Models             | 80%      | 40+   |
| Inference Engine      | 85%      | 15+   |
| Dashboard (NEW)       | 30%      | 30    |
| API Integration (NEW) | 40%      | 16    |

---

## 🚨 Common Issues

### Issue: Tests fail with "No module named X"

```bash
# Solution: Install dependencies
pip install -r requirements-dev.txt
```

### Issue: Database tests fail

```bash
# Solution: Database fixtures are in-memory
# Each test gets a fresh database via conftest.py
# If still failing, check schema in conftest.py matches production
```

### Issue: API tests skip

```bash
# Solution: Configure API keys in .env
# Tests automatically skip if API keys not configured
export THREAT_INTELLIGENCE_ABUSEIPDB_API_KEY=your_key_here
export VIRUSTOTAL_API_KEY=your_key_here
# ... etc
```

### Issue: Coverage report not generating

```bash
# Solution: Install coverage package
pip install pytest-cov coverage

# Generate report
pytest --cov=. --cov-report=html
```

---

## 📚 Additional Resources

- [Pytest Documentation](https://docs.pytest.org/)
- [Pytest Coverage Plugin](https://pytest-cov.readthedocs.io/)
- [Testing Best Practices](https://docs.python-guide.org/writing/tests/)
- [COM668 Module Handbook](../docs/COM668_Module_Handbook.pdf)

---

## 📞 Support

For questions about tests:

1. Check this README
2. Review existing tests for examples
3. Check pytest documentation
4. Open an issue on GitHub

---

**Last Updated**: December 2024
**Test Suite Version**: 2.0
**Compatible with**: IoTSentinel v1.0+
