# Code Manifest

**Generated**: 2025-11-05 01:33:47

This manifest lists all source code files created or modified for IoTSentinel.

## File Manifest Table

| File Path | Type | Lines | Purpose | Complexity |
|-----------|------|-------|---------|------------|
| `database/db_manager.py` | Created | 350 | SQLite database manager with CRUD operations | Medium |
| `database/schema.sql` | Created | 60 | Database schema definition | Low |
| `ml/feature_extractor.py` | Created | 250 | 15+ feature extraction from network connections | High |
| `ml/inference_engine.py` | Created | 280 | Real-time ML inference with dual models | High |
| `ml/train_autoencoder.py` | Created | 200 | Train Autoencoder neural network | High |
| `ml/train_isolation_forest.py` | Created | 180 | Train Isolation Forest model | Medium |
| `capture/zeek_log_parser.py` | Created | 320 | Parse Zeek JSON logs into database | Medium |
| `dashboard/app.py` | Created | 1200 | Complete Dash web dashboard with 5 tabs | High |
| `config/config_manager.py` | Created | 150 | Multi-layer configuration management | Low |
| `config/init_database.py` | Created | 80 | Initialize database schema | Low |
| `scripts/baseline_collector.py` | Created | 280 | 7-day baseline collection orchestration | Medium |
| `scripts/generate_test_data.py` | Created | 250 | Generate realistic test data | Low |
| `scripts/deploy_to_pi.sh` | Created | 120 | Automated deployment to Raspberry Pi | Low |
| `tests/test_database.py` | Created | 450 | 22 unit tests for database manager | Medium |
| `tests/test_ml.py` | Created | 480 | 23 unit tests for ML components | Medium |
| `tests/test_integration.py` | Created | 400 | 10 integration tests for pipeline | High |
| `utils/metrics_collector.py` | Created | 350 | System metrics collection and reporting | Medium |

**Total Files**: 17
**Total Lines of Code**: 5,400

## Code Statistics

- **Python Files**: 15
- **Shell Scripts**: 1
- **SQL Files**: 1

## Complexity Breakdown

- **High Complexity**: 5 files
- **Medium Complexity**: 7 files
- **Low Complexity**: 5 files

## Key Implementation Highlights

1. **Database Manager** (`db_manager.py`)
   - Implements connection pooling and transaction support
   - Uses parameterized queries to prevent SQL injection
   - Batch processing pattern for ML engine

2. **Feature Extractor** (`feature_extractor.py`)
   - Extracts 15+ features from network metadata
   - Handles missing values and zero division
   - Standardization (zero mean, unit variance)

3. **Inference Engine** (`inference_engine.py`)
   - Dual-model approach (Autoencoder + Isolation Forest)
   - Real-time processing with < 30s latency
   - Automatic alert generation with explanations

4. **Dashboard** (`app.py`)
   - 5 tabs: Network, Alerts, Devices, Analytics, System
   - Real-time updates every 5 seconds
   - Educational transparency features

