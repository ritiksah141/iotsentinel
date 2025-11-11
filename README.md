# 🛡️ IoTSentinel

**Professional Network Security Monitor for Raspberry Pi using Unsupervised Machine Learning**

[![Architecture](https://img.shields.io/badge/Architecture-Zeek--based-blue)]()
[![ML](https://img.shields.io/badge/ML-Autoencoder%20%2B%20Isolation%20Forest-green)]()
[![Tests](https://img.shields.io/badge/Tests-59%20passed-brightgreen)]()
[![Coverage](https://img.shields.io/badge/Coverage-84%25-brightgreen)]()
[![Platform](https://img.shields.io/badge/Platform-Raspberry%20Pi%205-red)]()

## 🎯 Project Overview

IoTSentinel is an educational network security monitor that uses **Zeek**, an enterprise-grade network analysis framework, combined with **unsupervised machine learning** to detect anomalies in home network traffic. It is designed to be a privacy-first, low-power solution that runs entirely on a Raspberry Pi.

The project's unique value proposition is **educational transparency**: it doesn't just block threats, it explains *why* an activity was flagged as anomalous, helping non-technical users understand their network's behavior.

### Key Features

- ✅ **Professional Architecture**: Leverages Zeek's powerful C++ engine for deep protocol analysis.
- ✅ **Unsupervised ML**: A dual-model approach using an Autoencoder and an Isolation Forest for zero-day threat detection.
- ✅ **Educational Dashboard**: A user-friendly web interface that explains *why* an alert was triggered, showing the contributing factors.
- ✅ **Privacy-First**: All data processing and analysis happens on-device. No data is sent to the cloud.
- ✅ **Low Power**: Optimized for a Raspberry Pi 5, consuming significantly less power than a traditional desktop-based solution.
- ✅ **Comprehensive Testing**: Includes 59 unit and integration tests, achieving 84% code coverage.

## 🏗️ Architecture

The system follows a modular, pipeline-based architecture:

```
┌────────────────────────────────────┐
│         Raspberry Pi 5             │
│  ┌──────────────────────────────┐  │
│  │ Zeek (C++)                   │  │
│  │ Real-time protocol analysis  │  │
│  │ ↓ (JSON logs)                │  │
│  └──────────────────────────────┘  │
│             ↓                      │
│  ┌──────────────────────────────┐  │
│  │ Python Log Parser            │  │
│  │ Parses JSON logs into a      │  │
│  │ → SQLite Database            │  │
│  └──────────────────────────────┘  │
│             ↓                      │
│  ┌──────────────────────────────┐  │
│  │ ML Inference Engine          │  │
│  │ - Extracts 15+ features      │  │
│  │ - Runs Autoencoder &         │  │
│  │   Isolation Forest models    │  │
│  └──────────────────────────────┘  │
│             ↓                      │
│  ┌──────────────────────────────┐  │
│  │ Dash Web Dashboard           │  │
│  │ - Displays network topology  │  │
│  │ - Shows educational alerts   │  │
│  └──────────────────────────────┘  │
└────────────────────────────────────┘
```

## 🚀 Getting Started

### Installation

1.  **Clone the repository**:
    ```bash
    git clone https://github.com/your_username/iotsentinel.git
    cd iotsentinel
    ```

2.  **Create a Python virtual environment**:
    ```bash
    python3 -m venv venv
    source venv/bin/activate
    ```

3.  **Install dependencies**:
    ```bash
    pip install -r requirements.txt
    ```
    *Note: For development on a non-Pi machine (like a Mac), you may need to adjust dependencies (e.g., `tensorflow` vs `tensorflow-macos`).*

4.  **Initialize the database**:
    ```bash
    python3 config/init_database.py
    ```

### Usage

The system operates in three main phases: data collection, model training, and monitoring.

**1. Baseline Data Collection (7 Days)**

To learn what "normal" traffic looks like on your network, run the baseline collector. This should be done on the Raspberry Pi connected to your home network.

```bash
python3 scripts/baseline_collector.py start
```
This process runs for 7 days. You can check its status at any time with:
```bash
python3 scripts/baseline_collector.py status
```

**2. Model Training**

After the 7-day collection period is complete, train the machine learning models:

```bash
# Train the Isolation Forest model
python3 ml/train_isolation_forest.py

# Train the Autoencoder model
python3 ml/train_autoencoder.py
```
This will create the model files in `data/models/`.

**3. Running the Application**

Once the models are trained, you can start the monitoring components. It's recommended to run these as background services.

- **Start the Log Parser**:
  ```bash
  python3 capture/zeek_log_parser.py --watch &
  ```
- **Start the ML Inference Engine**:
  ```bash
  python3 ml/inference_engine.py --continuous &
  ```
- **Start the Web Dashboard**:
  ```bash
  python3 dashboard/app.py
  ```
  You can then access the dashboard at `http://<your-pi-ip>:8050`.

### Testing

The project includes a comprehensive suite of **59 tests** with **84% code coverage**.

To run all tests:
```bash
pytest tests/
```

To run tests with a coverage report:
```bash
pytest tests/ --cov=. --cov-report=html
```
The HTML report will be generated in the `htmlcov/` directory.

## 📚 Documentation

Key project documentation can be found in the `docs/` directory:

- **[Comprehensive To-Do List](docs/COMPREHENSIVE_TODO_LIST.md)**: A detailed breakdown of all project tasks.
- **[Requirements Traceability Matrix](docs/REQUIREMENTS_TRACEABILITY_MATRIX.md)**: Maps requirements to design, code, and tests.
- **[Risk Register](docs/RISK_REGISTER.md)**: Identifies and mitigates project risks.
- **[Test Plan](docs/TEST_PLAN.md)**: Outlines the comprehensive testing strategy.
- **[Generated Docs](docs/generated/)**: Contains auto-generated reports like the Code Manifest and Test Coverage summary.

## 🔬 Technology Stack

- **Capture**: Zeek (formerly Bro)
- **Backend**: Python 3.11, SQLite
- **ML**: TensorFlow/Keras (Autoencoder), scikit-learn (Isolation Forest)
- **Frontend**: Dash by Plotly
- **Hardware**: Raspberry Pi 5 (4GB RAM recommended)

## 📝 License

This is an educational project. The code is provided as-is. Please see the `LICENSE` file for more details.