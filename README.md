# 🛡️ IoTSentinel

**Professional Network Security Monitor for Raspberry Pi using Unsupervised Machine Learning**

[![Architecture](https://img.shields.io/badge/Architecture-Zeek--based-blue)]()
[![ML](<https://img.shields.io/badge/ML-River%20ML%20(Incremental)-green>)]()
[![Tests](https://img.shields.io/badge/Tests-59%20passed-brightgreen)]()
[![Coverage](https://img.shields.io/badge/Coverage-84%25-brightgreen)]()
[![Platform](https://img.shields.io/badge/Platform-Raspberry%20Pi%205-red)]()

## 🎯 Project Overview

IoTSentinel is an educational network security monitor that uses **Zeek**, an enterprise-grade network analysis framework, combined with **unsupervised machine learning** to detect anomalies in home network traffic. It is designed to be a privacy-first, low-power solution that runs entirely on a Raspberry Pi.

The project's unique value proposition is **educational transparency**: it doesn't just block threats, it explains _why_ an activity was flagged as anomalous, helping non-technical users understand their network's behavior.

### Key Features

- ✅ **Professional Architecture**: Leverages Zeek's powerful C++ engine for deep protocol analysis.
- ✅ **Incremental ML**: River ML framework with HalfSpaceTrees and HoeffdingAdaptive for real-time, zero-day threat detection.
- ✅ **Educational Dashboard**: A user-friendly web interface that explains _why_ an alert was triggered, showing the contributing factors.
- ✅ **Privacy-First**: All data processing and analysis happens on-device. No data is sent to the cloud.
- ✅ **Low Power**: Optimized for a Raspberry Pi 5, consuming significantly less power than a traditional desktop-based solution.
- ✅ **Comprehensive Testing**: Includes 59 unit and integration tests, achieving 84% code coverage.

### 🤖 IoT-Specific Features

**Intelligent Device Classification**

- 📷🔊💡🔌 Automatic device type detection with visual icons
- 80+ manufacturer database (Nest, Ring, Philips Hue, Amazon, Google, etc.)
- Smart categorization: cameras, speakers, bulbs, plugs, thermostats, locks, and more
- Confidence scoring for classification accuracy

**IoT Security Assessment**

- 🛡️ Real-time security scoring (0-100) for your IoT network
- Vulnerability detection and security recommendations
- Device-specific security advice (e.g., "Disable remote access on cameras")
- Risk level indicators (Low/Medium/High/Critical)

**Enhanced Device Management**

- Custom device naming and notes
- Device grouping (Living Room, Kitchen, Security, etc.)
- First seen / Last seen timestamps
- Connection statistics and activity tracking

**Educational Transparency**

- Interactive tooltips explaining each chart in simple English
- "Why is this suspicious?" explanations for alerts
- Learning resources for understanding network security

### 🔐 Security Features

**Login Protection**

- Rate limiting: 5 failed attempts = 5-minute lockout
- Persistent SECRET_KEY from environment
- Bcrypt password hashing with salt
- Role-based access control (Admin/Viewer)

**Deployment Security**

- Automatic backups before every deployment
- Rollback capability with timestamped backups
- Health check endpoint (`/health`) for monitoring
- .env template with security best practices

**Network Security**

- Threat intelligence integration (AbuseIPDB)
- Firewall control and device blocking
- Lockdown mode for emergency isolation
- Email alerts for critical events

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
│  │ - Runs River ML Engine &     │  │
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

    _Note: For development on a non-Pi machine (like a Mac), you may need to adjust dependencies (e.g., `tensorflow` vs `tensorflow-macos`)._

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
# River ML learns incrementally - no training phase needed!
# The model learns automatically from the first network connection
# Simply run the orchestrator and dashboard
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

All project documentation is organized in the **[docs/](docs/)** directory.

### 🚀 Quick Start

- **[Quick Start Guide](docs/QUICK_START.md)** - Understand the two-branch system (main vs academic-evidence)
- **[Branch Strategy](docs/BRANCH_STRATEGY.md)** - Complete workflow explanation
- **[Deployment Guide](docs/DEPLOYMENT_GUIDE.md)** - Deploy to Raspberry Pi

### 📖 Feature Guides

- **[IoT Features](docs/IOT_FEATURES_GUIDE.md)** - IoT-specific capabilities
- **[Authentication](docs/AUTH_INTEGRATION_GUIDE.md)** - User authentication setup
- **[Device Grouping](docs/DEVICE_GROUPING_GUIDE.md)** - Organize devices
- **[Push Notifications](docs/PUSH_NOTIFICATIONS_GUIDE.md)** - Mobile alerts
- **[Email Alerts](docs/EMAIL_SETUP.md)** - Email configuration

### 🏗️ Architecture & Planning

- **[C4 Architecture](docs/C4_ARCHITECTURE.md)** - System design
- **[Database Schema](docs/DATABASE_SCHEMA.md)** - Data structure
- **[Risk Register](docs/RISK_REGISTER.md)** - Risk management

📚 **[Full Documentation Index](docs/README.md)** - Complete list of 20+ guides

## 🔬 Technology Stack

- **Capture**: Zeek (formerly Bro)
- **Backend**: Python 3.11, SQLite
- **ML**: River 0.21.0 (HalfSpaceTrees, HoeffdingAdaptive, SNARIMAX)
- **Frontend**: Dash by Plotly
- **Hardware**: Raspberry Pi 5 (4GB RAM recommended)

## 📝 License

This is an educational project. The code is provided as-is. Please see the `LICENSE` file for more details.
