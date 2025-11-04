# 🛡️ IoTSentinel

**Professional Network Security Monitor for Raspberry Pi using Unsupervised Machine Learning**

[![Architecture](https://img.shields.io/badge/Architecture-Zeek--based-blue)]()
[![ML](https://img.shields.io/badge/ML-Autoencoder%20%2B%20Isolation%20Forest-green)]()
[![Platform](https://img.shields.io/badge/Platform-Raspberry%20Pi%205-red)]()

## 🎯 Project Overview

IoTSentinel is an educational network security monitor that uses **Zeek** (enterprise-grade network security monitor) combined with **unsupervised machine learning** to detect anomalies in home network traffic.

### Key Features

- ✅ **Professional Architecture**: Leverages Zeek's C++ engine for protocol analysis
- ✅ **Unsupervised ML**: Autoencoder + Isolation Forest for zero-day detection
- ✅ **Educational Dashboard**: Explains "why" an alert was triggered
- ✅ **Privacy-First**: All processing on-device (no cloud)
- ✅ **Low Power**: Optimized for Raspberry Pi 5 (2-5W vs 100W+ PC)

## 🏗️ Architecture

```
┌─────────────────────────────────────┐
│         Raspberry Pi 5              │
│  ┌──────────────────────────────┐  │
│  │ Zeek (C++)                   │  │
│  │ Protocol-aware analysis      │  │
│  │ ↓ JSON logs                  │  │
│  └──────────────────────────────┘  │
│             ↓                        │
│  ┌──────────────────────────────┐  │
│  │ Python Parser                │  │
│  │ → SQLite Database            │  │
│  └──────────────────────────────┘  │
│             ↓                        │
│  ┌──────────────────────────────┐  │
│  │ ML Engine                    │  │
│  │ Autoencoder + Isolation      │  │
│  └──────────────────────────────┘  │
│             ↓                        │
│  ┌──────────────────────────────┐  │
│  │ Dash Dashboard               │  │
│  │ Educational Alerts           │  │
│  └──────────────────────────────┘  │
└─────────────────────────────────────┘
```

## 🚀 Quick Start

### On Raspberry Pi

```bash
# 1. Clone repository
git clone https://github.com/YOUR_USERNAME/iotsentinel.git
cd iotsentinel

# 2. Run setup
bash scripts/setup_pi.sh

# 3. Start 7-day baseline collection
source venv/bin/activate
python3 scripts/baseline_collector.py start

# 4. After 7 days, train models
python3 ml/train_autoencoder.py
python3 ml/train_isolation_forest.py

# 5. Start monitoring
sudo systemctl start iotsentinel-zeek-parser
sudo systemctl start iotsentinel-ml
python3 dashboard/app.py
```

### On Mac (Development)

```bash
# Clone and develop
git clone https://github.com/YOUR_USERNAME/iotsentinel.git
cd iotsentinel

# Install dependencies
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# Make changes, then deploy
bash scripts/deploy_to_pi.sh
```

## 📊 Assessment Alignment (70%+ Target)

| Criterion               | Implementation                                | Evidence          |
| ----------------------- | --------------------------------------------- | ----------------- |
| Professional Approaches | ✅ Uses Zeek (enterprise NSM)                 | Architecture docs |
| Technical Challenge     | ✅ Complex integration: Zeek + ML + Dashboard | Source code       |
| Innovation              | ✅ Educational transparency (unique UVP)      | Dashboard demo    |
| Evaluation              | ✅ Comparative ML analysis                    | AT3 Report        |

## 📚 Documentation

- [Architecture Overview](docs/ARCHITECTURE.md)
- [Setup Guide](docs/SETUP.md)
- [Zeek Configuration](config/)

## 🔬 Technology Stack

- **Capture**: Zeek 8.0.3 (C++)
- **Backend**: Python 3.11, SQLite
- **ML**: TensorFlow/Keras (Autoencoder), scikit-learn (Isolation Forest)
- **Frontend**: Dash by Plotly
- **Hardware**: Raspberry Pi 5 (4GB RAM)

## 📝 License

Educational Project - Ulster University BSc Computing Systems

## 🙏 Acknowledgments

- Zeek Project
- TensorFlow Team
- Plotly Dash Community
