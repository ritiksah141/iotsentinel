# IoTSentinel Architecture

## Overview

IoTSentinel uses a **Zeek-based architecture** for professional network security monitoring.

┌────────────────────────────────────────────────┐
│ Raspberry Pi 5 (4GB RAM) │
│ │
│ ┌───────────────────────────────────────────┐ │
│ │ Layer 1: Network Monitoring (Zeek) │ │
│ │ • C++ Engine (High Performance) │ │
│ │ • Protocol Analysis (TCP/UDP/HTTP/DNS) │ │
│ │ • JSON Log Output │ │
│ └───────────────────────────────────────────┘ │
│ ↓ │
│ ┌───────────────────────────────────────────┐ │
│ │ Layer 2: Data Processing (Python) │ │
│ │ • Zeek Log Parser │ │
│ │ • Feature Extraction │ │
│ │ • SQLite Database │ │
│ └───────────────────────────────────────────┘ │
│ ↓ │
│ ┌───────────────────────────────────────────┐ │
│ │ Layer 3: Machine Learning │ │
│ │ • Autoencoder (Neural Network) │ │
│ │ • Isolation Forest (Ensemble) │ │
│ │ • Anomaly Detection │ │
│ └───────────────────────────────────────────┘ │
│ ↓ │
│ ┌───────────────────────────────────────────┐ │
│ │ Layer 4: User Interface │ │
│ │ • Dash Dashboard │ │
│ │ • Educational Explanations │ │
│ │ • Alert Visualizations │ │
│ └───────────────────────────────────────────┘ │
└────────────────────────────────────────────────┘

```

## Key Design Decisions

### 1. Why Zeek?

**Professional Justification (for AT2/AT3):**

- **Industry Standard**: Zeek is used by enterprise security teams and government organizations
- **Protocol Intelligence**: Deep packet inspection with protocol-aware analysis
- **Performance**: C++ implementation handles high-throughput networks
- **Extensibility**: Scriptable and customizable for specific use cases

**Alternative Considered**: Raw packet capture with Scapy
- **Rejected because**: Would require manual protocol parsing, significantly higher CPU usage on Pi

### 2. Why Unsupervised ML?

**Autoencoder:**
- **Strengths**: Learns complex patterns, good for high-dimensional data
- **How it detects anomalies**: Trained on normal traffic, produces high reconstruction error for anomalies
- **Educational value**: Visualizable - can show which features caused high error

**Isolation Forest:**
- **Strengths**: Fast inference, handles outliers naturally
- **How it detects anomalies**: Isolates anomalies in fewer splits of decision trees
- **Comparison**: Provides validation against Autoencoder results

### 3. Privacy by Design

- **On-device processing**: No cloud uploads
- **Metadata only**: Zeek logs connection metadata, not payload
- **Local storage**: SQLite database stays on Pi
- **Transparency**: Dashboard shows exactly what's monitored

## Data Flow

### 1. Capture Phase (Zeek)
```

Network Traffic → Zeek → JSON Logs
↓
conn.log (connections)
http.log (HTTP metadata)
dns.log (DNS queries)

```

### 2. Processing Phase (Python)
```

JSON Logs → Parser → Database
↓
connections table
devices table

```

### 3. ML Phase
```

Database → Feature Extractor → Standardized Features
↓
ML Models → Predictions
↓
alerts table

```

### 4. Presentation Phase
```

Database → Dashboard → User
↓
Explanations + Visualizations
