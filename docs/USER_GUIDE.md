# IoTSentinel User Guide

This guide provides a comprehensive overview of IoTSentinel's key features, including custom rules, device grouping, reporting, and IoT-specific security capabilities.

---

## 1. Custom Alert Rules

Create custom rules to detect specific patterns and behaviors on your network.

### Rule Types
- **Data Volume:** Trigger alerts based on the amount of data transferred.
- **Connection Count:** Monitor the frequency of connections.
- **Port Activity:** Detect usage of specific network ports.
- **Time-Based:** Alert on activity occurring during specific hours.
- **Destination IP:** Monitor connections to specific external IP addresses.
- **Protocol:** Track the usage of network protocols like TCP, UDP, or ICMP.

### Managing Rules
You can create, edit, disable, and delete rules from the "Custom Alert Rules" card in the dashboard's settings. The system comes with pre-configured default rules for common scenarios like high data transfer and suspicious port activity.

### How it Works
The rule engine runs periodically in the background, evaluating all active rules against recent device activity. When a rule's conditions are met, a new alert is created and displayed on the dashboard.

---

## 2. Device Grouping

Organize your network devices into logical groups for easier management and analysis.

### Default Groups
IoTSentinel comes with 8 default groups:
- IoT Devices
- Computers
- Mobile Devices
- Network Infrastructure
- Security Devices
- Media Devices
- Printers & Peripherals
- Unknown Devices

### Managing Groups
- **Create New Groups:** From the "Groups" tab, you can create new groups with custom names, descriptions, colors, and icons.
- **Assign Devices:** Assign devices to groups from the device details modal.
- **Auto-Grouping:** Use the "Auto-Group Devices by Type" feature in the settings to automatically assign devices to appropriate groups.
- **Group Statistics:** The "Groups" tab displays statistics for each group, including the number of active devices, alerts, and total connections.

---

## 3. Export & Reporting

Export data and generate reports for offline analysis and record-keeping.

### Quick Exports
From the "Export & Reports" card in the settings, you can immediately export the following data to CSV files:
- Devices
- Alerts
- Connections
- Custom Alert Rules

### Custom Reports
You can also generate custom reports with a specified time period (in days) for the following report types:
- **Executive Summary:** A high-level overview of network status and security alerts.
- **Detailed Security Report:** In-depth statistics, including top data consumers and most contacted destinations.
- **Alert Report:** A CSV file of alerts for the specified period.
- **Connection Report:** A CSV file of network connections for the specified period.

### Scheduled Reports
For advanced use, you can configure a background task to automatically generate and save daily, weekly, or monthly reports.

---

## 4. IoT Security Features

IoTSentinel includes a suite of advanced features designed specifically for IoT security.

### IoT Device Intelligence
- **Advanced Fingerprinting:** Identifies devices based on multiple signals, including OS, open ports, and service discovery.
- **Vulnerability Detection:** Automatically checks devices against a database of known IoT vulnerabilities (e.g., for Mirai botnet susceptibility).
- **Behavior Analysis:** Establishes baseline behaviors for devices and detects anomalies.

### IoT Protocol Awareness
- **Deep Packet Inspection:** Analyzes IoT-specific protocols like MQTT, CoAP, and Zigbee.
- **Encryption Verification:** Detects whether protocols are using encryption (e.g., MQTT over TLS).

### IoT-Specific Threat Detection
- **Botnet Detection:** Identifies patterns associated with botnets like Mirai, including Telnet scanning and C2 communication.
- **DDoS Attack Detection:** Detects if a device is participating in or is a victim of a DDoS attack.

### Smart Home Context
- **Hub & Ecosystem Detection:** Identifies smart home hubs (e.g., Home Assistant, Philips Hue) and ecosystems (e.g., Google Home, Amazon Alexa).
- **Room Management:** Allows you to organize devices into virtual rooms for better contextualization.

### Privacy Focus
- **Cloud Connection Tracking:** Monitors and tracks data uploads to cloud providers like AWS and Google Cloud.
- **Tracker Detection:** Identifies connections to third-party analytics and advertising trackers.

### Network Segmentation
- **AI-Powered Recommendations:** Provides AI-driven recommendations for segmenting your network into VLANs (e.g., Trusted, IoT, Isolated, Guest) to improve security.
- **Violation Detection:** Monitors for and alerts on unauthorized communication between network segments.

### Lifecycle Management
- **Firmware Tracking:** Monitors firmware versions and alerts you to available updates.
- **EOL Detection:** Identifies devices that are at their end-of-life and no longer supported by the manufacturer.
- **Provisioning Workflow:** Tracks the onboarding process for new devices, from discovery to approval.

### Educational Content
- **Threat Scenarios:** Includes a library of real-world IoT threat scenarios with detailed explanations and mitigation steps.
