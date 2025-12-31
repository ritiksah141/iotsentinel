# IoTSentinel System Configuration Manual

This manual provides a comprehensive guide to configuring all major components of the IoTSentinel system, including AI features, API integrations, user authentication, and notification systems.

---

## 1. AI Chat Assistant Setup

The IoTSentinel dashboard includes an AI-powered chat assistant that can answer questions about your network security using a local LLM via Ollama.

### Features
- **100% Free & Private:** Runs locally on your network.
- **Network-Aware:** Knows your current device count, active alerts, and recent security events.
- **Automatic Fallback:** Uses rule-based responses if Ollama is unavailable.

### Installation
1.  **Install Ollama:**
    ```bash
    curl -fsSL https://ollama.com/install.sh | sh
    ```
2.  **Pull a Model:**
    - For Raspberry Pi 5 (recommended): `ollama pull llama3.2:3b`
    - For more powerful machines: `ollama pull mistral:7b`
3.  **Start the Ollama Service:**
    ```bash
    ollama serve
    ```

### Configuration
Edit `dashboard/app.py` to configure the AI assistant:
```python
# AI Assistant Configuration
OLLAMA_ENABLED = True
OLLAMA_API_URL = "http://localhost:11434/api/generate"
OLLAMA_MODEL = "llama3.2:3b"
OLLAMA_TIMEOUT = 30
```

---

## 2. API Integration Hub

Configure free threat intelligence APIs to enhance IoTSentinel's capabilities.

### Recommended Free APIs
- **AlienVault OTX:** Unlimited threat intelligence.
- **IPinfo:** 50,000 IP geolocation queries/month.
- **VirusTotal:** 500 malware and URL scans/day.

### Configuration Steps
1.  **Sign up** for the APIs you want to use (e.g., AlienVault OTX, IPinfo).
2.  **Add the API keys** to your `.env` file:
    ```env
    OTX_API_KEY=your_otx_key_here
    VIRUSTOTAL_API_KEY=your_virustotal_key_here
    IPINFO_API_KEY=your_ipinfo_key_here
    ```
3.  **Restart the dashboard.**
4.  **Verify** the integrations in the "API Integration Hub" card on the dashboard.

---

## 3. User Authentication

This section guides you through integrating the user authentication system.

### Setup Steps
1.  **Install Packages:**
    ```bash
    pip install flask-login bcrypt
    ```
2.  **Run Database Migration:** This creates the `users` table and a default admin user (`admin`/`admin`).
    ```bash
    python3 config/init_database.py
    ```
3.  **Update `dashboard/app.py`:**
    - Add authentication imports and initialize `LoginManager`.
    - Create the login page layout.
    - Wrap the main dashboard layout with an authentication check.
    - Add callbacks for navigation and handling login/logout.
4.  **Test Authentication:**
    - Start the dashboard and log in with the default credentials.
    - Test logout functionality.
    - **Crucially, change the default admin password immediately.**

---

## 4. Device Blocking

Block suspicious devices from accessing your network with a single click.

### Prerequisites
- A router with SSH access (e.g., OpenWrt, pfSense).
- SSH key authentication configured between the Raspberry Pi and the router.
- `iptables` installed on the router.

### Configuration
1.  **Configure SSH Access:** Set up SSH key-based authentication from your Pi to your router.
2.  **Configure IoTSentinel:** Edit `config/default_config.json` with your router's details:
    ```json
    "firewall": {
      "enabled": true,
      "router_ip": "192.168.1.1",
      "router_user": "root",
      "router_private_key_path": "/home/pi/.ssh/id_rsa_router"
    }
    ```
3.  **Test:** Use the "Block Device" button on the dashboard and verify that the device loses network access.

---

## 5. Email Notifications

Configure email alerts for security events and regular summary reports.

### Setup
1.  **Go to Settings** on the dashboard and find the "Email Notifications" card.
2.  **Fill in your SMTP details.** For Gmail, you'll need to generate an "App Password".
3.  **Save settings** and send a test email to verify the configuration.

### Gmail App Password
- Enable 2-Factor Authentication for your Google account.
- Go to App Passwords and generate a new password for "Mail" on "Other (Custom name)".
- Use this 16-character password in the dashboard settings.

---

## 6. Browser Push Notifications

Enable real-time browser push notifications for immediate alerts.

### Integration Steps
1.  **Add SSE Endpoint:** Add the Server-Sent Events (SSE) endpoint to `dashboard/app.py` to stream notifications.
2.  **Add UI Controls:** Add notification settings and a notification bell to the dashboard layout.
3.  **Add Callbacks:** Implement clientside and serverside callbacks to handle enabling, testing, and displaying notifications.
4.  **Integrate with Features:** Trigger notifications for new alerts, device blocking events, and custom rule triggers.
5.  **Test:** Enable notifications in your browser and send a test notification from the settings panel.

---

## 7. Threat Intelligence (AbuseIPDB)

Integrate AbuseIPDB for IP reputation lookups.

### Setup
1.  **Get a Free API Key:** Sign up at abuseipdb.com and create an API key. The free tier allows 1,000 lookups per day.
2.  **Configure IoTSentinel:** Add your API key to `config/default_config.json` or as an environment variable:
    ```json
    "threat_intelligence": {
      "enabled": true,
      "abuseipdb_api_key": "YOUR_API_KEY_HERE",  // pragma: allowlist secret
      "cache_hours": 24
    }
    ```
3.  **Restart the dashboard.** Threat intelligence will now be enabled, and alerts for suspicious connections will be enriched with IP reputation data.

---

## 8. Toast Notification System

IoTSentinel features an advanced toast notification system (v2.1) to provide real-time, interactive feedback to the user.

### Features
- **Categorization:** Toasts are organized by type (e.g., Security, Network, System) with distinct visual cues.
- **Interactivity:** Notifications can include action buttons for immediate responses, such as "Block Device" or "Retry".
- **Persistence & Queuing:** Critical alerts can be set to persist until dismissed, and a queue system manages multiple notifications gracefully.
- **History:** A complete history of all toasts is stored in the database and can be viewed and filtered through a dedicated UI panel.

### Configuration
The toast system is enabled by default and requires no initial setup. The behavior is managed through the `ToastManager` utility in `utils/toast_manager.py`. For detailed documentation on implementation, usage, and verification, please see the [Comprehensive Toast System Documentation](./archive/TOAST_SYSTEM_DOCUMENTATION.md).

---

## 9. Spotlight Search (Enhanced Edition)

IoTSentinel features a powerful macOS Spotlight-like universal search system for instant access to all dashboard features and modals.

### Features
- **Top Hit:** Best matching result prominently highlighted with a "TOP HIT" badge
- **Category Grouping:** Results organized by category (Analytics, Security, IoT, System, etc.)
- **Result Count:** Shows total matches and performance time
- **Recent Searches:** Stores and displays last 5 searches for quick access
- **Category Filters:** Click category badges to filter results
- **Quick Preview:** Shimmer effects and enhanced hover interactions
- **Search Performance:** Blazing fast clientside search (1-3ms average)
- **Keyboard Shortcut:** `Cmd+K` (Mac) or `Ctrl+K` (Windows/Linux) to open search
- **Dark Mode Support:** Full support for light and dark themes

### Usage
1. **Opening Search:**
   - Click the floating "Search" button (bottom-right corner)
   - Press `Cmd+K` / `Ctrl+K` keyboard shortcut

2. **Searching:**
   - Type your query (e.g., "firewall", "analytics", "security")
   - See real-time results with top hit highlighted
   - Results automatically grouped by category
   - View result count and search performance time

3. **Filtering:**
   - Click category badges to filter results (e.g., "Security (8)")
   - Click "All" to clear filter
   - Active filter shown with blue highlight

4. **Recent Searches:**
   - Open search modal with empty query
   - Click any recent search badge to repeat the search
   - Last 5 searches stored in browser localStorage

### Configuration
The spotlight search is enabled by default and requires no setup. The search catalog is defined in `SEARCH_FEATURE_CATALOG` in `dashboard/app.py` (37 searchable features). Search behavior is managed through JavaScript in `dashboard/assets/spotlight-search.js`.

**Key Files:**
- `dashboard/app.py`: Server-side rendering and callbacks (lines 2380-26710)
- `dashboard/assets/spotlight-search.js`: Clientside search logic and localStorage
- `dashboard/assets/custom.css`: Styling (lines 6661-6997)

**localStorage Keys:**
- `iotsentinel_recent_searches`: Stores recent search queries (max 5)

### Customization
To add new searchable features, edit the `SEARCH_FEATURE_CATALOG` in `dashboard/app.py`:
```python
SEARCH_FEATURE_CATALOG = [
    {
        "id": "your-modal-id",
        "name": "Feature Name",
        "description": "Feature description",
        "icon": "fa-icon-name",
        "category": "Category Name",
        "keywords": ["keyword1", "keyword2", "keyword3"],
        "action_type": "modal"
    }
]
```

For complete implementation details, architecture, and API reference, see the [Spotlight Search Enhancement Documentation](./archive/SPOTLIGHT_SEARCH_ENHANCEMENT.md).
