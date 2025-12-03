# 🔔 Browser Push Notifications - Integration Guide

This guide shows how to integrate real-time browser push notifications into the IoTSentinel dashboard.

---

## ✅ What's Already Complete

- ✅ Push notification manager (`utils/push_notification_manager.py`)
- ✅ Client-side notification handler (`dashboard/assets/notifications.js`)
- ✅ Notification creation methods for alerts, devices, rules, and system events
- ✅ Event queue management
- ✅ Automatic reconnection logic

---

## 📝 Step 1: Install Required Packages

```bash
cd /Users/ritiksah/iotsentinel

# No additional packages needed - uses browser native Notification API
# JavaScript file is already created
```

---

## 📝 Step 2: Add Server-Sent Events (SSE) Endpoint to app.py

### **2.1: Add Imports** (after existing imports, around line 30)

```python
from flask import Response, stream_with_context
from utils.push_notification_manager import (
    push_manager,
    notify_new_alert,
    notify_device_event,
    notify_rule_triggered,
    notify_system
)
import time
import json
```

### **2.2: Add SSE Endpoint** (before app.layout, around line 800)

```python
# ============================================================================
# SERVER-SENT EVENTS (SSE) FOR PUSH NOTIFICATIONS
# ============================================================================

@server.route('/notifications/stream')
def notification_stream():
    """
    Server-Sent Events endpoint for push notifications.

    This endpoint maintains a connection and streams notifications to the client.
    """
    from flask import request

    client_id = request.args.get('client_id', 'unknown')

    def event_stream():
        """Generator function for SSE stream"""
        # Subscribe client to notifications
        message_queue = push_manager.subscribe(client_id)

        try:
            # Send initial connection message
            yield f"data: {json.dumps({'type': 'connected', 'message': 'Connected to notification stream'})}\n\n"

            while True:
                try:
                    # Wait for notification (with timeout to send keep-alive)
                    message = message_queue.get(timeout=30)

                    # Send notification to client
                    yield f"data: {json.dumps(message)}\n\n"

                except queue.Empty:
                    # Send keep-alive ping every 30 seconds
                    yield f": ping\n\n"

                except GeneratorExit:
                    # Client disconnected
                    break

        except Exception as e:
            logger.error(f"Error in notification stream for client {client_id}: {e}")
        finally:
            # Unsubscribe client
            push_manager.unsubscribe(client_id)
            logger.info(f"Client {client_id} disconnected from notification stream")

    # Return SSE response
    return Response(
        stream_with_context(event_stream()),
        mimetype='text/event-stream',
        headers={
            'Cache-Control': 'no-cache',
            'X-Accel-Buffering': 'no',
            'Connection': 'keep-alive'
        }
    )


@server.route('/notifications/test')
def test_notification():
    """Test endpoint to trigger a notification"""
    notify_system("This is a test notification", notification_type='info')
    return {"status": "success", "message": "Test notification sent"}
```

---

## 📝 Step 3: Add Notification UI Controls to Dashboard

### **3.1: Add Notification Settings to Settings Panel**

Add this to the Settings accordion (around line 1500):

```python
dbc.AccordionItem([
    dbc.Card([
        dbc.CardBody([
            html.H5([html.I(className="fa fa-bell me-2"), "Push Notifications"], className="text-primary mb-4"),

            # Notification Status
            html.Div([
                html.H6("Notification Status", className="mb-3"),
                html.Div(id="notification-status-display", className="mb-3"),

                dbc.Row([
                    dbc.Col([
                        dbc.Button(
                            [html.I(className="fa fa-bell me-2"), "Enable Notifications"],
                            id="enable-notifications-btn",
                            color="success",
                            outline=True,
                            className="w-100 cyber-button"
                        ),
                    ], width=6),
                    dbc.Col([
                        dbc.Button(
                            [html.I(className="fa fa-bell-slash me-2"), "Disable Notifications"],
                            id="disable-notifications-btn",
                            color="danger",
                            outline=True,
                            className="w-100 cyber-button"
                        ),
                    ], width=6),
                ]),
            ], className="mb-4"),

            html.Hr(),

            # Notification Settings
            html.Div([
                html.H6("Notification Preferences", className="mb-3"),

                dbc.Row([
                    dbc.Col([
                        dbc.Label("Notify on Alert Severity:"),
                        dbc.Checklist(
                            id="notify-severity-filter",
                            options=[
                                {"label": " Critical Alerts", "value": "critical"},
                                {"label": " High Alerts", "value": "high"},
                                {"label": " Medium Alerts", "value": "medium"},
                                {"label": " Low Alerts", "value": "low"},
                            ],
                            value=["critical", "high", "medium"],
                            className="mb-3"
                        ),
                    ], width=6),
                    dbc.Col([
                        dbc.Label("Event Notifications:"),
                        dbc.Checklist(
                            id="notify-event-types",
                            options=[
                                {"label": " New Devices", "value": "new_device"},
                                {"label": " Device Blocked/Unblocked", "value": "device_blocked"},
                                {"label": " Device Offline", "value": "device_offline"},
                                {"label": " Rule Triggers", "value": "rule_triggered"},
                            ],
                            value=["new_device", "device_blocked", "rule_triggered"],
                            className="mb-3"
                        ),
                    ], width=6),
                ]),

                dbc.Row([
                    dbc.Col([
                        dbc.Label("Sound Alerts:"),
                        dbc.Switch(
                            id="notification-sound-toggle",
                            label="Play sound with notifications",
                            value=True,
                            className="mb-2"
                        ),
                        dbc.Label("Volume:", className="mt-2"),
                        dcc.Slider(
                            id="notification-volume-slider",
                            min=0,
                            max=100,
                            step=10,
                            value=50,
                            marks={0: '0%', 50: '50%', 100: '100%'},
                            tooltip={"placement": "bottom", "always_visible": False}
                        ),
                    ], width=6),
                    dbc.Col([
                        dbc.Label("Test Notifications:"),
                        dbc.Button(
                            [html.I(className="fa fa-vial me-2"), "Send Test Notification"],
                            id="test-notification-btn",
                            color="primary",
                            outline=True,
                            className="w-100 cyber-button mb-2"
                        ),
                        html.Div(id="test-notification-status", className="mt-2")
                    ], width=6),
                ]),
            ], className="mb-4"),

            html.Hr(),

            # Recent Notifications
            html.Div([
                html.H6("Recent Notifications", className="mb-3"),
                html.Div(id="recent-notifications-list", className="notification-history"),
                dbc.Button(
                    [html.I(className="fa fa-trash me-2"), "Clear History"],
                    id="clear-notifications-btn",
                    color="secondary",
                    outline=True,
                    size="sm",
                    className="mt-2"
                ),
            ]),
        ])
    ], className="cyber-card")
], title="🔔 Push Notifications", className="mb-3"),
```

### **3.2: Add Notification Badge to Navbar**

Add notification bell icon to navbar (around line 950):

```python
# Add to navbar items
dbc.NavItem([
    dbc.Button(
        [
            html.I(className="fa fa-bell"),
            dbc.Badge(
                "0",
                id="notification-badge",
                color="danger",
                pill=True,
                className="position-absolute top-0 start-100 translate-middle"
            )
        ],
        id="notification-bell-btn",
        color="link",
        className="position-relative",
        style={"color": "white"}
    ),
], className="me-2"),

# Add notification dropdown modal
dbc.Modal([
    dbc.ModalHeader("Recent Notifications"),
    dbc.ModalBody([
        html.Div(id="notification-dropdown-list")
    ]),
    dbc.ModalFooter([
        dbc.Button("Mark All Read", id="mark-all-read-btn", color="primary", size="sm"),
        dbc.Button("Close", id="close-notification-modal", color="secondary", size="sm")
    ])
], id="notification-modal", size="lg"),
```

---

## 📝 Step 4: Add Notification Callbacks

### **4.1: JavaScript Integration Callback**

```python
# Add clientside callback to handle JS notification manager
app.clientside_callback(
    """
    function(n_clicks) {
        if (n_clicks) {
            if (window.iotsentinelNotifications) {
                window.iotsentinelNotifications.enable();
                return 'Notifications enabled';
            }
            return 'Notification manager not loaded';
        }
        return '';
    }
    """,
    Output('notification-status-display', 'children'),
    Input('enable-notifications-btn', 'n_clicks'),
    prevent_initial_call=True
)
```

### **4.2: Test Notification Callback**

```python
@app.callback(
    Output('test-notification-status', 'children'),
    Input('test-notification-btn', 'n_clicks'),
    prevent_initial_call=True
)
def send_test_notification(n_clicks):
    """Send a test notification to all connected clients"""
    if n_clicks is None:
        raise dash.exceptions.PreventUpdate

    try:
        # Send test notification
        notify_system(
            message="This is a test notification from IoTSentinel. Your notifications are working correctly!",
            notification_type='info'
        )

        return dbc.Alert(
            [html.I(className="fa fa-check-circle me-2"), "Test notification sent successfully"],
            color="success",
            dismissable=True,
            duration=3000
        )
    except Exception as e:
        logger.error(f"Error sending test notification: {e}")
        return dbc.Alert(
            [html.I(className="fa fa-times-circle me-2"), f"Error: {str(e)}"],
            color="danger",
            dismissable=True,
            duration=3000
        )


@app.callback(
    Output('notification-badge', 'children'),
    Input('interval-component', 'n_intervals')
)
def update_notification_badge(n):
    """Update notification badge count"""
    # This would query unread notifications from queue
    # For now, return subscriber count
    return str(push_manager.get_subscriber_count())
```

### **4.3: Settings Persistence Callback**

```python
app.clientside_callback(
    """
    function(sound_enabled, volume, severity_filter, event_types) {
        if (window.iotsentinelNotifications) {
            window.iotsentinelNotifications.setSetting('soundEnabled', sound_enabled);
            window.iotsentinelNotifications.setSetting('soundVolume', volume / 100);
            window.iotsentinelNotifications.setSetting('severityFilter', severity_filter);
            window.iotsentinelNotifications.setSetting('eventTypes', event_types);
        }
        return '';
    }
    """,
    Output('notification-status-display', 'children', allow_duplicate=True),
    [Input('notification-sound-toggle', 'value'),
     Input('notification-volume-slider', 'value'),
     Input('notify-severity-filter', 'value'),
     Input('notify-event-types', 'value')],
    prevent_initial_call=True
)
```

---

## 📝 Step 5: Integrate Notifications with Existing Features

### **5.1: Send Notification When New Alert is Created**

In your alert creation code (around line 2200), add:

```python
# After creating alert in database
notify_new_alert(
    device_ip=device_ip,
    device_name=device.get('device_name', 'Unknown'),
    severity=severity,
    explanation=explanation,
    alert_id=alert_id
)
```

### **5.2: Send Notification When Device is Blocked**

In your device blocking callback:

```python
# After blocking device
notify_device_event(
    device_ip=device_ip,
    device_name=device.get('device_name', 'Unknown'),
    event_type='device_blocked',
    message=f"Device {device_ip} has been blocked from network access"
)
```

### **5.3: Send Notification When Custom Rule Triggers**

In your rule evaluation code:

```python
# When rule triggers
notify_rule_triggered(
    rule_name=rule['name'],
    device_ip=device_ip,
    device_name=device.get('device_name', 'Unknown'),
    severity=rule['severity'],
    explanation=alert['explanation']
)
```

### **5.4: Send Notification for New Devices**

In your device discovery code:

```python
# When new device detected
notify_device_event(
    device_ip=new_device_ip,
    device_name='New Device',
    event_type='new_device',
    message=f"New device detected on network: {new_device_ip}"
)
```

---

## 📝 Step 6: Add CSS Styling

Add to `dashboard/assets/custom.css`:

```css
/* Notification Bell */
#notification-bell-btn {
    transition: all 0.3s ease;
}

#notification-bell-btn:hover {
    transform: scale(1.1);
}

#notification-badge {
    font-size: 0.7rem;
    padding: 0.25em 0.5em;
}

/* Notification History */
.notification-history {
    max-height: 400px;
    overflow-y: auto;
    border: 1px solid rgba(0, 255, 204, 0.2);
    border-radius: 8px;
    padding: 1rem;
    background: rgba(0, 0, 0, 0.2);
}

.notification-item {
    padding: 0.75rem;
    border-left: 4px solid;
    margin-bottom: 0.5rem;
    background: rgba(255, 255, 255, 0.05);
    border-radius: 4px;
    transition: background 0.2s ease;
}

.notification-item:hover {
    background: rgba(255, 255, 255, 0.1);
}

.notification-item.critical {
    border-left-color: #dc3545;
}

.notification-item.high {
    border-left-color: #fd7e14;
}

.notification-item.medium {
    border-left-color: #ffc107;
}

.notification-item.low {
    border-left-color: #17a2b8;
}

.notification-item.info {
    border-left-color: #0dcaf0;
}

.notification-timestamp {
    font-size: 0.75rem;
    color: #6c757d;
}

/* Pulse animation for new notifications */
@keyframes pulse-notification {
    0% {
        box-shadow: 0 0 0 0 rgba(220, 53, 69, 0.7);
    }
    70% {
        box-shadow: 0 0 0 10px rgba(220, 53, 69, 0);
    }
    100% {
        box-shadow: 0 0 0 0 rgba(220, 53, 69, 0);
    }
}

.notification-pulse {
    animation: pulse-notification 2s infinite;
}
```

---

## 🧪 Step 7: Test Push Notifications

### **7.1: Start Dashboard**

```bash
python3 dashboard/app.py
```

### **7.2: Enable Notifications**

1. Navigate to Settings → Push Notifications
2. Click "Enable Notifications"
3. Browser will prompt for permission - click "Allow"
4. You should see connection status update

### **7.3: Test Notification**

1. In Settings → Push Notifications
2. Click "Send Test Notification"
3. Should see browser notification popup
4. Check that notification appears in Recent Notifications list

### **7.4: Test Alert Notification**

1. Trigger an alert (or wait for automatic detection)
2. Should receive browser notification
3. Verify severity color coding
4. Test clicking notification to focus window

### **7.5: Test Persistence**

1. Close browser tab
2. Reopen dashboard
3. Verify notifications reconnect automatically
4. Check that settings are preserved

### **7.6: Test Multiple Tabs**

1. Open dashboard in multiple tabs
2. Send test notification
3. Verify all tabs receive notification
4. Check subscriber count in badge

---

## 🔧 Advanced Features

### **1. Custom Notification Sounds**

Create audio files in `dashboard/assets/sounds/`:

```bash
mkdir -p dashboard/assets/sounds

# Add sound files:
# - critical-alert.mp3 (loud, urgent)
# - high-alert.mp3 (moderate urgency)
# - medium-alert.mp3 (gentle alert)
# - low-alert.mp3 (soft beep)
# - info-beep.mp3 (info sound)
```

### **2. Notification Grouping**

Prevent notification spam by grouping similar notifications:

```javascript
// In notifications.js, modify showNotification():
const tag = notification.device_ip || notification.type || 'iotsentinel';
// Using same tag will replace previous notification for that device
```

### **3. Action Buttons**

Handle notification action buttons:

```javascript
// In notifications.js
if ('serviceWorker' in navigator) {
    navigator.serviceWorker.addEventListener('message', (event) => {
        if (event.data.action === 'acknowledge') {
            // Send acknowledge request to server
            fetch(`/api/alerts/${event.data.alert_id}/acknowledge`, {
                method: 'POST'
            });
        }
    });
}
```

### **4. Do Not Disturb Hours**

Add quiet hours feature:

```python
# In settings
dbc.Row([
    dbc.Col([
        dbc.Label("Do Not Disturb Hours:"),
        dbc.Input(id="dnd-start", type="time", value="22:00"),
    ], width=6),
    dbc.Col([
        dbc.Label("Until:"),
        dbc.Input(id="dnd-end", type="time", value="08:00"),
    ], width=6),
])
```

### **5. Notification History with Database**

Store notification history:

```python
# Add to init_database.py
cursor.execute('''
    CREATE TABLE IF NOT EXISTS notification_history (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        notification_type TEXT,
        title TEXT,
        body TEXT,
        severity TEXT,
        device_ip TEXT,
        is_read INTEGER DEFAULT 0
    )
''')
```

---

## 🔒 Security Considerations

### **1. Rate Limiting**

Prevent notification spam:

```python
from collections import defaultdict
from time import time

notification_counts = defaultdict(list)

def rate_limit_notification(device_ip: str, max_per_minute: int = 10) -> bool:
    """Check if device exceeds notification rate limit"""
    now = time()
    # Clean old entries
    notification_counts[device_ip] = [
        t for t in notification_counts[device_ip]
        if now - t < 60
    ]

    if len(notification_counts[device_ip]) >= max_per_minute:
        return False  # Rate limit exceeded

    notification_counts[device_ip].append(now)
    return True
```

### **2. User-Specific Notifications**

Filter notifications by user role:

```python
def notify_alert_filtered(alert_data, user_role='admin'):
    """Send notification only to users with appropriate role"""
    if alert_data['severity'] in ['critical', 'high'] or user_role == 'admin':
        notify_new_alert(**alert_data)
```

### **3. SSL/HTTPS Required**

Browser push notifications require HTTPS in production:

```python
# In production config
server.config['SESSION_COOKIE_SECURE'] = True
server.config['PREFERRED_URL_SCHEME'] = 'https'
```

---

## 📊 Monitoring

### **Track Notification Metrics:**

```python
@server.route('/notifications/stats')
def notification_stats():
    """Get notification statistics"""
    return {
        'active_subscribers': push_manager.get_subscriber_count(),
        'total_sent_today': get_notifications_sent_today(),
        'delivery_rate': calculate_delivery_rate()
    }
```

---

## 🎉 Completion Checklist

- [ ] Verified push notification manager module
- [ ] Created notifications.js asset file
- [ ] Added SSE endpoint to app.py
- [ ] Added notification settings to UI
- [ ] Added notification bell to navbar
- [ ] Added notification callbacks
- [ ] Integrated with alert creation
- [ ] Integrated with device blocking
- [ ] Integrated with rule triggers
- [ ] Added CSS styling
- [ ] Tested browser permission request
- [ ] Tested notification delivery
- [ ] Tested reconnection logic
- [ ] Tested notification sounds
- [ ] Verified multi-tab support
- [ ] (Optional) Added notification history database
- [ ] (Optional) Added custom sounds
- [ ] (Optional) Added do-not-disturb hours

---

## ❓ Troubleshooting

**Notifications not appearing**
- Check browser permission: Settings → Site Settings → Notifications
- Verify SSE connection: Check browser dev tools Network tab for `/notifications/stream`
- Check console for JavaScript errors

**"Notification API not supported" error**
- Some browsers don't support notifications (check compatibility)
- HTTPS required in production (works on localhost in development)

**Notifications stop after a while**
- Check keep-alive ping is working (30 second timeout)
- Verify reconnection logic triggers
- Check server logs for disconnection errors

**Multiple notifications for same alert**
- Verify notification tag is set correctly
- Check for duplicate event listeners

**High server load with many clients**
- Implement connection limits per user
- Add rate limiting
- Consider using Redis for pub/sub instead of in-memory queues

---

**Your dashboard now has real-time browser push notifications!** 🔔
