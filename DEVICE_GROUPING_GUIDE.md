# 📁 Device Grouping - Integration Guide

This guide shows how to integrate device grouping features into the IoTSentinel dashboard.

---

## ✅ What's Already Complete

- ✅ Database tables for device groups (`device_groups`, `device_group_members`)
- ✅ Device group manager module (`utils/device_group_manager.py`)
- ✅ 8 default device groups pre-created
- ✅ Group operations: create, update, delete, add/remove devices
- ✅ Group statistics and analytics
- ✅ Auto-grouping by device type

---

## 📝 Step 1: Run Database Migration

```bash
cd /Users/ritiksah/iotsentinel

# Reinitialize database to create device group tables
python3 config/init_database.py

# You should see:
# ✓ Default device groups created:
#   - IoT Devices
#   - Computers
#   - Mobile Devices
#   - Network Infrastructure
#   - Security Devices
#   - Media Devices
#   - Printers & Peripherals
#   - Unknown Devices
```

---

## 📝 Step 2: Update dashboard/app.py

### **2.1: Add Import** (after existing imports, around line 30)

```python
# Device group manager import
from utils.device_group_manager import DeviceGroupManager

# Initialize device group manager
group_manager = DeviceGroupManager(DB_PATH)
```

### **2.2: Add Device Groups View** (new tab in main layout, around line 1200)

Add this as a new tab in your main dashboard:

```python
dbc.Tab([
    dbc.Container([
        # Header
        dbc.Row([
            dbc.Col([
                html.H3([html.I(className="fa fa-folder-open me-2"), "Device Groups"], className="text-cyber"),
                html.P("Organize and manage devices by category", className="text-muted"),
            ], width=8),
            dbc.Col([
                dbc.Button(
                    [html.I(className="fa fa-plus me-2"), "New Group"],
                    id="create-group-btn",
                    color="primary",
                    className="cyber-button float-end"
                ),
            ], width=4),
        ], className="mb-4"),

        # Group List
        html.Div(id="device-groups-container"),

        # Create Group Modal
        dbc.Modal([
            dbc.ModalHeader("Create New Group"),
            dbc.ModalBody([
                dbc.Row([
                    dbc.Col([
                        dbc.Label("Group Name:"),
                        dbc.Input(
                            id="new-group-name",
                            placeholder="e.g., Guest Devices",
                            className="cyber-input mb-3"
                        ),
                    ], width=12),
                ]),
                dbc.Row([
                    dbc.Col([
                        dbc.Label("Description:"),
                        dbc.Textarea(
                            id="new-group-description",
                            placeholder="Brief description of this group",
                            className="cyber-input mb-3",
                            rows=3
                        ),
                    ], width=12),
                ]),
                dbc.Row([
                    dbc.Col([
                        dbc.Label("Color:"),
                        dbc.Input(
                            id="new-group-color",
                            type="color",
                            value="#0dcaf0",
                            className="form-control-color mb-3"
                        ),
                    ], width=6),
                    dbc.Col([
                        dbc.Label("Icon:"),
                        dbc.Select(
                            id="new-group-icon",
                            options=[
                                {"label": "📁 Folder", "value": "fa-folder"},
                                {"label": "💡 IoT", "value": "fa-lightbulb"},
                                {"label": "💻 Computer", "value": "fa-laptop"},
                                {"label": "📱 Mobile", "value": "fa-mobile-alt"},
                                {"label": "🔒 Security", "value": "fa-shield-alt"},
                                {"label": "📺 Media", "value": "fa-tv"},
                                {"label": "🖨 Printer", "value": "fa-print"},
                                {"label": "🌐 Network", "value": "fa-network-wired"},
                                {"label": "⚙️ Settings", "value": "fa-cog"},
                                {"label": "⭐ Star", "value": "fa-star"},
                            ],
                            value="fa-folder"
                        ),
                    ], width=6),
                ]),
                html.Div(id="create-group-status", className="mt-3")
            ]),
            dbc.ModalFooter([
                dbc.Button("Create", id="confirm-create-group", color="primary"),
                dbc.Button("Cancel", id="cancel-create-group", color="secondary")
            ])
        ], id="create-group-modal", size="lg"),

        # Group Details Modal
        dbc.Modal([
            dbc.ModalHeader(id="group-details-header"),
            dbc.ModalBody([
                html.Div(id="group-details-content")
            ]),
            dbc.ModalFooter([
                dbc.Button("Close", id="close-group-details", color="secondary")
            ])
        ], id="group-details-modal", size="xl"),

    ], fluid=True, className="mt-4")
], label="📁 Groups", tab_id="groups", className="cyber-tab"),
```

---

## 📝 Step 3: Add Group Display Callback

```python
# ============================================================================
# DEVICE GROUPING CALLBACKS
# ============================================================================

@app.callback(
    Output('device-groups-container', 'children'),
    Input('interval-component', 'n_intervals')
)
def display_device_groups(n):
    """Display all device groups with statistics"""
    groups = group_manager.get_all_groups()

    if not groups:
        return dbc.Alert(
            "No device groups found. Click 'New Group' to create one.",
            color="info"
        )

    group_cards = []

    for group in groups:
        # Get group statistics
        stats = group_manager.get_group_statistics(group['id'], days=7)

        card = dbc.Card([
            dbc.CardHeader([
                html.Div([
                    html.I(
                        className=f"fa {group['icon']} me-2",
                        style={"color": group['color'], "fontSize": "1.5rem"}
                    ),
                    html.Strong(group['name'], style={"fontSize": "1.2rem"}),
                    dbc.Badge(
                        f"{group['device_count']} devices",
                        color="primary",
                        pill=True,
                        className="ms-2"
                    ),
                ], className="d-flex align-items-center"),
            ], style={"borderLeft": f"4px solid {group['color']}"}),
            dbc.CardBody([
                html.P(group['description'] or "No description", className="text-muted mb-3"),

                # Statistics
                dbc.Row([
                    dbc.Col([
                        html.Div([
                            html.I(className="fa fa-check-circle text-success me-2"),
                            html.Span(f"{stats.get('active_devices', 0)} Active"),
                        ], className="mb-2"),
                    ], width=6),
                    dbc.Col([
                        html.Div([
                            html.I(className="fa fa-exclamation-triangle text-warning me-2"),
                            html.Span(f"{stats.get('alert_count', 0)} Alerts"),
                        ], className="mb-2"),
                    ], width=6),
                ]),
                dbc.Row([
                    dbc.Col([
                        html.Div([
                            html.I(className="fa fa-exchange-alt text-info me-2"),
                            html.Span(f"{stats.get('total_connections', 0):,} Connections"),
                        ], className="mb-2"),
                    ], width=6),
                    dbc.Col([
                        html.Div([
                            html.I(className="fa fa-database text-primary me-2"),
                            html.Span(f"{stats.get('total_data_mb', 0):.1f} MB"),
                        ], className="mb-2"),
                    ], width=6),
                ]),

                # Actions
                html.Hr(),
                dbc.ButtonGroup([
                    dbc.Button(
                        [html.I(className="fa fa-eye me-2"), "View Devices"],
                        id={'type': 'view-group', 'id': group['id']},
                        color="primary",
                        outline=True,
                        size="sm"
                    ),
                    dbc.Button(
                        [html.I(className="fa fa-edit me-2"), "Edit"],
                        id={'type': 'edit-group', 'id': group['id']},
                        color="info",
                        outline=True,
                        size="sm"
                    ),
                    dbc.Button(
                        [html.I(className="fa fa-trash me-2"), "Delete"],
                        id={'type': 'delete-group', 'id': group['id']},
                        color="danger",
                        outline=True,
                        size="sm"
                    ),
                ], className="w-100"),
            ]),
        ], className="cyber-card mb-3")

        group_cards.append(dbc.Col(card, width=12, md=6, lg=4))

    return dbc.Row(group_cards)
```

---

## 📝 Step 4: Add Group Management Callbacks

### **4.1: Create Group Modal Toggle**

```python
@app.callback(
    Output('create-group-modal', 'is_open'),
    [Input('create-group-btn', 'n_clicks'),
     Input('confirm-create-group', 'n_clicks'),
     Input('cancel-create-group', 'n_clicks')],
    State('create-group-modal', 'is_open'),
    prevent_initial_call=True
)
def toggle_create_group_modal(create, confirm, cancel, is_open):
    """Toggle create group modal"""
    return not is_open if any([create, confirm, cancel]) else is_open
```

### **4.2: Create Group**

```python
@app.callback(
    [Output('create-group-status', 'children'),
     Output('new-group-name', 'value'),
     Output('new-group-description', 'value'),
     Output('new-group-color', 'value'),
     Output('new-group-icon', 'value')],
    Input('confirm-create-group', 'n_clicks'),
    [State('new-group-name', 'value'),
     State('new-group-description', 'value'),
     State('new-group-color', 'value'),
     State('new-group-icon', 'value')],
    prevent_initial_call=True
)
def create_group(n_clicks, name, description, color, icon):
    """Create a new device group"""
    if n_clicks is None:
        raise dash.exceptions.PreventUpdate

    # Validate input
    if not name or not name.strip():
        return (
            dbc.Alert("Group name is required", color="warning", dismissable=True),
            dash.no_update, dash.no_update, dash.no_update, dash.no_update
        )

    # Create group
    group_id = group_manager.create_group(
        name=name.strip(),
        description=description or "",
        color=color or "#0dcaf0",
        icon=icon or "fa-folder"
    )

    if group_id:
        return (
            dbc.Alert(f"Group '{name}' created successfully!", color="success", dismissable=True),
            "",  # Clear name
            "",  # Clear description
            "#0dcaf0",  # Reset color
            "fa-folder"  # Reset icon
        )
    else:
        return (
            dbc.Alert(f"Failed to create group. Group name may already exist.", color="danger", dismissable=True),
            dash.no_update, dash.no_update, dash.no_update, dash.no_update
        )
```

### **4.3: View Group Details**

```python
@app.callback(
    [Output('group-details-modal', 'is_open'),
     Output('group-details-header', 'children'),
     Output('group-details-content', 'children')],
    [Input({'type': 'view-group', 'id': dash.dependencies.ALL}, 'n_clicks'),
     Input('close-group-details', 'n_clicks')],
    [State({'type': 'view-group', 'id': dash.dependencies.ALL}, 'id'),
     State('group-details-modal', 'is_open')],
    prevent_initial_call=True
)
def view_group_details(view_clicks, close_click, button_ids, is_open):
    """Display group details and device list"""
    ctx = dash.callback_context

    if not ctx.triggered:
        raise dash.exceptions.PreventUpdate

    triggered_id = ctx.triggered[0]['prop_id']

    # Close modal
    if 'close-group-details' in triggered_id:
        return False, "", ""

    # Open modal with group details
    if 'view-group' in triggered_id:
        # Find which button was clicked
        group_id = None
        for i, clicks in enumerate(view_clicks):
            if clicks:
                group_id = button_ids[i]['id']
                break

        if group_id is None:
            raise dash.exceptions.PreventUpdate

        # Get group info
        group = group_manager.get_group_by_id(group_id)
        if not group:
            return True, "Error", dbc.Alert("Group not found", color="danger")

        # Get devices in group
        devices = group_manager.get_group_devices(group_id)

        # Build header
        header = html.Div([
            html.I(className=f"fa {group['icon']} me-2", style={"color": group['color']}),
            group['name'],
            dbc.Badge(f"{len(devices)} devices", color="primary", pill=True, className="ms-2")
        ])

        # Build device list
        if not devices:
            device_list = dbc.Alert("No devices in this group", color="info")
        else:
            device_items = []
            for device in devices:
                device_items.append(
                    dbc.ListGroupItem([
                        html.Div([
                            html.Strong(device.get('device_name', 'Unknown')),
                            html.Small(f" ({device['device_ip']})", className="text-muted ms-2"),
                            dbc.Badge(
                                device.get('device_type', 'Unknown').upper(),
                                color="secondary",
                                className="ms-2"
                            ),
                            dbc.Button(
                                [html.I(className="fa fa-times")],
                                id={'type': 'remove-from-group', 'group': group_id, 'device': device['device_ip']},
                                color="danger",
                                outline=True,
                                size="sm",
                                className="float-end"
                            ),
                        ]),
                        html.Small(f"Last seen: {device.get('last_seen', 'Never')[:19]}", className="text-muted")
                    ])
                )

            device_list = dbc.ListGroup(device_items)

        # Build content
        content = html.Div([
            html.P(group['description'] or "No description", className="text-muted mb-3"),

            html.H6("Devices in this group:", className="mt-4 mb-3"),
            device_list,

            html.Hr(className="my-4"),

            html.H6("Add Devices:", className="mb-3"),
            dbc.Row([
                dbc.Col([
                    dbc.Select(
                        id={'type': 'add-device-select', 'group': group_id},
                        options=[],  # Will be populated dynamically
                        placeholder="Select device to add..."
                    ),
                ], width=8),
                dbc.Col([
                    dbc.Button(
                        [html.I(className="fa fa-plus me-2"), "Add"],
                        id={'type': 'add-to-group-btn', 'group': group_id},
                        color="primary",
                        className="w-100"
                    ),
                ], width=4),
            ]),
            html.Div(id={'type': 'add-device-status', 'group': group_id}, className="mt-2"),
        ])

        return True, header, content

    raise dash.exceptions.PreventUpdate
```

### **4.4: Delete Group**

```python
@app.callback(
    Output('device-groups-container', 'children', allow_duplicate=True),
    Input({'type': 'delete-group', 'id': dash.dependencies.ALL}, 'n_clicks'),
    State({'type': 'delete-group', 'id': dash.dependencies.ALL}, 'id'),
    prevent_initial_call=True
)
def delete_group(clicks, button_ids):
    """Delete a device group"""
    if not any(clicks):
        raise dash.exceptions.PreventUpdate

    # Find which button was clicked
    group_id = None
    for i, click_count in enumerate(clicks):
        if click_count:
            group_id = button_ids[i]['id']
            break

    if group_id is None:
        raise dash.exceptions.PreventUpdate

    # Delete group
    success = group_manager.delete_group(group_id)

    if success:
        logger.info(f"Deleted group {group_id}")

    # Trigger refresh by returning updated groups
    return display_device_groups(0)
```

---

## 📝 Step 5: Add Device Group Assignment to Device Modal

### **5.1: Add Group Dropdown to Device Details**

In the device details modal (around line 1980), add:

```python
# In device modal, add group management section
html.Div([
    html.Strong("Device Groups: ", className="mb-2"),
    html.Div(id={'type': 'device-groups-display', 'ip': device_ip}),

    dbc.Row([
        dbc.Col([
            dbc.Select(
                id={'type': 'assign-group-select', 'ip': device_ip},
                options=[],  # Populated by callback
                placeholder="Assign to group..."
            ),
        ], width=8),
        dbc.Col([
            dbc.Button(
                [html.I(className="fa fa-plus")],
                id={'type': 'assign-group-btn', 'ip': device_ip},
                color="primary",
                size="sm",
                className="w-100"
            ),
        ], width=4),
    ], className="mt-2"),

    html.Div(id={'type': 'group-assign-status', 'ip': device_ip}, className="mt-2")
], className="mb-3"),
```

### **5.2: Callback to Display Current Groups**

```python
@app.callback(
    Output({'type': 'device-groups-display', 'ip': dash.dependencies.MATCH}, 'children'),
    Input('device-details-modal', 'is_open'),
    State({'type': 'device-groups-display', 'ip': dash.dependencies.MATCH}, 'id'),
    prevent_initial_call=True
)
def display_device_groups(is_open, component_id):
    """Display groups a device belongs to"""
    if not is_open:
        raise dash.exceptions.PreventUpdate

    device_ip = component_id['ip']
    groups = group_manager.get_device_groups(device_ip)

    if not groups:
        return html.Small("Not in any group", className="text-muted")

    badges = []
    for group in groups:
        badges.append(
            dbc.Badge(
                [
                    html.I(className=f"fa {group['icon']} me-1"),
                    group['name'],
                    html.I(
                        className="fa fa-times ms-2",
                        id={'type': 'remove-group-badge', 'device': device_ip, 'group': group['id']},
                        style={"cursor": "pointer"}
                    )
                ],
                color="secondary",
                pill=True,
                className="me-1 mb-1",
                style={"borderLeft": f"3px solid {group['color']}"}
            )
        )

    return html.Div(badges)
```

### **5.3: Callback to Assign Device to Group**

```python
@app.callback(
    Output({'type': 'group-assign-status', 'ip': dash.dependencies.MATCH}, 'children'),
    Input({'type': 'assign-group-btn', 'ip': dash.dependencies.MATCH}, 'n_clicks'),
    [State({'type': 'assign-group-select', 'ip': dash.dependencies.MATCH}, 'value'),
     State({'type': 'assign-group-btn', 'ip': dash.dependencies.MATCH}, 'id')],
    prevent_initial_call=True
)
def assign_device_to_group(n_clicks, group_id, button_id):
    """Assign device to selected group"""
    if n_clicks is None or not group_id:
        raise dash.exceptions.PreventUpdate

    device_ip = button_id['ip']

    success = group_manager.add_device_to_group(device_ip, int(group_id))

    if success:
        return dbc.Alert("Device added to group", color="success", dismissable=True, duration=2000)
    else:
        return dbc.Alert("Device already in group", color="warning", dismissable=True, duration=2000)
```

---

## 📝 Step 6: Add Auto-Grouping Feature

### **6.1: Add Auto-Group Button to Settings**

```python
# In Settings panel
dbc.Button(
    [html.I(className="fa fa-magic me-2"), "Auto-Group Devices by Type"],
    id="auto-group-btn",
    color="info",
    outline=True,
    className="w-100 cyber-button mb-2"
),
html.Div(id="auto-group-status", className="mt-2"),
```

### **6.2: Auto-Group Callback**

```python
@app.callback(
    Output('auto-group-status', 'children'),
    Input('auto-group-btn', 'n_clicks'),
    prevent_initial_call=True
)
def auto_group_devices(n_clicks):
    """Automatically assign devices to groups based on their type"""
    if n_clicks is None:
        raise dash.exceptions.PreventUpdate

    try:
        result = group_manager.auto_group_by_type()

        total_grouped = sum(result.values())

        if total_grouped > 0:
            details = [html.P(f"Successfully grouped {total_grouped} devices:", className="mb-2")]
            for device_type, count in result.items():
                if count > 0:
                    details.append(html.Li(f"{device_type}: {count} devices"))

            return dbc.Alert([
                html.Strong("Auto-grouping complete!"),
                html.Ul(details, className="mb-0 mt-2")
            ], color="success", dismissable=True)
        else:
            return dbc.Alert("All devices are already grouped", color="info", dismissable=True, duration=3000)

    except Exception as e:
        logger.error(f"Error in auto-grouping: {e}")
        return dbc.Alert(f"Error: {str(e)}", color="danger", dismissable=True, duration=3000)
```

---

## 📝 Step 7: Add Group Filtering to Device List

### **7.1: Add Group Filter Dropdown**

```python
# Above device list
dbc.Row([
    dbc.Col([
        html.H5("Network Devices", className="d-inline-block"),
    ], width=6),
    dbc.Col([
        dbc.Select(
            id="group-filter-select",
            options=[
                {"label": "All Devices", "value": "all"},
                {"label": "Ungrouped Devices", "value": "ungrouped"},
            ],
            value="all",
            className="cyber-input"
        ),
    ], width=6),
], className="mb-3"),
```

### **7.2: Filter Device List by Group**

```python
@app.callback(
    Output('device-list-container', 'children'),
    [Input('interval-component', 'n_intervals'),
     Input('group-filter-select', 'value')]
)
def display_filtered_devices(n, group_filter):
    """Display devices filtered by group"""
    if group_filter == "ungrouped":
        devices = group_manager.get_ungrouped_devices()
    elif group_filter == "all":
        devices = db_manager.get_all_devices()
    elif group_filter.isdigit():
        # Specific group selected
        devices = group_manager.get_group_devices(int(group_filter))
    else:
        devices = db_manager.get_all_devices()

    # Build device list as before...
    return device_cards
```

---

## 🧪 Step 8: Test Device Grouping

### **8.1: Start Dashboard**

```bash
python3 dashboard/app.py
```

### **8.2: Test Group Creation**

1. Navigate to Groups tab
2. Click "New Group"
3. Enter group details (name, description, color, icon)
4. Click "Create"
5. Verify group appears in list

### **8.3: Test Adding Devices to Groups**

1. Click "View Devices" on a group
2. Use the dropdown to select a device
3. Click "Add"
4. Verify device appears in group

### **8.4: Test Auto-Grouping**

1. Navigate to Settings
2. Click "Auto-Group Devices by Type"
3. Verify devices are automatically assigned to matching groups
4. Check group statistics update

### **8.5: Test Group Filtering**

1. Navigate to main device list
2. Select a group from filter dropdown
3. Verify only devices in that group are shown
4. Select "Ungrouped Devices"
5. Verify only ungrouped devices are shown

---

## 🎨 Advanced Features

### **1. Group-Based Alerts**

Create alerts specific to device groups:

```python
@app.callback(
    Output('group-alerts-container', 'children'),
    Input('interval-component', 'n_intervals'),
    State('selected-group-id', 'data')
)
def display_group_alerts(n, group_id):
    """Display alerts for devices in a specific group"""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    cursor.execute("""
        SELECT a.*
        FROM alerts a
        INNER JOIN device_group_members m ON a.device_ip = m.device_ip
        WHERE m.group_id = ?
        ORDER BY a.timestamp DESC
        LIMIT 50
    """, (group_id,))

    alerts = cursor.fetchall()
    conn.close()

    # Build alert list...
```

### **2. Group Comparison Dashboard**

Compare statistics across groups:

```python
def create_group_comparison_chart():
    """Create chart comparing group statistics"""
    groups = group_manager.get_all_groups()

    group_names = []
    device_counts = []
    alert_counts = []
    data_volumes = []

    for group in groups:
        stats = group_manager.get_group_statistics(group['id'])
        group_names.append(group['name'])
        device_counts.append(stats.get('device_count', 0))
        alert_counts.append(stats.get('alert_count', 0))
        data_volumes.append(stats.get('total_data_mb', 0))

    fig = go.Figure(data=[
        go.Bar(name='Devices', x=group_names, y=device_counts),
        go.Bar(name='Alerts', x=group_names, y=alert_counts),
    ])

    fig.update_layout(barmode='group', title="Group Comparison")
    return fig
```

### **3. Bulk Device Management**

Perform actions on all devices in a group:

```python
@app.callback(
    Output('bulk-action-status', 'children'),
    Input('group-bulk-action-btn', 'n_clicks'),
    [State('selected-group-id', 'data'),
     State('bulk-action-select', 'value')],
    prevent_initial_call=True
)
def perform_bulk_action(n_clicks, group_id, action):
    """Perform bulk action on group devices"""
    if n_clicks is None:
        raise dash.exceptions.PreventUpdate

    devices = group_manager.get_group_devices(group_id)

    if action == 'block_all':
        for device in devices:
            db_manager.set_device_blocked(device['device_ip'], True)
        return dbc.Alert(f"Blocked {len(devices)} devices", color="success")

    elif action == 'trust_all':
        for device in devices:
            db_manager.set_device_trusted(device['device_ip'], True)
        return dbc.Alert(f"Trusted {len(devices)} devices", color="success")

    # Add more bulk actions...
```

### **4. Group Schedules**

Apply time-based rules to groups:

```python
# Add to database
cursor.execute('''
    CREATE TABLE IF NOT EXISTS group_schedules (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        group_id INTEGER NOT NULL,
        action TEXT CHECK(action IN ('block', 'unblock', 'alert')),
        start_time TIME NOT NULL,
        end_time TIME NOT NULL,
        days_of_week TEXT,
        is_active INTEGER DEFAULT 1,
        FOREIGN KEY (group_id) REFERENCES device_groups(id)
    )
''')
```

---

## 🔒 Security Considerations

### **1. Group Access Control**

Restrict group management to admin users:

```python
@app.callback(...)
def create_group(...):
    if not current_user.is_authenticated or current_user.role != 'admin':
        return dbc.Alert("Insufficient permissions", color="danger")

    # Continue with group creation...
```

### **2. Group Deletion Protection**

Prevent deletion of critical groups:

```python
def delete_group(self, group_id: int) -> bool:
    """Delete group with protection for default groups"""
    group = self.get_group_by_id(group_id)

    # Protect default groups
    if group and group['name'] in ['IoT Devices', 'Computers', 'Mobile Devices']:
        logger.warning(f"Attempted to delete protected group: {group['name']}")
        return False

    # Continue with deletion...
```

---

## 🎉 Completion Checklist

- [ ] Ran database migration (created group tables)
- [ ] Added device group manager import to app.py
- [ ] Added Groups tab to main dashboard
- [ ] Added group display callback
- [ ] Added create group modal and callback
- [ ] Added group details modal
- [ ] Added delete group callback
- [ ] Added device group assignment to device modal
- [ ] Added auto-grouping feature
- [ ] Added group filter to device list
- [ ] Tested creating groups
- [ ] Tested adding devices to groups
- [ ] Tested removing devices from groups
- [ ] Tested auto-grouping
- [ ] Tested group filtering
- [ ] (Optional) Added group comparison charts
- [ ] (Optional) Added bulk device management
- [ ] (Optional) Added group schedules

---

## ❓ Troubleshooting

**"Table device_groups already exists" error**
- This is normal if you've run init_database.py multiple times
- The tables use `CREATE TABLE IF NOT EXISTS` so it's safe

**Groups not appearing**
- Check database: `sqlite3 data/database/iotsentinel.db "SELECT * FROM device_groups;"`
- Verify callback is running (check browser console)

**Cannot add device to group**
- Verify device exists in devices table
- Check for foreign key constraints
- Review server logs for SQL errors

**Auto-grouping not working**
- Ensure devices have `device_type` field populated
- Check type values match expected types (iot, computer, mobile, etc.)
- Verify group names match defaults

---

**Your dashboard now has comprehensive device grouping capabilities!** 📁
