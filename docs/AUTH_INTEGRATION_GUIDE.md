# 🔐 User Authentication - Integration Guide

This guide shows how to integrate the authentication system into the IoTSentinel dashboard.

---

## ✅ What's Already Complete

- ✅ Database `users` table created (`config/init_database.py`)
- ✅ Default admin user (username: `admin`, password: `admin`) # pragma: allowlist secret
- ✅ Authentication utilities (`utils/auth.py`)
- ✅ Password hashing with bcrypt
- ✅ User management functions

---

## 📝 Step 1: Install Required Package

```bash
cd /Users/ritiksah/iotsentinel
pip install flask-login
pip install bcrypt

# Update requirements
pip freeze | grep -i "flask-login\|bcrypt" >> requirements.txt
```

---

## 📝 Step 2: Run Database Migration

```bash
# Reinitialize database to create users table
python3 config/init_database.py

# You should see:
# ✓ Database initialized
# ✓ Default admin user created:
#   Username: admin
#   Password: admin
#   ⚠️  CHANGE THIS PASSWORD AFTER FIRST LOGIN!
```

---

## 📝 Step 3: Update dashboard/app.py

### **3.1: Add Imports** (after existing imports, around line 30)

```python
# Authentication imports
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from utils.auth import AuthManager, User

# Initialize authentication
auth_manager = AuthManager(DB_PATH)

# Setup Flask-Login
login_manager = LoginManager()
login_manager.init_app(server)
login_manager.login_view = '/login'

@login_manager.user_loader
def load_user(user_id):
    """Load user by ID for Flask-Login"""
    return auth_manager.get_user_by_id(int(user_id))
```

### **3.2: Create Login Page Layout** (before the main app.layout, around line 900)

```python
# ============================================================================
# LOGIN PAGE LAYOUT
# ============================================================================

login_layout = dbc.Container([
    dbc.Row([
        dbc.Col([
            dbc.Card([
                dbc.CardBody([
                    html.Div([
                        html.H2("🛡️ IoTSentinel", className="text-center text-cyber mb-4"),
                        html.P("Network Security Dashboard", className="text-center text-muted mb-4"),

                        dbc.Alert(id="login-alert", is_open=False, duration=4000),

                        dbc.Label("Username", className="form-label"),
                        dbc.Input(
                            id="login-username",
                            type="text",
                            placeholder="Enter username",
                            className="mb-3 cyber-input",
                            autocomplete="username"
                        ),

                        dbc.Label("Password", className="form-label"),
                        dbc.Input(
                            id="login-password",
                            type="password",
                            placeholder="Enter password",
                            className="mb-3 cyber-input",
                            autocomplete="current-password"
                        ),

                        dbc.Button(
                            "Login",
                            id="login-button",
                            color="primary",
                            className="w-100 cyber-button",
                            size="lg"
                        ),

                        html.Hr(className="my-4"),

                        html.Div([
                            html.Small([
                                html.I(className="fa fa-info-circle me-1"),
                                "Default credentials: ",
                                html.Strong("admin / admin")
                            ], className="text-muted")
                        ], className="text-center")
                    ])
                ])
            ], className="cyber-card shadow-lg", style={"maxWidth": "400px", "margin": "0 auto"})
        ], width=12)
    ], justify="center", className="min-vh-100 align-items-center", style={"background": "linear-gradient(135deg, #667eea 0%, #764ba2 100%)"})
], fluid=True)
```

### **3.3: Update Main App Layout** (wrap existing layout with auth check)

Replace the current `app.layout = ...` section with:

```python
# ============================================================================
# APP LAYOUT - WITH AUTHENTICATION
# ============================================================================

# Store original dashboard layout
dashboard_layout = html.Div([
    # ... (all existing dashboard content - keep as is) ...
], id="main-dashboard")

# Conditional layout based on authentication
app.layout = html.Div([
    dcc.Location(id='url', refresh=True),
    dcc.Store(id='user-session', storage_type='session'),
    html.Div(id='page-content')
])
```

### **3.4: Add Navigation Callback** (around line 2800, before **main**)

```python
# ============================================================================
# AUTHENTICATION CALLBACKS
# ============================================================================

@app.callback(
    Output('page-content', 'children'),
    Input('url', 'pathname'),
    Input('user-session', 'data')
)
def display_page(pathname, user_data):
    """Route to login or dashboard based on authentication"""
    # Check if user is authenticated
    if current_user.is_authenticated:
        # User is logged in, show dashboard
        if pathname == '/logout':
            logout_user()
            return login_layout
        return dashboard_layout
    else:
        # User not logged in, show login page
        if pathname == '/login' or pathname == '/':
            return login_layout
        else:
            # Redirect to login for any other path
            return login_layout


@app.callback(
    [Output('login-alert', 'children'),
     Output('login-alert', 'is_open'),
     Output('login-alert', 'color'),
     Output('url', 'pathname', allow_duplicate=True),
     Output('user-session', 'data', allow_duplicate=True)],
    Input('login-button', 'n_clicks'),
    [State('login-username', 'value'),
     State('login-password', 'value')],
    prevent_initial_call=True
)
def handle_login(n_clicks, username, password):
    """Handle login button click"""
    if n_clicks is None:
        raise dash.exceptions.PreventUpdate

    # Validate inputs
    if not username or not password:
        return "Please enter both username and password", True, "warning", dash.no_update, dash.no_update

    # Verify credentials
    user = auth_manager.verify_user(username, password)

    if user:
        # Login successful
        login_user(user)
        return "Login successful! Redirecting...", True, "success", "/dashboard", {'username': username, 'role': user.role}
    else:
        # Login failed
        return "Invalid username or password", True, "danger", dash.no_update, dash.no_update


# Add logout button to navbar (modify existing navbar in layout section)
# In the navbar section, add:
navbar_items.append(
    dbc.NavItem(
        dbc.Button(
            [html.I(className="fa fa-sign-out-alt me-2"), "Logout"],
            id="logout-button",
            color="danger",
            outline=True,
            size="sm",
            href="/logout",
            external_link=True
        ),
        className="ms-auto"
    )
)
```

---

## 📝 Step 4: Add User Management UI (Optional but Recommended)

### **4.1: Add User Management Card to Settings**

In the Settings accordion (around line 1430), add:

```python
dbc.Row([
    dbc.Col([
        dbc.Card([
            dbc.CardHeader("👥 User Management"),
            dbc.CardBody([
                html.Div(id="user-list-container"),

                html.Hr(),

                html.H6("Create New User", className="mt-3"),
                dbc.Row([
                    dbc.Col([
                        dbc.Input(id="new-username", placeholder="Username", className="cyber-input")
                    ], width=4),
                    dbc.Col([
                        dbc.Input(id="new-password", type="password", placeholder="Password", className="cyber-input")
                    ], width=4),
                    dbc.Col([
                        dbc.Select(
                            id="new-user-role",
                            options=[
                                {"label": "Admin", "value": "admin"},
                                {"label": "Viewer", "value": "viewer"}
                            ],
                            value="viewer"
                        )
                    ], width=2),
                    dbc.Col([
                        dbc.Button("Create User", id="create-user-btn", color="primary", className="cyber-button")
                    ], width=2)
                ]),
                html.Div(id="user-management-status", className="mt-2")
            ])
        ], className="cyber-card")
    ], width=12)
], className="mt-3")
```

### **4.2: Add User Management Callbacks**

```python
@app.callback(
    Output('user-list-container', 'children'),
    Input('url', 'pathname')
)
def display_users(pathname):
    """Display list of users"""
    users = auth_manager.get_all_users()

    if not users:
        return html.P("No users found", className="text-muted")

    user_items = []
    for user in users:
        user_items.append(
            dbc.ListGroupItem([
                html.Div([
                    html.Strong(user['username']),
                    dbc.Badge(user['role'].upper(), color="primary" if user['role'] == 'admin' else "secondary", className="ms-2"),
                    html.Span(f"Last login: {user.get('last_login', 'Never')[:19] if user.get('last_login') else 'Never'}", className="ms-3 text-muted small")
                ])
            ])
        )

    return dbc.ListGroup(user_items)


@app.callback(
    Output('user-management-status', 'children'),
    Input('create-user-btn', 'n_clicks'),
    [State('new-username', 'value'),
     State('new-password', 'value'),
     State('new-user-role', 'value')],
    prevent_initial_call=True
)
def create_new_user(n_clicks, username, password, role):
    """Create a new user"""
    if n_clicks is None:
        raise dash.exceptions.PreventUpdate

    # Validate inputs
    if not username or not password:
        return dbc.Alert("Username and password are required", color="warning", dismissable=True)

    if len(password) < 6:
        return dbc.Alert("Password must be at least 6 characters", color="warning", dismissable=True)

    # Create user
    success = auth_manager.create_user(username, password, role)

    if success:
        return dbc.Alert(f"User '{username}' created successfully!", color="success", dismissable=True)
    else:
        return dbc.Alert(f"Failed to create user. Username may already exist.", color="danger", dismissable=True)
```

---

## 📝 Step 5: Update CSS for Login Page (Optional)

Add to `dashboard/assets/custom.css`:

```css
/* Login page styling */
.min-vh-100 {
  min-height: 100vh;
}

.text-cyber {
  color: #00ffcc;
  text-shadow: 0 0 10px rgba(0, 255, 204, 0.5);
}

.cyber-input:focus {
  border-color: #00ffcc;
  box-shadow: 0 0 10px rgba(0, 255, 204, 0.3);
}

/* Logout button in navbar */
#logout-button {
  border-color: #dc3545 !important;
  color: #dc3545 !important;
}

#logout-button:hover {
  background-color: #dc3545 !important;
  color: white !important;
}
```

---

## 🧪 Step 6: Test Authentication

### **6.1: Start Dashboard**

```bash
python3 dashboard/app.py
```

### **6.2: Test Login**

1. Navigate to http://localhost:8050
2. You should see the login page
3. Enter credentials:
   - Username: `admin`
   - Password: `admin` # pragma: allowlist secret
4. Click "Login"
5. You should be redirected to the main dashboard

### **6.3: Test Logout**

1. Click "Logout" button in navbar
2. You should be redirected back to login page

### **6.4: Test Invalid Credentials**

1. Try logging in with wrong password
2. Should see error: "Invalid username or password"

### **6.5: Change Default Password**

1. Login as admin
2. Go to Settings → User Management
3. Create a new admin user with secure password
4. Logout
5. Login with new credentials
6. Delete or deactivate the default `admin` user

---

## 🔒 Security Best Practices

### **Password Requirements**

The current implementation has minimal validation. Consider adding:

```python
def validate_password(password: str) -> tuple[bool, str]:
    """Validate password strength"""
    if len(password) < 8:
        return False, "Password must be at least 8 characters"

    if not any(c.isupper() for c in password):
        return False, "Password must contain at least one uppercase letter"

    if not any(c.islower() for c in password):
        return False, "Password must contain at least one lowercase letter"

    if not any(c.isdigit() for c in password):
        return False, "Password must contain at least one number"

    if not any(c in '!@#$%^&*()_+-=[]{}|;:,.<>?' for c in password):
        return False, "Password must contain at least one special character"

    return True, "Password is strong"
```

### **Session Security**

Add to app initialization:

```python
# Secure session configuration
server.config['SECRET_KEY'] = 'CHANGE-THIS-TO-A-RANDOM-SECRET-KEY'  # pragma: allowlist secret
server.config['SESSION_COOKIE_SECURE'] = True  # Requires HTTPS
server.config['SESSION_COOKIE_HTTPONLY'] = True
server.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
server.config['PERMANENT_SESSION_LIFETIME'] = 3600  # 1 hour
```

### **Rate Limiting**

Consider adding Flask-Limiter to prevent brute-force attacks:

```bash
pip install Flask-Limiter

# In app.py:
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

limiter = Limiter(
    app=server,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"]
)

@limiter.limit("5 per minute")  # Max 5 login attempts per minute
@app.callback(...)
def handle_login(...):
    ...
```

---

## ⚠️ Important Security Notes

1. **Change default password immediately** after first login
2. **Use HTTPS in production** - Authentication over HTTP is insecure
3. **Generate a secure SECRET_KEY** - Don't use default or commit to git
4. **Regular password changes** - Enforce password rotation policy
5. **Audit logs** - Log all authentication attempts and user actions
6. **Multi-factor authentication** - Consider adding 2FA for admin users
7. **Account lockout** - Lock accounts after X failed login attempts

---

## 📊 Database Queries for User Management

```bash
sqlite3 data/database/iotsentinel.db

# View all users
SELECT id, username, role, created_at, last_login FROM users;

# Create new admin user
INSERT INTO users (username, password_hash, role)
VALUES ('your_username', '$2b$12$...', 'admin');

# Delete user (soft delete)
UPDATE users SET is_active = 0 WHERE username = 'old_user';

# Reset password (you'll need to generate hash with bcrypt)
# In Python:
# import bcrypt
# hash = bcrypt.hashpw(b'new_password', bcrypt.gensalt()).decode('utf-8')
UPDATE users SET password_hash = '$2b$12$...' WHERE username = 'admin';
```

---

## 🎉 Completion Checklist

- [ ] Installed flask-login and bcrypt
- [ ] Ran database migration (created users table)
- [ ] Added authentication imports to app.py
- [ ] Created login page layout
- [ ] Added navigation callback
- [ ] Added login/logout callbacks
- [ ] Tested login with admin/admin
- [ ] Tested logout functionality
- [ ] Changed default admin password
- [ ] (Optional) Added user management UI
- [ ] (Optional) Updated CSS styling
- [ ] (Optional) Implemented rate limiting
- [ ] Configured secure session settings

---

## ❓ Troubleshooting

**"ModuleNotFoundError: No module named 'flask_login'"**

- Run: `pip install flask-login`

**"Database is locked" error**

- Close any open database connections
- Restart the dashboard

**"Invalid username or password" with correct credentials**

- Check database: `sqlite3 data/database/iotsentinel.db "SELECT * FROM users;"`
- Verify bcrypt is installed: `python3 -c "import bcrypt; print('OK')"`

**Login page doesn't appear**

- Check console for errors
- Verify `app.layout` is correctly set to conditional layout
- Check Flask server logs

**Logged in but dashboard doesn't load**

- Check `display_page()` callback logic
- Verify `current_user.is_authenticated` is True
- Check browser console for JavaScript errors

---

**Your dashboard is now secured with user authentication!** 🔐
