"""
Admin & User Management callbacks — user CRUD, preferences, system modals,
reports, scheduling, privacy dashboard, dashboard templates.

Extracted from app.py.  All callbacks are registered via ``register(app)``.
"""

import json
import base64
import io
import os
import logging
from datetime import datetime
from pathlib import Path

import dash
import dash_bootstrap_components as dbc
import pandas as pd
import plotly.express as px
import plotly.graph_objs as go
from dash import dcc, html, Input, Output, State, callback_context, ALL, no_update

from flask_login import current_user
from flask import request, send_file

from dashboard.shared import (
    db_manager,
    auth_manager,
    chart_factory,
    export_helper,
    logger,
    config,
    audit_logger,
    security_audit_logger,
    totp_manager,
    trend_analyzer,
    report_builder,
    report_scheduler,
    template_manager,
    report_queue,
    privacy_analyzer,
    log_user_action,
    log_settings_change,
    can_export_data,
    can_delete_data,
    ROLES,
    get_db_connection,
    create_timestamp_display,
    DASHBOARD_TEMPLATES,
    ToastManager,
    PermissionManager,
)


# ============================================================================
# HELPER FUNCTIONS
# ============================================================================

def save_model_file(filename: str, file_data: bytes) -> bool:
    """Save uploaded model file to the appropriate location."""
    try:
        from pathlib import Path

        # Determine destination based on filename
        if 'river' in filename.lower() or filename == 'river_engine.pkl':
            dest_path = Path('data/models') / filename
        elif 'halfspace' in filename.lower():
            dest_path = Path('data/models/halfspacetrees.pkl')
        elif 'hoeffding' in filename.lower():
            dest_path = Path('data/models/hoeffding_adaptive.pkl')
        elif 'snarimax' in filename.lower():
            dest_path = Path('data/models/snarimax.pkl')
        elif 'feature_extractor' in filename.lower() or filename == 'feature_extractor.pkl':
            dest_path = Path(config.get('ml', 'feature_extractor_path'))
        else:
            # Save to models directory
            dest_path = Path('data/models') / filename

        # Create parent directory if it doesn't exist
        dest_path.parent.mkdir(parents=True, exist_ok=True)

        # Backup existing file if it exists
        if dest_path.exists():
            backup_path = dest_path.with_suffix(f".bak_{datetime.now().strftime('%Y%m%d_%H%M%S')}{dest_path.suffix}")
            dest_path.rename(backup_path)
            logger.info(f"Backed up existing model to {backup_path}")

        # Write the new file
        with open(dest_path, 'wb') as f:
            f.write(file_data)

        logger.info(f"Successfully saved model file to {dest_path}")
        return True

    except Exception as e:
        logger.error(f"Error saving model file {filename}: {e}")
        return False


# ============================================================================
# REGISTER ALL CALLBACKS
# ============================================================================

def register(app):
    """Register all admin / user-management callbacks with the Dash app."""

    # ========================================================================
    # USER MANAGEMENT CALLBACKS
    # ========================================================================

    # User list callback (Admin only)
    @app.callback(
        [Output('user-list-container', 'children', allow_duplicate=True),
         Output('admin-only-notice', 'children'),
         Output('toast-container', 'children', allow_duplicate=True)],
        [Input('user-modal', 'is_open'),
         Input('refresh-users-btn', 'n_clicks'),
         Input('user-search-input', 'value'),
         Input('user-role-filter', 'value')],
        prevent_initial_call=True
    )
    def display_user_list(is_open, refresh_clicks, search_query, role_filter):
        """Display list of active users (admin only)"""
        ctx = callback_context

        if not is_open:
            raise dash.exceptions.PreventUpdate

        # Check if refresh button was clicked for toast notification
        show_refresh_toast = ctx.triggered and ctx.triggered[0]['prop_id'] == 'refresh-users-btn.n_clicks'

        if not current_user.is_authenticated:
            return html.Div(), None, dash.no_update

        # Check if user is admin
        if not current_user.is_admin():
            return (
                dbc.Alert([
                    html.I(className="fa fa-info-circle me-2"),
                    "Only administrators can view and manage users"
                ], color="info", className="mt-3"),
                dbc.Alert([
                    html.I(className="fa fa-lock me-2"),
                    "Admin access required"
                ], color="warning"),
                dash.no_update
            )

        # Get all users
        users = auth_manager.get_all_users()

        if not users:
            return html.P("No users found", className="text-muted"), None, dash.no_update

        # Apply search filter
        if search_query:
            search_lower = search_query.lower()
            users = [u for u in users if search_lower in u['username'].lower() or
                     (u.get('email') and search_lower in u.get('email', '').lower())]

        # Apply role filter
        if role_filter and role_filter != 'all':
            users = [u for u in users if u['role'] == role_filter]

        if not users:
            return html.Div([
                html.I(className="fa fa-search me-2 text-muted"),
                html.Span("No users match your search criteria", className="text-muted")
            ], className="text-center py-4"), None, dash.no_update

        # Create user table
        table_header = [
            html.Thead(html.Tr([
                html.Th("Username"),
                html.Th("Role"),
                html.Th("Status"),
                html.Th("Created", className="text-center"),
                html.Th("Actions", className="text-center")
            ]))
        ]

        rows = []
        for user in users:
            rows.append(html.Tr([
                html.Td([
                    html.I(className="fa fa-user me-2"),
                    user['username']
                ]),
                html.Td([
                    dbc.Badge(
                        user['role'].upper(),
                        color="danger" if user['role'] == 'admin' else "primary",
                        className="me-1"
                    )
                ]),
                html.Td([
                    dbc.Badge(
                        "Active" if user['is_active'] else "Inactive",
                        color="success" if user['is_active'] else "secondary"
                    )
                ]),
                html.Td(user.get('created_at', 'N/A')[:10], className="text-center"),
                html.Td([
                    dbc.ButtonGroup([
                        dbc.Button([
                            html.I(className="fa fa-trash")
                        ], id={'type': 'delete-user-btn', 'index': user['id']},
                           color="danger", size="sm", outline=True,
                           disabled=(user['username'] == current_user.username))  # Can't delete yourself
                    ], size="sm")
                ], className="text-center")
            ]))

        table_body = [html.Tbody(rows)]

        user_table = dbc.Table(
            table_header + table_body,
            bordered=True,
            hover=True,
            responsive=True,
            dark=False,
            className="mt-3 table-adaptive"
        )

        # Generate success toast if refresh button was clicked
        toast = ToastManager.success(
            "User list refreshed",
            detail_message=f"Displaying {len(users)} user(s)"
        ) if show_refresh_toast else dash.no_update

        return user_table, None, toast

    # Activity log callback for User Management modal
    @app.callback(
        Output('user-activity-log', 'children'),
        [Input('user-management-tabs', 'active_tab'),
         Input('refresh-users-btn', 'n_clicks')],
        prevent_initial_call=True
    )
    def display_activity_log(active_tab, refresh_clicks):
        """Display user activity log (admin only)"""
        if active_tab != 'activity-log-tab':
            raise dash.exceptions.PreventUpdate

        if not current_user.is_authenticated or not current_user.is_admin():
            return dbc.Alert("Admin access required", color="warning")

        # Try to get activity logs from database
        try:
            # Get recent login attempts and user activities
            activities = []

            # Get all users to show recent activity
            users = auth_manager.get_all_users()

            for user in users[:10]:  # Limit to recent users
                activities.append({
                    'icon': 'fa-user-plus',
                    'color': 'success',
                    'action': f"User '{user['username']}' account created",
                    'time': user.get('created_at', 'Unknown')[:16] if user.get('created_at') else 'Unknown',
                    'role': user['role']
                })

            if not activities:
                return html.Div([
                    html.I(className="fa fa-inbox fa-3x text-muted mb-3"),
                    html.P("No activity records found", className="text-muted")
                ], className="text-center py-5")

            # Build activity list
            activity_items = []
            for activity in activities:
                activity_items.append(
                    html.Div([
                        html.Div([
                            html.I(className=f"fa {activity['icon']} text-{activity['color']} me-3",
                                   style={"fontSize": "1.2rem", "width": "24px"}),
                            html.Div([
                                html.Div(activity['action'], className="fw-semibold"),
                                html.Small([
                                    html.I(className="fa fa-clock me-1"),
                                    activity['time'],
                                    html.Span(" • ", className="mx-2"),
                                    dbc.Badge(activity['role'].upper(),
                                             color="danger" if activity['role'] == 'admin' else "primary",
                                             className="ms-1")
                                ], className="text-muted")
                            ], className="flex-grow-1")
                        ], className="d-flex align-items-start")
                    ], className="p-3 border-bottom")
                )

            return html.Div(activity_items)

        except Exception as e:
            return dbc.Alert(f"Error loading activity log: {str(e)}", color="danger")

    # Create new user callback (Admin only)
    @app.callback(
        [Output('add-user-status', 'children'),
         Output('new-user-username', 'value'),
         Output('new-user-email', 'value'),
         Output('new-user-password', 'value'),
         Output('user-list-container', 'children', allow_duplicate=True),
         Output('toast-container', 'children', allow_duplicate=True)],
        Input('create-user-btn', 'n_clicks'),
        [State('new-user-username', 'value'),
         State('new-user-email', 'value'),
         State('new-user-password', 'value'),
         State('new-user-role', 'value')],
        prevent_initial_call=True
    )
    def create_new_user(n_clicks, username, email, password, role):
        """Create a new user (Admin only)"""
        if n_clicks is None or not current_user.is_authenticated or not current_user.is_admin():
            raise dash.exceptions.PreventUpdate

        # Validation
        if not username or not password:
            toast = ToastManager.warning(
                "Validation Error",
                detail_message="Username and password are required"
            )
            return dbc.Alert("Username and password are required", color="warning"), dash.no_update, dash.no_update, dash.no_update, dash.no_update, toast

        if len(username) < 3:
            toast = ToastManager.warning(
                "Validation Error",
                detail_message="Username must be at least 3 characters"
            )
            return dbc.Alert("Username must be at least 3 characters", color="warning"), dash.no_update, dash.no_update, dash.no_update, dash.no_update, toast

        if not auth_manager.is_password_strong_enough(password):
            toast = ToastManager.warning(
                "Validation Error",
                detail_message="Password is not strong enough. It must be at least 8 characters long and contain at least one uppercase letter, one lowercase letter, one digit, and one special character."
            )
            return dbc.Alert("Password is not strong enough. It must be at least 8 characters long and contain at least one uppercase letter, one lowercase letter, one digit, and one special character.", color="warning"), dash.no_update, dash.no_update, dash.no_update, dash.no_update, toast

        # Create user
        success = auth_manager.create_user(username, password, role or 'viewer', email)

        if success:
            logger.info(f"Admin {current_user.username} created new user: {username} (role: {role})")

            # Log to security audit
            security_audit_logger.log(
                event_type='user_created',
                severity='info',
                user_id=current_user.id,
                username=current_user.username,
                resource_type='user',
                resource_id=username,
                details={'created_user': username, 'role': role or 'viewer', 'email': email, 'created_by': current_user.username},
                result='success'
            )

            # Log to audit trail
            log_user_action(
                audit_logger,
                'create',
                username,
                success=True
            )

            # Refresh user list
            users = auth_manager.get_all_users()
            rows = []
            for user in users:
                rows.append(html.Tr([
                    html.Td([html.I(className="fa fa-user me-2"), user['username']]),
                    html.Td([dbc.Badge(user['role'].upper(), color="danger" if user['role'] == 'admin' else "primary")]),
                    html.Td([dbc.Badge("Active" if user['is_active'] else "Inactive", color="success" if user['is_active'] else "secondary")]),
                    html.Td(user.get('created_at', 'N/A')[:10], className="text-center"),
                    html.Td([
                        dbc.Button([html.I(className="fa fa-trash")],
                                  id={'type': 'delete-user-btn', 'index': user['id']},
                                  color="danger", size="sm", outline=True,
                                  disabled=(user['username'] == current_user.username))
                    ], className="text-center")
                ]))

            user_table = dbc.Table(
                [html.Thead(html.Tr([html.Th("Username"), html.Th("Role"), html.Th("Status"), html.Th("Created", className="text-center"), html.Th("Actions", className="text-center")]))] +
                [html.Tbody(rows)],
                bordered=True, hover=True, responsive=True, dark=False, className="mt-3 table-adaptive"
            )

            toast = ToastManager.success(
                "User Created",
                detail_message=f"User '{username}' created successfully!"
            )

            return dbc.Alert([html.I(className="fa fa-check-circle me-2"), f"User '{username}' created successfully!"], color="success"), "", "", "", user_table, toast
        else:
            log_user_action(
                audit_logger,
                'create',
                username,
                success=False,
                error_message="Username already exists"
            )
            toast = ToastManager.error(
                "User Creation Failed",
                detail_message="Username already exists"
            )
            return dbc.Alert("Username already exists", color="danger"), dash.no_update, dash.no_update, dash.no_update, dash.no_update, toast

    # Delete user callback - Show confirmation modal
    @app.callback(
        [Output('user-delete-modal', 'is_open'),
         Output('user-delete-id-store', 'data'),
         Output('user-delete-confirm-username', 'children')],
        Input({'type': 'delete-user-btn', 'index': dash.dependencies.ALL}, 'n_clicks'),
        [State('user-delete-modal', 'is_open'),
         State('user-delete-id-store', 'data')],
        prevent_initial_call=True
    )
    def show_delete_user_modal(n_clicks, is_open, stored_user_id):
        """Show confirmation modal before deleting user"""
        if not current_user.is_authenticated or not current_user.is_admin():
            raise dash.exceptions.PreventUpdate

        ctx = dash.callback_context
        if not ctx.triggered_id:
            raise dash.exceptions.PreventUpdate

        if not n_clicks or all(c is None for c in n_clicks):
            raise dash.exceptions.PreventUpdate

        user_id = ctx.triggered_id['index']

        # Prevent deleting current user
        if user_id == current_user.id:
            return False, None, ""

        # Get username for display
        users = auth_manager.get_all_users()
        username = next((u['username'] for u in users if u['id'] == user_id), "Unknown User")

        return True, user_id, f"User: {username}"

    # Delete user confirmed callback
    @app.callback(
        [Output('user-list-container', 'children', allow_duplicate=True),
         Output('toast-container', 'children', allow_duplicate=True),
         Output('user-delete-modal', 'is_open', allow_duplicate=True)],
        [Input('user-delete-confirm', 'n_clicks'),
         Input('user-delete-cancel', 'n_clicks')],
        State('user-delete-id-store', 'data'),
        prevent_initial_call=True
    )
    def delete_user_confirmed(confirm_clicks, cancel_clicks, user_id):
        """Delete user after confirmation"""
        if not current_user.is_authenticated or not current_user.is_admin():
            raise dash.exceptions.PreventUpdate

        ctx = dash.callback_context
        if not ctx.triggered_id:
            raise dash.exceptions.PreventUpdate

        button_id = ctx.triggered_id

        # If cancel button clicked, just close modal
        if button_id == 'user-delete-cancel':
            return dash.no_update, dash.no_update, False

        # If confirm button clicked, delete user
        if button_id == 'user-delete-confirm' and user_id:
            # Get user info before deletion for audit logging
            try:
                conn = db_manager.conn
                cursor = conn.cursor()
                cursor.execute("SELECT username, role FROM users WHERE id = ?", (user_id,))
                deleted_user_info = cursor.fetchone()
                deleted_username = deleted_user_info[0] if deleted_user_info else f"user_id_{user_id}"
                deleted_role = deleted_user_info[1] if deleted_user_info else 'unknown'
            except Exception as e:
                logger.error(f"Error fetching user info for audit: {e}")
                deleted_username = f"user_id_{user_id}"
                deleted_role = 'unknown'

            # Hard delete user (permanently remove from database)
            success = auth_manager.delete_user(user_id, current_user.id, hard_delete=True)

            if success:
                logger.info(f"Admin {current_user.username} permanently deleted user ID: {user_id}")

                # Log successful deletion to security audit
                security_audit_logger.log(
                    event_type='user_deleted',
                    severity='warning',
                    user_id=current_user.id,
                    username=current_user.username,
                    resource_type='user',
                    resource_id=str(user_id),
                    details={'deleted_user': deleted_username, 'deleted_role': deleted_role, 'deleted_by': current_user.username},
                    result='success'
                )
            else:
                # Log failed deletion attempt
                security_audit_logger.log(
                    event_type='user_deleted',
                    severity='error',
                    user_id=current_user.id,
                    username=current_user.username,
                    resource_type='user',
                    resource_id=str(user_id),
                    details={'attempted_user': deleted_username},
                    result='failure',
                    failure_reason='Database operation failed'
                )

                # Refresh user list
                users = auth_manager.get_all_users()
                rows = []
                for user in users:
                    rows.append(html.Tr([
                        html.Td([html.I(className="fa fa-user me-2"), user['username']]),
                        html.Td([dbc.Badge(user['role'].upper(), color="danger" if user['role'] == 'admin' else "primary")]),
                        html.Td([dbc.Badge("Active" if user['is_active'] else "Inactive", color="success" if user['is_active'] else "secondary")]),
                        html.Td(user.get('created_at', 'N/A')[:10], className="text-center"),
                        html.Td([
                            dbc.Button([html.I(className="fa fa-trash")],
                                      id={'type': 'delete-user-btn', 'index': user['id']},
                                      color="danger", size="sm", outline=True,
                                      disabled=(user['username'] == current_user.username))
                        ], className="text-center")
                    ]))

                user_table = dbc.Table(
                    [html.Thead(html.Tr([html.Th("Username"), html.Th("Role"), html.Th("Status"), html.Th("Created", className="text-center"), html.Th("Actions", className="text-center")]))] +
                    [html.Tbody(rows)],
                    bordered=True, hover=True, striped=True, className="mb-0"
                )

                toast = ToastManager.success(
                    "User Deleted",
                    detail_message="User deleted successfully"
                )
                return user_table, toast, False

            toast = ToastManager.error(
                "Delete Failed",
                detail_message="Failed to delete user"
            )
            return dash.no_update, toast, False

        raise dash.exceptions.PreventUpdate

    # ========================================================================
    # HEADER / PROFILE CALLBACKS
    # ========================================================================

    # Update current user display in header and profile dropdown
    @app.callback(
        Output('current-user-display-dropdown', 'children'),
        Input('url', 'pathname'),
        prevent_initial_call=False
    )
    def update_current_user_display(pathname):
        """Update the current user display in profile dropdown"""
        if current_user.is_authenticated:
            role_badge = dbc.Badge(
                current_user.role.upper(),
                color="danger" if current_user.role == 'admin' else "primary",
                className="ms-2",
                pill=True
            )
            return [current_user.username, " ", role_badge]
        return "User"

    # Show/hide admin menu items
    @app.callback(
        [Output('admin-divider', 'style'),
         Output('profile-user-mgmt-btn', 'style')],
        Input('url', 'pathname'),
        prevent_initial_call=False
    )
    def toggle_admin_menu_items(pathname):
        """Show admin menu items only for admin users"""
        if current_user.is_authenticated and current_user.is_admin():
            return {"display": "block"}, {"display": "block"}
        return {"display": "none"}, {"display": "none"}

    # Open profile edit modal
    @app.callback(
        Output("profile-edit-modal", "is_open"),
        [Input("edit-profile-btn", "n_clicks"),
         Input("close-profile-modal-btn", "n_clicks")],
        [State("profile-edit-modal", "is_open")],
        prevent_initial_call=True,
    )
    def toggle_profile_edit_modal(open_clicks, close_clicks, is_open):
        ctx = dash.callback_context
        if not ctx.triggered:
            raise dash.exceptions.PreventUpdate
        trigger_id = ctx.triggered[0]['prop_id'].split('.')[0]
        if trigger_id == 'close-profile-modal-btn':
            return False
        if trigger_id == 'edit-profile-btn' and open_clicks:
            return True
        return is_open

    # Populate profile edit modal with current user data
    @app.callback(
        [Output('edit-username', 'value'),
         Output('edit-email', 'value')],
        Input('profile-edit-modal', 'is_open'),
        prevent_initial_call=False
    )
    def populate_profile_data(is_open):
        """Populate profile fields when modal opens"""
        if current_user.is_authenticated and is_open:
            # Get current user data from database
            user_data = auth_manager.get_user_data(current_user.id)
            if user_data:
                return user_data.get('username', ''), user_data.get('email', '')
        return '', ''

    # Open user management modal (admin only)
    @app.callback(
        Output("user-modal", "is_open", allow_duplicate=True),
        Input("profile-user-mgmt-btn", "n_clicks"),
        State("user-modal", "is_open"),
        prevent_initial_call=True
    )
    def open_user_management_modal(n_clicks, is_open):
        """Open user management modal (admin only)"""
        if not current_user.is_authenticated or not current_user.is_admin():
            raise dash.exceptions.PreventUpdate

        if n_clicks:
            return True
        raise dash.exceptions.PreventUpdate

    # Update profile information
    @app.callback(
        [Output('toast-container', 'children', allow_duplicate=True),
         Output('profile-edit-modal', 'is_open', allow_duplicate=True)],
        Input('update-profile-btn', 'n_clicks'),
        [State('edit-username', 'value'),
         State('edit-email', 'value')],
        prevent_initial_call=True
    )
    def update_profile_info(n_clicks, username, email):
        """Update user profile information"""
        if n_clicks is None:
            raise dash.exceptions.PreventUpdate

        if not current_user.is_authenticated:
            toast = ToastManager.error(
                "Authentication Required",
                detail_message="Not authenticated"
            )
            return toast, dash.no_update

        if not username or not email:
            toast = ToastManager.warning(
                "Validation Error",
                detail_message="Please fill in all fields"
            )
            return toast, dash.no_update

        # Update user profile
        success = auth_manager.update_user_profile(current_user.id, username, email)

        if success:
            toast = ToastManager.success(
                "Profile Updated",
                detail_message="Profile updated successfully!"
            )
            return toast, False
        else:
            toast = ToastManager.error(
                "Update Failed",
                detail_message="Failed to update profile. Username may already exist."
            )
            return toast, dash.no_update

    # Change password from profile edit modal
    @app.callback(
        [Output('toast-container', 'children', allow_duplicate=True),
         Output('profile-edit-modal', 'is_open', allow_duplicate=True)],
        Input('profile-change-password-btn', 'n_clicks'),
        [State('profile-current-password', 'value'),
         State('profile-new-password', 'value'),
         State('profile-new-password-confirm', 'value')],
        prevent_initial_call=True
    )
    def change_password_from_profile(n_clicks, current_password, new_password, confirm_password):
        """Change password from profile edit modal"""
        if n_clicks is None:
            raise dash.exceptions.PreventUpdate

        if not current_user.is_authenticated:
            toast = ToastManager.error(
                "Authentication Required",
                detail_message="Not authenticated"
            )
            return toast, dash.no_update

        if not current_password or not new_password or not confirm_password:
            toast = ToastManager.warning(
                "Validation Error",
                detail_message="Please fill in all password fields"
            )
            return toast, dash.no_update

        if new_password != confirm_password:
            toast = ToastManager.warning(
                "Validation Error",
                detail_message="New passwords do not match"
            )
            return toast, dash.no_update

        if len(new_password) < 6:
            toast = ToastManager.warning(
                "Validation Error",
                detail_message="Password must be at least 6 characters"
            )
            return toast, dash.no_update

        # Verify current password
        user = auth_manager.verify_user(current_user.username, current_password)
        if not user:
            toast = ToastManager.error(
                "Verification Failed",
                detail_message="Current password is incorrect"
            )
            return toast, dash.no_update

        # Change password
        success = auth_manager.change_password(current_user.id, new_password)

        if success:
            toast = ToastManager.success(
                "Password Updated",
                detail_message="Password changed successfully!"
            )
            return toast, False
        else:
            toast = ToastManager.error(
                "Update Failed",
                detail_message="Failed to change password"
            )
            return toast, dash.no_update

    # ========================================================================
    # SAVE USER PREFERENCES
    # ========================================================================

    @app.callback(
        [Output('refresh-interval', 'interval', allow_duplicate=True),
         Output('theme-store', 'data', allow_duplicate=True),
         Output('ws', 'message', allow_duplicate=True),
         Output('toast-container', 'children', allow_duplicate=True),
         Output('preferences-modal', 'is_open', allow_duplicate=True)],
        Input('save-preferences-btn', 'n_clicks'),
        [State('refresh-interval-dropdown', 'value'),
         State('retention-dropdown', 'value'),
         State('anomaly-threshold-slider', 'value'),
         State('display-density-dropdown', 'value'),
         State('timezone-dropdown', 'value'),
         State('alert-notification-prefs', 'value'),
         State('theme-dropdown', 'value'),
         State('language-dropdown', 'value'),
         State('layout-dropdown', 'value'),
         State('auto-export-dropdown', 'value'),
         State('backup-schedule-dropdown', 'value'),
         State('backup-retention-input', 'value')],
        prevent_initial_call=True
    )
    def save_preferences(n_clicks, refresh_interval, retention, threshold, display_density, timezone, alert_prefs,
                         theme, language, layout, auto_export, backup_schedule, backup_retention):
        """Save user preferences to database and apply them"""
        if n_clicks is None:
            raise dash.exceptions.PreventUpdate

        if not current_user.is_authenticated:
            toast = ToastManager.warning(
                "Authentication Required",
                detail_message="Please login to save preferences"
            )
            return dash.no_update, dash.no_update, dash.no_update, toast, dash.no_update

        # Save to user_preferences table
        user_id = current_user.id

        try:
            conn = db_manager.conn
            cursor = conn.cursor()

            # Insert or update preferences
            preferences = {
                'refresh_interval': str(refresh_interval),
                'data_retention': str(retention),
                'anomaly_threshold': str(threshold),
                'display_density': display_density,
                'timezone': timezone,
                'alert_notifications': ','.join(alert_prefs) if alert_prefs else '',
                'theme': theme,
                'language': language,
                'layout': layout,
                'auto_export': auto_export,
                'backup_schedule': backup_schedule,
                'backup_retention': str(backup_retention) if backup_retention else '30'
            }

            for key, value in preferences.items():
                cursor.execute("""
                    INSERT INTO user_preferences (user_id, preference_key, preference_value)
                    VALUES (?, ?, ?)
                    ON CONFLICT(user_id, preference_key) DO UPDATE SET preference_value = excluded.preference_value
                """, (user_id, key, value))

            conn.commit()

            toast = ToastManager.success(
                "Preferences Saved",
                detail_message="Preferences saved and applied successfully!"
            )

            # Apply preferences immediately
            return (
                refresh_interval,  # Update refresh interval
                {'theme': theme},  # Update theme
                dash.no_update,
                toast,
                False  # Close modal
            )

        except Exception as e:
            logger.error(f"Error saving preferences: {e}")
            toast = ToastManager.error(
                "Save Failed",
                detail_message=f"Error saving preferences: {str(e)}"
            )
            return dash.no_update, dash.no_update, dash.no_update, toast, dash.no_update

    # ========================================================================
    # SYSTEM MODAL CALLBACKS
    # ========================================================================

    # System modal toggle
    @app.callback(
        Output("system-modal", "is_open"),
        [Input("system-card-btn", "n_clicks"),
         Input("close-system-modal-btn", "n_clicks")],
        State("system-modal", "is_open"),
        prevent_initial_call=True
    )
    def toggle_system_modal(open_clicks, close_clicks, is_open):
        ctx = dash.callback_context
        if not ctx.triggered:
            raise dash.exceptions.PreventUpdate
        trigger_id = ctx.triggered[0]['prop_id'].split('.')[0]
        if trigger_id == 'close-system-modal-btn':
            return False
        if trigger_id == 'system-card-btn' and open_clicks:
            return not is_open
        return is_open

    # System Modal - Timestamp Update
    @app.callback(
        [Output('system-timestamp-display', 'children'),
         Output('system-timestamp-store', 'data'),
         Output('toast-container', 'children', allow_duplicate=True)],
        [Input('system-modal', 'is_open'),
         Input('refresh-system-btn', 'n_clicks')],
        prevent_initial_call=True
    )
    def update_system_timestamp(is_open, refresh_clicks):
        """Update timestamp display for System Modal"""
        from dash import callback_context
        ctx = callback_context

        # Check if refresh button was clicked
        show_toast = ctx.triggered and ctx.triggered[0]['prop_id'] == 'refresh-system-btn.n_clicks' if ctx.triggered else False

        if not is_open:
            raise dash.exceptions.PreventUpdate

        # Get current timestamp
        current_time = datetime.now()
        timestamp_str = current_time.isoformat()

        # Create display element
        display = create_timestamp_display(current_time)

        # Create toast only if refresh was clicked
        toast = ToastManager.success(
            "System data refreshed",
            detail_message="System resources and performance data updated successfully"
        ) if show_toast else dash.no_update

        return display, timestamp_str, toast

    # Model Accuracy Display Callback
    @app.callback(
        Output('model-accuracy-display', 'children'),
        [Input('system-modal', 'is_open')],
        prevent_initial_call=True
    )
    def update_model_accuracy_display(is_open):
        """Update model accuracy display with River model statistics."""
        if not is_open:
            raise dash.exceptions.PreventUpdate

        try:
            conn = get_db_connection()
            cursor = conn.cursor()

            # Get latest model performance metrics (using 'river' model_type)
            cursor.execute('''
                SELECT model_type, precision, recall, f1_score,
                       timestamp
                FROM model_performance
                WHERE model_type = 'river'
                ORDER BY timestamp DESC
                LIMIT 1
            ''')
            model_data = cursor.fetchone()

            if not model_data:
                # No performance data yet - query actual ML predictions to show activity
                cursor.execute('''
                    SELECT COUNT(*) as total_predictions,
                           SUM(CASE WHEN is_anomaly = 1 THEN 1 ELSE 0 END) as anomalies_detected
                    FROM ml_predictions
                    WHERE model_type = 'river'
                    AND timestamp > datetime('now', '-24 hours')
                ''')
                prediction_stats = cursor.fetchone()

                total = prediction_stats['total_predictions'] if prediction_stats else 0
                anomalies = prediction_stats['anomalies_detected'] if prediction_stats else 0

                return html.Div([
                    dbc.Alert([
                        html.I(className="fa fa-info-circle me-2"),
                        f"River models active - {total} predictions in last 24h ({anomalies} anomalies detected)"
                    ], color="info", className="mb-3"),
                    html.Div([
                        html.Small("Active River Models:", className="text-muted d-block mb-2"),
                        dbc.Badge("HalfSpaceTrees", color="success", className="me-2"),
                        dbc.Badge("HoeffdingAdaptive", color="success", className="me-2"),
                        dbc.Badge("SNARIMAX", color="success")
                    ])
                ])

            # If we have performance data, show it
            f1 = model_data['f1_score'] or 0
            precision = model_data['precision'] or 0
            recall = model_data['recall'] or 0

            f1_pct = int(f1 * 100)
            precision_pct = int(precision * 100)
            recall_pct = int(recall * 100)

            return html.Div([
                html.Div([
                    html.Span("River ML Engine", className="fw-bold small"),
                    html.Span(f" - Last updated: {model_data['timestamp']}", className="text-muted small ms-2")
                ]),
                dbc.Progress(
                    value=f1_pct,
                    color="success",
                    className="mb-3",
                    style={"height": "25px"},
                    label=f"F1: {f1_pct}%"
                ),
                dbc.Row([
                    dbc.Col([
                        html.Small("Precision", className="text-muted"),
                        dbc.Progress(value=precision_pct, color="info", label=f"{precision_pct}%", style={"height": "15px"})
                    ], md=6),
                    dbc.Col([
                        html.Small("Recall", className="text-muted"),
                        dbc.Progress(value=recall_pct, color="warning", label=f"{recall_pct}%", style={"height": "15px"})
                    ], md=6)
                ])
            ])

        except Exception as e:
            logger.error(f"Error updating model accuracy: {e}")
            return dbc.Alert("River models active and learning", color="info")

    # ========================================================================
    # USER MANAGEMENT MODAL TOGGLE
    # ========================================================================

    @app.callback(
        Output("user-modal", "is_open", allow_duplicate=True),
        [Input("user-card-btn", "n_clicks"),
         Input("close-user-modal-btn", "n_clicks")],
        State("user-modal", "is_open"),
        prevent_initial_call=True
    )
    def toggle_user_modal(open_clicks, close_clicks, is_open):
        ctx = dash.callback_context
        if not ctx.triggered:
            raise dash.exceptions.PreventUpdate
        trigger_id = ctx.triggered[0]['prop_id'].split('.')[0]
        if trigger_id == 'close-user-modal-btn':
            return False
        if trigger_id == 'user-card-btn' and open_clicks:
            return not is_open
        return is_open

    # ========================================================================
    # PREFERENCES MODAL TOGGLE & LOAD
    # ========================================================================

    @app.callback(
        Output("preferences-modal", "is_open"),
        [Input("preferences-card-btn", "n_clicks"),
         Input("cancel-preferences-btn", "n_clicks")],
        State("preferences-modal", "is_open"),
        prevent_initial_call=True
    )
    def toggle_preferences_modal(open_clicks, cancel_clicks, is_open):
        ctx = dash.callback_context
        if not ctx.triggered:
            raise dash.exceptions.PreventUpdate
        trigger_id = ctx.triggered[0]['prop_id'].split('.')[0]
        if trigger_id == 'cancel-preferences-btn':
            return False
        if trigger_id == 'preferences-card-btn' and open_clicks:
            return not is_open
        return is_open

    @app.callback(
        [Output('refresh-interval-dropdown', 'value'),
         Output('retention-dropdown', 'value'),
         Output('anomaly-threshold-slider', 'value'),
         Output('display-density-dropdown', 'value'),
         Output('timezone-dropdown', 'value'),
         Output('alert-notification-prefs', 'value'),
         Output('theme-dropdown', 'value'),
         Output('language-dropdown', 'value'),
         Output('layout-dropdown', 'value'),
         Output('auto-export-dropdown', 'value'),
         Output('backup-schedule-dropdown', 'value'),
         Output('backup-retention-input', 'value')],
        Input("preferences-modal", "is_open"),
        prevent_initial_call=True
    )
    def load_preferences(is_open):
        """Load user preferences from database when modal opens"""
        if not is_open or not current_user.is_authenticated:
            raise dash.exceptions.PreventUpdate

        user_id = current_user.id

        # Default values
        defaults = {
            'refresh_interval': 10000,
            'data_retention': 30,
            'anomaly_threshold': 0.85,
            'display_density': 'comfortable',
            'timezone': 'UTC',
            'alert_notifications': 'critical,high',
            'theme': 'light',
            'language': 'en',
            'layout': 'grid',
            'auto_export': 'disabled',
            'backup_schedule': 'daily',
            'backup_retention': 30
        }

        try:
            conn = db_manager.conn
            cursor = conn.cursor()

            # Load all preferences for user
            cursor.execute("""
                SELECT preference_key, preference_value
                FROM user_preferences
                WHERE user_id = ?
            """, (user_id,))

            results = cursor.fetchall()

            # Update defaults with saved preferences
            for key, value in results:
                if key in defaults:
                    # Convert string values back to appropriate types
                    if key == 'refresh_interval':
                        defaults[key] = int(value)
                    elif key == 'data_retention':
                        defaults[key] = int(value)
                    elif key == 'anomaly_threshold':
                        defaults[key] = float(value)
                    elif key == 'backup_retention':
                        defaults[key] = int(value)
                    else:
                        defaults[key] = value

            # Convert alert_notifications string back to list
            alert_prefs = defaults['alert_notifications'].split(',') if defaults['alert_notifications'] else []

            return (
                defaults['refresh_interval'],
                defaults['data_retention'],
                defaults['anomaly_threshold'],
                defaults['display_density'],
                defaults['timezone'],
                alert_prefs,
                defaults['theme'],
                defaults['language'],
                defaults['layout'],
                defaults['auto_export'],
                defaults['backup_schedule'],
                defaults['backup_retention']
            )

        except Exception as e:
            logger.error(f"Error loading preferences: {e}")
            raise dash.exceptions.PreventUpdate

    # ========================================================================
    # EXPORT / IMPORT ML MODELS
    # ========================================================================

    @app.callback(
        [Output('toast-container', 'children', allow_duplicate=True),
         Output('download-export', 'data', allow_duplicate=True)],
        Input('export-models-btn', 'n_clicks'),
        prevent_initial_call=True
    )
    def export_models_config(n_clicks):
        """Export ML models configuration as JSON."""
        if not n_clicks:
            raise dash.exceptions.PreventUpdate

        try:
            model_config = {
                "version": "2.0",
                "engine": "river",
                "export_date": datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                "models": {
                    "halfspacetrees": {"status": "active", "type": "anomaly_detection"},
                    "hoeffdingadaptive": {"status": "active", "type": "attack_classification"},
                    "snarimax": {"status": "active", "type": "traffic_forecasting"}
                },
                "settings": {
                    "anomaly_threshold": 0.7,
                    "detection_sensitivity": "medium",
                    "learning_mode": "incremental"
                }
            }

            export_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            filename = f"river_models_config_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"

            toast = ToastManager.success(
                "Models exported successfully!",
                header="Export Complete",
                detail_message=f"Export Details:\n• File: {filename}\n• Export Time: {export_time}\n• Models: River ML (HalfSpaceTrees, HoeffdingAdaptive, SNARIMAX)\n• Size: {len(json.dumps(model_config))} bytes\n\nThe River ML configuration has been saved to your downloads folder."
            )

            return toast, dict(
                content=json.dumps(model_config, indent=2),
                filename=filename
            )
        except Exception as e:
            logger.error(f"Error exporting models: {e}")
            toast = ToastManager.error(
                "Export failed!",
                header="Export Error",
                detail_message=f"Error Details:\n{str(e)}\n\nPossible Solutions:\n• Check file permissions\n• Verify disk space\n• Try exporting again\n• Check browser console for errors"
            )
            return toast, None

    # Import Models Callback (System & ML Models Modal)
    @app.callback(
        [Output('import-models-status', 'children'),
         Output('toast-container', 'children', allow_duplicate=True)],
        Input('import-models-upload', 'contents'),
        State('import-models-upload', 'filename'),
        prevent_initial_call=True
    )
    def import_models(contents_list, filenames_list):
        """Import ML models from uploaded files (.pkl, .h5, or .zip)."""
        if not contents_list:
            raise dash.exceptions.PreventUpdate

        try:
            import zipfile
            import io
            from pathlib import Path

            # Ensure we have lists
            if not isinstance(contents_list, list):
                contents_list = [contents_list]
                filenames_list = [filenames_list]

            imported_files = []
            errors = []

            for contents, filename in zip(contents_list, filenames_list):
                try:
                    # Parse the uploaded file
                    content_type, content_string = contents.split(',')
                    decoded = base64.b64decode(content_string)

                    if filename.endswith('.zip'):
                        # Handle zip file containing multiple models
                        with zipfile.ZipFile(io.BytesIO(decoded)) as zf:
                            for name in zf.namelist():
                                if name.endswith(('.pkl', '.h5')):
                                    file_data = zf.read(name)
                                    success = save_model_file(name, file_data)
                                    if success:
                                        imported_files.append(name)
                                    else:
                                        errors.append(f"Failed to save {name}")

                    elif filename.endswith(('.pkl', '.h5')):
                        # Handle individual model file
                        success = save_model_file(filename, decoded)
                        if success:
                            imported_files.append(filename)
                        else:
                            errors.append(f"Failed to save {filename}")
                    else:
                        errors.append(f"Unsupported file type: {filename}")

                except Exception as e:
                    errors.append(f"Error processing {filename}: {str(e)}")
                    logger.error(f"Error importing model file {filename}: {e}")

            # Build status message
            status_items = []
            if imported_files:
                status_items.append(html.Div([
                    html.I(className="fa fa-check-circle text-success me-2"),
                    f"Successfully imported: {', '.join(imported_files)}"
                ], className="mb-1"))

            if errors:
                for error in errors:
                    status_items.append(html.Div([
                        html.I(className="fa fa-exclamation-circle text-danger me-2"),
                        error
                    ], className="mb-1"))

            status = html.Div(status_items) if status_items else None

            # Show toast
            if imported_files and not errors:
                toast = ToastManager.success(
                "Models Imported",
                detail_message="Models Imported"
            )
            elif errors:
                toast = ToastManager.warning(
                "Import Warning",
                detail_message="Import Warning"
            )
            else:
                toast = dash.no_update

            return status, toast

        except Exception as e:
            logger.error(f"Error in import_models callback: {e}")
            error_status = html.Div([
                html.I(className="fa fa-exclamation-circle text-danger me-2"),
                f"Error: {str(e)}"
            ])
            toast = ToastManager.error(
                "Import Error",
                detail_message="Import Error"
            )
            return error_status, toast

    # ========================================================================
    # REFRESH SYSTEM INFO
    # ========================================================================

    @app.callback(
        Output('toast-container', 'children', allow_duplicate=True),
        Input('refresh-system-btn', 'n_clicks'),
        prevent_initial_call=True
    )
    def refresh_system_info(n_clicks):
        """Refresh system information."""
        if not n_clicks:
            raise dash.exceptions.PreventUpdate

        toast = ToastManager.success(
                "Refreshed",
                detail_message="Refreshed"
            )
        return toast

    # ========================================================================
    # DOWNLOAD DIAGNOSTICS LOG
    # ========================================================================

    @app.callback(
        [Output('toast-container', 'children', allow_duplicate=True),
         Output('download-export', 'data', allow_duplicate=True)],
        Input('download-logs-btn', 'n_clicks'),
        prevent_initial_call=True
    )
    def download_full_logs(n_clicks):
        """Download system logs as text file."""
        if not n_clicks:
            raise dash.exceptions.PreventUpdate

        try:
            import os
            from datetime import datetime

            # Collect system information
            log_lines = [
                "=" * 80,
                "IoTSentinel System Diagnostics Log",
                f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
                "=" * 80,
                "",
                "=== SYSTEM INFORMATION ===",
            ]

            # Get basic system stats
            try:
                import psutil
                log_lines.extend([
                    f"CPU Usage: {psutil.cpu_percent()}%",
                    f"Memory Usage: {psutil.virtual_memory().percent}%",
                    f"Disk Usage: {psutil.disk_usage('/').percent}%",
                    f"Python Version: {os.sys.version}",
                    ""
                ])
            except:
                log_lines.append("System stats unavailable")
                log_lines.append("")

            # Get database statistics
            log_lines.append("=== DATABASE STATISTICS ===")
            try:
                conn = db_manager.conn
                cursor = conn.cursor()

                cursor.execute("SELECT COUNT(*) FROM devices")
                device_count = cursor.fetchone()[0]
                log_lines.append(f"Total Devices: {device_count}")

                cursor.execute("SELECT COUNT(*) FROM connections")
                conn_count = cursor.fetchone()[0]
                log_lines.append(f"Total Connections: {conn_count}")

                cursor.execute("SELECT COUNT(*) FROM alerts")
                alert_count = cursor.fetchone()[0]
                log_lines.append(f"Total Alerts: {alert_count}")
            except Exception as e:
                log_lines.append(f"Database error: {str(e)}")

            log_lines.append("")
            log_lines.append("=== RECENT ALERTS (Last 50) ===")

            # Get recent alerts
            try:
                conn = db_manager.conn
                cursor = conn.cursor()

                cursor.execute('''
                    SELECT timestamp, device_ip, severity, explanation
                    FROM alerts
                    ORDER BY timestamp DESC
                    LIMIT 50
                ''')
                alerts = cursor.fetchall()

                if alerts:
                    for alert in alerts:
                        log_lines.append(
                            f"[{alert['timestamp']}] {alert['severity'].upper()}: {alert['device_ip']} - {alert['explanation'][:100]}"
                        )
                else:
                    log_lines.append("No alerts found")

            except Exception as e:
                log_lines.append(f"Error retrieving alerts: {str(e)}")

            log_lines.append("")
            log_lines.append("=" * 80)
            log_lines.append("End of Diagnostics Log")
            log_lines.append("=" * 80)

            toast = ToastManager.success(
                "Download Complete",
                detail_message="Download Complete"
            )

            return toast, dict(
                content="\n".join(log_lines),
                filename=f"iotsentinel_diagnostics_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"
            )

        except Exception as e:
            logger.error(f"Error downloading logs: {e}")
            toast = ToastManager.error(
                "Download Error",
                detail_message="Download Error"
            )
            return toast, None

    # ========================================================================
    # ADVANCED REPORTING & ANALYTICS CALLBACKS
    # ========================================================================

    # Callback to open/close custom reports modal
    @app.callback(
        Output('custom-reports-modal', 'is_open'),
        [Input('open-reports-modal', 'n_clicks'),
         Input('close-reports-modal', 'n_clicks')],
        [State('custom-reports-modal', 'is_open')],
        prevent_initial_call=True
    )
    def toggle_reports_modal(open_clicks, close_clicks, is_open):
        """Toggle the custom reports modal."""
        ctx = dash.callback_context
        if not ctx.triggered:
            raise dash.exceptions.PreventUpdate

        button_id = ctx.triggered[0]['prop_id'].split('.')[0]

        if button_id == 'open-reports-modal':
            return True
        elif button_id == 'close-reports-modal':
            return False

        return is_open

    # Callback to handle template selection buttons
    @app.callback(
        Output('report-template-select', 'value'),
        [Input('select-exec-template', 'n_clicks'),
         Input('select-security-template', 'n_clicks'),
         Input('select-network-template', 'n_clicks'),
         Input('select-device-template', 'n_clicks'),
         Input('select-threat-template', 'n_clicks')],
        prevent_initial_call=True
    )
    def select_template_from_card(exec_clicks, security_clicks, network_clicks, device_clicks, threat_clicks):
        """Update template selection when a template card is clicked."""
        ctx = dash.callback_context
        if not ctx.triggered:
            raise dash.exceptions.PreventUpdate

        button_id = ctx.triggered[0]['prop_id'].split('.')[0]

        template_map = {
            'select-exec-template': 'executive_summary',
            'select-security-template': 'security_audit',
            'select-network-template': 'network_activity',
            'select-device-template': 'device_inventory',
            'select-threat-template': 'threat_analysis'
        }

        return template_map.get(button_id, 'executive_summary')

    # Callback to update template preview
    @app.callback(
        Output('template-preview', 'children'),
        Input('report-template-select', 'value')
    )
    def update_template_preview(template_name):
        """Update the template preview when selection changes."""
        if not template_manager:
            return html.Div("Advanced reporting not available", className="text-muted")

        try:
            template = template_manager.get_template(template_name)
            if not template:
                return html.Div("Template not found", className="text-danger")

            # Build preview content
            preview_content = [
                html.H6([
                    html.I(className="fa fa-info-circle me-2"),
                    template.name
                ], className="mb-2"),
                html.P(template.description, className="text-muted mb-3"),
                html.Hr(),
                html.Strong("Sections included:", className="d-block mb-2"),
                html.Ul([
                    html.Li(section.title)
                    for section in sorted(template.sections, key=lambda s: s.order)
                ], className="mb-0")
            ]

            return preview_content

        except Exception as e:
            logger.error(f"Error updating template preview: {e}")
            return html.Div("Error loading preview", className="text-danger")

    # Callback to populate recent reports list
    @app.callback(
        Output('recent-reports-list', 'children'),
        [Input('report-builder-tabs', 'active_tab'),
         Input('report-job-poll', 'n_intervals')],
        prevent_initial_call=True
    )
    def update_recent_reports_list(active_tab, n_intervals):
        """Update recent reports list when tab is active."""
        if active_tab != 'recent-tab':
            raise dash.exceptions.PreventUpdate

        if not report_queue:
            return dbc.Alert([
                html.I(className="fa fa-exclamation-circle me-2"),
                "Report queue not available"
            ], color="warning", className="text-center")

        try:
            # Get completed jobs
            from utils.report_queue import JobStatus
            completed_jobs = report_queue.list_jobs(status=JobStatus.COMPLETED, limit=20)

            if not completed_jobs:
                return dbc.Alert([
                    html.I(className="fa fa-info-circle me-2"),
                    "No recent reports. Generate your first report!"
                ], color="info", className="text-center")

            # Build report cards
            report_cards = []
            template_icons = {
                'executive_summary': 'fa-chart-pie',
                'security_audit': 'fa-shield-alt',
                'network_activity': 'fa-network-wired',
                'device_inventory': 'fa-tablet-alt',
                'threat_analysis': 'fa-bug'
            }
            template_names = {
                'executive_summary': 'Executive Summary',
                'security_audit': 'Security Audit',
                'network_activity': 'Network Activity',
                'device_inventory': 'Device Inventory',
                'threat_analysis': 'Threat Analysis'
            }
            format_colors = {
                'pdf': 'danger',
                'excel': 'success',
                'json': 'info'
            }

            for job in completed_jobs:
                template_name = job.get('template_name', 'unknown')
                format_type = job.get('format', 'pdf')
                result_path = job.get('result_path', '')
                completed_at = job.get('completed_at', '')

                # Parse timestamp
                from datetime import datetime
                try:
                    dt = datetime.fromisoformat(completed_at)
                    time_str = dt.strftime('%b %d, %Y %I:%M %p')
                except:
                    time_str = completed_at

                card = dbc.Card([
                    dbc.CardBody([
                        dbc.Row([
                            dbc.Col([
                                html.I(className=f"fa {template_icons.get(template_name, 'fa-file')} fa-2x text-primary")
                            ], width="auto"),
                            dbc.Col([
                                html.H6(template_names.get(template_name, template_name.replace('_', ' ').title()), className="mb-1"),
                                html.Small([
                                    html.I(className="fa fa-clock me-1"),
                                    time_str
                                ], className="text-muted d-block mb-2"),
                                dbc.Badge(format_type.upper(), color=format_colors.get(format_type, 'secondary'), className="me-2"),
                                dbc.Badge([
                                    html.I(className="fa fa-check me-1"),
                                    "Ready"
                                ], color="success")
                            ]),
                            dbc.Col([
                                dbc.Button([
                                    html.I(className="fa fa-download me-2"),
                                    "Download"
                                ],
                                id={'type': 'download-report-btn', 'index': job.get('job_id', '')},
                                color="primary",
                                size="sm",
                                outline=True,
                                n_clicks=0
                                ) if result_path else html.Div()
                            ], width="auto", className="d-flex align-items-center")
                        ])
                    ])
                ], className="mb-3 shadow-sm hover-shadow")

                report_cards.append(card)

            return report_cards

        except Exception as e:
            logger.error(f"Error loading recent reports: {e}")
            return dbc.Alert([
                html.I(className="fa fa-exclamation-circle me-2"),
                f"Error loading reports: {str(e)}"
            ], color="danger", className="text-center")

    # Callback to handle report download with toast notification
    @app.callback(
        [Output('download-custom-report', 'data', allow_duplicate=True),
         Output('toast-container', 'children', allow_duplicate=True)],
        Input({'type': 'download-report-btn', 'index': ALL}, 'n_clicks'),
        prevent_initial_call=True
    )
    def download_report_with_toast(n_clicks_list):
        """Handle report download button clicks with toast notification."""
        ctx = dash.callback_context
        if not ctx.triggered or not any(n_clicks_list):
            raise dash.exceptions.PreventUpdate

        try:
            # Get the job ID that was clicked
            import json
            triggered_id = ctx.triggered[0]['prop_id']
            job_id = json.loads(triggered_id.split('.')[0])['index']

            if not report_queue:
                toast = ToastManager.error(
                    "Download failed",
                    detail_message="Report queue not available"
                )
                return dash.no_update, toast

            # Get job details
            job_status = report_queue.get_job_status(job_id)
            if not job_status:
                toast = ToastManager.error(
                    "Report not found",
                    detail_message=f"Could not find report with ID {job_id}"
                )
                return dash.no_update, toast

            result_path = job_status.get('result_path')
            if not result_path:
                toast = ToastManager.error(
                    "Download failed",
                    detail_message="Report file path not available"
                )
                return dash.no_update, toast

            # Check if file exists
            from pathlib import Path
            report_file = Path(result_path)
            if not report_file.exists():
                toast = ToastManager.error(
                    "File not found",
                    detail_message="Report file has been deleted or moved"
                )
                return dash.no_update, toast

            # Show success toast
            template_name = job_status.get('template_name', 'Report')
            format_type = job_status.get('format', 'pdf').upper()
            toast = ToastManager.success(
                "Download started",
                detail_message=f"Downloading {template_name} ({format_type})"
            )

            # Trigger download
            return dcc.send_file(result_path), toast

        except Exception as e:
            logger.error(f"Error downloading report: {e}")
            toast = ToastManager.error(
                "Download error",
                detail_message=str(e)
            )
            return dash.no_update, toast

    # Callback to generate and download custom report
    @app.callback(
        [Output('current-report-job-id', 'data'),
         Output('report-job-poll', 'disabled'),
         Output('report-progress-container', 'style'),
         Output('generate-report-btn', 'children'),
         Output('generate-report-btn', 'disabled'),
         Output('toast-container', 'children', allow_duplicate=True)],
        Input('generate-report-btn', 'n_clicks'),
        [State('report-template-select', 'value'),
         State('report-format-select', 'value'),
         State('report-days-input', 'value')],
        prevent_initial_call=True
    )
    def submit_report_generation(n_clicks, template_name, format_type, days):
        """Submit report generation job to queue."""
        if not n_clicks:
            raise dash.exceptions.PreventUpdate

        # Check if queue is available
        if not report_queue:
            toast = ToastManager.error(
                "Report generation unavailable",
                detail_message="Report queue not initialized"
            )
            return (
                None,
                True,  # Keep polling disabled
                {"display": "none"},  # Hide progress
                [html.I(className="fa fa-exclamation-triangle me-2"), "Not Available"],
                True,  # Disable button
                toast
            )

        try:
            # Submit job to queue
            job_id = report_queue.submit_job(
                template_name=template_name,
                format=format_type,
                parameters={'days': int(days) if days else 7},
                priority=5
            )

            # Update button to show processing state
            processing_button = [
                dbc.Spinner(size="sm", spinner_class_name="me-2"),
                "Generating..."
            ]

            # Show success toast
            toast = ToastManager.info(
                "Report queued",
                detail_message="Report generation started in background"
            )

            logger.info(f"Report job submitted: {job_id}")

            return (
                job_id,  # Store job ID
                False,  # Enable polling
                {"display": "block"},  # Show progress bar
                processing_button,  # Update button
                True,  # Disable button while processing
                toast
            )

        except Exception as e:
            logger.error(f"Error submitting report job: {e}")
            toast = ToastManager.error(
                "Queue error",
                detail_message=str(e)
            )
            error_button = [
                html.I(className="fa fa-exclamation-triangle me-2"),
                "Error - Try Again"
            ]
            return None, True, {"display": "none"}, error_button, False, toast

    # Poll job status and update progress
    @app.callback(
        [Output('report-progress-bar', 'value'),
         Output('report-progress-text', 'children'),
         Output('report-status', 'children'),
         Output('download-custom-report', 'data'),
         Output('report-job-poll', 'disabled', allow_duplicate=True),
         Output('report-progress-container', 'style', allow_duplicate=True),
         Output('generate-report-btn', 'children', allow_duplicate=True),
         Output('generate-report-btn', 'disabled', allow_duplicate=True),
         Output('current-report-job-id', 'data', allow_duplicate=True),
         Output('toast-container', 'children', allow_duplicate=True)],
        Input('report-job-poll', 'n_intervals'),
        State('current-report-job-id', 'data'),
        prevent_initial_call=True
    )
    def poll_job_status(n_intervals, job_id):
        """Poll report generation job status and update progress."""
        if not job_id or not report_queue:
            raise dash.exceptions.PreventUpdate

        try:
            # Get job status
            job_status = report_queue.get_job_status(job_id)

            if not job_status:
                # Job not found
                return (
                    0,  # Progress 0
                    "Job not found",  # Progress text
                    dbc.Alert("Job not found", color="warning"),  # Status
                    None,  # No download
                    True,  # Disable polling
                    {"display": "none"},  # Hide progress
                    [html.I(className="fa fa-download me-2"), "Generate Report"],  # Reset button
                    False,  # Enable button
                    None,  # Clear job ID
                    ToastManager.error("Job not found", detail_message="Report job was not found")
                )

            status = job_status['status']
            progress = job_status.get('progress', 0)

            # Update progress bar and text
            progress_text = f"{progress}% - {status}"

            if status == 'pending':
                status_alert = dbc.Alert([
                    html.I(className="fa fa-clock me-2"),
                    "Report queued, waiting to start..."
                ], color="info")

            elif status == 'processing':
                status_alert = dbc.Alert([
                    dbc.Spinner(size="sm", spinner_class_name="me-2"),
                    f"Generating report... {progress}%"
                ], color="primary")

            elif status == 'completed':
                # Job completed - prepare download
                result_path = job_status.get('result_path')

                if result_path and Path(result_path).exists():
                    # Read the generated report
                    try:
                        with open(result_path, 'rb') as f:
                            content = f.read()

                        filename = Path(result_path).name
                        download_data = {
                            'content': base64.b64encode(content).decode(),
                            'filename': filename,
                            'type': 'application/octet-stream',
                            'base64': True
                        }

                        return (
                            100,  # Progress 100%
                            "Complete!",  # Progress text
                            dbc.Alert([
                                html.I(className="fa fa-check-circle me-2"),
                                f"Report generated successfully!"
                            ], color="success"),  # Status
                            download_data,  # Trigger download
                            True,  # Disable polling
                            {"display": "none"},  # Hide progress
                            [html.I(className="fa fa-download me-2"), "Generate Report"],  # Reset button
                            False,  # Enable button
                            None,  # Clear job ID
                            ToastManager.success("Report ready", detail_message=f"Downloaded as {filename}")
                        )
                    except Exception as e:
                        logger.error(f"Error reading report file: {e}")

                # Completed but no file
                return (
                    100,
                    "Completed (no file)",
                    dbc.Alert("Report completed but file not found", color="warning"),
                    None,
                    True,  # Disable polling
                    {"display": "none"},
                    [html.I(className="fa fa-download me-2"), "Generate Report"],
                    False,
                    None,
                    ToastManager.warning("Report completed", detail_message="But file not found")
                )

            elif status == 'failed':
                error_msg = job_status.get('error_message', 'Unknown error')
                return (
                    0,  # Progress 0
                    "Failed",  # Progress text
                    dbc.Alert([
                        html.I(className="fa fa-exclamation-circle me-2"),
                        f"Error: {error_msg}"
                    ], color="danger"),  # Status
                    None,  # No download
                    True,  # Disable polling
                    {"display": "none"},  # Hide progress
                    [html.I(className="fa fa-exclamation-triangle me-2"), "Generation Failed"],  # Error button
                    False,  # Enable button
                    None,  # Clear job ID
                    ToastManager.error("Generation failed", detail_message=error_msg)
                )

            else:
                # Unknown status - keep polling
                return (
                    progress,
                    progress_text,
                    status_alert,
                    None,  # No download yet
                    False,  # Keep polling
                    {"display": "block"},  # Show progress
                    [dbc.Spinner(size="sm", spinner_class_name="me-2"), "Generating..."],  # Processing button
                    True,  # Keep button disabled
                    job_id,  # Keep job ID
                    dash.no_update
                )

        except Exception as e:
            logger.error(f"Error polling job status: {e}")
            return (
                0,
                "Error",
                dbc.Alert(f"Error: {str(e)}", color="danger"),
                None,
                True,  # Stop polling
                {"display": "none"},
                [html.I(className="fa fa-download me-2"), "Generate Report"],
                False,
                None,
                ToastManager.error("Polling error", detail_message=str(e))
            )

    # ========================================================================
    # REPORT SCHEDULER CALLBACKS
    # ========================================================================

    # Toggle Schedule Type Input Visibility
    @app.callback(
        [Output('cron-expression-div', 'style'),
         Output('interval-hours-div', 'style')],
        Input('schedule-type-radio', 'value'),
        prevent_initial_call=True
    )
    def toggle_schedule_type_inputs(schedule_type):
        """Show/hide cron or interval inputs based on selected type."""
        if schedule_type == 'cron':
            return {'display': 'block'}, {'display': 'none'}
        else:  # interval
            return {'display': 'none'}, {'display': 'block'}

    # List Active Schedules
    @app.callback(
        [Output('schedules-list-container', 'children'),
         Output('toast-container', 'children', allow_duplicate=True)],
        [Input('refresh-schedules-btn', 'n_clicks'),
         Input('email-modal-tabs', 'active_tab')],
        prevent_initial_call=True
    )
    def list_schedules(refresh_clicks, active_tab):
        """List all active report schedules."""
        if active_tab != 'schedules-list-tab':
            raise dash.exceptions.PreventUpdate

        # Determine if refresh button was clicked
        ctx = dash.callback_context
        was_refresh = ctx.triggered_id == 'refresh-schedules-btn' if ctx.triggered else False

        try:
            # Check if ReportScheduler is available
            if not report_scheduler:
                return (
                    dbc.Alert([
                        html.I(className="fa fa-info-circle me-2"),
                        "Report scheduler not available. Ensure scheduler is initialized in the backend."
                    ], color="info"),
                    dash.no_update
                )

            schedules = report_scheduler.list_schedules()

            # Create toast if refresh was clicked
            toast = dash.no_update
            if was_refresh:
                toast = ToastManager.success(
                    "Schedules refreshed",
                    detail_message=f"Found {len(schedules)} active schedule(s)"
                )

            if not schedules:
                return (
                    dbc.Alert([
                        html.I(className="fa fa-info-circle me-2"),
                        "No active schedules found. Create a new schedule to get started."
                    ], color="info", className="m-3"),
                    toast
                )

            # Build visual schedule cards
            schedule_cards = []

            # Template icon mapping
            template_icons = {
                'executive_summary': 'fa-chart-pie',
                'security_audit': 'fa-shield-alt',
                'network_activity': 'fa-network-wired',
                'device_inventory': 'fa-mobile-alt',
                'threat_analysis': 'fa-exclamation-triangle'
            }

            # Format badge colors
            format_colors = {
                'pdf': 'danger',
                'excel': 'success',
                'json': 'info'
            }

            for schedule in schedules:
                # Extract schedule details
                schedule_id = schedule.get('id', 'unknown')
                schedule_name = schedule.get('name', 'Unnamed Schedule')
                next_run = schedule.get('next_run', 'N/A')
                trigger_info = schedule.get('trigger', 'N/A')

                # Parse trigger to get readable format
                if isinstance(trigger_info, str):
                    if 'cron' in trigger_info.lower():
                        trigger_type = 'Cron Schedule'
                        trigger_icon = 'fa-calendar-alt'
                    elif 'interval' in trigger_info.lower():
                        trigger_type = 'Interval Schedule'
                        trigger_icon = 'fa-clock'
                    else:
                        trigger_type = 'Custom Schedule'
                        trigger_icon = 'fa-calendar-check'
                else:
                    trigger_type = 'Schedule'
                    trigger_icon = 'fa-calendar'

                # Get template name and format from schedule
                template = schedule.get('template', 'unknown')
                report_format = schedule.get('format', 'pdf')
                template_icon = template_icons.get(template, 'fa-file-alt')
                format_color = format_colors.get(report_format, 'secondary')

                # Get template display name
                template_names = {
                    'executive_summary': 'Executive Summary',
                    'security_audit': 'Security Audit',
                    'network_activity': 'Network Activity',
                    'device_inventory': 'Device Inventory',
                    'threat_analysis': 'Threat Analysis'
                }
                template_display = template_names.get(template, template.replace('_', ' ').title())

                # Determine if schedule is paused (placeholder - scheduler needs to track this)
                is_paused = schedule.get('paused', False)
                status_badge = dbc.Badge(
                    [html.I(className=f"fa fa-{'pause' if is_paused else 'check-circle'} me-1"),
                     "Paused" if is_paused else "Active"],
                    color="warning" if is_paused else "success",
                    className="me-2"
                )

                # Create schedule card
                card = dbc.Col([
                    dbc.Card([
                        dbc.CardHeader([
                            dbc.Row([
                                dbc.Col([
                                    html.I(className=f"fa {template_icon} me-2 text-primary"),
                                    html.Span(schedule_id, className="fw-bold")
                                ], width=8),
                                dbc.Col([
                                    status_badge,
                                    dbc.Badge(report_format.upper(), color=format_color, className="ms-1")
                                ], width=4, className="text-end")
                            ])
                        ], className="bg-light"),
                        dbc.CardBody([
                            html.H6(template_display, className="card-title mb-2"),
                            html.P([
                                html.I(className=f"fa {trigger_icon} me-2 text-muted"),
                                html.Small(trigger_info, className="text-muted")
                            ], className="mb-2"),
                            html.P([
                                html.I(className="fa fa-clock me-2 text-info"),
                                html.Small([html.Strong("Next Run: "), next_run], className="text-muted")
                            ], className="mb-3"),
                            dbc.ButtonGroup([
                                dbc.Button([
                                    html.I(className=f"fa fa-{'play' if is_paused else 'pause'} me-1"),
                                    "Resume" if is_paused else "Pause"
                                ],
                                    id={'type': 'pause-schedule', 'index': schedule_id},
                                    color="warning",
                                    size="sm",
                                    outline=True,
                                    className="w-50"
                                ),
                                dbc.Button([
                                    html.I(className="fa fa-trash me-1"),
                                    "Delete"
                                ],
                                    id={'type': 'delete-schedule', 'index': schedule_id},
                                    color="danger",
                                    size="sm",
                                    outline=True,
                                    className="w-50"
                                )
                            ], className="w-100")
                        ])
                    ], className="shadow-sm mb-3 h-100 hover-shadow", style={"transition": "all 0.3s"})
                ], md=6, lg=4, className="mb-3")

                schedule_cards.append(card)

            return dbc.Row(schedule_cards, className="g-3"), toast

        except Exception as e:
            logger.error(f"Error listing schedules: {e}")
            return dbc.Alert([
                html.I(className="fa fa-exclamation-circle me-2"),
                f"Error loading schedules: {str(e)}"
            ], color="danger", className="m-3"), dash.no_update

    # Add New Schedule
    @app.callback(
        [Output('add-schedule-status', 'children'),
         Output('toast-container', 'children', allow_duplicate=True)],
        Input('add-schedule-btn', 'n_clicks'),
        [State('schedule-id-input', 'value'),
         State('schedule-template-select', 'value'),
         State('schedule-format-select', 'value'),
         State('schedule-type-radio', 'value'),
         State('schedule-cron-input', 'value'),
         State('schedule-interval-input', 'value'),
         State('schedule-days-input', 'value'),
         State('schedule-email-input', 'value')],
        prevent_initial_call=True
    )
    def add_new_schedule(n_clicks, schedule_id, template, format_type, schedule_type,
                        cron_expr, interval_hours, days, recipient):
        """Add a new report schedule."""
        if not n_clicks:
            raise dash.exceptions.PreventUpdate

        try:
            # Validate inputs
            if not schedule_id or not schedule_id.strip():
                status = dbc.Alert([
                    html.I(className="fa fa-exclamation-triangle me-2"),
                    "Please enter a schedule ID/name"
                ], color="warning")
                return status, dash.no_update

            # Check if scheduler is available
            if not report_scheduler:
                status = dbc.Alert([
                    html.I(className="fa fa-exclamation-circle me-2"),
                    "Report scheduler not available"
                ], color="danger")
                return status, dash.no_update

            scheduler = report_scheduler

            # Prepare parameters
            parameters = {
                'days': int(days) if days else 7
            }
            if recipient and recipient.strip():
                parameters['recipient'] = recipient.strip()

            # Add schedule based on type
            if schedule_type == 'cron':
                if not cron_expr or not cron_expr.strip():
                    status = dbc.Alert([
                        html.I(className="fa fa-exclamation-triangle me-2"),
                        "Please enter a cron expression"
                    ], color="warning")
                    return status, dash.no_update

                success = scheduler.add_custom_schedule(
                    schedule_id=schedule_id.strip(),
                    template_name=template,
                    cron_expression=cron_expr.strip(),
                    format=format_type,
                    parameters=parameters
                )
            else:  # interval
                if not interval_hours:
                    status = dbc.Alert([
                        html.I(className="fa fa-exclamation-triangle me-2"),
                        "Please enter interval hours"
                    ], color="warning")
                    return status, dash.no_update

                success = scheduler.add_custom_schedule(
                    schedule_id=schedule_id.strip(),
                    template_name=template,
                    interval_hours=int(interval_hours),
                    format=format_type,
                    parameters=parameters
                )

            if success:
                status = dbc.Alert([
                    html.I(className="fa fa-check-circle me-2"),
                    f"Schedule '{schedule_id}' added successfully!"
                ], color="success")

                toast = ToastManager.success(
                    "Schedule created",
                    detail_message=f"{schedule_id} will run automatically"
                )

                return status, toast
            else:
                status = dbc.Alert([
                    html.I(className="fa fa-times-circle me-2"),
                    "Failed to add schedule. Check logs for details."
                ], color="danger")
                return status, dash.no_update

        except Exception as e:
            logger.error(f"Error adding schedule: {e}")
            status = dbc.Alert([
                html.I(className="fa fa-exclamation-circle me-2"),
                f"Error: {str(e)}"
            ], color="danger")
            return status, dash.no_update

    # Pause/Resume Schedule
    @app.callback(
        [Output('schedules-list-container', 'children', allow_duplicate=True),
         Output('toast-container', 'children', allow_duplicate=True)],
        Input({'type': 'pause-schedule', 'index': ALL}, 'n_clicks'),
        State('schedules-list-container', 'children'),
        prevent_initial_call=True
    )
    def pause_resume_schedule(n_clicks_list, current_content):
        """Pause or resume a report schedule."""
        ctx = dash.callback_context
        if not ctx.triggered or not any(n_clicks_list):
            raise dash.exceptions.PreventUpdate

        try:
            # Get the schedule ID that was clicked
            triggered_id = ctx.triggered[0]['prop_id']
            import json
            # Parse the pattern-matching ID
            schedule_id = json.loads(triggered_id.split('.')[0])['index']

            # Check if scheduler is available
            if not report_scheduler:
                toast = ToastManager.error(
                    "Scheduler Error",
                    detail_message="Report scheduler not available"
                )
                return current_content, toast

            # Check if schedule exists and get current state
            schedules = report_scheduler.list_schedules()
            target_schedule = None
            for schedule in schedules:
                if schedule.get('id') == schedule_id:
                    target_schedule = schedule
                    break

            if not target_schedule:
                toast = ToastManager.error(
                    "Schedule Not Found",
                    detail_message=f"Schedule '{schedule_id}' not found"
                )
                return current_content, toast

            # Get current pause state
            is_paused = target_schedule.get('paused', False)

            # Toggle pause/resume
            if is_paused:
                # Resume the schedule
                success = report_scheduler.resume_schedule(schedule_id)
                action = "resumed"
            else:
                # Pause the schedule
                success = report_scheduler.pause_schedule(schedule_id)
                action = "paused"

            if success:
                toast = ToastManager.success(
                    f"Schedule {action}",
                    detail_message=f"Schedule '{schedule_id}' has been {action}"
                )

                # Refresh the schedule list
                schedules = report_scheduler.list_schedules()
                if not schedules:
                    refreshed_content = dbc.Alert([
                        html.I(className="fa fa-info-circle me-2"),
                        "No active schedules found."
                    ], color="info", className="m-3")
                else:
                    # Rebuild the cards with updated state
                    schedule_cards = []
                    template_icons = {
                        'executive_summary': 'fa-chart-pie',
                        'security_audit': 'fa-shield-alt',
                        'network_activity': 'fa-network-wired',
                        'device_inventory': 'fa-mobile-alt',
                        'threat_analysis': 'fa-exclamation-triangle'
                    }
                    format_colors = {
                        'pdf': 'danger',
                        'excel': 'success',
                        'json': 'info'
                    }
                    template_names = {
                        'executive_summary': 'Executive Summary',
                        'security_audit': 'Security Audit',
                        'network_activity': 'Network Activity',
                        'device_inventory': 'Device Inventory',
                        'threat_analysis': 'Threat Analysis'
                    }

                    for schedule in schedules:
                        s_id = schedule.get('id', 'unknown')
                        next_run = schedule.get('next_run', 'N/A')
                        trigger_info = schedule.get('trigger', 'N/A')

                        if isinstance(trigger_info, str):
                            if 'cron' in trigger_info.lower():
                                trigger_icon = 'fa-calendar-alt'
                            elif 'interval' in trigger_info.lower():
                                trigger_icon = 'fa-clock'
                            else:
                                trigger_icon = 'fa-calendar-check'
                        else:
                            trigger_icon = 'fa-calendar'

                        template = schedule.get('template', 'unknown')
                        report_format = schedule.get('format', 'pdf')
                        template_icon = template_icons.get(template, 'fa-file-alt')
                        format_color = format_colors.get(report_format, 'secondary')
                        template_display = template_names.get(template, template.replace('_', ' ').title())

                        is_paused = schedule.get('paused', False)
                        status_badge = dbc.Badge(
                            [html.I(className=f"fa fa-{'pause' if is_paused else 'check-circle'} me-1"),
                             "Paused" if is_paused else "Active"],
                            color="warning" if is_paused else "success",
                            className="me-2"
                        )

                        card = dbc.Col([
                            dbc.Card([
                                dbc.CardHeader([
                                    dbc.Row([
                                        dbc.Col([
                                            html.I(className=f"fa {template_icon} me-2 text-primary"),
                                            html.Span(s_id, className="fw-bold")
                                        ], width=8),
                                        dbc.Col([
                                            status_badge,
                                            dbc.Badge(report_format.upper(), color=format_color, className="ms-1")
                                        ], width=4, className="text-end")
                                    ])
                                ], className="bg-light"),
                                dbc.CardBody([
                                    html.H6(template_display, className="card-title mb-2"),
                                    html.P([
                                        html.I(className=f"fa {trigger_icon} me-2 text-muted"),
                                        html.Small(trigger_info, className="text-muted")
                                    ], className="mb-2"),
                                    html.P([
                                        html.I(className="fa fa-clock me-2 text-info"),
                                        html.Small([html.Strong("Next Run: "), next_run], className="text-muted")
                                    ], className="mb-3"),
                                    dbc.ButtonGroup([
                                        dbc.Button([
                                            html.I(className=f"fa fa-{'play' if is_paused else 'pause'} me-1"),
                                            "Resume" if is_paused else "Pause"
                                        ],
                                            id={'type': 'pause-schedule', 'index': s_id},
                                            color="warning",
                                            size="sm",
                                            outline=True,
                                            className="w-50"
                                        ),
                                        dbc.Button([
                                            html.I(className="fa fa-trash me-1"),
                                            "Delete"
                                        ],
                                            id={'type': 'delete-schedule', 'index': s_id},
                                            color="danger",
                                            size="sm",
                                            outline=True,
                                            className="w-50"
                                        )
                                    ], className="w-100")
                                ])
                            ], className="shadow-sm mb-3 h-100 hover-shadow", style={"transition": "all 0.3s"})
                        ], md=6, lg=4, className="mb-3")

                        schedule_cards.append(card)

                    refreshed_content = dbc.Row(schedule_cards, className="g-3")

                return refreshed_content, toast
            else:
                toast = ToastManager.error(
                    f"Failed to {action.rstrip('d')} schedule",
                    detail_message=f"Could not {action.rstrip('d')} schedule '{schedule_id}'"
                )
                return current_content, toast

        except Exception as e:
            logger.error(f"Error pausing/resuming schedule: {e}")
            toast = ToastManager.error(
                "Error",
                detail_message=f"Error managing schedule: {str(e)}"
            )
            return current_content, toast

    # Delete Schedule
    @app.callback(
        [Output('schedules-list-container', 'children', allow_duplicate=True),
         Output('toast-container', 'children', allow_duplicate=True)],
        Input({'type': 'delete-schedule', 'index': ALL}, 'n_clicks'),
        State('schedules-list-container', 'children'),
        prevent_initial_call=True
    )
    def delete_schedule(n_clicks_list, current_content):
        """Delete a report schedule."""
        ctx = dash.callback_context
        if not ctx.triggered or not any(n_clicks_list):
            raise dash.exceptions.PreventUpdate

        try:
            # Get the schedule ID that was clicked
            triggered_id = ctx.triggered[0]['prop_id']
            import json
            # Parse the pattern-matching ID
            schedule_id = json.loads(triggered_id.split('.')[0])['index']

            # Check if scheduler is available
            if not report_scheduler:
                toast = ToastManager.error(
                    "Scheduler Error",
                    detail_message="Report scheduler not available"
                )
                return current_content, toast

            # Delete the schedule
            success = report_scheduler.remove_custom_schedule(schedule_id)

            if success:
                toast = ToastManager.success(
                    "Schedule Deleted",
                    detail_message=f"Schedule '{schedule_id}' has been removed",
                    icon="trash"
                )

                # Refresh the schedule list
                schedules = report_scheduler.list_schedules()
                if not schedules:
                    refreshed_content = dbc.Alert([
                        html.I(className="fa fa-info-circle me-2"),
                        "No active schedules found. Create a new schedule to get started."
                    ], color="info", className="m-3")
                else:
                    # Rebuild the cards
                    schedule_cards = []
                    template_icons = {
                        'executive_summary': 'fa-chart-pie',
                        'security_audit': 'fa-shield-alt',
                        'network_activity': 'fa-network-wired',
                        'device_inventory': 'fa-mobile-alt',
                        'threat_analysis': 'fa-exclamation-triangle'
                    }
                    format_colors = {
                        'pdf': 'danger',
                        'excel': 'success',
                        'json': 'info'
                    }
                    template_names = {
                        'executive_summary': 'Executive Summary',
                        'security_audit': 'Security Audit',
                        'network_activity': 'Network Activity',
                        'device_inventory': 'Device Inventory',
                        'threat_analysis': 'Threat Analysis'
                    }

                    for schedule in schedules:
                        s_id = schedule.get('id', 'unknown')
                        next_run = schedule.get('next_run', 'N/A')
                        trigger_info = schedule.get('trigger', 'N/A')

                        if isinstance(trigger_info, str):
                            if 'cron' in trigger_info.lower():
                                trigger_icon = 'fa-calendar-alt'
                            elif 'interval' in trigger_info.lower():
                                trigger_icon = 'fa-clock'
                            else:
                                trigger_icon = 'fa-calendar-check'
                        else:
                            trigger_icon = 'fa-calendar'

                        template = schedule.get('template', 'unknown')
                        report_format = schedule.get('format', 'pdf')
                        template_icon = template_icons.get(template, 'fa-file-alt')
                        format_color = format_colors.get(report_format, 'secondary')
                        template_display = template_names.get(template, template.replace('_', ' ').title())

                        is_paused = schedule.get('paused', False)
                        status_badge = dbc.Badge(
                            [html.I(className=f"fa fa-{'pause' if is_paused else 'check-circle'} me-1"),
                             "Paused" if is_paused else "Active"],
                            color="warning" if is_paused else "success",
                            className="me-2"
                        )

                        card = dbc.Col([
                            dbc.Card([
                                dbc.CardHeader([
                                    dbc.Row([
                                        dbc.Col([
                                            html.I(className=f"fa {template_icon} me-2 text-primary"),
                                            html.Span(s_id, className="fw-bold")
                                        ], width=8),
                                        dbc.Col([
                                            status_badge,
                                            dbc.Badge(report_format.upper(), color=format_color, className="ms-1")
                                        ], width=4, className="text-end")
                                    ])
                                ], className="bg-light"),
                                dbc.CardBody([
                                    html.H6(template_display, className="card-title mb-2"),
                                    html.P([
                                        html.I(className=f"fa {trigger_icon} me-2 text-muted"),
                                        html.Small(trigger_info, className="text-muted")
                                    ], className="mb-2"),
                                    html.P([
                                        html.I(className="fa fa-clock me-2 text-info"),
                                        html.Small([html.Strong("Next Run: "), next_run], className="text-muted")
                                    ], className="mb-3"),
                                    dbc.ButtonGroup([
                                        dbc.Button([
                                            html.I(className=f"fa fa-{'play' if is_paused else 'pause'} me-1"),
                                            "Resume" if is_paused else "Pause"
                                        ],
                                            id={'type': 'pause-schedule', 'index': s_id},
                                            color="warning",
                                            size="sm",
                                            outline=True,
                                            className="w-50"
                                        ),
                                        dbc.Button([
                                            html.I(className="fa fa-trash me-1"),
                                            "Delete"
                                        ],
                                            id={'type': 'delete-schedule', 'index': s_id},
                                            color="danger",
                                            size="sm",
                                            outline=True,
                                            className="w-50"
                                        )
                                    ], className="w-100")
                                ])
                            ], className="shadow-sm mb-3 h-100 hover-shadow", style={"transition": "all 0.3s"})
                        ], md=6, lg=4, className="mb-3")

                        schedule_cards.append(card)

                    refreshed_content = dbc.Row(schedule_cards, className="g-3")

                return refreshed_content, toast
            else:
                toast = ToastManager.error(
                    "Delete Failed",
                    detail_message=f"Could not delete schedule '{schedule_id}'"
                )
                return current_content, toast

        except Exception as e:
            logger.error(f"Error deleting schedule: {e}")
            toast = ToastManager.error(
                "Error",
                detail_message=f"Error deleting schedule: {str(e)}"
            )
            return current_content, toast

    # Enable Daily Digest
    @app.callback(
        [Output('digest-status', 'children'),
         Output('toast-container', 'children', allow_duplicate=True)],
        Input('enable-digest-btn', 'n_clicks'),
        [State('digest-hour-input', 'value'),
         State('digest-minute-input', 'value'),
         State('digest-email-input', 'value')],
        prevent_initial_call=True
    )
    def enable_daily_digest(n_clicks, hour, minute, recipient):
        """Enable daily security digest email."""
        if not n_clicks:
            raise dash.exceptions.PreventUpdate

        try:
            if not report_scheduler:
                status = dbc.Alert([
                    html.I(className="fa fa-exclamation-circle me-2"),
                    "Report scheduler not available"
                ], color="danger")
                return status, dash.no_update

            scheduler = report_scheduler

            # Validate inputs
            hour_val = int(hour) if hour is not None else 8
            minute_val = int(minute) if minute is not None else 0

            if hour_val < 0 or hour_val > 23:
                status = dbc.Alert([
                    html.I(className="fa fa-exclamation-triangle me-2"),
                    "Hour must be between 0 and 23"
                ], color="warning")
                return status, dash.no_update

            if minute_val < 0 or minute_val > 59:
                status = dbc.Alert([
                    html.I(className="fa fa-exclamation-triangle me-2"),
                    "Minute must be between 0 and 59"
                ], color="warning")
                return status, dash.no_update

            # Add daily digest schedule
            recipient_email = recipient.strip() if recipient and recipient.strip() else None
            success = scheduler.add_daily_digest_schedule(
                hour=hour_val,
                minute=minute_val,
                recipient=recipient_email
            )

            if success:
                status = dbc.Alert([
                    html.I(className="fa fa-check-circle me-2"),
                    f"Daily digest enabled! Will send at {hour_val:02d}:{minute_val:02d} every day."
                ], color="success")

                toast = ToastManager.success(
                    "Daily digest enabled",
                    detail_message=f"Scheduled for {hour_val:02d}:{minute_val:02d} daily"
                )

                return status, toast
            else:
                status = dbc.Alert([
                    html.I(className="fa fa-times-circle me-2"),
                    "Failed to enable daily digest. Check logs for details."
                ], color="danger")
                return status, dash.no_update

        except Exception as e:
            logger.error(f"Error enabling daily digest: {e}")
            status = dbc.Alert([
                html.I(className="fa fa-exclamation-circle me-2"),
                f"Error: {str(e)}"
            ], color="danger")
            return status, dash.no_update

    # Send Test Digest
    @app.callback(
        [Output('digest-status', 'children', allow_duplicate=True),
         Output('toast-container', 'children', allow_duplicate=True)],
        Input('test-digest-btn', 'n_clicks'),
        State('digest-email-input', 'value'),
        prevent_initial_call=True
    )
    def send_test_digest(n_clicks, recipient):
        """Send a test daily digest email immediately."""
        if not n_clicks:
            raise dash.exceptions.PreventUpdate

        try:
            if not report_scheduler:
                status = dbc.Alert([
                    html.I(className="fa fa-exclamation-circle me-2"),
                    "Report scheduler not available"
                ], color="danger")
                return status, dash.no_update

            scheduler = report_scheduler
            recipient_email = recipient.strip() if recipient and recipient.strip() else None

            success = scheduler.send_digest_now(recipient=recipient_email)

            if success:
                status = dbc.Alert([
                    html.I(className="fa fa-check-circle me-2"),
                    "Test digest sent successfully! Check your email."
                ], color="success")

                toast = ToastManager.success(
                    "Test digest sent",
                    detail_message="Check your email inbox"
                )

                return status, toast
            else:
                status = dbc.Alert([
                    html.I(className="fa fa-times-circle me-2"),
                    "Failed to send test digest. Check logs for details."
                ], color="danger")
                return status, dash.no_update

        except Exception as e:
            logger.error(f"Error sending test digest: {e}")
            status = dbc.Alert([
                html.I(className="fa fa-exclamation-circle me-2"),
                f"Error: {str(e)}"
            ], color="danger")
            return status, dash.no_update

    # ========================================================================
    # PRIVACY DASHBOARD CALLBACKS
    # ========================================================================

    @app.callback(
        [Output('privacy-summary-cards', 'children'),
         Output('privacy-devices-table', 'children'),
         Output('privacy-last-updated', 'children'),
         Output('toast-container', 'children', allow_duplicate=True)],
        [Input('privacy-interval', 'n_intervals'),
         Input('privacy-refresh-btn', 'n_clicks')],
        prevent_initial_call=True
    )
    def update_privacy_dashboard(n_intervals, refresh_clicks):
        """Update the privacy dashboard with device data collection analysis."""
        ctx = callback_context
        triggered_by_refresh = (
            ctx.triggered and
            'privacy-refresh-btn' in ctx.triggered[0]['prop_id'] and
            refresh_clicks is not None and
            refresh_clicks > 0
        )

        if privacy_analyzer is None:
            toast = ToastManager.warning(
                "Privacy analyzer not available",
                detail_message="The privacy analyzer module is not initialized. Please check system logs."
            ) if triggered_by_refresh else dash.no_update
            return dbc.Alert("Privacy analyzer not available", color="warning"), html.Div(), "Not available", toast

        try:
            # Get privacy summary for all devices
            summaries = privacy_analyzer.get_all_devices_privacy_summary(days=7)

            if not summaries:
                toast = ToastManager.info(
                    "No devices found",
                    detail_message="No devices are currently available for privacy analysis."
                ) if triggered_by_refresh else dash.no_update
                return (
                    dbc.Alert("No devices found for privacy analysis", color="info"),
                    html.Div(),
                    f"Last updated: {datetime.now().strftime('%I:%M:%S %p')}",
                    toast
                )

            # Calculate aggregate statistics
            total_devices = len(summaries)
            high_risk = len([s for s in summaries if s['privacy_risk_level'] in ['critical', 'high']])
            critical_data = sum([s['critical_data_types'] for s in summaries])

            # Summary cards
            summary_cards = dbc.Row([
                dbc.Col([
                    dbc.Card([
                        dbc.CardBody([
                            html.I(className="fa fa-devices fa-2x mb-2 text-primary"),
                            html.H3(str(total_devices), className="mb-1 fw-bold"),
                            html.P("Devices Monitored", className="text-muted mb-0 small")
                        ], className="text-center p-3")
                    ], className="glass-card border-0 shadow-sm")
                ], width=3),
                dbc.Col([
                    dbc.Card([
                        dbc.CardBody([
                            html.I(className="fa fa-exclamation-triangle fa-2x mb-2 text-danger"),
                            html.H3(str(high_risk), className="mb-1 fw-bold text-danger"),
                            html.P("High Privacy Risk", className="text-muted mb-0 small")
                        ], className="text-center p-3")
                    ], className="glass-card border-0 shadow-sm")
                ], width=3),
                dbc.Col([
                    dbc.Card([
                        dbc.CardBody([
                            html.I(className="fa fa-database fa-2x mb-2 text-warning"),
                            html.H3(str(critical_data), className="mb-1 fw-bold text-warning"),
                            html.P("Critical Data Types", className="text-muted mb-0 small")
                        ], className="text-center p-3")
                    ], className="glass-card border-0 shadow-sm")
                ], width=3),
                dbc.Col([
                    dbc.Card([
                        dbc.CardBody([
                            html.I(className="fa fa-cloud fa-2x mb-2 text-info"),
                            html.H3(str(sum([s['unique_cloud_services'] for s in summaries])), className="mb-1 fw-bold text-info"),
                            html.P("Cloud Services", className="text-muted mb-0 small")
                        ], className="text-center p-3")
                    ], className="glass-card border-0 shadow-sm")
                ], width=3)
            ])

            # Device table
            table_rows = []
            for summary in summaries[:20]:  # Limit to top 20
                risk_level = summary['privacy_risk_level']
                risk_color = {
                    'critical': 'danger',
                    'high': 'warning',
                    'medium': 'info',
                    'low': 'success',
                    'minimal': 'secondary'
                }.get(risk_level, 'secondary')

                table_rows.append(
                    html.Tr([
                        html.Td(summary['device_name']),
                        html.Td((summary.get('device_type') or 'unknown').replace('_', ' ').title()),
                        html.Td(dbc.Badge(f"{summary['privacy_risk_score']}/100", color=risk_color)),
                        html.Td(str(summary['data_types_count'])),
                        html.Td(str(summary['critical_data_types']), className="text-danger fw-bold" if summary['critical_data_types'] > 0 else ""),
                        html.Td(str(summary['unique_cloud_services'])),
                        html.Td(
                            dbc.Button("View Details", size="sm", color="primary", outline=True,
                                     id={'type': 'privacy-detail-btn', 'index': summary['device_ip']})
                        )
                    ])
                )

            devices_table = dbc.Table([
                html.Thead([
                    html.Tr([
                        html.Th("Device"),
                        html.Th("Type"),
                        html.Th("Privacy Risk"),
                        html.Th("Data Types"),
                        html.Th("Critical Data"),
                        html.Th("Cloud Services"),
                        html.Th("Actions")
                    ])
                ]),
                html.Tbody(table_rows)
            ], bordered=True, striped=True, hover=True, responsive=True, dark=False, className="mb-0 table-adaptive")

            last_updated = f"Last updated: {datetime.now().strftime('%I:%M:%S %p')}"

            # Create success toast if triggered by refresh button
            toast = ToastManager.success(
                "Privacy dashboard updated",
                detail_message=f"Analyzed {total_devices} device{'s' if total_devices != 1 else ''} - {high_risk} with high privacy risk detected."
            ) if triggered_by_refresh else dash.no_update

            return summary_cards, devices_table, last_updated, toast

        except Exception as e:
            logger.error(f"Error updating privacy dashboard: {e}")
            toast = ToastManager.error(
                "Privacy dashboard update failed",
                detail_message=f"Error: {str(e)}"
            ) if triggered_by_refresh else dash.no_update
            return (
                dbc.Alert(f"Error: {str(e)}", color="danger"),
                html.Div(),
                f"Error: {str(e)}",
                toast
            )

    @app.callback(
        [Output('privacy-detail-modal', 'is_open'),
         Output('privacy-detail-modal-title', 'children'),
         Output('privacy-detail-modal-body', 'children')],
        [Input({'type': 'privacy-detail-btn', 'index': ALL}, 'n_clicks'),
         Input('privacy-detail-modal-close', 'n_clicks')],
        [State('privacy-detail-modal', 'is_open')],
        prevent_initial_call=True
    )
    def toggle_privacy_detail_modal(detail_clicks, close_click, is_open):
        """Show detailed privacy analysis for a specific device."""
        ctx = callback_context

        if not ctx.triggered:
            return dash.no_update, dash.no_update, dash.no_update

        triggered_id = ctx.triggered[0]['prop_id']
        triggered_value = ctx.triggered[0]['value']

        # Don't process if triggered value is None or 0
        if triggered_value is None or triggered_value == 0:
            return dash.no_update, dash.no_update, dash.no_update

        # Close modal
        if 'privacy-detail-modal-close' in triggered_id:
            return False, dash.no_update, dash.no_update

        # Open modal with device details - check if a privacy detail button was clicked
        if 'privacy-detail-btn' in triggered_id:
            # Check if privacy analyzer is available
            if privacy_analyzer is None:
                return True, "Error", dbc.Alert("Privacy analyzer not available", color="warning")

            # Get device IP from triggered button
            import json
            try:
                # Remove the .n_clicks suffix from the end
                button_id_str = triggered_id.rsplit('.', 1)[0]
                button_id = json.loads(button_id_str)
                device_ip = button_id['index']
            except (json.JSONDecodeError, KeyError, IndexError):
                return dash.no_update, dash.no_update, dash.no_update

            # Get detailed analysis
            analysis = privacy_analyzer.analyze_device_data_collection(device_ip, days=7)

            if 'error' in analysis:
                return True, "Error", dbc.Alert(f"Error: {analysis['error']}", color="danger")

            device_name = analysis.get('device_name', 'Unknown Device')
            risk = analysis.get('privacy_risk', {})
            cloud_services = analysis.get('cloud_services', {})
            data_types = analysis.get('data_types_collected', [])
            stats = analysis.get('transmission_stats', {})

            # Build modal content
            content = [
                # Risk overview
                dbc.Alert([
                    html.H5(f"Privacy Risk: {risk.get('level', 'Unknown').upper()}", className="mb-2"),
                    html.H3(f"{risk.get('score', 0)}/100", className="mb-3"),
                    html.Div([html.Li(factor) for factor in risk.get('factors', [])], className="mb-0")
                ], color=risk.get('color', 'secondary')),

                # Data types collected
                html.H6("Data Types Collected", className="mt-4 mb-3"),
                dbc.Row([
                    dbc.Col([
                        dbc.Badge([
                            html.I(className=f"fa fa-{'exclamation-triangle' if dt['sensitivity'] in ['critical', 'high'] else 'info-circle'} me-1"),
                            dt['name'],
                            dbc.Badge(dt['sensitivity'].upper(), className="ms-2", color="danger" if dt['sensitivity'] == 'critical' else "warning" if dt['sensitivity'] == 'high' else "info")
                        ], color="light", text_color="dark", className="mb-2 me-2 p-2")
                    ], width="auto")
                    for dt in data_types
                ], className="mb-4"),

                # Cloud services
                html.H6("Cloud Service Connections", className="mt-4 mb-3"),
                dbc.Table([
                    html.Thead([
                        html.Tr([
                            html.Th("Service"),
                            html.Th("Category"),
                            html.Th("Connections"),
                            html.Th("Potential Data")
                        ])
                    ]),
                    html.Tbody([
                        html.Tr([
                            html.Td(svc.get('provider', 'Unknown')),
                            html.Td(svc.get('category', 'Unknown')),
                            html.Td(str(svc.get('connections', 0))),
                            html.Td(", ".join(svc.get('potential_data_types', [])))
                        ])
                        for svc in cloud_services.get('top_services', [])[:10]
                    ])
                ], bordered=True, striped=True, hover=True, responsive=True, dark=False, className="mb-4 table-adaptive"),

                # Transmission statistics
                html.H6("Data Transmission Statistics", className="mt-4 mb-3"),
                dbc.Row([
                    dbc.Col([
                        dbc.Card([
                            dbc.CardBody([
                                html.H5(f"{stats.get('total_mb', 0)} MB", className="mb-0"),
                                html.Small("Data Transmitted", className="text-muted")
                            ])
                        ], className="text-center")
                    ], width=3),
                    dbc.Col([
                        dbc.Card([
                            dbc.CardBody([
                                html.H5(f"{stats.get('events_per_day', 0)}/day", className="mb-0"),
                                html.Small("Transmission Events", className="text-muted")
                            ])
                        ], className="text-center")
                    ], width=3),
                    dbc.Col([
                        dbc.Card([
                            dbc.CardBody([
                                html.H5(str(cloud_services.get('unique_services', 0)), className="mb-0"),
                                html.Small("Unique Services", className="text-muted")
                            ])
                        ], className="text-center")
                    ], width=3),
                    dbc.Col([
                        dbc.Card([
                            dbc.CardBody([
                                html.H5(str(len(data_types)), className="mb-0"),
                                html.Small("Data Types", className="text-muted")
                            ])
                        ], className="text-center")
                    ], width=3)
                ]),

                # Recommendations
                html.H6("Privacy Recommendations", className="mt-4 mb-3"),
                dbc.Alert([
                    html.Ul([html.Li(rec) for rec in risk.get('recommendations', [])])
                ], color="info")
            ]

            return True, f"Privacy Analysis: {device_name}", content

        return dash.no_update, dash.no_update, dash.no_update

    # ========================================================================
    # ROLE-BASED DASHBOARD TEMPLATE CALLBACKS
    # ========================================================================

    # Load user's saved template from database on page load (server-side for auth)
    @app.callback(
        Output('dashboard-template-store', 'data'),
        Input('url', 'pathname'),
        prevent_initial_call=False
    )
    def load_user_template_on_page_load(pathname):
        """Load user's saved dashboard template from database preferences."""
        if not current_user.is_authenticated:
            return 'custom'  # Default for non-authenticated users

        try:
            conn = db_manager.conn
            cursor = conn.cursor()

            # Get user's saved template preference
            cursor.execute('''
                SELECT preference_value
                FROM user_preferences
                WHERE user_id = ? AND preference_key = 'dashboard_template'
            ''', (current_user.id,))

            result = cursor.fetchone()
            if result and result[0]:
                return result[0]

            # No saved preference - return custom as default
            logger.info(f"No saved template for {current_user.username}, using custom")
            return 'custom'

        except Exception as e:
            logger.error(f"Error loading user template: {e}")
            return 'custom'

    # Save template selection to store (only when user changes it) + Audit Trail
    @app.callback(
        [Output('dashboard-template-store', 'data', allow_duplicate=True),
         Output('toast-container', 'children', allow_duplicate=True)],
        Input('dashboard-template-select', 'value'),
        State('dashboard-template-store', 'data'),
        prevent_initial_call=True
    )
    def save_dashboard_template(template, current_template):
        """Save user's selected dashboard template preference and log to audit trail."""
        if not template:
            return no_update, no_update

        # Only show toast if template actually changed (not on initial sync)
        if template == current_template:
            return no_update, no_update

        # Check if this is triggered by modal opening (not a user action)
        ctx = callback_context
        if not ctx.triggered:
            return no_update, no_update

        trigger_id = ctx.triggered[0]['prop_id'].split('.')[0]

        # If triggered by anything other than user changing the value, skip
        if trigger_id != 'dashboard-template-select':
            return no_update, no_update

        # Log template change to audit trail (only if user is authenticated)
        if current_user.is_authenticated:
            try:
                conn = db_manager.conn
                cursor = conn.cursor()

                # Get client IP and user agent (no credentials stored)
                ip_address = request.remote_addr if request else None
                user_agent = request.headers.get('User-Agent', 'Unknown')[:200] if request else None

                # Save template to user preferences (persistent storage)
                cursor.execute('''
                    INSERT INTO user_preferences (user_id, preference_key, preference_value)
                    VALUES (?, 'dashboard_template', ?)
                    ON CONFLICT(user_id, preference_key)
                    DO UPDATE SET preference_value = excluded.preference_value, updated_at = CURRENT_TIMESTAMP
                ''', (current_user.id, template))

                # Log template change to audit trail
                cursor.execute('''
                    INSERT INTO template_change_audit
                    (user_id, username, old_template, new_template, ip_address, user_agent)
                    VALUES (?, ?, ?, ?, ?, ?)
                ''', (
                    current_user.id,
                    current_user.username,
                    current_template,
                    template,
                    ip_address,
                    user_agent
                ))
                conn.commit()

                logger.info(f"Template saved and logged: {current_user.username} changed from {current_template} to {template}")
            except Exception as e:
                logger.error(f"Failed to save/log template change: {e}")

        template_name = DASHBOARD_TEMPLATES.get(template, {}).get('name', template)
        template_desc = DASHBOARD_TEMPLATES.get(template, {}).get('description', '')

        toast = ToastManager.create_toast(
            message=f"Dashboard template changed to {template_name}",
            toast_type="info",
            header="Layout Updated",
            detail_message=f"{template_desc}. Your dashboard will now show features optimized for this template. You can change this anytime in Preferences.",
            show_detail_button=True,
            duration=4000
        )

        logger.info(f"Dashboard template changed to: {template}")
        return template, toast

    # Apply template by hiding/showing feature cards (clientside)
    app.clientside_callback(
        """
        function(template) {
            // Define template configurations
            const templates = {
                'security_admin': {
                    visible: [
                        'analytics-card-btn', 'threat-card-btn', 'firewall-card-btn',
                        'threat-map-card-btn', 'forensic-timeline-card-btn', 'attack-surface-card-btn',
                        'auto-response-card-btn', 'vuln-scanner-card-btn', 'device-mgmt-card-btn',
                        'timeline-card-btn', 'system-card-btn'
                    ]
                },
                'home_user': {
                    visible: [
                        'device-mgmt-card-btn', 'privacy-card-btn', 'system-card-btn',
                        'smarthome-card-btn', 'threat-map-card-btn', 'analytics-card-btn',
                        'preferences-card-btn', 'quick-settings-btn'
                    ]
                },
                'developer': {
                    visible: 'all'
                },
                'custom': {
                    visible: 'custom'
                }
            };

            if (!template || template === 'custom') {
                // Don't modify layout for custom template
                return window.dash_clientside.no_update;
            }

            const config = templates[template];
            if (!config) return window.dash_clientside.no_update;

            // Get all masonry items (feature cards)
            const items = document.querySelectorAll('.masonry-item');

            items.forEach(item => {
                const button = item.querySelector('[id$=\"-btn\"]');
                if (!button) return;

                const buttonId = button.id;

                // Show or hide based on template
                if (config.visible === 'all') {
                    // Developer: show everything
                    item.style.display = '';
                    item.style.opacity = '1';
                    item.classList.remove('template-hidden');
                } else if (Array.isArray(config.visible)) {
                    // Security Admin or Home User: show only specified features
                    if (config.visible.includes(buttonId)) {
                        item.classList.remove('template-hidden');
                        item.style.display = '';
                        requestAnimationFrame(() => {
                            item.style.opacity = '1';
                        });
                    } else {
                        item.style.opacity = '0';
                        item.classList.add('template-hidden');
                        const hideTemplate = () => {
                            if (item.classList.contains('template-hidden')) {
                                item.style.display = 'none';
                            }
                            item.removeEventListener('transitionend', hideTemplate);
                        };
                        item.addEventListener('transitionend', hideTemplate);
                        setTimeout(() => hideTemplate(), 350);
                    }
                }
            });

            return window.dash_clientside.no_update;
        }
        """,
        Output('admin-features-section', 'className', allow_duplicate=True),
        Input('dashboard-template-store', 'data'),
        prevent_initial_call=True
    )

    # Initialize template selection from store on modal open (avoids circular dependency)
    @app.callback(
        Output('dashboard-template-select', 'value', allow_duplicate=True),
        Input('profile-edit-modal', 'is_open'),
        State('dashboard-template-store', 'data'),
        prevent_initial_call=True
    )
    def sync_template_selection(is_open, stored_template):
        """Sync stored template preference to radio button when preferences modal opens."""
        if not is_open:
            return no_update
        return stored_template or 'custom'

    # Update template options dynamically based on user role
    @app.callback(
        Output('dashboard-template-select', 'options'),
        Input('profile-edit-modal', 'is_open'),
        prevent_initial_call=False
    )
    def update_template_options(is_open):
        """Show Security Admin template option only for admin users."""
        base_options = [
            {
                'label': html.Div([
                    html.I(className="fa fa-home text-success me-2"),
                    html.Span("Home User", className="fw-bold"),
                    html.Br(),
                    html.Small("Focus: Device Status, Privacy Score, Basic Security Health", className="text-muted")
                ]),
                'value': 'home_user'
            },
            {
                'label': html.Div([
                    html.I(className="fa fa-code text-info me-2"),
                    html.Span("Developer/Auditor", className="fw-bold"),
                    html.Br(),
                    html.Small("Focus: All Features, API Hub, Analytics, Performance", className="text-muted")
                ]),
                'value': 'developer'
            },
            {
                'label': html.Div([
                    html.I(className="fa fa-sliders text-warning me-2"),
                    html.Span("Custom", className="fw-bold"),
                    html.Br(),
                    html.Small("Use your own customized widget layout", className="text-muted")
                ]),
                'value': 'custom'
            }
        ]

        # Add Security Admin option only for admin users
        if current_user.is_authenticated and current_user.is_admin():
            admin_option = {
                'label': html.Div([
                    html.I(className="fa fa-shield-halved text-danger me-2"),
                    html.Span("Security Admin", className="fw-bold"),
                    html.Br(),
                    html.Small("Focus: Threat Intelligence, Alerts, Firewall, Forensics", className="text-muted")
                ]),
                'value': 'security_admin'
            }
            return [admin_option] + base_options

        return base_options
