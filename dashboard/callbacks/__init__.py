"""
IoTSentinel Dashboard - Callback Registration
==============================================
This package contains all dashboard callbacks split by functional area.
Each module has a register(app) function that registers callbacks on the Dash app.
"""


def register_all_callbacks(app, login_layout, dashboard_layout):
    """Register all callbacks from all modules on the given Dash app instance."""
    from . import callbacks_auth
    from . import callbacks_overview
    from . import callbacks_alerts
    from . import callbacks_devices
    from . import callbacks_analytics
    from . import callbacks_integrations
    from . import callbacks_compliance
    from . import callbacks_admin
    from . import callbacks_global

    callbacks_auth.register(app, login_layout, dashboard_layout)
    callbacks_overview.register(app)
    callbacks_alerts.register(app)
    callbacks_devices.register(app)
    callbacks_analytics.register(app)
    callbacks_integrations.register(app)
    callbacks_compliance.register(app)
    callbacks_admin.register(app)
    callbacks_global.register(app)
