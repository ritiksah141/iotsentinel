"""
IoTSentinel Dashboard - Layouts Package
=======================================
Contains tab layout definitions and the login page.
"""
from .login import login_layout
from .setup_wizard import setup_wizard_layout

__all__ = ["login_layout", "setup_wizard_layout"]
