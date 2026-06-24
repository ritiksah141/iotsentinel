#!/usr/bin/env python3
"""Regression tests for the new-user email-verification flow.

Two real bugs this pins:
1. create_user() creates a user with email_verified=0, and AuthManager.authenticate()
   rejects an unverified non-admin login — so registration MUST mark the email verified
   after the OTP (handle_registration does this now). Otherwise the very next login fails
   with "email not verified" even though registration succeeded with the correct code.
2. On a LAN appliance without SMTP, the verification code must still be obtainable — the
   send-code path surfaces it on-screen rather than only by email.

Run: pytest tests/test_email_verification_flow.py -v
"""
import sys
import bcrypt
import pytest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from database.db_manager import DatabaseManager
from utils.auth import AuthManager


def _users_schema(conn):
    conn.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            email TEXT,
            email_verified INTEGER DEFAULT 0,
            role TEXT CHECK(role IN ('admin', 'viewer')) DEFAULT 'viewer',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_login TIMESTAMP,
            is_active INTEGER DEFAULT 1,
            must_change_password INTEGER DEFAULT 0
        )
    """)
    conn.commit()


@pytest.fixture
def auth():
    db = DatabaseManager(':memory:')
    _users_schema(db.conn)
    yield AuthManager(db_manager=db)
    db.close()
    DatabaseManager._instances.pop(str(Path(':memory:').resolve()), None)


def test_create_user_starts_unverified(auth):
    assert auth.create_user('alice', 'Str0ng!pass', 'viewer', 'alice@example.com') is True
    row = auth.db_manager.conn.execute(
        "SELECT email_verified FROM users WHERE username='alice'").fetchone()
    assert row[0] == 0, "new self-registered users start unverified"


def test_unverified_login_is_rejected_then_verified_login_succeeds(auth):
    auth.create_user('bob', 'Str0ng!pass', 'viewer', 'bob@example.com')
    # Unverified non-admin must be blocked (this is the gate that produced the
    # "email not verified" toast right after a successful registration).
    assert auth.verify_user('bob', 'Str0ng!pass') is None, \
        "unverified user must not be able to log in"

    # handle_registration sets this after the OTP is confirmed.
    auth.db_manager.conn.execute(
        "UPDATE users SET email_verified=1 WHERE username='bob'")
    auth.db_manager.conn.commit()

    user = auth.verify_user('bob', 'Str0ng!pass')
    assert user is not None and user.username == 'bob', \
        "after the verified OTP, login must succeed"


def test_registration_handler_sets_email_verified():
    """Source guard: handle_registration must persist email_verified after the OTP, or a
    verified registration is immediately locked out on the next login."""
    src = (Path(__file__).parent.parent /
           "dashboard/callbacks/callbacks_auth.py").read_text()
    assert "UPDATE users SET email_verified = 1" in src
    assert "State('email-verified', 'data')" in src


def test_code_shown_onscreen_without_smtp():
    """Source guard: without SMTP the code must be surfaced in the verification hint, not
    only emailed (so registration works on a LAN-only appliance)."""
    src = (Path(__file__).parent.parent /
           "dashboard/callbacks/callbacks_auth.py").read_text()
    assert "verification-code-hint" in src
    login = (Path(__file__).parent.parent / "dashboard/layouts/login.py").read_text()
    assert 'id="verification-code-hint"' in login
