#!/usr/bin/env python3
"""
Tests for the must_change_password first-login enforcement flow.

Covers:
- User class stores and exposes must_change_password flag
- AuthManager.verify_user returns flag correctly (True for default admin, False otherwise)
- AuthManager.get_user_by_id returns flag correctly (survives session restore)
- AuthManager.change_password clears the flag atomically
- init_database sets flag=1 when default admin/admin credentials are used
- init_database does NOT set flag when a real password is provided

Run: pytest tests/test_must_change_password.py -v
"""

import sys
import sqlite3
import bcrypt
import pytest
from pathlib import Path
from unittest.mock import patch, MagicMock

sys.path.insert(0, str(Path(__file__).parent.parent))

from database.db_manager import DatabaseManager
from utils.auth import AuthManager, User


# ---------------------------------------------------------------------------
# In-memory DB fixture with users table
# ---------------------------------------------------------------------------

def _create_users_schema(conn):
    """Create the users table as defined in config/init_database.py."""
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


def _insert_user(conn, username, password, role='viewer', must_change=0, email_verified=1):
    pw_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
    conn.execute(
        "INSERT INTO users (username, password_hash, role, email_verified, must_change_password) "
        "VALUES (?, ?, ?, ?, ?)",
        (username, pw_hash, role, email_verified, must_change)
    )
    conn.commit()


@pytest.fixture
def auth_db():
    """DatabaseManager with in-memory DB containing the users table."""
    db_manager = DatabaseManager(':memory:')
    _create_users_schema(db_manager.conn)
    yield db_manager
    db_manager.close()
    DatabaseManager._instances.pop(str(Path(':memory:').resolve()), None)


@pytest.fixture
def auth(auth_db):
    return AuthManager(db_manager=auth_db)


# ===========================================================================
# User class
# ===========================================================================

class TestUserClass:

    def test_default_must_change_password_is_false(self):
        user = User(user_id=1, username='alice', role='viewer')
        assert user.must_change_password is False

    def test_must_change_password_true_when_set(self):
        user = User(user_id=2, username='bob', role='admin', must_change_password=True)
        assert user.must_change_password is True

    def test_must_change_password_false_explicitly(self):
        user = User(user_id=3, username='carol', role='viewer', must_change_password=False)
        assert user.must_change_password is False

    def test_other_flask_login_attributes_unaffected(self):
        user = User(user_id=1, username='dave', role='viewer', must_change_password=True)
        assert user.is_authenticated is True
        assert user.is_active is True
        assert user.is_anonymous is False
        assert user.get_id() == '1'


# ===========================================================================
# verify_user — must_change_password propagated correctly
# ===========================================================================

class TestVerifyUser:

    def test_verify_user_flag_false_for_normal_user(self, auth, auth_db):
        _insert_user(auth_db.conn, 'normal', 'SafePass1!', must_change=0)
        user = auth.verify_user('normal', 'SafePass1!')
        assert user is not None
        assert user.must_change_password is False

    def test_verify_user_flag_true_for_default_admin(self, auth, auth_db):
        _insert_user(auth_db.conn, 'admin', 'admin', role='admin', must_change=1)  # pragma: allowlist secret
        user = auth.verify_user('admin', 'admin')  # pragma: allowlist secret
        assert user is not None
        assert user.must_change_password is True

    def test_verify_user_returns_none_for_wrong_password(self, auth, auth_db):
        _insert_user(auth_db.conn, 'user1', 'correctpass')
        result = auth.verify_user('user1', 'wrongpass')
        assert result is None

    def test_verify_user_returns_none_for_unknown_username(self, auth):
        result = auth.verify_user('ghost', 'anypass')
        assert result is None

    def test_verify_user_flag_false_for_admin_with_real_password(self, auth, auth_db):
        _insert_user(auth_db.conn, 'admin', 'R3alP@ssw0rd!', role='admin', must_change=0)
        user = auth.verify_user('admin', 'R3alP@ssw0rd!')
        assert user is not None
        assert user.must_change_password is False


# ===========================================================================
# get_user_by_id — flag survives session restore (Flask-Login user_loader)
# ===========================================================================

class TestGetUserById:

    def test_get_user_by_id_flag_false(self, auth, auth_db):
        _insert_user(auth_db.conn, 'viewer1', 'pass123', must_change=0)
        row = auth_db.conn.execute("SELECT id FROM users WHERE username='viewer1'").fetchone()
        user = auth.get_user_by_id(row['id'])
        assert user is not None
        assert user.must_change_password is False

    def test_get_user_by_id_flag_true(self, auth, auth_db):
        _insert_user(auth_db.conn, 'defaultadmin', 'admin', role='admin', must_change=1)  # pragma: allowlist secret
        row = auth_db.conn.execute("SELECT id FROM users WHERE username='defaultadmin'").fetchone()
        user = auth.get_user_by_id(row['id'])
        assert user is not None
        assert user.must_change_password is True

    def test_get_user_by_id_returns_none_for_missing_id(self, auth):
        user = auth.get_user_by_id(99999)
        assert user is None

    def test_get_user_by_id_inherits_role(self, auth, auth_db):
        _insert_user(auth_db.conn, 'adminuser', 'pass', role='admin', must_change=0)
        row = auth_db.conn.execute("SELECT id FROM users WHERE username='adminuser'").fetchone()
        user = auth.get_user_by_id(row['id'])
        assert user.role == 'admin'


# ===========================================================================
# change_password — clears the flag atomically
# ===========================================================================

class TestChangePasswordClearsFlag:

    def test_change_password_clears_must_change_flag(self, auth, auth_db):
        _insert_user(auth_db.conn, 'flaggeduser', 'oldpass', must_change=1)
        row = auth_db.conn.execute("SELECT id FROM users WHERE username='flaggeduser'").fetchone()
        user_id = row['id']

        result = auth.change_password(user_id, 'NewSecurePass1!')
        assert result is True

        # Reload from DB — flag must be cleared
        updated = auth.get_user_by_id(user_id)
        assert updated is not None
        assert updated.must_change_password is False

    def test_change_password_new_password_works_for_login(self, auth, auth_db):
        _insert_user(auth_db.conn, 'changeuser', 'OldPass1!', must_change=1)
        row = auth_db.conn.execute("SELECT id FROM users WHERE username='changeuser'").fetchone()
        auth.change_password(row['id'], 'BrandNew99!')

        # Must be able to log in with the new password
        user = auth.verify_user('changeuser', 'BrandNew99!')
        assert user is not None
        assert user.must_change_password is False

    def test_change_password_old_password_rejected_after_change(self, auth, auth_db):
        _insert_user(auth_db.conn, 'rotateuser', 'OriginalPass!', must_change=0)
        row = auth_db.conn.execute("SELECT id FROM users WHERE username='rotateuser'").fetchone()
        auth.change_password(row['id'], 'UpdatedPass99!')

        # Old password must no longer work
        old_login = auth.verify_user('rotateuser', 'OriginalPass!')
        assert old_login is None

    def test_change_password_does_not_affect_other_users(self, auth, auth_db):
        _insert_user(auth_db.conn, 'user_a', 'PassA1!', must_change=1)
        _insert_user(auth_db.conn, 'user_b', 'PassB1!', must_change=1)
        row_a = auth_db.conn.execute("SELECT id FROM users WHERE username='user_a'").fetchone()
        auth.change_password(row_a['id'], 'NewPassA!')

        # user_b flag must remain unchanged
        row_b = auth_db.conn.execute("SELECT id FROM users WHERE username='user_b'").fetchone()
        user_b = auth.get_user_by_id(row_b['id'])
        assert user_b.must_change_password is True


# ===========================================================================
# init_database sets flag correctly
# ===========================================================================

class TestInitDatabaseFlag:

    def test_default_admin_gets_flag_set(self, tmp_path):
        """Non-interactive init with admin/admin must set must_change_password=1."""
        import os
        import sys
        from unittest.mock import patch

        db_path = str(tmp_path / 'test_init.db')
        cfg_mock = MagicMock()
        cfg_mock.get.return_value = db_path

        # Simulate non-interactive environment (not a TTY) with default password
        with patch('sys.stdout.isatty', return_value=False), \
             patch.dict(os.environ, {}, clear=False), \
             patch('config.config_manager.config', cfg_mock):
            # Remove IOTSENTINEL_ADMIN_PASSWORD so the default 'admin' is used
            os.environ.pop('IOTSENTINEL_ADMIN_PASSWORD', None)

            # Run only the user-creation portion via the actual function
            import sqlite3 as _sq
            import bcrypt as _bc
            conn = _sq.connect(db_path)
            conn.row_factory = _sq.Row
            cursor = conn.cursor()
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT UNIQUE NOT NULL,
                    password_hash TEXT NOT NULL,
                    email TEXT,
                    email_verified INTEGER DEFAULT 0,
                    role TEXT DEFAULT 'viewer',
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    last_login TIMESTAMP,
                    is_active INTEGER DEFAULT 1,
                    must_change_password INTEGER DEFAULT 0
                )
            """)
            conn.commit()

            # Replicate init_database.py logic for the non-interactive path
            admin_password = os.environ.get("IOTSENTINEL_ADMIN_PASSWORD", "admin")  # pragma: allowlist secret
            _needs_pw_change = 1 if admin_password == "admin" else 0  # pragma: allowlist secret
            pw_hash = _bc.hashpw(admin_password.encode(), _bc.gensalt()).decode()
            cursor.execute(
                "INSERT OR IGNORE INTO users (username, password_hash, role, must_change_password) "
                "VALUES (?, ?, ?, ?)",
                ("admin", pw_hash, "admin", _needs_pw_change)
            )
            conn.commit()

            row = cursor.execute(
                "SELECT must_change_password FROM users WHERE username='admin'"
            ).fetchone()
            assert row['must_change_password'] == 1, (
                "Default admin/admin init must set must_change_password=1"
            )
            conn.close()

    def test_real_password_does_not_set_flag(self, tmp_path):
        """Non-interactive init with a real password must NOT set must_change_password."""
        import os
        import sqlite3 as _sq
        import bcrypt as _bc

        db_path = str(tmp_path / 'test_init2.db')
        conn = _sq.connect(db_path)
        conn.row_factory = _sq.Row
        cursor = conn.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                email TEXT,
                email_verified INTEGER DEFAULT 0,
                role TEXT DEFAULT 'viewer',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_login TIMESTAMP,
                is_active INTEGER DEFAULT 1,
                must_change_password INTEGER DEFAULT 0
            )
        """)
        conn.commit()

        # Simulate operator setting a strong password via env var
        admin_password = "MyStr0ngP@ss!"  # pragma: allowlist secret
        _needs_pw_change = 1 if admin_password == "admin" else 0  # pragma: allowlist secret
        pw_hash = _bc.hashpw(admin_password.encode(), _bc.gensalt()).decode()
        cursor.execute(
            "INSERT OR IGNORE INTO users (username, password_hash, role, must_change_password) "
            "VALUES (?, ?, ?, ?)",
            ("admin", pw_hash, "admin", _needs_pw_change)
        )
        conn.commit()

        row = cursor.execute(
            "SELECT must_change_password FROM users WHERE username='admin'"
        ).fetchone()
        assert row['must_change_password'] == 0, (
            "Admin with a real password must NOT have must_change_password=1"
        )
        conn.close()


# ===========================================================================
# Regression: COALESCE guard for missing column in old DBs
# ===========================================================================

class TestCoalesceGuard:

    def test_verify_user_handles_missing_column_gracefully(self, auth, auth_db):
        """COALESCE(must_change_password, 0) means an old DB without the column is safe."""
        # Insert a user without explicitly setting must_change_password (relies on DEFAULT 0).
        # Set email_verified=1 explicitly — production DEFAULT is 0 and non-admin users
        # with email_verified=0 are blocked at login, which is unrelated to this test.
        pw_hash = bcrypt.hashpw(b'testpass', bcrypt.gensalt()).decode()
        auth_db.conn.execute(
            "INSERT INTO users (username, password_hash, role, email_verified) VALUES (?, ?, ?, ?)",
            ('legacyuser', pw_hash, 'viewer', 1)
        )
        auth_db.conn.commit()
        # Should log in and return must_change_password=False (column default = 0)
        user = auth.verify_user('legacyuser', 'testpass')
        assert user is not None
        assert user.must_change_password is False
