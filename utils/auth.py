#!/usr/bin/env python3
"""
Authentication Module for IoTSentinel Dashboard

Provides user authentication, session management, and password utilities.
"""

import bcrypt
import sqlite3
import logging
from datetime import datetime
from typing import Optional, Dict, Any
from pathlib import Path

logger = logging.getLogger(__name__)


class User:
    """User model for Flask-Login"""

    def __init__(self, user_id: int, username: str, role: str):
        self.id = user_id
        self.username = username
        self.role = role
        self.is_authenticated = True
        self.is_active = True
        self.is_anonymous = False

    def get_id(self):
        """Required by Flask-Login"""
        return str(self.id)

    def is_admin(self) -> bool:
        """Check if user has admin role"""
        return self.role == 'admin'


class AuthManager:
    """Manages user authentication and session operations"""

    def __init__(self, db_manager=None, db_path: str = None):
        """
        Initialize authentication manager.

        Args:
            db_manager: DatabaseManager instance (preferred)
            db_path: Path to SQLite database (legacy, for backward compatibility)
        """
        if db_manager is not None:
            self.db_manager = db_manager
            self.db_path = None
        else:
            # Legacy mode: import and create db_manager from path
            from database.db_manager import DatabaseManager
            self.db_manager = DatabaseManager(db_path=db_path)
            self.db_path = db_path

    def verify_user(self, username: str, password: str) -> Optional[User]:
        """
        Verify username and password.

        Args:
            username: Username to check
            password: Plain text password

        Returns:
            User object if credentials are valid, None otherwise
        """
        try:
            conn = self.db_manager.conn
            cursor = conn.cursor()

            cursor.execute("""
                SELECT id, username, password_hash, role, is_active
                FROM users
                WHERE username = ?
            """, (username,))

            user_row = cursor.fetchone()

            if not user_row:
                logger.warning(f"Login attempt with unknown username: {username}")
                return None

            if not user_row['is_active']:
                logger.warning(f"Login attempt with inactive user: {username}")
                return None

            # Verify password
            password_hash = user_row['password_hash']
            if bcrypt.checkpw(password.encode('utf-8'), password_hash.encode('utf-8')):
                # Update last login time
                self._update_last_login(user_row['id'])

                logger.info(f"Successful login: {username}")
                return User(
                    user_id=user_row['id'],
                    username=user_row['username'],
                    role=user_row['role']
                )
            else:
                logger.warning(f"Failed login attempt for user: {username}")
                return None

        except sqlite3.Error as e:
            logger.error(f"Database error during authentication: {e}")
            return None

    def get_user_by_id(self, user_id: int) -> Optional[User]:
        """
        Get user by ID (for Flask-Login user_loader).

        Args:
            user_id: User ID

        Returns:
            User object if found, None otherwise
        """
        try:
            conn = self.db_manager.conn
            cursor = conn.cursor()

            cursor.execute("""
                SELECT id, username, role, is_active
                FROM users
                WHERE id = ?
            """, (user_id,))

            user_row = cursor.fetchone()

            if user_row and user_row['is_active']:
                return User(
                    user_id=user_row['id'],
                    username=user_row['username'],
                    role=user_row['role']
                )
            return None

        except sqlite3.Error as e:
            logger.error(f"Error fetching user by ID {user_id}: {e}")
            return None

    def _update_last_login(self, user_id: int):
        """Update user's last login timestamp"""
        try:
            conn = self.db_manager.conn
            cursor = conn.cursor()

            cursor.execute("""
                UPDATE users
                SET last_login = ?
                WHERE id = ?
            """, (datetime.now().isoformat(), user_id))

            conn.commit()

        except sqlite3.Error as e:
            logger.error(f"Error updating last login for user {user_id}: {e}")

    def get_user_data(self, user_id: int) -> Optional[Dict[str, Any]]:
        """
        Get user data as dictionary including email.

        Args:
            user_id: User ID

        Returns:
            Dictionary with user data if found, None otherwise
        """
        try:
            conn = self.db_manager.conn

            cursor = conn.cursor()

            cursor.execute("""
                SELECT id, username, email, role, is_active, created_at
                FROM users
                WHERE id = ?
            """, (user_id,))

            user_row = cursor.fetchone()

            if user_row:
                return dict(user_row)
            return None

        except sqlite3.Error as e:
            logger.error(f"Error getting user data {user_id}: {e}")
            return None

    def create_user(self, username: str, password: str, role: str = 'viewer', email: str = None) -> bool:
        """
        Create a new user.

        Args:
            username: Username (must be unique)
            password: Plain text password
            role: User role ('admin' or 'viewer')
            email: Email address (optional)

        Returns:
            True if user created successfully, False otherwise
        """
        try:
            # Hash password
            password_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

            conn = self.db_manager.conn
            cursor = conn.cursor()

            cursor.execute("""
                INSERT INTO users (username, password_hash, role, email)
                VALUES (?, ?, ?, ?)
            """, (username, password_hash, role, email))

            conn.commit()

            logger.info(f"Created new user: {username} (role: {role})")
            return True

        except sqlite3.IntegrityError:
            logger.warning(f"Attempted to create duplicate username: {username}")
            return False
        except sqlite3.Error as e:
            logger.error(f"Error creating user {username}: {e}")
            return False

    def change_password(self, user_id: int, new_password: str) -> bool:
        """
        Change user's password.

        Args:
            user_id: User ID
            new_password: New plain text password

        Returns:
            True if password changed successfully, False otherwise
        """
        try:
            # Hash new password
            password_hash = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

            conn = self.db_manager.conn
            cursor = conn.cursor()

            cursor.execute("""
                UPDATE users
                SET password_hash = ?
                WHERE id = ?
            """, (password_hash, user_id))

            conn.commit()

            logger.info(f"Password changed for user ID: {user_id}")
            return True

        except sqlite3.Error as e:
            logger.error(f"Error changing password for user {user_id}: {e}")
            return False

    def update_user_profile(self, user_id: int, username: str, email: str) -> bool:
        """
        Update user's profile information (username and email).

        Args:
            user_id: User ID
            username: New username
            email: New email address

        Returns:
            True if profile updated successfully, False otherwise
        """
        try:
            conn = self.db_manager.conn
            cursor = conn.cursor()

            cursor.execute("""
                UPDATE users
                SET username = ?, email = ?
                WHERE id = ?
            """, (username, email, user_id))

            conn.commit()

            logger.info(f"Profile updated for user ID: {user_id}")
            return True

        except sqlite3.IntegrityError:
            logger.warning(f"Username {username} already exists")
            return False
        except sqlite3.Error as e:
            logger.error(f"Error updating profile for user {user_id}: {e}")
            return False

    def delete_user(self, user_id: int, current_user_id: int = None) -> bool:
        """
        Soft delete user (set is_active = 0).

        Args:
            user_id: User ID to delete
            current_user_id: Current logged-in user ID (to prevent self-deletion)

        Returns:
            True if user deactivated successfully, False otherwise
        """
        try:
            # Prevent self-deletion
            if current_user_id and user_id == current_user_id:
                logger.warning(f"Attempted self-deletion prevented for user ID: {user_id}")
                return False

            conn = self.db_manager.conn
            cursor = conn.cursor()

            cursor.execute("""
                UPDATE users
                SET is_active = 0
                WHERE id = ?
            """, (user_id,))

            conn.commit()

            logger.info(f"Deactivated user ID: {user_id}")
            return True

        except sqlite3.Error as e:
            logger.error(f"Error deactivating user {user_id}: {e}")
            return False

    def get_all_users(self) -> list:
        """
        Get all active users.

        Returns:
            List of user dictionaries
        """
        try:
            conn = self.db_manager.conn

            cursor = conn.cursor()

            cursor.execute("""
                SELECT id, username, role, created_at, last_login, is_active
                FROM users
                WHERE is_active = 1
                ORDER BY created_at DESC
            """)

            users = [dict(row) for row in cursor.fetchall()]

            return users

        except sqlite3.Error as e:
            logger.error(f"Error fetching users: {e}")
            return []

    def get_user_preference(self, user_id: int, preference_key: str, default=None):
        """
        Get a user preference value.

        Args:
            user_id: User ID
            preference_key: Preference key (e.g., 'display_density', 'timezone')
            default: Default value if preference not found

        Returns:
            Preference value or default
        """
        try:
            conn = self.db_manager.conn

            cursor = conn.cursor()

            cursor.execute("""
                SELECT preference_value FROM user_preferences
                WHERE user_id = ? AND preference_key = ?
            """, (user_id, preference_key))

            result = cursor.fetchone()

            if result:
                return result['preference_value']
            return default

        except sqlite3.Error as e:
            logger.error(f"Error fetching preference {preference_key} for user {user_id}: {e}")
            return default

    def set_user_preference(self, user_id: int, preference_key: str, preference_value: str) -> bool:
        """
        Set a user preference.

        Args:
            user_id: User ID
            preference_key: Preference key
            preference_value: Preference value

        Returns:
            True if preference set successfully, False otherwise
        """
        try:
            conn = self.db_manager.conn
            cursor = conn.cursor()

            cursor.execute("""
                INSERT INTO user_preferences (user_id, preference_key, preference_value)
                VALUES (?, ?, ?)
                ON CONFLICT(user_id, preference_key) DO UPDATE SET
                    preference_value = excluded.preference_value,
                    updated_at = CURRENT_TIMESTAMP
            """, (user_id, preference_key, preference_value))

            conn.commit()

            logger.info(f"Set preference {preference_key} for user {user_id}")
            return True

        except sqlite3.Error as e:
            logger.error(f"Error setting preference {preference_key} for user {user_id}: {e}")
            return False

    def get_all_user_preferences(self, user_id: int) -> Dict[str, str]:
        """
        Get all preferences for a user.

        Args:
            user_id: User ID

        Returns:
            Dictionary mapping preference keys to values
        """
        try:
            conn = self.db_manager.conn

            cursor = conn.cursor()

            cursor.execute("""
                SELECT preference_key, preference_value
                FROM user_preferences
                WHERE user_id = ?
            """, (user_id,))

            preferences = {row['preference_key']: row['preference_value'] for row in cursor.fetchall()}

            # Apply defaults for missing preferences
            defaults = self._get_default_preferences()
            for key, value in defaults.items():
                if key not in preferences:
                    preferences[key] = value

            return preferences

        except sqlite3.Error as e:
            logger.error(f"Error fetching preferences for user {user_id}: {e}")
            return self._get_default_preferences()

    def _get_default_preferences(self) -> Dict[str, str]:
        """Get default user preferences."""
        return {
            'display_density': 'comfortable',  # comfortable, compact, spacious
            'timezone': 'UTC',  # User's timezone
            'date_format': 'YYYY-MM-DD HH:mm:ss',
            'auto_backup': 'enabled',  # enabled, disabled
            'backup_schedule': 'daily',  # daily, weekly, monthly
            'backup_retention_days': '30',
            'language': 'en',
            'theme': 'dark',  # dark, light, auto
            'notifications_enabled': 'true',
            'alert_email_enabled': 'false',
            'dashboard_refresh_interval': '10',  # seconds
        }

    def update_user_settings(self, user_id: int, settings: Dict[str, str]) -> bool:
        """
        Update multiple user settings at once.

        Args:
            user_id: User ID
            settings: Dictionary of setting key-value pairs

        Returns:
            True if all settings updated successfully, False otherwise
        """
        try:
            conn = self.db_manager.conn
            cursor = conn.cursor()

            for key, value in settings.items():
                cursor.execute("""
                    INSERT INTO user_preferences (user_id, preference_key, preference_value)
                    VALUES (?, ?, ?)
                    ON CONFLICT(user_id, preference_key) DO UPDATE SET
                        preference_value = excluded.preference_value,
                        updated_at = CURRENT_TIMESTAMP
                """, (user_id, key, value))

            conn.commit()

            logger.info(f"Updated {len(settings)} settings for user {user_id}")
            return True

        except sqlite3.Error as e:
            logger.error(f"Error updating settings for user {user_id}: {e}")
            return False

    def create_password_reset_token(self, email: str) -> Optional[str]:
        """
        Create a password reset token for a user.

        Args:
            email: User's email address

        Returns:
            Reset token if user exists, None otherwise
        """
        import secrets
        from datetime import datetime, timedelta

        try:
            conn = self.db_manager.conn
            cursor = conn.cursor()

            # Check if user exists
            cursor.execute("SELECT id FROM users WHERE email = ? AND is_active = 1", (email,))
            user_row = cursor.fetchone()

            if not user_row:
                return None

            user_id = user_row[0]

            # Generate reset token
            reset_token = secrets.token_urlsafe(32)
            expires_at = (datetime.now() + timedelta(hours=1)).isoformat()

            # Store token
            cursor.execute("""
                INSERT INTO password_reset_tokens (user_id, token, expires_at)
                VALUES (?, ?, ?)
            """, (user_id, reset_token, expires_at))

            conn.commit()

            logger.info(f"Created password reset token for user ID: {user_id}")
            return reset_token

        except sqlite3.Error as e:
            logger.error(f"Error creating password reset token: {e}")
            return None

    def verify_reset_token(self, token: str) -> Optional[int]:
        """
        Verify password reset token and return user ID if valid.

        Args:
            token: Reset token

        Returns:
            User ID if token is valid, None otherwise
        """
        from datetime import datetime

        try:
            conn = self.db_manager.conn
            cursor = conn.cursor()

            cursor.execute("""
                SELECT user_id, expires_at, used
                FROM password_reset_tokens
                WHERE token = ?
            """, (token,))

            token_row = cursor.fetchone()

            if not token_row:
                return None

            user_id, expires_at, used = token_row

            # Check if token is already used
            if used:
                logger.warning(f"Attempted to use already-used reset token")
                return None

            # Check if token is expired
            expires_datetime = datetime.fromisoformat(expires_at)
            if datetime.now() > expires_datetime:
                logger.warning(f"Attempted to use expired reset token")
                return None

            return user_id

        except sqlite3.Error as e:
            logger.error(f"Error verifying reset token: {e}")
            return None

    def reset_password_with_token(self, token: str, new_password: str) -> bool:
        """
        Reset password using a valid token.

        Args:
            token: Reset token
            new_password: New password

        Returns:
            True if password reset successfully, False otherwise
        """
        try:
            # Verify token
            user_id = self.verify_reset_token(token)
            if not user_id:
                return False

            # Change password
            if not self.change_password(user_id, new_password):
                return False

            # Mark token as used
            conn = self.db_manager.conn
            cursor = conn.cursor()

            cursor.execute("""
                UPDATE password_reset_tokens
                SET used = 1
                WHERE token = ?
            """, (token,))

            conn.commit()

            logger.info(f"Password reset completed for user ID: {user_id}")
            return True

        except sqlite3.Error as e:
            logger.error(f"Error resetting password with token: {e}")
            return False

    def get_user_by_username(self, username: str) -> Optional[Dict[str, Any]]:
        """
        Get user data by username.

        Args:
            username: Username to look up

        Returns:
            Dictionary with user data if found, None otherwise
        """
        try:
            conn = self.db_manager.conn

            cursor = conn.cursor()

            cursor.execute("""
                SELECT id, username, email, role, is_active, created_at, last_login
                FROM users
                WHERE username = ?
            """, (username,))

            user_row = cursor.fetchone()

            if user_row:
                return dict(user_row)
            return None

        except sqlite3.Error as e:
            logger.error(f"Error getting user by username {username}: {e}")
            return None

    def get_user_by_email(self, email: str) -> Optional[Dict[str, Any]]:
        """
        Get user data by email.

        Args:
            email: Email to look up

        Returns:
            Dictionary with user data if found, None otherwise
        """
        try:
            conn = self.db_manager.conn

            cursor = conn.cursor()

            cursor.execute("""
                SELECT id, username, email, role, is_active, created_at, last_login
                FROM users
                WHERE email = ?
            """, (email,))

            user_row = cursor.fetchone()

            if user_row:
                return dict(user_row)
            return None

        except sqlite3.Error as e:
            logger.error(f"Error getting user by email {email}: {e}")
            return None
