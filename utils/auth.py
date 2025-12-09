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

    def __init__(self, db_path: str):
        """
        Initialize authentication manager.

        Args:
            db_path: Path to SQLite database
        """
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
            conn = sqlite3.connect(self.db_path)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()

            cursor.execute("""
                SELECT id, username, password_hash, role, is_active
                FROM users
                WHERE username = ?
            """, (username,))

            user_row = cursor.fetchone()
            conn.close()

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
            conn = sqlite3.connect(self.db_path)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()

            cursor.execute("""
                SELECT id, username, role, is_active
                FROM users
                WHERE id = ?
            """, (user_id,))

            user_row = cursor.fetchone()
            conn.close()

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
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()

            cursor.execute("""
                UPDATE users
                SET last_login = ?
                WHERE id = ?
            """, (datetime.now().isoformat(), user_id))

            conn.commit()
            conn.close()

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
            conn = sqlite3.connect(self.db_path)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()

            cursor.execute("""
                SELECT id, username, email, role, is_active, created_at
                FROM users
                WHERE id = ?
            """, (user_id,))

            user_row = cursor.fetchone()
            conn.close()

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

            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()

            cursor.execute("""
                INSERT INTO users (username, password_hash, role, email)
                VALUES (?, ?, ?, ?)
            """, (username, password_hash, role, email))

            conn.commit()
            conn.close()

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

            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()

            cursor.execute("""
                UPDATE users
                SET password_hash = ?
                WHERE id = ?
            """, (password_hash, user_id))

            conn.commit()
            conn.close()

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
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()

            cursor.execute("""
                UPDATE users
                SET username = ?, email = ?
                WHERE id = ?
            """, (username, email, user_id))

            conn.commit()
            conn.close()

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

            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()

            cursor.execute("""
                UPDATE users
                SET is_active = 0
                WHERE id = ?
            """, (user_id,))

            conn.commit()
            conn.close()

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
            conn = sqlite3.connect(self.db_path)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()

            cursor.execute("""
                SELECT id, username, role, created_at, last_login, is_active
                FROM users
                WHERE is_active = 1
                ORDER BY created_at DESC
            """)

            users = [dict(row) for row in cursor.fetchall()]
            conn.close()

            return users

        except sqlite3.Error as e:
            logger.error(f"Error fetching users: {e}")
            return []
