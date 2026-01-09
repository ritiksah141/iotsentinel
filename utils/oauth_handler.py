"""
Google OAuth Handler

Handles OAuth 2.0 authentication flow with Google Sign-In
"""

import os
import sqlite3
from datetime import datetime, timedelta
from typing import Optional, Dict, Tuple
from authlib.integrations.flask_client import OAuth
from flask import session, url_for
import logging

logger = logging.getLogger(__name__)


class GoogleOAuthHandler:
    """Handles Google OAuth authentication"""

    def __init__(self, app, db_path: str = None, db_manager=None):
        """
        Initialize Google OAuth handler

        Args:
            app: Flask app instance
            db_path: Path to SQLite database
            db_manager: Shared DatabaseManager instance
        """
        if db_manager is not None:
            self.db_manager = db_manager
            self.db_path = None
        else:
            from database.db_manager import DatabaseManager
            self.db_path = db_path or 'data/database/iotsentinel.db'
            self.db_manager = DatabaseManager(db_path=self.db_path)
        self.oauth = OAuth(app)

        # Get OAuth credentials from environment
        self.client_id = os.getenv('GOOGLE_CLIENT_ID', '')
        self.client_secret = os.getenv('GOOGLE_CLIENT_SECRET', '')
        self.redirect_uri = os.getenv('OAUTH_REDIRECT_URI', 'http://localhost:8050/auth/google/callback')

        if not self.client_id or not self.client_secret:
            logger.warning("Google OAuth credentials not configured. OAuth will be disabled.")
            self.enabled = False
            return

        self.enabled = True

        # Register Google OAuth client
        self.google = self.oauth.register(
            name='google',
            client_id=self.client_id,
            client_secret=self.client_secret,
            server_metadata_url='https://accounts.google.com/.well-known/openid-configuration',
            client_kwargs={
                'scope': 'openid email profile',
                'prompt': 'select_account'  # Always show account selector
            }
        )

        logger.info("Google OAuth handler initialized successfully")

    def get_authorization_url(self) -> Tuple[str, str]:
        """
        Generate OAuth authorization URL

        Returns:
            Tuple of (authorization_url, state)
        """
        if not self.enabled:
            raise Exception("Google OAuth is not configured")

        redirect_uri = self.redirect_uri
        return self.google.authorize_redirect(redirect_uri)

    def handle_callback(self, request) -> Optional[Dict]:
        """
        Handle OAuth callback from Google

        Args:
            request: Flask request object

        Returns:
            User info dict if successful, None otherwise
        """
        if not self.enabled:
            logger.error("Google OAuth callback received but OAuth is not configured")
            return None

        try:
            # Get access token
            token = self.google.authorize_access_token()

            if not token:
                logger.error("Failed to get access token from Google")
                return None

            # Get user info from Google
            resp = self.google.get('https://www.googleapis.com/oauth2/v3/userinfo')
            user_info = resp.json()

            if not user_info or 'sub' not in user_info:
                logger.error("Failed to get user info from Google")
                return None

            # Extract user data
            oauth_user_data = {
                'provider': 'google',
                'provider_user_id': user_info['sub'],
                'email': user_info.get('email', ''),
                'name': user_info.get('name', ''),
                'picture': user_info.get('picture', ''),
                'email_verified': user_info.get('email_verified', False),
                'access_token': token.get('access_token', ''),
                'refresh_token': token.get('refresh_token', ''),
                'token_expires_at': datetime.now() + timedelta(seconds=token.get('expires_in', 3600))
            }

            logger.info(f"Successfully authenticated Google user: {oauth_user_data['email']}")
            return oauth_user_data

        except Exception as e:
            logger.error(f"Error handling OAuth callback: {str(e)}")
            return None

    def create_or_update_oauth_user(self, oauth_data: Dict) -> Optional[int]:
        """
        Create or update user from OAuth data

        Args:
            oauth_data: OAuth user data from Google

        Returns:
            User ID if successful, None otherwise
        """
        conn = self.db_manager.conn
        cursor = conn.cursor()

        try:
            # Check if OAuth account already exists
            cursor.execute("""
                SELECT user_id FROM oauth_accounts
                WHERE provider = ? AND provider_user_id = ?
            """, (oauth_data['provider'], oauth_data['provider_user_id']))

            existing = cursor.fetchone()

            if existing:
                # Update existing OAuth account
                user_id = existing[0]

                cursor.execute("""
                    UPDATE oauth_accounts
                    SET access_token = ?,
                        refresh_token = ?,
                        token_expires_at = ?,
                        last_login = ?
                    WHERE provider = ? AND provider_user_id = ?
                """, (
                    oauth_data['access_token'],
                    oauth_data['refresh_token'],
                    oauth_data['token_expires_at'],
                    datetime.now(),
                    oauth_data['provider'],
                    oauth_data['provider_user_id']
                ))

                logger.info(f"Updated OAuth account for user_id {user_id}")

            else:
                # Check if user exists with this email
                cursor.execute("SELECT id FROM users WHERE email = ?", (oauth_data['email'],))
                user_exists = cursor.fetchone()

                if user_exists:
                    # Link OAuth to existing user
                    user_id = user_exists[0]
                    logger.info(f"Linking Google account to existing user {user_id}")
                else:
                    # Create new user
                    # Generate username from email or name
                    username = oauth_data['email'].split('@')[0]
                    base_username = username

                    # Check if username exists and make it unique
                    counter = 1
                    while True:
                        cursor.execute("SELECT id FROM users WHERE username = ?", (username,))
                        if not cursor.fetchone():
                            break
                        username = f"{base_username}{counter}"
                        counter += 1

                    # Insert new user (OAuth users don't have password)
                    cursor.execute("""
                        INSERT INTO users (username, email, password_hash, role, email_verified, created_at)
                        VALUES (?, ?, ?, ?, ?, ?)
                    """, (
                        username,
                        oauth_data['email'],
                        '',  # No password for OAuth users
                        'viewer',  # Default role
                        1 if oauth_data.get('email_verified') else 0,
                        datetime.now()
                    ))

                    user_id = cursor.lastrowid
                    logger.info(f"Created new user {user_id} from Google OAuth")

                # Create OAuth account link
                cursor.execute("""
                    INSERT INTO oauth_accounts
                    (user_id, provider, provider_user_id, email, access_token, refresh_token, token_expires_at, created_at, last_login)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    user_id,
                    oauth_data['provider'],
                    oauth_data['provider_user_id'],
                    oauth_data['email'],
                    oauth_data['access_token'],
                    oauth_data['refresh_token'],
                    oauth_data['token_expires_at'],
                    datetime.now(),
                    datetime.now()
                ))

            conn.commit()

            return user_id

        except Exception as e:
            logger.error(f"Error creating/updating OAuth user: {str(e)}")
            conn.rollback()
            return None

    def get_user_by_id(self, user_id: int) -> Optional[Dict]:
        """
        Get user details by ID

        Args:
            user_id: User ID

        Returns:
            User dict if found, None otherwise
        """
        conn = self.db_manager.conn
        cursor = conn.cursor()

        cursor.execute("""
            SELECT id, username, email, role, email_verified
            FROM users
            WHERE id = ?
        """, (user_id,))

        row = cursor.fetchone()

        if row:
            return {
                'id': row[0],
                'username': row[1],
                'email': row[2],
                'role': row[3],
                'email_verified': row[4]
            }

        return None

    def refresh_access_token(self, user_id: int) -> Optional[str]:
        """
        Refresh OAuth access token

        Args:
            user_id: User ID

        Returns:
            New access token if successful, None otherwise
        """
        if not self.enabled:
            return None

        conn = self.db_manager.conn
        cursor = conn.cursor()

        try:
            # Get refresh token
            cursor.execute("""
                SELECT refresh_token, provider
                FROM oauth_accounts
                WHERE user_id = ?
                ORDER BY last_login DESC
                LIMIT 1
            """, (user_id,))

            result = cursor.fetchone()

            if not result or not result[0]:
                logger.warning(f"No refresh token found for user {user_id}")
                return None

            refresh_token = result[0]
            provider = result[1]

            if provider != 'google':
                logger.error(f"Unsupported OAuth provider: {provider}")
                return None

            # Use Authlib to refresh token
            token = self.google.fetch_access_token(
                grant_type='refresh_token',
                refresh_token=refresh_token
            )

            if token and 'access_token' in token:
                new_access_token = token['access_token']
                new_expires_at = datetime.now() + timedelta(seconds=token.get('expires_in', 3600))

                # Update token in database
                cursor.execute("""
                    UPDATE oauth_accounts
                    SET access_token = ?,
                        token_expires_at = ?
                    WHERE user_id = ? AND provider = ?
                """, (new_access_token, new_expires_at, user_id, provider))

                conn.commit()

                logger.info(f"Refreshed access token for user {user_id}")
                return new_access_token

            return None

        except Exception as e:
            logger.error(f"Error refreshing access token: {str(e)}")
            conn.rollback()
            return None

    def revoke_oauth_account(self, user_id: int, provider: str = 'google') -> bool:
        """
        Revoke OAuth account link

        Args:
            user_id: User ID
            provider: OAuth provider

        Returns:
            True if successful, False otherwise
        """
        conn = self.db_manager.conn
        cursor = conn.cursor()

        try:
            cursor.execute("""
                DELETE FROM oauth_accounts
                WHERE user_id = ? AND provider = ?
            """, (user_id, provider))

            conn.commit()

            logger.info(f"Revoked {provider} OAuth for user {user_id}")
            return True

        except Exception as e:
            logger.error(f"Error revoking OAuth account: {str(e)}")
            conn.rollback()
            return False


# Helper function to check if OAuth is properly configured
def is_oauth_configured() -> bool:
    """Check if OAuth credentials are configured"""
    client_id = os.getenv('GOOGLE_CLIENT_ID', '')
    client_secret = os.getenv('GOOGLE_CLIENT_SECRET', '')
    return bool(client_id and client_secret)
