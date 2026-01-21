#!/usr/bin/env python3
"""
TOTP (Time-based One-Time Password) Manager for IoTSentinel

Handles two-factor authentication using TOTP tokens compatible with
Google Authenticator, Authy, Microsoft Authenticator, etc.
"""

import pyotp
import qrcode
import io
import base64
import secrets
import logging
from typing import Tuple, List, Optional

logger = logging.getLogger(__name__)


class TOTPManager:
    """Manages TOTP secrets, QR codes, and verification for 2FA."""

    def __init__(self, db_manager, issuer_name="IoTSentinel"):
        """
        Initialize TOTP manager.

        Args:
            db_manager: Database manager instance
            issuer_name: Name shown in authenticator apps
        """
        self.db_manager = db_manager
        self.issuer_name = issuer_name

    def generate_secret(self) -> str:
        """
        Generate a new TOTP secret.

        Returns:
            Base32-encoded secret string
        """
        return pyotp.random_base32()

    def generate_backup_codes(self, count: int = 8) -> List[str]:
        """
        Generate backup codes for account recovery.

        Args:
            count: Number of backup codes to generate

        Returns:
            List of backup codes (8 digits each)
        """
        codes = []
        for _ in range(count):
            # Generate 8-digit code
            code = ''.join([str(secrets.randbelow(10)) for _ in range(8)])
            codes.append(code)
        return codes

    def get_provisioning_uri(self, secret: str, username: str) -> str:
        """
        Generate provisioning URI for QR code.

        Args:
            secret: TOTP secret
            username: User's username

        Returns:
            otpauth:// URI for QR code
        """
        totp = pyotp.TOTP(secret)
        return totp.provisioning_uri(
            name=username,
            issuer_name=self.issuer_name
        )

    def generate_qr_code(self, secret: str, username: str) -> str:
        """
        Generate QR code as base64-encoded image.

        Args:
            secret: TOTP secret
            username: User's username

        Returns:
            Base64-encoded PNG image
        """
        uri = self.get_provisioning_uri(secret, username)

        # Generate QR code
        qr = qrcode.QRCode(
            version=1,
            error_correction=qrcode.constants.ERROR_CORRECT_L,
            box_size=10,
            border=4,
        )
        qr.add_data(uri)
        qr.make(fit=True)

        img = qr.make_image(fill_color="black", back_color="white")

        # Convert to base64
        buffer = io.BytesIO()
        img.save(buffer, format='PNG')
        buffer.seek(0)
        img_base64 = base64.b64encode(buffer.getvalue()).decode()

        return f"data:image/png;base64,{img_base64}"

    def verify_token(self, secret: str, token: str) -> bool:
        """
        Verify a TOTP token.

        Args:
            secret: User's TOTP secret
            token: 6-digit token to verify

        Returns:
            True if token is valid, False otherwise
        """
        try:
            totp = pyotp.TOTP(secret)
            # Allow 1 time step before/after for clock drift
            return totp.verify(token, valid_window=1)
        except Exception as e:
            logger.error(f"Error verifying TOTP token: {e}")
            return False

    def setup_totp(self, user_id: int, username: str) -> Tuple[str, str, List[str]]:
        """
        Set up TOTP for a user (generate secret, QR code, backup codes).

        Args:
            user_id: User's ID
            username: User's username

        Returns:
            Tuple of (secret, qr_code_base64, backup_codes)
        """
        # Generate secret and backup codes
        secret = self.generate_secret()
        backup_codes = self.generate_backup_codes()
        qr_code = self.generate_qr_code(secret, username)

        # Store in database (not enabled yet - user must verify first)
        conn = self.db_manager.conn
        cursor = conn.cursor()

        # Format backup codes as comma-separated string
        backup_codes_str = ','.join(backup_codes)

        cursor.execute('''
            INSERT OR REPLACE INTO totp_secrets
            (user_id, secret, enabled, backup_codes)
            VALUES (?, ?, 0, ?)
        ''', (user_id, secret, backup_codes_str))

        conn.commit()

        logger.info(f"TOTP setup initiated for user {username} (ID: {user_id})")

        return secret, qr_code, backup_codes

    def enable_totp(self, user_id: int, token: str) -> bool:
        """
        Enable TOTP after user verifies with a valid token.

        Args:
            user_id: User's ID
            token: 6-digit verification token

        Returns:
            True if enabled successfully, False if token invalid
        """
        conn = self.db_manager.conn
        cursor = conn.cursor()

        # Get secret
        cursor.execute(
            'SELECT secret FROM totp_secrets WHERE user_id = ?',
            (user_id,)
        )
        result = cursor.fetchone()

        if not result:
            logger.error(f"No TOTP secret found for user {user_id}")
            return False

        secret = result['secret']

        # Verify token
        if not self.verify_token(secret, token):
            logger.warning(f"Invalid TOTP token for user {user_id}")
            return False

        # Enable TOTP
        cursor.execute('''
            UPDATE totp_secrets
            SET enabled = 1, verified_at = CURRENT_TIMESTAMP
            WHERE user_id = ?
        ''', (user_id,))

        conn.commit()

        logger.info(f"2FA enabled for user {user_id}")
        return True

    def disable_totp(self, user_id: int) -> bool:
        """
        Disable TOTP for a user.

        Args:
            user_id: User's ID

        Returns:
            True if disabled successfully
        """
        try:
            conn = self.db_manager.conn
            cursor = conn.cursor()

            cursor.execute(
                'UPDATE totp_secrets SET enabled = 0 WHERE user_id = ?',
                (user_id,)
            )

            conn.commit()

            logger.info(f"2FA disabled for user {user_id}")
            return True

        except Exception as e:
            logger.error(f"Error disabling TOTP for user {user_id}: {e}")
            return False

    def is_totp_enabled(self, user_id: int) -> bool:
        """
        Check if TOTP is enabled for a user.

        Args:
            user_id: User's ID

        Returns:
            True if TOTP is enabled, False otherwise
        """
        try:
            conn = self.db_manager.conn
            cursor = conn.cursor()

            cursor.execute(
                'SELECT enabled FROM totp_secrets WHERE user_id = ?',
                (user_id,)
            )
            result = cursor.fetchone()

            return bool(result and result['enabled'])

        except Exception as e:
            logger.error(f"Error checking TOTP status for user {user_id}: {e}")
            return False

    def verify_backup_code(self, user_id: int, code: str) -> bool:
        """
        Verify and consume a backup code.

        Args:
            user_id: User's ID
            code: Backup code to verify

        Returns:
            True if code is valid and consumed, False otherwise
        """
        try:
            conn = self.db_manager.conn
            cursor = conn.cursor()

            cursor.execute(
                'SELECT backup_codes FROM totp_secrets WHERE user_id = ?',
                (user_id,)
            )
            result = cursor.fetchone()

            if not result:
                return False

            backup_codes = result['backup_codes'].split(',') if result['backup_codes'] else []

            # Check if code exists
            if code not in backup_codes:
                logger.warning(f"Invalid backup code for user {user_id}")
                return False

            # Remove used code
            backup_codes.remove(code)
            new_codes_str = ','.join(backup_codes)

            cursor.execute(
                'UPDATE totp_secrets SET backup_codes = ? WHERE user_id = ?',
                (new_codes_str, user_id)
            )

            conn.commit()

            logger.info(f"Backup code used for user {user_id}. {len(backup_codes)} codes remaining.")
            return True

        except Exception as e:
            logger.error(f"Error verifying backup code for user {user_id}: {e}")
            return False

    def get_totp_status(self, user_id: int) -> dict:
        """
        Get comprehensive TOTP status for a user.

        Args:
            user_id: User's ID

        Returns:
            Dictionary with TOTP status information
        """
        try:
            conn = self.db_manager.conn
            cursor = conn.cursor()

            cursor.execute('''
                SELECT enabled, verified_at, backup_codes, created_at
                FROM totp_secrets
                WHERE user_id = ?
            ''', (user_id,))

            result = cursor.fetchone()

            if not result:
                return {
                    'enabled': False,
                    'setup': False,
                    'verified_at': None,
                    'backup_codes_remaining': 0,
                    'created_at': None
                }

            backup_codes = result['backup_codes'].split(',') if result['backup_codes'] else []

            return {
                'enabled': bool(result['enabled']),
                'setup': True,
                'verified_at': result['verified_at'],
                'backup_codes_remaining': len(backup_codes),
                'created_at': result['created_at']
            }

        except Exception as e:
            logger.error(f"Error getting TOTP status for user {user_id}: {e}")
            return {
                'enabled': False,
                'setup': False,
                'verified_at': None,
                'backup_codes_remaining': 0,
                'created_at': None,
                'error': str(e)
            }
