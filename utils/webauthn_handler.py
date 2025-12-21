"""
WebAuthn/FIDO2 Biometric Authentication Handler

Handles biometric authentication using Web Authentication API (WebAuthn)
Supports Touch ID, Face ID, Windows Hello, and hardware security keys
"""

import os
import sqlite3
import secrets
import json
from datetime import datetime
from typing import Optional, Dict, List, Tuple
from webauthn import (
    generate_registration_options,
    verify_registration_response,
    generate_authentication_options,
    verify_authentication_response,
    options_to_json
)
from webauthn.helpers.structs import (
    PublicKeyCredentialDescriptor,
    AuthenticatorSelectionCriteria,
    UserVerificationRequirement,
    AuthenticatorAttachment,
    ResidentKeyRequirement
)
from webauthn.helpers.cose import COSEAlgorithmIdentifier
import logging

logger = logging.getLogger(__name__)


class WebAuthnHandler:
    """Handles WebAuthn registration and authentication"""

    def __init__(self, db_path: str):
        """
        Initialize WebAuthn handler

        Args:
            db_path: Path to SQLite database
        """
        self.db_path = db_path

        # Get configuration from environment
        self.rp_id = os.getenv('WEBAUTHN_RP_ID', 'localhost')
        self.rp_name = os.getenv('WEBAUTHN_RP_NAME', 'IoTSentinel')
        self.origin = os.getenv('WEBAUTHN_ORIGIN', 'http://localhost:8050')

        # In-memory challenge storage (use Redis in production)
        self.challenges = {}

        logger.info(f"WebAuthn handler initialized (RP ID: {self.rp_id}, Origin: {self.origin})")

    def generate_registration_options(self, user_id: int, username: str, email: str) -> Dict:
        """
        Generate WebAuthn registration options for a user

        Args:
            user_id: User ID
            username: Username
            email: User email

        Returns:
            Registration options dict
        """
        try:
            # Get existing credentials for this user
            existing_credentials = self._get_user_credentials(user_id)

            # Generate registration options
            options = generate_registration_options(
                rp_id=self.rp_id,
                rp_name=self.rp_name,
                user_id=str(user_id),  # Library handles encoding internally
                user_name=username,
                user_display_name=email,
                exclude_credentials=existing_credentials,
                authenticator_selection=AuthenticatorSelectionCriteria(
                    authenticator_attachment=AuthenticatorAttachment.PLATFORM,
                    resident_key=ResidentKeyRequirement.PREFERRED,
                    user_verification=UserVerificationRequirement.PREFERRED
                ),
                supported_pub_key_algs=[
                    COSEAlgorithmIdentifier.ECDSA_SHA_256,
                    COSEAlgorithmIdentifier.RSASSA_PKCS1_v1_5_SHA_256
                ]
            )

            # Store challenge temporarily (expires in 60 seconds)
            challenge_key = f"reg_{user_id}_{secrets.token_hex(8)}"
            self.challenges[challenge_key] = {
                'challenge': options.challenge,
                'user_id': user_id,
                'timestamp': datetime.now()
            }

            # Convert to JSON-serializable dict
            options_dict = json.loads(options_to_json(options))
            options_dict['challenge_key'] = challenge_key

            logger.info(f"Generated registration options for user {user_id}")
            return options_dict

        except Exception as e:
            logger.error(f"Error generating registration options: {e}")
            raise

    def verify_registration(self, user_id: int, credential_data: Dict, challenge_key: str, device_name: str = "My Device") -> bool:
        """
        Verify WebAuthn registration response

        Args:
            user_id: User ID
            credential_data: Registration credential from client
            challenge_key: Challenge key from registration options
            device_name: Name for this device/credential

        Returns:
            True if registration successful
        """
        try:
            # Retrieve challenge
            if challenge_key not in self.challenges:
                logger.error(f"Challenge not found: {challenge_key}")
                return False

            challenge_data = self.challenges[challenge_key]

            # Verify user_id matches
            if challenge_data['user_id'] != user_id:
                logger.error(f"User ID mismatch in challenge")
                return False

            # Verify registration response
            verification = verify_registration_response(
                credential=credential_data,
                expected_challenge=challenge_data['challenge'],
                expected_origin=self.origin,
                expected_rp_id=self.rp_id
            )

            # Store credential in database
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()

            cursor.execute("""
                INSERT INTO webauthn_credentials
                (user_id, credential_id, public_key, sign_count, aaguid, device_name, created_at, last_used)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                user_id,
                verification.credential_id.decode('utf-8') if isinstance(verification.credential_id, bytes) else verification.credential_id,
                verification.credential_public_key.decode('utf-8') if isinstance(verification.credential_public_key, bytes) else verification.credential_public_key,
                verification.sign_count,
                verification.aaguid,
                device_name,
                datetime.now(),
                None
            ))

            conn.commit()
            conn.close()

            # Clean up challenge
            del self.challenges[challenge_key]

            logger.info(f"Successfully registered WebAuthn credential for user {user_id}")
            return True

        except Exception as e:
            logger.error(f"Error verifying registration: {e}")
            return False

    def generate_authentication_options(self, username: Optional[str] = None) -> Dict:
        """
        Generate WebAuthn authentication options

        Args:
            username: Optional username to get credentials for

        Returns:
            Authentication options dict
        """
        try:
            # Get allowed credentials
            allowed_credentials = []

            if username:
                # Get user ID from username
                conn = sqlite3.connect(self.db_path)
                cursor = conn.cursor()
                cursor.execute("SELECT id FROM users WHERE username = ?", (username,))
                result = cursor.fetchone()
                conn.close()

                if result:
                    user_id = result[0]
                    allowed_credentials = self._get_user_credentials(user_id)

            # Generate authentication options
            options = generate_authentication_options(
                rp_id=self.rp_id,
                allow_credentials=allowed_credentials,
                user_verification=UserVerificationRequirement.PREFERRED
            )

            # Store challenge
            challenge_key = f"auth_{secrets.token_hex(16)}"
            self.challenges[challenge_key] = {
                'challenge': options.challenge,
                'username': username,
                'timestamp': datetime.now()
            }

            # Convert to JSON
            options_dict = json.loads(options_to_json(options))
            options_dict['challenge_key'] = challenge_key

            logger.info(f"Generated authentication options for username: {username or 'any'}")
            return options_dict

        except Exception as e:
            logger.error(f"Error generating authentication options: {e}")
            raise

    def verify_authentication(self, credential_data: Dict, challenge_key: str) -> Optional[int]:
        """
        Verify WebAuthn authentication response

        Args:
            credential_data: Authentication credential from client
            challenge_key: Challenge key from authentication options

        Returns:
            User ID if authentication successful, None otherwise
        """
        try:
            # Retrieve challenge
            if challenge_key not in self.challenges:
                logger.error(f"Challenge not found: {challenge_key}")
                return None

            challenge_data = self.challenges[challenge_key]

            # Get credential from database
            credential_id = credential_data.get('id')
            if not credential_id:
                logger.error("No credential ID in response")
                return None

            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()

            cursor.execute("""
                SELECT user_id, public_key, sign_count
                FROM webauthn_credentials
                WHERE credential_id = ?
            """, (credential_id,))

            result = cursor.fetchone()

            if not result:
                logger.error(f"Credential not found: {credential_id}")
                conn.close()
                return None

            user_id, public_key, current_sign_count = result

            # Verify authentication response
            verification = verify_authentication_response(
                credential=credential_data,
                expected_challenge=challenge_data['challenge'],
                expected_origin=self.origin,
                expected_rp_id=self.rp_id,
                credential_public_key=public_key.encode('utf-8') if isinstance(public_key, str) else public_key,
                credential_current_sign_count=current_sign_count
            )

            # Update sign count and last used
            cursor.execute("""
                UPDATE webauthn_credentials
                SET sign_count = ?,
                    last_used = ?
                WHERE credential_id = ?
            """, (verification.new_sign_count, datetime.now(), credential_id))

            conn.commit()
            conn.close()

            # Clean up challenge
            del self.challenges[challenge_key]

            logger.info(f"Successfully authenticated user {user_id} with WebAuthn")
            return user_id

        except Exception as e:
            logger.error(f"Error verifying authentication: {e}")
            return None

    def _get_user_credentials(self, user_id: int) -> List[PublicKeyCredentialDescriptor]:
        """
        Get user's existing credentials

        Args:
            user_id: User ID

        Returns:
            List of credential descriptors
        """
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        cursor.execute("""
            SELECT credential_id
            FROM webauthn_credentials
            WHERE user_id = ?
        """, (user_id,))

        results = cursor.fetchall()
        conn.close()

        credentials = []
        for row in results:
            credential_id = row[0]
            credentials.append(
                PublicKeyCredentialDescriptor(
                    id=credential_id.encode('utf-8') if isinstance(credential_id, str) else credential_id
                )
            )

        return credentials

    def get_user_credentials_list(self, user_id: int) -> List[Dict]:
        """
        Get list of user's registered credentials

        Args:
            user_id: User ID

        Returns:
            List of credential info dicts
        """
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        cursor.execute("""
            SELECT credential_id, device_name, created_at, last_used
            FROM webauthn_credentials
            WHERE user_id = ?
            ORDER BY created_at DESC
        """, (user_id,))

        results = cursor.fetchall()
        conn.close()

        credentials = []
        for row in results:
            credentials.append({
                'credential_id': row[0],
                'device_name': row[1],
                'created_at': row[2],
                'last_used': row[3]
            })

        return credentials

    def remove_credential(self, user_id: int, credential_id: str) -> bool:
        """
        Remove a credential

        Args:
            user_id: User ID
            credential_id: Credential ID to remove

        Returns:
            True if removed successfully
        """
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()

            cursor.execute("""
                DELETE FROM webauthn_credentials
                WHERE user_id = ? AND credential_id = ?
            """, (user_id, credential_id))

            conn.commit()
            rows_affected = cursor.rowcount
            conn.close()

            if rows_affected > 0:
                logger.info(f"Removed credential {credential_id} for user {user_id}")
                return True
            else:
                logger.warning(f"Credential {credential_id} not found for user {user_id}")
                return False

        except Exception as e:
            logger.error(f"Error removing credential: {e}")
            return False

    def cleanup_old_challenges(self, max_age_seconds: int = 300):
        """
        Clean up old challenges (should be called periodically)

        Args:
            max_age_seconds: Maximum age of challenges in seconds (default 5 minutes)
        """
        now = datetime.now()
        keys_to_delete = []

        for key, data in self.challenges.items():
            age = (now - data['timestamp']).total_seconds()
            if age > max_age_seconds:
                keys_to_delete.append(key)

        for key in keys_to_delete:
            del self.challenges[key]

        if keys_to_delete:
            logger.info(f"Cleaned up {len(keys_to_delete)} old WebAuthn challenges")


# Helper function to check if WebAuthn is supported
def is_webauthn_available() -> bool:
    """Check if WebAuthn can be used"""
    # WebAuthn works on localhost and HTTPS
    origin = os.getenv('WEBAUTHN_ORIGIN', 'http://localhost:8050')
    return origin.startswith('https://') or 'localhost' in origin
