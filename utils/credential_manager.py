#!/usr/bin/env python3
"""
Credential Manager for IoTSentinel

Provides secure encryption/decryption of API keys and credentials using Fernet
(symmetric encryption). The encryption key is stored in environment variables
and never in the database or code.

Security Features:
- Fernet encryption (AES-128 CBC with HMAC)
- Key derivation from environment variable
- No plaintext credentials in database
- Auto-generate encryption key if missing

Usage:
    from utils.credential_manager import CredentialManager

    cred_mgr = CredentialManager()

    # Encrypt a credential
    encrypted = cred_mgr.encrypt("my-api-key-12345")

    # Decrypt a credential
    decrypted = cred_mgr.decrypt(encrypted)
"""

import os
import logging
from pathlib import Path
from cryptography.fernet import Fernet
from dotenv import load_dotenv

logger = logging.getLogger(__name__)


class CredentialManager:
    """Manages encryption/decryption of sensitive credentials."""

    def __init__(self):
        """Initialize the credential manager with encryption key."""
        # Load environment variables
        env_path = Path(__file__).parent.parent / '.env'
        if env_path.exists():
            load_dotenv(dotenv_path=env_path)

        # Get or generate encryption key
        self.encryption_key = self._get_or_create_key()
        self.cipher = Fernet(self.encryption_key)

    def _get_or_create_key(self) -> bytes:
        """
        Get encryption key from environment or generate a new one.

        Returns:
            Encryption key as bytes
        """
        key = os.getenv('IOTSENTINEL_ENCRYPTION_KEY')

        if key:
            try:
                # Validate the key
                _ = Fernet(key.encode())
                logger.info("Using existing encryption key from environment")
                return key.encode()
            except Exception as e:
                logger.warning(f"Invalid encryption key in environment: {e}")
                logger.warning("Generating new encryption key")

        # Generate new key
        new_key = Fernet.generate_key()

        # Save to .env file
        env_path = Path(__file__).parent.parent / '.env'
        try:
            # Read existing .env content
            existing_content = ""
            if env_path.exists():
                with open(env_path, 'r') as f:
                    existing_content = f.read()

            # Check if key already exists in file
            if 'IOTSENTINEL_ENCRYPTION_KEY=' not in existing_content:
                with open(env_path, 'a') as f:
                    if existing_content and not existing_content.endswith('\n'):
                        f.write('\n')
                    f.write(f'\n# Auto-generated encryption key for API credentials\n')
                    f.write(f'IOTSENTINEL_ENCRYPTION_KEY={new_key.decode()}\n')
                logger.info(f"Generated and saved new encryption key to {env_path}")
            else:
                logger.info("Encryption key already exists in .env file")

        except Exception as e:
            logger.error(f"Failed to save encryption key to .env: {e}")
            logger.warning("Encryption key will only be valid for this session")

        return new_key

    def encrypt(self, plaintext: str) -> str:
        """
        Encrypt a plaintext string.

        Args:
            plaintext: The string to encrypt

        Returns:
            Encrypted string (base64 encoded)
        """
        if not plaintext:
            return ""

        try:
            encrypted_bytes = self.cipher.encrypt(plaintext.encode())
            return encrypted_bytes.decode()
        except Exception as e:
            logger.error(f"Encryption failed: {e}")
            raise

    def decrypt(self, encrypted: str) -> str:
        """
        Decrypt an encrypted string.

        Args:
            encrypted: The encrypted string (base64 encoded)

        Returns:
            Decrypted plaintext string
        """
        if not encrypted:
            return ""

        try:
            decrypted_bytes = self.cipher.decrypt(encrypted.encode())
            return decrypted_bytes.decode()
        except Exception as e:
            logger.error(f"Decryption failed: {e}")
            raise

    def is_encrypted(self, value: str) -> bool:
        """
        Check if a value appears to be encrypted.

        Args:
            value: String to check

        Returns:
            True if value appears to be encrypted
        """
        if not value:
            return False

        # Fernet tokens start with 'gAAAAA'
        try:
            self.cipher.decrypt(value.encode())
            return True
        except Exception:
            return False

    @staticmethod
    def generate_new_key() -> str:
        """
        Generate a new Fernet encryption key.

        Returns:
            New encryption key as string
        """
        return Fernet.generate_key().decode()


# Global instance
_credential_manager = None


def get_credential_manager() -> CredentialManager:
    """
    Get the global credential manager instance.

    Returns:
        CredentialManager instance
    """
    global _credential_manager
    if _credential_manager is None:
        _credential_manager = CredentialManager()
    return _credential_manager
