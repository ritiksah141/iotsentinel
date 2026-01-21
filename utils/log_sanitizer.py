#!/usr/bin/env python3
"""
Log Sanitizer for IoTSentinel

Prevents sensitive data (passwords, API keys, tokens, etc.) from being logged.
Provides safe logging functions that automatically redact credentials.
"""

import re
from typing import Any, Dict, Optional


# Sensitive field patterns (case-insensitive)
SENSITIVE_PATTERNS = [
    r'password',
    r'passwd',
    r'pwd',
    r'api[_-]?key',
    r'apikey',
    r'token',
    r'secret',
    r'auth',
    r'credential',
    r'private[_-]?key',
    r'access[_-]?key',
    r'session',
    r'cookie',
    r'csrf',
    r'bearer',
    r'webhook[_-]?url',
    r'bot[_-]?token',
    r'smtp[_-]?password',
    r'db[_-]?password',
    r'oauth',
    r'client[_-]?secret',
]

# Compile regex patterns
SENSITIVE_REGEX = re.compile('|'.join(SENSITIVE_PATTERNS), re.IGNORECASE)

# URL pattern to detect credentials in URLs
URL_CREDENTIAL_PATTERN = re.compile(
    r'(https?://[^:]+):([^@]+)@',  # https://user:password@host  # pragma: allowlist secret
    re.IGNORECASE
)

# API key patterns in strings
API_KEY_PATTERNS = [
    re.compile(r'["\']?api[_-]?key["\']?\s*[:=]\s*["\']?([A-Za-z0-9_\-]{16,})["\']?', re.IGNORECASE),
    re.compile(r'Bearer\s+([A-Za-z0-9_\-\.]{16,})', re.IGNORECASE),
    re.compile(r'token["\']?\s*[:=]\s*["\']?([A-Za-z0-9_\-]{16,})["\']?', re.IGNORECASE),
]


def sanitize_value(key: str, value: Any, redact_text: str = "***REDACTED***") -> Any:
    """
    Sanitize a single value if the key matches sensitive patterns.

    Args:
        key: The field name
        value: The field value
        redact_text: Text to replace sensitive data with

    Returns:
        Original value if not sensitive, redacted text if sensitive
    """
    if value is None:
        return None

    # Check if key matches sensitive patterns
    if SENSITIVE_REGEX.search(key):
        # Keep first 4 characters for debugging purposes if it's a long string
        if isinstance(value, str) and len(value) > 8:
            return f"{value[:4]}...{redact_text}"
        return redact_text

    # Return unchanged if not sensitive
    return value


def sanitize_dict(data: Dict[str, Any], redact_text: str = "***REDACTED***") -> Dict[str, Any]:
    """
    Recursively sanitize a dictionary by redacting sensitive fields.

    Args:
        data: Dictionary to sanitize
        redact_text: Text to replace sensitive data with

    Returns:
        Sanitized copy of the dictionary
    """
    if not isinstance(data, dict):
        return data

    sanitized = {}
    for key, value in data.items():
        if isinstance(value, dict):
            # Recursively sanitize nested dictionaries
            sanitized[key] = sanitize_dict(value, redact_text)
        elif isinstance(value, list):
            # Sanitize list items
            sanitized[key] = [
                sanitize_dict(item, redact_text) if isinstance(item, dict) else sanitize_value(key, item, redact_text)
                for item in value
            ]
        else:
            # Sanitize individual values
            sanitized[key] = sanitize_value(key, value, redact_text)

    return sanitized


def sanitize_url(url: str, redact_text: str = "***REDACTED***") -> str:
    """
    Remove credentials from URLs.

    Args:
        url: URL that may contain credentials
        redact_text: Text to replace credentials with

    Returns:
        Sanitized URL
    """
    if not isinstance(url, str):
        return url

    # Remove user:password from URLs
    sanitized = URL_CREDENTIAL_PATTERN.sub(r'\1:' + redact_text + '@', url)

    return sanitized


def sanitize_string(text: str, redact_text: str = "***REDACTED***") -> str:
    """
    Remove API keys, tokens, and credentials from strings.

    Args:
        text: String that may contain sensitive data
        redact_text: Text to replace sensitive data with

    Returns:
        Sanitized string
    """
    if not isinstance(text, str):
        return text

    sanitized = text

    # Remove credentials from URLs
    sanitized = sanitize_url(sanitized, redact_text)

    # Remove API keys and tokens
    for pattern in API_KEY_PATTERNS:
        sanitized = pattern.sub(lambda m: m.group(0).replace(m.group(1), redact_text), sanitized)

    return sanitized


def safe_log_data(data: Any, redact_text: str = "***REDACTED***") -> Any:
    """
    Prepare data for safe logging by redacting all sensitive information.

    This is the main function to use before logging any user data.

    Args:
        data: Data to sanitize (dict, str, list, etc.)
        redact_text: Text to replace sensitive data with

    Returns:
        Sanitized copy of the data
    """
    if isinstance(data, dict):
        return sanitize_dict(data, redact_text)
    elif isinstance(data, str):
        return sanitize_string(data, redact_text)
    elif isinstance(data, list):
        return [safe_log_data(item, redact_text) for item in data]
    else:
        return data


def get_safe_credentials_summary(credentials: Dict[str, Any]) -> str:
    """
    Get a safe summary of credentials for logging (shows which fields exist but not values).

    Args:
        credentials: Credential dictionary

    Returns:
        Safe string describing which credentials are present
    """
    if not credentials:
        return "No credentials"

    present = []
    for key in credentials.keys():
        if credentials.get(key):
            present.append(key)

    return f"Credentials present: {', '.join(present)}" if present else "Empty credentials"


# Example usage:
if __name__ == "__main__":
    # Test data  # pragma: allowlist secret
    test_data = {
        "username": "admin",
        "password": "SuperSecret123!",  # pragma: allowlist secret
        "api_key": "FAKE_API_KEY_12345678901234567890",  # pragma: allowlist secret
        "email": "user@example.com",
        "webhook_url": "https://hooks.slack.com/services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXX",
        "nested": {
            "db_password": "mysql_secret_pwd",  # pragma: allowlist secret
            "public_info": "This is safe"
        }
    }

    print("Original:", test_data)
    print("Sanitized:", sanitize_dict(test_data))

    test_url = "https://user:password123@api.example.com/data?token=secret_token_here"  # pragma: allowlist secret
    print("\nOriginal URL:", test_url)
    print("Sanitized URL:", sanitize_url(test_url))

    test_string = "Connecting with api_key=FAKE_API_KEY_ABC123XYZ and token='bearer_token_example'"
    print("\nOriginal String:", test_string)
    print("Sanitized String:", sanitize_string(test_string))
