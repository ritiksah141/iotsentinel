#!/usr/bin/env python3
"""
Test script to verify log sanitization works correctly.
Ensures no credentials are leaked in logs.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from utils.log_sanitizer import (
    sanitize_dict,
    sanitize_url,
    sanitize_string,
    safe_log_data,
    get_safe_credentials_summary
)


def test_basic_sanitization():
    """Test basic dictionary sanitization."""
    print("=" * 60)
    print("TEST 1: Basic Dictionary Sanitization")
    print("=" * 60)

    test_data = {  # pragma: allowlist secret
        "username": "admin",
        "password": "SuperSecret123!",  # pragma: allowlist secret
        "api_key": "sk_live_51H8vY2eZvKYlo2C0aIiXyZ",  # pragma: allowlist secret
        "email": "user@example.com",
        "webhook_url": "https://hooks.slack.com/services/SECRET",
    }

    print("\n📝 Original data:")
    for key, value in test_data.items():
        print(f"  {key}: {value}")

    sanitized = sanitize_dict(test_data)

    print("\n✅ Sanitized data:")
    for key, value in sanitized.items():
        print(f"  {key}: {value}")

    # Verify sensitive data is redacted
    assert "SuperSecret123!" not in str(sanitized), "Password leaked!"
    assert "sk_live_51H8vY2eZvKYlo2C0aIiXyZ" not in str(sanitized), "API key leaked!"
    assert "SECRET" not in str(sanitized), "Webhook URL secret leaked!"
    assert sanitized['email'] == "user@example.com", "Email should not be redacted"

    print("\n✅ PASSED: No credentials in sanitized output\n")


def test_nested_sanitization():
    """Test nested dictionary sanitization."""
    print("=" * 60)
    print("TEST 2: Nested Dictionary Sanitization")
    print("=" * 60)

    test_data = {  # pragma: allowlist secret
        "user": {
            "username": "admin",
            "credentials": {
                "password": "MyP@ssw0rd!",  # pragma: allowlist secret
                "api_token": "ghp_1234567890abcdefghij",
                "public_name": "John Doe"
            }
        },
        "integration": {
            "slack": {
                "webhook_url": "https://hooks.slack.com/TXXXXXX/BXXXXXX/xxxxxxxxxx",
                "bot_token": "xoxb-1234567890-abcdefghijklmnop"  # pragma: allowlist secret
            }
        }
    }

    print("\n📝 Original nested data:")
    print(f"  Password: {test_data['user']['credentials']['password']}")
    print(f"  Token: {test_data['user']['credentials']['api_token']}")
    print(f"  Webhook: {test_data['integration']['slack']['webhook_url']}")

    sanitized = safe_log_data(test_data)

    print("\n✅ Sanitized nested data:")
    print(f"  Password: {sanitized['user']['credentials']['password']}")
    print(f"  Token: {sanitized['user']['credentials']['api_token']}")
    print(f"  Webhook: {sanitized['integration']['slack']['webhook_url']}")
    print(f"  Public name: {sanitized['user']['credentials']['public_name']}")

    # Verify
    assert "MyP@ssw0rd!" not in str(sanitized), "Nested password leaked!"
    assert "ghp_1234567890abcdefghij" not in str(sanitized), "Nested token leaked!"
    assert sanitized['user']['credentials']['public_name'] == "John Doe", "Public data should remain"

    print("\n✅ PASSED: Nested credentials properly redacted\n")


def test_url_sanitization():
    """Test URL credential sanitization."""
    print("=" * 60)
    print("TEST 3: URL Credential Sanitization")
    print("=" * 60)

    test_urls = [  # pragma: allowlist secret
        "https://user:password@api.example.com/data",  # pragma: allowlist secret
        "http://admin:secret123@internal.server:8080/path",  # pragma: allowlist secret
        "https://api.example.com/data?token=secret_token",
        "https://safe.example.com/public"
    ]

    for url in test_urls:
        sanitized = sanitize_url(url)
        print(f"\n📝 Original: {url}")
        print(f"✅ Sanitized: {sanitized}")

        # Check that credentials are removed
        if "@" in url and "://" in url:
            parts = url.split("://")[1].split("@")
            if len(parts) > 1 and ":" in parts[0]:
                password = parts[0].split(":")[1]
                assert password not in sanitized, f"URL password leaked: {password}"

    print("\n✅ PASSED: URL credentials properly redacted\n")


def test_string_sanitization():
    """Test string pattern sanitization."""
    print("=" * 60)
    print("TEST 4: String Pattern Sanitization")
    print("=" * 60)

    test_strings = [
        "Connecting with api_key=sk_test_abc123xyz456789",
        "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9",
        "Using token='secret_token_here_12345'",
        "This is a safe string with no credentials"
    ]

    for text in test_strings:
        sanitized = sanitize_string(text)
        print(f"\n📝 Original: {text[:60]}...")
        print(f"✅ Sanitized: {sanitized[:60]}...")

        # Verify sensitive patterns are removed
        if "sk_test_" in text or "Bearer " in text or "token=" in text:
            assert text != sanitized, "Sensitive string should be modified"

    print("\n✅ PASSED: String patterns properly sanitized\n")


def test_credentials_summary():
    """Test safe credential summary generation."""
    print("=" * 60)
    print("TEST 5: Safe Credential Summary")
    print("=" * 60)

    creds = {  # pragma: allowlist secret
        "api_key": "sk_live_xxxxxxxxxxxxxx", # pragma: allowlist secret
        "webhook_url": "https://hooks.slack.com/xxxx",
        "bot_token": "xoxb-xxxxxxxxxxxx",  # pragma: allowlist secret
        "email": "user@example.com"
    }

    summary = get_safe_credentials_summary(creds)

    print(f"\n📝 Credentials: {len(creds)} fields")
    print(f"✅ Safe summary: {summary}")

    # Verify no actual values in summary
    assert "sk_live_" not in summary, "API key value leaked in summary!"
    assert "xoxb-" not in summary, "Token value leaked in summary!"
    assert "hooks.slack.com" not in summary, "URL leaked in summary!"

    print("\n✅ PASSED: Summary contains no credential values\n")


def test_integration_logging_safety():
    """Test that integration logging would be safe."""
    print("=" * 60)
    print("TEST 6: Integration Logging Safety Simulation")
    print("=" * 60)

    # Simulate what would be logged
    integration_config = {
        "slack": {
            "webhook_url": "https://hooks.slack.com/services/T00/B00/SECRET123",
            "enabled": True
        },
        "telegram": {
            "bot_token": "1234567890:ABCdefGHIjklMNOpqrsTUVwxyz",
            "chat_id": "987654321",
            "enabled": True
        },
        "email": {
            "smtp_host": "smtp.gmail.com",
            "smtp_user": "alerts@example.com",
            "smtp_password": "MyEmailP@ssw0rd!",  # pragma: allowlist secret
            "enabled": True
        }
    }

    # This is what would actually be logged
    safe_config = safe_log_data(integration_config)

    print("\n📝 Original config (SHOULD NEVER BE LOGGED):")
    print(f"  Slack webhook: {integration_config['slack']['webhook_url']}")
    print(f"  Telegram token: {integration_config['telegram']['bot_token']}")
    print(f"  Email password: {integration_config['email']['smtp_password']}")

    print("\n✅ Safe config (SAFE TO LOG):")
    print(f"  Slack webhook: {safe_config['slack']['webhook_url']}")
    print(f"  Telegram token: {safe_config['telegram']['bot_token']}")
    print(f"  Email password: {safe_config['email']['smtp_password']}")

    # Verify nothing leaked
    safe_str = str(safe_config)
    assert "SECRET123" not in safe_str, "Slack secret leaked!"
    assert "ABCdefGHIjklMNOpqrsTUVwxyz" not in safe_str, "Telegram token leaked!"
    assert "MyEmailP@ssw0rd!" not in safe_str, "Email password leaked!"

    print("\n✅ PASSED: Integration configs safe to log\n")


def main():
    """Run all tests."""
    print("\n" + "=" * 60)
    print("🔒 LOG SANITIZATION SECURITY TEST SUITE")
    print("=" * 60)
    print("\nVerifying that no credentials leak into logs...\n")

    try:
        test_basic_sanitization()
        test_nested_sanitization()
        test_url_sanitization()
        test_string_sanitization()
        test_credentials_summary()
        test_integration_logging_safety()

        print("=" * 60)
        print("✅ ALL TESTS PASSED!")
        print("=" * 60)
        print("\n🔒 Log sanitization is working correctly.")
        print("✅ Safe to use in production - credentials will be redacted.\n")

        return 0

    except AssertionError as e:
        print("\n" + "=" * 60)
        print("❌ TEST FAILED!")
        print("=" * 60)
        print(f"\n⚠️  Error: {e}\n")
        print("⚠️  CREDENTIAL LEAK DETECTED - DO NOT DEPLOY!")
        print("⚠️  Fix the sanitization before going to production!\n")
        return 1
    except Exception as e:
        print(f"\n❌ Unexpected error: {e}\n")
        return 1


if __name__ == "__main__":
    exit(main())
