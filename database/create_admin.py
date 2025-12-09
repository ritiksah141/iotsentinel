#!/usr/bin/env python3
"""
Create Admin User Script

This script creates a new admin user for IoTSentinel.
Use this when you need to create an admin account from the command line.
"""

import sys
import getpass
from pathlib import Path

# Add parent directory to path (since script is in database/ folder)
sys.path.insert(0, str(Path(__file__).parent.parent))

from utils.auth import AuthManager


def create_admin_user():
    """Interactive script to create a new admin user"""
    print("=" * 60)
    print("IoTSentinel - Create Admin User")
    print("=" * 60)
    print()

    # Database path (script is in database/ folder, db is in data/database/)
    db_path = Path(__file__).parent.parent / "data" / "database" / "iotsentinel.db"

    if not db_path.exists():
        print(f"Error: Database not found at {db_path}")
        print("Please ensure the database exists first.")
        return False

    # Initialize auth manager
    auth_manager = AuthManager(str(db_path))

    # Get username
    while True:
        username = input("Enter admin username: ").strip()
        if not username:
            print("Username cannot be empty!")
            continue
        if len(username) < 3:
            print("Username must be at least 3 characters!")
            continue
        break

    # Get password
    while True:
        password = getpass.getpass("Enter admin password: ")
        if not password:
            print("Password cannot be empty!")
            continue
        if len(password) < 6:
            print("Password must be at least 6 characters!")
            continue

        password_confirm = getpass.getpass("Confirm admin password: ")
        if password != password_confirm:
            print("Passwords do not match! Try again.")
            continue
        break

    # Create the admin user
    print()
    print(f"Creating admin user '{username}'...")
    success = auth_manager.create_user(username, password, role='admin')

    if success:
        print()
        print("✓ Admin user created successfully!")
        print()
        print("You can now login with:")
        print(f"  Username: {username}")
        print(f"  Password: (the password you entered)")
        print()
        return True
    else:
        print()
        print("✗ Failed to create admin user.")
        print("  Possible reasons:")
        print("  - Username already exists")
        print("  - Database error")
        print()
        return False


if __name__ == "__main__":
    try:
        success = create_admin_user()
        sys.exit(0 if success else 1)
    except KeyboardInterrupt:
        print("\n\nCancelled by user.")
        sys.exit(1)
    except Exception as e:
        print(f"\n\nError: {e}")
        sys.exit(1)
