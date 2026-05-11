#!/usr/bin/env python3
"""
Reset admin username and/or password directly in the SQLite database.
Run from the project root:  python scripts/reset_admin.py
"""
import sqlite3
import getpass
import sys
from pathlib import Path

DB_PATH = Path(__file__).parent.parent / "data" / "database" / "iotsentinel.db"


def main():
    if not DB_PATH.exists():
        print(f"Database not found: {DB_PATH}")
        sys.exit(1)

    try:
        import bcrypt
    except ImportError:
        print("bcrypt not installed. Run: pip install bcrypt")
        sys.exit(1)

    con = sqlite3.connect(DB_PATH)
    con.row_factory = sqlite3.Row
    cur = con.cursor()

    # Show current admin accounts
    rows = cur.execute(
        "SELECT id, username, email, is_active FROM users WHERE role = 'admin'"
    ).fetchall()

    if not rows:
        print("No admin accounts found in the database.")
        con.close()
        sys.exit(1)

    print("\nExisting admin accounts:")
    for r in rows:
        status = "active" if r["is_active"] else "disabled"
        print(f"  [{r['id']}] {r['username']}  ({r['email'] or 'no email'})  [{status}]")

    # Pick which admin to reset
    if len(rows) == 1:
        target = rows[0]
    else:
        try:
            uid = int(input("\nEnter the ID of the admin to reset: ").strip())
        except ValueError:
            print("Invalid ID.")
            con.close()
            sys.exit(1)
        target = next((r for r in rows if r["id"] == uid), None)
        if not target:
            print("ID not found.")
            con.close()
            sys.exit(1)

    print(f"\nResetting admin: {target['username']} (id={target['id']})")

    # New username (optional)
    new_username = input("New username (leave blank to keep current): ").strip()
    if new_username and new_username != target["username"]:
        import re
        if not re.match(r'^[a-zA-Z0-9_\-\.]+$', new_username):
            print("Username may only contain letters, numbers, underscores, hyphens, and dots.")
            con.close()
            sys.exit(1)
        clash = cur.execute(
            "SELECT id FROM users WHERE username = ? AND id != ?",
            (new_username, target["id"])
        ).fetchone()
        if clash:
            print(f"Username '{new_username}' is already taken.")
            con.close()
            sys.exit(1)
    else:
        new_username = target["username"]

    # New password
    while True:
        new_password = getpass.getpass("New password: ")
        if len(new_password) < 8:
            print("Password must be at least 8 characters.")
            continue
        confirm = getpass.getpass("Confirm password: ")
        if new_password != confirm:
            print("Passwords do not match. Try again.")
            continue
        break

    password_hash = bcrypt.hashpw(new_password.encode(), bcrypt.gensalt()).decode()

    cur.execute(
        """UPDATE users
           SET username = ?, password_hash = ?, is_active = 1, email_verified = 1
           WHERE id = ?""",
        (new_username, password_hash, target["id"])
    )
    con.commit()
    con.close()

    print(f"\nDone. Admin credentials updated.")
    print(f"  Username       : {new_username}")
    print(f"  Email verified : yes")
    print(f"  Account        : re-enabled (is_active = 1)")


if __name__ == "__main__":
    main()
