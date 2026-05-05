#!/usr/bin/env python3
"""
reset_password.py — Manitec Mail Server
Run locally or on your Render instance shell to reset a user password.

Usage:
    python reset_password.py
    python reset_password.py --username joe
"""
import sqlite3
import getpass
import os
import argparse
import bcrypt

DB_PATH = os.getenv("DB_PATH", "users.db")


def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()


def list_users(conn):
    rows = conn.execute("SELECT id, username, from_address FROM users").fetchall()
    if not rows:
        print("\u274c No users found in database.")
        return []
    print("\n--- Existing Users ---")
    for row in rows:
        print(f"  [{row[0]}] {row[1]} ({row[2]})")
    return rows


def reset_password(username=None):
    conn = sqlite3.connect(DB_PATH)
    users = list_users(conn)
    if not users:
        conn.close()
        return

    if not username:
        username = input("\nEnter username to reset: ").strip().lower()

    row = conn.execute("SELECT id, username FROM users WHERE username = ?", (username,)).fetchone()
    if not row:
        print(f"\u274c User '{username}' not found.")
        conn.close()
        return

    print(f"\n\U0001f510 Resetting password for: {row[1]}")
    new_password = getpass.getpass("New password: ")
    confirm = getpass.getpass("Confirm new password: ")

    if new_password != confirm:
        print("\u274c Passwords don't match. No changes made.")
        conn.close()
        return

    if len(new_password) < 8:
        print("\u274c Password must be at least 8 characters.")
        conn.close()
        return

    new_hash = hash_password(new_password)
    conn.execute("UPDATE users SET password_hash = ? WHERE username = ?", (new_hash, username))
    conn.commit()
    conn.close()
    print(f"\u2705 Password for '{username}' has been reset successfully.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Manitec Mail — Password Reset Tool")
    parser.add_argument("--username", "-u", help="Username to reset (optional, prompts if omitted)")
    args = parser.parse_args()
    reset_password(args.username)
