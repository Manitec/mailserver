"""Local user management script — run this locally, not on Render.

Usage:
    python init_users.py

For Render deployments, users are seeded automatically via MAIL_USER_N env vars.
See .env.example for the format.
"""
import sqlite3
import getpass
import os
import bcrypt

DB_PATH = os.getenv("DB_PATH", "users.db")


def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()


def init_db():
    conn = sqlite3.connect(DB_PATH)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            username      TEXT    UNIQUE NOT NULL,
            password_hash TEXT    NOT NULL,
            account_key   TEXT    NOT NULL,
            from_address  TEXT    NOT NULL
        )
    """)
    conn.commit()
    conn.close()
    print("✅ Database initialized")


def add_user():
    print("\n--- Add New User ---")
    username = input("Username: ").strip().lower()
    password = getpass.getpass("Password: ")
    confirm = getpass.getpass("Confirm password: ")
    if password != confirm:
        print("❌ Passwords don't match")
        return
    account_key = input("Mail360 Account Key: ").strip()
    from_address = input("Email Address: ").strip()
    conn = sqlite3.connect(DB_PATH)
    try:
        conn.execute(
            "INSERT OR IGNORE INTO users (username, password_hash, account_key, from_address) VALUES (?, ?, ?, ?)",
            (username, hash_password(password), account_key, from_address),
        )
        conn.commit()
        print(f"✅ User '{username}' created ({from_address})")
    except sqlite3.IntegrityError:
        print(f"❌ Username '{username}' already exists")
    finally:
        conn.close()


def list_users():
    conn = sqlite3.connect(DB_PATH)
    rows = conn.execute("SELECT id, username, account_key, from_address FROM users").fetchall()
    conn.close()
    print("\n--- Users ---")
    for row in rows:
        print(f"ID: {row[0]} | User: {row[1]} | Account: {row[2]} | Email: {row[3]}")


def main():
    init_db()
    while True:
        print("\n=== Manitec Mail User Manager ===")
        print("1. Add new user")
        print("2. List users")
        print("3. Exit")
        choice = input("Choose: ").strip()
        if choice == "1":
            add_user()
        elif choice == "2":
            list_users()
        elif choice == "3":
            break
        else:
            print("Invalid choice")


if __name__ == "__main__":
    main()
