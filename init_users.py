import sqlite3
import hashlib
import getpass

DB_PATH = "users.db"

def hash_password(password: str) -> str:
    return hashlib.sha256(password.encode("utf-8")).hexdigest()


def init_db():
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            account_key TEXT NOT NULL,
            from_address TEXT NOT NULL
        )
        """
    )
    conn.commit()
    conn.close()
    print("✅ Database initialized")


def add_user():
    print("
--- Add New User ---")
    username = input("Username: ").strip().lower()
    password = getpass.getpass("Password: ")
    confirm = getpass.getpass("Confirm password: ")

    if password != confirm:
        print("❌ Passwords don't match")
        return

    account_key = input("Mail360 Account Key: ").strip()
    from_address = input("Email Address: ").strip()

    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()

    try:
        cur.execute(
            "INSERT OR IGNORE INTO users (username, password_hash, account_key, from_address) VALUES (?, ?, ?, ?)",
            (username, hash_password(password), account_key, from_address),
        )
        conn.commit()
        print(f"✅ User '{username}' created with email {from_address}")
    except sqlite3.IntegrityError:
        print(f"❌ Username '{username}' already exists")
    finally:
        conn.close()


def list_users():
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("SELECT id, username, account_key, from_address FROM users")
    rows = cur.fetchall()
    conn.close()

    print("
--- Users ---")
    for row in rows:
        print(f"ID: {row[0]} | User: {row[1]} | Account: {row[2]} | Email: {row[3]}")


def main():
    init_db()

    while True:
        print("
=== Manitec Mail User Manager ===")
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
