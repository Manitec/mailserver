"""
db.py — Turso (libSQL) connection layer.
All database access goes through get_db().
Falls back to local SQLite if TURSO_URL is not set (local dev).
"""
import os
import libsql_experimental as libsql

TURSO_URL = os.getenv("TURSO_URL", "")
TURSO_AUTH_TOKEN = os.getenv("TURSO_AUTH_TOKEN", "")


def get_db():
    """Return a libsql connection. Remote Turso if env vars set, else local file."""
    if TURSO_URL:
        conn = libsql.connect(
            database=TURSO_URL,
            auth_token=TURSO_AUTH_TOKEN,
        )
    else:
        # Local dev fallback
        conn = libsql.connect("users.db")
    return conn


def init_db():
    conn = get_db()
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
