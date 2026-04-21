"""
db.py — Turso connection layer using libsql-client (pure Python, HTTP-based).
Falls back to local SQLite if TURSO_URL is not set (local dev).
"""
import os
import sqlite3

TURSO_URL = os.getenv("TURSO_URL", "")
TURSO_AUTH_TOKEN = os.getenv("TURSO_AUTH_TOKEN", "")

USE_TURSO = bool(TURSO_URL and TURSO_AUTH_TOKEN)


class TursoConnection:
    """
    Thin synchronous wrapper around libsql_client.
    Mimics the sqlite3 connection interface used in main.py.
    """
    def __init__(self):
        import libsql_client
        self._client = libsql_client.create_client_sync(
            url=TURSO_URL,
            auth_token=TURSO_AUTH_TOKEN,
        )

    def execute(self, sql: str, params: tuple = ()):
        result = self._client.execute(sql, list(params))
        return _TursoResult(result)

    def commit(self):
        pass  # libsql-client auto-commits each statement

    def close(self):
        self._client.close()


class _TursoResult:
    def __init__(self, result):
        self._rows = result.rows

    def fetchone(self):
        return self._rows[0] if self._rows else None

    def fetchall(self):
        return self._rows


def get_db():
    """Return a connection — Turso if env vars set, else local SQLite."""
    if USE_TURSO:
        return TursoConnection()
    # Local dev fallback
    conn = sqlite3.connect(os.getenv("DB_PATH", "users.db"))
    conn.row_factory = sqlite3.Row
    return conn


def _row_to_dict(row) -> dict | None:
    """Normalize rows from both Turso and sqlite3 into plain dicts."""
    if row is None:
        return None
    # sqlite3.Row supports keys(); Turso rows are index-based tuples
    if hasattr(row, 'keys'):
        return dict(row)
    return {
        "id": row[0],
        "username": row[1],
        "password_hash": row[2],
        "account_key": row[3],
        "from_address": row[4],
    }


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
