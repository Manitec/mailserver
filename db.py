"""
db.py - Turso HTTP API via httpx (no WebSockets, no Rust, works on Render free tier).
Falls back to local SQLite when TURSO_URL is not set.
"""
import os
import sqlite3
import httpx

_raw_url = os.getenv("TURSO_URL", "").rstrip("/")
# Turso env vars come as libsql:// — convert to https:// for HTTP API
TURSO_URL = _raw_url.replace("libsql://", "https://") if _raw_url else ""
TURSO_AUTH_TOKEN = os.getenv("TURSO_AUTH_TOKEN", "")
USE_TURSO = bool(TURSO_URL and TURSO_AUTH_TOKEN)


def _turso_request(statements: list[dict]) -> list:
    url = f"{TURSO_URL}/v2/pipeline"
    headers = {
        "Authorization": f"Bearer {TURSO_AUTH_TOKEN}",
        "Content-Type": "application/json",
    }
    requests = [{"type": "execute", "stmt": {"sql": s["q"], "args": [
        {"type": "text", "value": str(v)} if isinstance(v, str)
        else {"type": "integer", "value": str(v)} if isinstance(v, int)
        else {"type": "null"} if v is None
        else {"type": "text", "value": str(v)}
        for v in s.get("params", [])
    ]}} for s in statements]
    requests.append({"type": "close"})

    resp = httpx.post(url, json={"requests": requests}, headers=headers, timeout=10)
    resp.raise_for_status()
    return resp.json()["results"]


class TursoConnection:
    def __init__(self):
        self._last_result = None

    def execute(self, sql: str, params: tuple = ()):
        result = _turso_request([{"q": sql, "params": list(params)}])
        self._last_result = result[0]
        return _TursoResult(self._last_result)

    def commit(self):
        pass

    def close(self):
        pass


class _TursoResult:
    def __init__(self, result):
        try:
            response = result.get("response", {})
            rs = response.get("result", {})
            cols = [c["name"] for c in rs.get("cols", [])]
            self._rows = [
                {cols[i]: (cell.get("value") if cell.get("type") != "null" else None)
                 for i, cell in enumerate(row)}
                for row in rs.get("rows", [])
            ]
        except Exception:
            self._rows = []

    def fetchone(self):
        return self._rows[0] if self._rows else None

    def fetchall(self):
        return self._rows


class SQLiteConnection:
    def __init__(self):
        self._conn = sqlite3.connect(os.getenv("DB_PATH", "users.db"))
        self._conn.row_factory = sqlite3.Row

    def execute(self, sql: str, params: tuple = ()):
        cursor = self._conn.execute(sql, params)
        return _SQLiteResult(cursor)

    def commit(self):
        self._conn.commit()

    def close(self):
        self._conn.close()


class _SQLiteResult:
    def __init__(self, cursor):
        self._cursor = cursor

    def fetchone(self):
        row = self._cursor.fetchone()
        return dict(row) if row else None

    def fetchall(self):
        return [dict(r) for r in self._cursor.fetchall()]


def get_db():
    return TursoConnection() if USE_TURSO else SQLiteConnection()


def _row_to_dict(row) -> dict | None:
    if row is None:
        return None
    if isinstance(row, dict):
        return row
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
