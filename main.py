from fastapi import FastAPI, HTTPException, Request, Form
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse, FileResponse, RedirectResponse, JSONResponse
from pydantic import BaseModel
from dotenv import load_dotenv
import os
import httpx
import secrets
import sqlite3
import hashlib
import time
import bcrypt

from middleware import RateLimitMiddleware
from validators import is_valid_email, sanitize_input, is_strong_password

# Load credentials
load_dotenv()
CLIENT_ID = os.getenv("CLIENT_ID")
CLIENT_SECRET = os.getenv("CLIENT_SECRET")
REFRESH_TOKEN = os.getenv("REFRESH_TOKEN")

BASE_URL = "https://mail360.zoho.com"
DB_PATH = os.getenv("DB_PATH", "users.db")

SESSION_TTL = 86400  # 24 hours in seconds

app = FastAPI(title="Manitec Mail")

# ---------------------------------------------------------------------------
# Database helpers
# ---------------------------------------------------------------------------

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    """Ensure all required tables exist (safe to call on every startup)."""
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
    conn.execute("""
        CREATE TABLE IF NOT EXISTS sessions (
            token      TEXT    PRIMARY KEY,
            user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            expires_at INTEGER NOT NULL
        )
    """)
    conn.execute("CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id)")
    conn.commit()
    conn.close()


def create_session(user_id: int) -> str:
    token = secrets.token_urlsafe(32)
    expires_at = int(time.time()) + SESSION_TTL
    conn = get_db()
    conn.execute(
        "INSERT INTO sessions (token, user_id, expires_at) VALUES (?, ?, ?)",
        (token, user_id, expires_at),
    )
    conn.commit()
    conn.close()
    return token


def get_session_user_id(token: str) -> int | None:
    """Return user_id for a valid, non-expired token, or None."""
    conn = get_db()
    row = conn.execute(
        "SELECT user_id FROM sessions WHERE token = ? AND expires_at > ?",
        (token, int(time.time())),
    ).fetchone()
    conn.close()
    return row["user_id"] if row else None


def delete_session(token: str):
    conn = get_db()
    conn.execute("DELETE FROM sessions WHERE token = ?", (token,))
    conn.commit()
    conn.close()


def purge_expired_sessions():
    """Clean up expired rows — called after login to keep the table lean."""
    conn = get_db()
    conn.execute("DELETE FROM sessions WHERE expires_at <= ?", (int(time.time()),))
    conn.commit()
    conn.close()


# Run migrations on startup
init_db()

# ---------------------------------------------------------------------------
# Password helpers
# ---------------------------------------------------------------------------

SHA256_LEN = 64  # hex-encoded SHA-256 is always 64 chars


def _is_sha256_hash(value: str) -> bool:
    """Detect a legacy SHA-256 hex hash (64 lowercase hex chars)."""
    if len(value) != SHA256_LEN:
        return False
    try:
        int(value, 16)
        return True
    except ValueError:
        return False


def hash_password_bcrypt(password: str) -> str:
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()


def verify_password(password: str, stored_hash: str) -> bool:
    """Verify against bcrypt or legacy SHA-256, transparently."""
    if _is_sha256_hash(stored_hash):
        # Legacy path — compare with SHA-256
        return hashlib.sha256(password.encode()).hexdigest() == stored_hash
    # Modern path — bcrypt
    return bcrypt.checkpw(password.encode(), stored_hash.encode())


def migrate_to_bcrypt(user_id: int, password: str):
    """Upgrade a legacy SHA-256 hash to bcrypt in-place on successful login."""
    new_hash = hash_password_bcrypt(password)
    conn = get_db()
    conn.execute(
        "UPDATE users SET password_hash = ? WHERE id = ?",
        (new_hash, user_id),
    )
    conn.commit()
    conn.close()


# ---------------------------------------------------------------------------
# Middleware
# ---------------------------------------------------------------------------

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["GET", "POST", "DELETE"],
    allow_headers=["*"],
)

app.add_middleware(RateLimitMiddleware, max_requests=100, window_seconds=60)

app.add_middleware(
    TrustedHostMiddleware,
    allowed_hosts=[
        "localhost",
        "127.0.0.1",
        "mail.manitec.pw",
        "manitec.pw",
        "mailserver-gjlu.onrender.com/",
        "*.onrender.com",
    ],
)

# NOTE: StaticFiles mount is at the BOTTOM of this file so that
# named routes (like the /static/index.html block below) take priority.

# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------

class SendRequest(BaseModel):
    to: str
    subject: str
    content: str


class ForwardRequest(BaseModel):
    to: str
    subject: str
    content: str
    original_content: str


# ---------------------------------------------------------------------------
# User / auth helpers
# ---------------------------------------------------------------------------

def get_user_by_username(username: str):
    conn = get_db()
    row = conn.execute(
        "SELECT id, username, password_hash, account_key, from_address "
        "FROM users WHERE username = ?",
        (username,),
    ).fetchone()
    conn.close()
    return dict(row) if row else None


def get_user_by_id(user_id: int):
    conn = get_db()
    row = conn.execute(
        "SELECT id, username, password_hash, account_key, from_address "
        "FROM users WHERE id = ?",
        (user_id,),
    ).fetchone()
    conn.close()
    return dict(row) if row else None


def get_current_user(request: Request):
    token = request.cookies.get("session")
    if not token:
        raise HTTPException(status_code=401, detail="Not authenticated")
    user_id = get_session_user_id(token)
    if user_id is None:
        raise HTTPException(status_code=401, detail="Session expired or invalid")
    user = get_user_by_id(user_id)
    if not user:
        raise HTTPException(status_code=401, detail="User not found")
    return user


def get_access_token() -> str:
    url = f"{BASE_URL}/api/access-token"
    payload = {
        "refresh_token": REFRESH_TOKEN,
        "client_id": CLIENT_ID,
        "client_secret": CLIENT_SECRET,
    }
    resp = httpx.post(url, json=payload)
    resp.raise_for_status()
    return resp.json()["data"]["access_token"]


# ---------------------------------------------------------------------------
# Login page HTML
# ---------------------------------------------------------------------------

LOGIN_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Login - Manitec Mail</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: linear-gradient(135deg, #0f172a 0%, #1e293b 100%);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            color: #f1f5f9;
        }
        .login-container {
            background: #334155;
            padding: 40px;
            border-radius: 16px;
            box-shadow: 0 20px 40px rgba(0, 0, 0, 0.4);
            width: 100%;
            max-width: 400px;
            border: 1px solid #475569;
        }
        .login-header { text-align: center; margin-bottom: 30px; }
        .login-header h1 { font-size: 28px; margin-bottom: 10px; color: #3b82f6; }
        .login-header p { color: #94a3b8; font-size: 14px; }
        .form-group { margin-bottom: 20px; }
        label { display: block; margin-bottom: 8px; font-size: 14px; font-weight: 500; color: #e2e8f0; }
        input {
            width: 100%;
            padding: 12px 16px;
            background: #1e293b;
            border: 1px solid #475569;
            border-radius: 8px;
            color: #f1f5f9;
            font-size: 16px;
            transition: all 0.2s;
        }
        input:focus { outline: none; border-color: #3b82f6; box-shadow: 0 0 0 3px rgba(59, 130, 246, 0.2); }
        button {
            width: 100%;
            padding: 14px;
            background: #3b82f6;
            color: white;
            border: none;
            border-radius: 8px;
            font-size: 16px;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.2s;
        }
        button:hover { background: #2563eb; transform: translateY(-1px); box-shadow: 0 4px 12px rgba(59, 130, 246, 0.3); }
        .error {
            background: rgba(239, 68, 68, 0.1);
            border: 1px solid #ef4444;
            color: #ef4444;
            padding: 12px;
            border-radius: 8px;
            margin-bottom: 20px;
            font-size: 14px;
            display: none;
        }
        .error.show { display: block; }
    </style>
</head>
<body>
    <div class="login-container">
        <div class="login-header">
            <h1>Manitec Mail</h1>
            <p>Sign in to continue</p>
        </div>
        <div id="error" class="error">Invalid username or password</div>
        <form id="loginForm">
            <div class="form-group">
                <label for="username">Username</label>
                <input id="username" name="username" required autofocus autocomplete="username" autocapitalize="none">
            </div>
            <div class="form-group">
                <label for="password">Password</label>
                <input type="password" id="password" name="password" required autocomplete="current-password">
            </div>
            <button type="submit">Sign in</button>
        </form>
    </div>
    <script>
        document.getElementById('loginForm').addEventListener('submit', async (e) => {
            e.preventDefault();
            const formData = new FormData();
            formData.append('username', document.getElementById('username').value);
            formData.append('password', document.getElementById('password').value);
            try {
                const resp = await fetch('/login', { method: 'POST', body: formData });
                if (resp.ok) { window.location.href = '/'; }
                else {
                    document.getElementById('error').classList.add('show');
                    document.getElementById('password').value = '';
                }
            } catch (err) {
                document.getElementById('error').textContent = 'Error: ' + err.message;
                document.getElementById('error').classList.add('show');
            }
        });
    </script>
</body>
</html>"""


# ---------------------------------------------------------------------------
# Auth routes
# ---------------------------------------------------------------------------

@app.get("/login")
def login_page():
    return HTMLResponse(content=LOGIN_HTML)


@app.post("/login")
def do_login(username: str = Form(...), password: str = Form(...)):
    username_clean = sanitize_input(username, max_length=64).lower()
    user = get_user_by_username(username_clean)

    if not user or not verify_password(password, user["password_hash"]):
        raise HTTPException(status_code=401, detail="Invalid credentials")

    # Transparent migration: upgrade SHA-256 → bcrypt on successful login
    if _is_sha256_hash(user["password_hash"]):
        migrate_to_bcrypt(user["id"], password)

    purge_expired_sessions()
    token = create_session(user["id"])

    response = RedirectResponse(url="/", status_code=302)
    response.set_cookie(
        key="session",
        value=token,
        httponly=True,
        secure=True,
        samesite="lax",
        max_age=SESSION_TTL,
    )
    return response


@app.get("/logout")
def logout(request: Request):
    token = request.cookies.get("session")
    if token:
        delete_session(token)
    response = RedirectResponse(url="/login", status_code=302)
    response.delete_cookie("session")
    return response


# ---------------------------------------------------------------------------
# App routes
# ---------------------------------------------------------------------------

@app.get("/")
def read_root(request: Request):
    token = request.cookies.get("session")
    if not token or get_session_user_id(token) is None:
        return RedirectResponse(url="/login", status_code=302)
    return FileResponse("static/index.html")


@app.get("/static/index.html")
def block_static_index(request: Request):
    token = request.cookies.get("session")
    if not token or get_session_user_id(token) is None:
        return RedirectResponse(url="/login", status_code=302)
    return RedirectResponse(url="/", status_code=302)


@app.get("/me")
def get_me(request: Request):
    user = get_current_user(request)
    return {"username": user["username"], "email": user["from_address"]}


@app.get("/inbox")
def get_inbox(request: Request, limit: int = 50):
    user = get_current_user(request)
    token = get_access_token()
    url = f"{BASE_URL}/api/accounts/{user['account_key']}/messages"
    headers = {"Authorization": f"Zoho-oauthtoken {token}"}
    params = {"searchKey": "in:inbox", "limit": limit}
    resp = httpx.get(url, headers=headers, params=params)
    resp.raise_for_status()
    return resp.json()["data"]


@app.get("/message/{message_id}")
def get_message_content(request: Request, message_id: str):
    user = get_current_user(request)
    token = get_access_token()
    url = f"{BASE_URL}/api/accounts/{user['account_key']}/messages/{message_id}/content"
    headers = {"Authorization": f"Zoho-oauthtoken {token}"}
    params = {"includeBlockContent": "true"}
    resp = httpx.get(url, headers=headers, params=params)
    resp.raise_for_status()
    return resp.json()["data"]


@app.post("/send")
def send_email(request: Request, req: SendRequest):
    user = get_current_user(request)
    token = get_access_token()
    to_addr = sanitize_input(req.to, max_length=320)
    subject = sanitize_input(req.subject, max_length=255)
    content = sanitize_input(req.content, max_length=10000)
    if not is_valid_email(to_addr):
        raise HTTPException(status_code=400, detail="Invalid recipient email")
    url = f"{BASE_URL}/api/accounts/{user['account_key']}/messages"
    headers = {"Authorization": f"Zoho-oauthtoken {token}"}
    payload = {
        "fromAddress": user["from_address"],
        "toAddress": to_addr,
        "subject": subject,
        "content": content,
        "mailFormat": "plaintext",
    }
    resp = httpx.post(url, headers=headers, json=payload)
    if resp.status_code in (200, 201, 202):
        return {"status": "sent"}
    raise HTTPException(status_code=resp.status_code, detail=resp.text)


@app.delete("/message/{message_id}")
def delete_message(request: Request, message_id: str):
    user = get_current_user(request)
    token = get_access_token()
    url = f"{BASE_URL}/api/accounts/{user['account_key']}/messages/{message_id}"
    headers = {"Authorization": f"Zoho-oauthtoken {token}"}
    resp = httpx.delete(url, headers=headers)
    resp.raise_for_status()
    return {"status": "deleted"}


@app.post("/reply/{message_id}")
def reply_to_message(request: Request, message_id: str, req: SendRequest):
    user = get_current_user(request)
    token = get_access_token()
    to_addr = sanitize_input(req.to, max_length=320)
    subject = sanitize_input(req.subject, max_length=255)
    content = sanitize_input(req.content, max_length=10000)
    if not is_valid_email(to_addr):
        raise HTTPException(status_code=400, detail="Invalid recipient email")
    url = f"{BASE_URL}/api/accounts/{user['account_key']}/messages/{message_id}"
    headers = {"Authorization": f"Zoho-oauthtoken {token}"}
    payload = {
        "action": "reply",
        "fromAddress": user["from_address"],
        "toAddress": to_addr,
        "subject": subject,
        "content": content,
        "mailFormat": "plaintext",
    }
    resp = httpx.post(url, headers=headers, json=payload)
    if resp.status_code in (200, 201, 202):
        return {"status": "sent"}
    raise HTTPException(status_code=resp.status_code, detail=resp.text)


@app.post("/forward")
def forward_message(request: Request, req: ForwardRequest):
    user = get_current_user(request)
    token = get_access_token()
    to_addr = sanitize_input(req.to, max_length=320)
    subject = sanitize_input(req.subject, max_length=255)
    content = sanitize_input(req.content, max_length=8000)
    original_content = sanitize_input(req.original_content, max_length=8000)
    if not is_valid_email(to_addr):
        raise HTTPException(status_code=400, detail="Invalid recipient email")
    url = f"{BASE_URL}/api/accounts/{user['account_key']}/messages"
    headers = {"Authorization": f"Zoho-oauthtoken {token}"}
    full_content = f"{content}\n\n--- Forwarded message ---\n{original_content}"
    payload = {
        "fromAddress": user["from_address"],
        "toAddress": to_addr,
        "subject": subject,
        "content": full_content,
        "mailFormat": "plaintext",
    }
    resp = httpx.post(url, headers=headers, json=payload)
    if resp.status_code in (200, 201, 202):
        return {"status": "sent"}
    raise HTTPException(status_code=resp.status_code, detail=resp.text)


# ---------------------------------------------------------------------------
# Admin
# ---------------------------------------------------------------------------

@app.get("/admin")
def admin_page():
    return HTMLResponse(content="""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Admin - Add User | Manitec Mail</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: linear-gradient(135deg, #0f172a 0%, #1e293b 100%); min-height: 100vh; display: flex; align-items: center; justify-content: center; color: #f1f5f9; }
        .container { background: #334155; padding: 40px; border-radius: 16px; box-shadow: 0 20px 40px rgba(0,0,0,.4); width: 100%; max-width: 450px; border: 1px solid #475569; }
        h1 { text-align: center; margin-bottom: 24px; color: #3b82f6; font-size: 24px; }
        .form-group { margin-bottom: 20px; }
        label { display: block; margin-bottom: 8px; font-size: 14px; font-weight: 500; color: #e2e8f0; }
        input { width: 100%; padding: 12px 16px; background: #1e293b; border: 1px solid #475569; border-radius: 8px; color: #f1f5f9; font-size: 14px; }
        input:focus { outline: none; border-color: #3b82f6; box-shadow: 0 0 0 3px rgba(59,130,246,0.2); }
        button { width: 100%; padding: 14px; background: #10b981; color: white; border: none; border-radius: 8px; font-size: 16px; font-weight: 600; cursor: pointer; transition: all 0.2s; }
        button:hover { background: #059669; transform: translateY(-1px); }
        .success { background: rgba(16,185,129,0.1); border: 1px solid #10b981; color: #10b981; padding: 12px; border-radius: 8px; margin-bottom: 20px; font-size: 14px; display: none; }
        .error { background: rgba(239,68,68,0.1); border: 1px solid #ef4444; color: #ef4444; padding: 12px; border-radius: 8px; margin-bottom: 20px; font-size: 14px; display: none; }
        .back-link { display: block; text-align: center; margin-top: 20px; color: #94a3b8; text-decoration: none; font-size: 14px; }
        .back-link:hover { color: #3b82f6; }
    </style>
</head>
<body>
    <div class="container">
        <h1>Add New User</h1>
        <div id="success" class="success">User created successfully!</div>
        <div id="error" class="error"></div>
        <form id="addUserForm">
            <div class="form-group"><label>Username</label><input type="text" id="username" required placeholder="john.doe"></div>
            <div class="form-group"><label>Password</label><input type="password" id="password" required placeholder="Secure password"></div>
            <div class="form-group"><label>Mail360 Account Key</label><input type="text" id="account_key" required placeholder="e.g., AbC123XyZ789"></div>
            <div class="form-group"><label>Email Address</label><input type="email" id="email" required placeholder="john@manitec.pw"></div>
            <button type="submit">Create User</button>
        </form>
        <a href="/" class="back-link">← Back to Mail</a>
    </div>
    <script>
        document.getElementById('addUserForm').addEventListener('submit', async (e) => {
            e.preventDefault();
            const fd = new FormData();
            fd.append('username', document.getElementById('username').value);
            fd.append('password', document.getElementById('password').value);
            fd.append('account_key', document.getElementById('account_key').value);
            fd.append('email', document.getElementById('email').value);
            document.getElementById('success').style.display = 'none';
            document.getElementById('error').style.display = 'none';
            try {
                const resp = await fetch('/admin/add-user', { method: 'POST', body: fd });
                if (resp.ok) { document.getElementById('success').style.display = 'block'; document.getElementById('addUserForm').reset(); }
                else { const err = await resp.text(); document.getElementById('error').textContent = 'Error: ' + err; document.getElementById('error').style.display = 'block'; }
            } catch (err) { document.getElementById('error').textContent = 'Error: ' + err.message; document.getElementById('error').style.display = 'block'; }
        });
    </script>
</body>
</html>""")


@app.post("/admin/add-user")
def add_user(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    account_key: str = Form(...),
    email: str = Form(...),
):
    current = get_current_user(request)
    if current["id"] != 2:
        raise HTTPException(status_code=403, detail="Admin only")
    username_clean = sanitize_input(username, max_length=64).lower()
    account_key_clean = sanitize_input(account_key, max_length=128)
    email_clean = sanitize_input(email, max_length=255)
    if not is_valid_email(email_clean):
        raise HTTPException(status_code=400, detail="Invalid email address")
    ok, msg = is_strong_password(password)
    if not ok:
        raise HTTPException(status_code=400, detail=msg)
    conn = get_db()
    try:
        conn.execute(
            "INSERT INTO users (username, password_hash, account_key, from_address) VALUES (?, ?, ?, ?)",
            (username_clean, hash_password_bcrypt(password), account_key_clean, email_clean),
        )
        conn.commit()
        return {"status": "user created", "username": username_clean, "email": email_clean}
    except sqlite3.IntegrityError:
        raise HTTPException(status_code=400, detail="Username already exists")
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# Settings
# ---------------------------------------------------------------------------

@app.get("/settings")
def settings_page():
    return HTMLResponse(content="""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Settings | Manitec Mail</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: linear-gradient(135deg, #0f172a 0%, #1e293b 100%); min-height: 100vh; display: flex; align-items: center; justify-content: center; color: #f1f5f9; }
        .container { background: #334155; padding: 40px; border-radius: 16px; box-shadow: 0 20px 40px rgba(0,0,0,.4); width: 100%; max-width: 450px; border: 1px solid #475569; }
        h1 { text-align: center; margin-bottom: 24px; color: #3b82f6; font-size: 24px; }
        .form-group { margin-bottom: 20px; }
        label { display: block; margin-bottom: 8px; font-size: 14px; font-weight: 500; color: #e2e8f0; }
        input { width: 100%; padding: 12px 16px; background: #1e293b; border: 1px solid #475569; border-radius: 8px; color: #f1f5f9; font-size: 14px; }
        input:focus { outline: none; border-color: #3b82f6; box-shadow: 0 0 0 3px rgba(59,130,246,0.2); }
        button { width: 100%; padding: 14px; background: #3b82f6; color: white; border: none; border-radius: 8px; font-size: 16px; font-weight: 600; cursor: pointer; transition: all 0.2s; }
        button:hover { background: #2563eb; transform: translateY(-1px); }
        .success { background: rgba(16,185,129,0.1); border: 1px solid #10b981; color: #10b981; padding: 12px; border-radius: 8px; margin-bottom: 20px; font-size: 14px; display: none; }
        .error { background: rgba(239,68,68,0.1); border: 1px solid #ef4444; color: #ef4444; padding: 12px; border-radius: 8px; margin-bottom: 20px; font-size: 14px; display: none; }
        .warning { background: rgba(245,158,11,0.1); border: 1px solid #f59e0b; color: #f59e0b; padding: 12px; border-radius: 8px; margin-bottom: 20px; font-size: 14px; }
        .back-link { display: block; text-align: center; margin-top: 20px; color: #94a3b8; text-decoration: none; font-size: 14px; }
        .back-link:hover { color: #3b82f6; }
    </style>
</head>
<body>
    <div class="container">
        <h1>Change Password</h1>
        <div class="warning">You must know your current password to change it.</div>
        <div id="success" class="success">Password changed successfully!</div>
        <div id="error" class="error"></div>
        <form id="changePasswordForm">
            <div class="form-group"><label>Current Password</label><input type="password" id="current_password" required autocomplete="current-password"></div>
            <div class="form-group"><label>New Password</label><input type="password" id="new_password" required autocomplete="new-password"></div>
            <div class="form-group"><label>Confirm New Password</label><input type="password" id="confirm_password" required autocomplete="new-password"></div>
            <button type="submit">Change Password</button>
        </form>
        <a href="/" class="back-link">← Back to Mail</a>
    </div>
    <script>
        document.getElementById('changePasswordForm').addEventListener('submit', async (e) => {
            e.preventDefault();
            const np = document.getElementById('new_password').value;
            const cp = document.getElementById('confirm_password').value;
            document.getElementById('success').style.display = 'none';
            document.getElementById('error').style.display = 'none';
            if (np !== cp) { document.getElementById('error').textContent = 'New passwords do not match'; document.getElementById('error').style.display = 'block'; return; }
            const fd = new FormData();
            fd.append('current_password', document.getElementById('current_password').value);
            fd.append('new_password', np);
            try {
                const resp = await fetch('/settings/change-password', { method: 'POST', body: fd });
                if (resp.ok) { document.getElementById('success').style.display = 'block'; document.getElementById('changePasswordForm').reset(); setTimeout(() => { window.location.href = '/logout'; }, 2000); }
                else { const err = await resp.text(); document.getElementById('error').textContent = 'Error: ' + err; document.getElementById('error').style.display = 'block'; }
            } catch (err) { document.getElementById('error').textContent = 'Error: ' + err.message; document.getElementById('error').style.display = 'block'; }
        });
    </script>
</body>
</html>""")


@app.post("/settings/change-password")
def change_password(
    request: Request,
    current_password: str = Form(...),
    new_password: str = Form(...),
):
    user = get_current_user(request)
    if not verify_password(current_password, user["password_hash"]):
        raise HTTPException(status_code=401, detail="Current password is incorrect")
    ok, msg = is_strong_password(new_password)
    if not ok:
        raise HTTPException(status_code=400, detail=msg)
    conn = get_db()
    try:
        conn.execute(
            "UPDATE users SET password_hash = ? WHERE id = ?",
            (hash_password_bcrypt(new_password), user["id"]),
        )
        conn.commit()
        return {"status": "password changed"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# Static files
# ---------------------------------------------------------------------------

@app.get("/static/sw.js")
def service_worker():
    return FileResponse("static/sw.js", media_type="application/javascript")


# Static files mount LAST — named routes above take priority.
app.mount("/static", StaticFiles(directory="static"), name="static")


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=int(os.getenv("PORT", 8000)))
