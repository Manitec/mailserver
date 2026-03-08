from fastapi import FastAPI, HTTPException, Request, Form
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse, FileResponse, RedirectResponse
from pydantic import BaseModel
from dotenv import load_dotenv
import os
import httpx
import secrets
import sqlite3
import hashlib

# Load credentials
load_dotenv()
CLIENT_ID = os.getenv("CLIENT_ID")
CLIENT_SECRET = os.getenv("CLIENT_SECRET")
REFRESH_TOKEN = os.getenv("REFRESH_TOKEN")

BASE_URL = "https://mail360.zoho.com"
DB_PATH = "users.db"

app = FastAPI()

# Session storage: token -> user_id
active_sessions: dict[str, int] = {}

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["GET", "POST", "DELETE"],
    allow_headers=["*"],
)

app.mount("/static", StaticFiles(directory="static"), name="static")


class SendRequest(BaseModel):
    to: str
    subject: str
    content: str


class ForwardRequest(BaseModel):
    to: str
    subject: str
    content: str
    original_content: str


def hash_password(password: str) -> str:
    return hashlib.sha256(password.encode("utf-8")).hexdigest()


def get_user_by_username(username: str):
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("SELECT id, username, password_hash, account_key, from_address FROM users WHERE username = ?", (username,))
    row = cur.fetchone()
    conn.close()
    if not row:
        return None
    return {"id": row[0], "username": row[1], "password_hash": row[2], "account_key": row[3], "from_address": row[4]}


def get_user_by_id(user_id: int):
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("SELECT id, username, password_hash, account_key, from_address FROM users WHERE id = ?", (user_id,))
    row = cur.fetchone()
    conn.close()
    if not row:
        return None
    return {"id": row[0], "username": row[1], "password_hash": row[2], "account_key": row[3], "from_address": row[4]}


def get_current_user(request: Request):
    session_token = request.cookies.get("session")
    print(f"\n=== AUTH CHECK ===")
    print(f"Cookie token: {session_token[:20] if session_token else 'None'}...")
    print(f"Active sessions count: {len(active_sessions)}")
    
    if not session_token:
        print("No session cookie!")
        raise HTTPException(status_code=401, detail="Not authenticated")
    
    if session_token not in active_sessions:
        print(f"Token not in active_sessions!")
        print(f"Available keys: {list(active_sessions.keys())[:3]}")
        raise HTTPException(status_code=401, detail="Not authenticated")
    
    user_id = active_sessions[session_token]
    user = get_user_by_id(user_id)
    
    if not user:
        print(f"User ID {user_id} not found in DB!")
        raise HTTPException(status_code=401, detail="User not found")
    
    print(f"Authenticated as: {user['username']}")
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


LOGIN_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Login - Mail360 Client</title>
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
        label {
            display: block;
            margin-bottom: 8px;
            font-size: 14px;
            font-weight: 500;
            color: #e2e8f0;
        }
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
        input:focus {
            outline: none;
            border-color: #3b82f6;
            box-shadow: 0 0 0 3px rgba(59, 130, 246, 0.2);
        }
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
        button:hover {
            background: #2563eb;
            transform: translateY(-1px);
            box-shadow: 0 4px 12px rgba(59, 130, 246, 0.3);
        }
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
            <h1>📧 Mail360</h1>
            <p>Email Client Login</p>
        </div>
        <div id="error" class="error">Invalid username or password</div>
        <form id="loginForm">
            <div class="form-group">
                <label for="username">Username</label>
                <input id="username" name="username" required autofocus>
            </div>
            <div class="form-group">
                <label for="password">Password</label>
                <input type="password" id="password" name="password" required>
            </div>
            <button type="submit">Login</button>
        </form>
    </div>
    <script>
        document.getElementById('loginForm').addEventListener('submit', async (e) => {
            e.preventDefault();
            const username = document.getElementById('username').value;
            const password = document.getElementById('password').value;
            const formData = new FormData();
            formData.append('username', username);
            formData.append('password', password);
            try {
                const resp = await fetch('/login', { method: 'POST', body: formData });
                if (resp.ok) {
                    window.location.href = '/';
                } else {
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

@app.get("/admin")
def admin_page():
    """Simple web admin interface to add users"""
    return HTMLResponse(content="""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Admin - Add User | Mail360</title>
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
        .container {
            background: #334155;
            padding: 40px;
            border-radius: 16px;
            box-shadow: 0 20px 40px rgba(0, 0, 0, 0.4);
            width: 100%;
            max-width: 450px;
            border: 1px solid #475569;
        }
        h1 {
            text-align: center;
            margin-bottom: 24px;
            color: #3b82f6;
            font-size: 24px;
        }
        .form-group {
            margin-bottom: 20px;
        }
        label {
            display: block;
            margin-bottom: 8px;
            font-size: 14px;
            font-weight: 500;
            color: #e2e8f0;
        }
        input {
            width: 100%;
            padding: 12px 16px;
            background: #1e293b;
            border: 1px solid #475569;
            border-radius: 8px;
            color: #f1f5f9;
            font-size: 14px;
        }
        input:focus {
            outline: none;
            border-color: #3b82f6;
            box-shadow: 0 0 0 3px rgba(59, 130, 246, 0.2);
        }
        button {
            width: 100%;
            padding: 14px;
            background: #10b981;
            color: white;
            border: none;
            border-radius: 8px;
            font-size: 16px;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.2s;
        }
        button:hover {
            background: #059669;
            transform: translateY(-1px);
        }
        .success {
            background: rgba(16, 185, 129, 0.1);
            border: 1px solid #10b981;
            color: #10b981;
            padding: 12px;
            border-radius: 8px;
            margin-bottom: 20px;
            font-size: 14px;
            display: none;
        }
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
        .back-link {
            display: block;
            text-align: center;
            margin-top: 20px;
            color: #94a3b8;
            text-decoration: none;
            font-size: 14px;
        }
        .back-link:hover {
            color: #3b82f6;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>👤 Add New User</h1>
        <div id="success" class="success">User created successfully!</div>
        <div id="error" class="error"></div>
        <form id="addUserForm">
            <div class="form-group">
                <label for="username">Username</label>
                <input type="text" id="username" name="username" required placeholder="john.doe">
            </div>
            <div class="form-group">
                <label for="password">Password</label>
                <input type="password" id="password" name="password" required placeholder="Secure password">
            </div>
            <div class="form-group">
                <label for="account_key">Mail360 Account Key</label>
                <input type="text" id="account_key" name="account_key" required placeholder="e.g., AbC123XyZ789">
            </div>
            <div class="form-group">
                <label for="email">Email Address</label>
                <input type="email" id="email" name="email" required placeholder="john@manitec.pw">
            </div>
            <button type="submit">➕ Create User</button>
        </form>
        <a href="/" class="back-link">← Back to Mail</a>
    </div>

    <script>
        document.getElementById('addUserForm').addEventListener('submit', async (e) => {
            e.preventDefault();
            
            const formData = new FormData();
            formData.append('username', document.getElementById('username').value);
            formData.append('password', document.getElementById('password').value);
            formData.append('account_key', document.getElementById('account_key').value);
            formData.append('email', document.getElementById('email').value);
            
            document.getElementById('success').style.display = 'none';
            document.getElementById('error').style.display = 'none';
            
            try {
                const resp = await fetch('/admin/add-user', {
                    method: 'POST',
                    body: formData
                });
                
                if (resp.ok) {
                    document.getElementById('success').style.display = 'block';
                    document.getElementById('addUserForm').reset();
                } else {
                    const err = await resp.text();
                    document.getElementById('error').textContent = 'Error: ' + err;
                    document.getElementById('error').style.display = 'block';
                }
            } catch (err) {
                document.getElementById('error').textContent = 'Error: ' + err.message;
                document.getElementById('error').style.display = 'block';
            }
        });
    </script>
</body>
</html>""")

@app.post("/admin/add-user")
def add_user(request: Request, username: str = Form(...), password: str = Form(...), 
             account_key: str = Form(...), email: str = Form(...)):
    # Only logged-in users can add new users (simple security)
    # You could restrict to just user ID 1 (first user) if you want:
     current = get_current_user(request)
     if current["id"] != 2:
         raise HTTPException(status_code=403, detail="Admin only")
     conn = sqlite3.connect(DB_PATH)
     cur = conn.cursor()
     try:
        cur.execute(
            "INSERT INTO users (username, password_hash, account_key, from_address) VALUES (?, ?, ?, ?)",
            (username, hash_password(password), account_key, email),
        )
        conn.commit()
        return {"status": "user created", "username": username, "email": email}
     except sqlite3.IntegrityError:
        raise HTTPException(status_code=400, detail="Username already exists")
     finally:
       conn.close()
@app.get("/debug/user")
def debug_user(request: Request):
    try:
        user = get_current_user(request)
        return {"logged_in": True, "user": user["username"], "email": user["from_address"]}
    except:
        return {"logged_in": False, "error": "Not authenticated"}

@app.get("/login")
def login_page():
    return HTMLResponse(content=LOGIN_HTML)


@app.post("/login")
def do_login(username: str = Form(...), password: str = Form(...)):
    print(f"\n=== LOGIN ATTEMPT ===")
    print(f"Username: {username}")
    
    user = get_user_by_username(username)
    if not user:
        print("User not found!")
        raise HTTPException(status_code=401, detail="Invalid credentials")
    
    if user["password_hash"] != hash_password(password):
        print("Password mismatch!")
        raise HTTPException(status_code=401, detail="Invalid credentials")
    
    session_token = secrets.token_urlsafe(32)
    active_sessions[session_token] = user["id"]
    
    print(f"User {user['username']} (ID: {user['id']}) logged in")
    print(f"Session token: {session_token[:20]}...")
    print(f"Total active sessions: {len(active_sessions)}")
    print(f"Active sessions keys: {list(active_sessions.keys())[:3]}")
    
    response = RedirectResponse(url="/", status_code=302)
    response.set_cookie(
        key="session",
        value=session_token,
        httponly=False,
        secure=False,
        samesite="lax",
        max_age=86400
    )
    return response

@app.post("/admin/add-user")
def add_user(request: Request, username: str = Form(...), password: str = Form(...), 
             account_key: str = Form(...), email: str = Form(...)):
    # Check if requester is admin (first user)
    current = get_current_user(request)
    if current["id"] != 1:  # Only user ID 1 (first user) is admin
        raise HTTPException(status_code=403, detail="Admin only")
    
    # Add new user to DB
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    try:
        cur.execute(
            "INSERT INTO users (username, password_hash, account_key, from_address) VALUES (?, ?, ?, ?)",
            (username, hash_password(password), account_key, email),
        )
        conn.commit()
        return {"status": "user created"}
    except sqlite3.IntegrityError:
        raise HTTPException(status_code=400, detail="Username exists")
    finally:
        conn.close()


@app.get("/logout")
def logout(request: Request):
    session_token = request.cookies.get("session")
    if session_token in active_sessions:
        del active_sessions[session_token]
    response = RedirectResponse(url="/login", status_code=302)
    response.delete_cookie("session")
    return response


@app.get("/")
def read_root(request: Request):
    session_token = request.cookies.get("session")
    if not session_token or session_token not in active_sessions:
        return RedirectResponse(url="/login", status_code=302)
    return FileResponse("static/index.html")


@app.get("/inbox")
def get_inbox(request: Request, limit: int = 10):
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

@app.get("/me")
def get_current_user_info(request: Request):
    user = get_current_user(request)
    return {
        "username": user["username"],
        "email": user["from_address"]
    }


@app.post("/send")
def send_email(request: Request, req: SendRequest):
    user = get_current_user(request)
    token = get_access_token()
    url = f"{BASE_URL}/api/accounts/{user['account_key']}/messages"
    headers = {"Authorization": f"Zoho-oauthtoken {token}"}
    payload = {
        "fromAddress": user["from_address"],
        "toAddress": req.to,
        "subject": req.subject,
        "content": req.content,
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
    url = f"{BASE_URL}/api/accounts/{user['account_key']}/messages/{message_id}"
    headers = {"Authorization": f"Zoho-oauthtoken {token}"}
    payload = {
        "action": "reply",
        "fromAddress": user["from_address"],
        "toAddress": req.to,
        "subject": req.subject,
        "content": req.content,
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
    url = f"{BASE_URL}/api/accounts/{user['account_key']}/messages"
    headers = {"Authorization": f"Zoho-oauthtoken {token}"}

    full_content = f"{req.content}\n\n--- Forwarded message ---\n{req.original_content}"

    payload = {
        "fromAddress": user["from_address"],
        "toAddress": req.to,
        "subject": req.subject,
        "content": full_content,
        "mailFormat": "plaintext",
    }
    resp = httpx.post(url, headers=headers, json=payload)
    if resp.status_code in (200, 201, 202):
        return {"status": "sent"}
    raise HTTPException(status_code=resp.status_code, detail=resp.text)


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=int(os.getenv("PORT", 8000)))
