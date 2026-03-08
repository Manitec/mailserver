from fastapi import FastAPI, HTTPException, Request, Form
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse, FileResponse, RedirectResponse
from pydantic import BaseModel
from dotenv import load_dotenv
import os
import httpx
import secrets

# Load credentials
load_dotenv()
CLIENT_ID = os.getenv("CLIENT_ID")
CLIENT_SECRET = os.getenv("CLIENT_SECRET")
REFRESH_TOKEN = os.getenv("REFRESH_TOKEN")
# Set this in your environment variables
APP_PASSWORD = os.getenv("APP_PASSWORD")
# Account config
ACCOUNT_KEY = "I7k71md8l03w9"
FROM_ADDRESS = "justin.lavey@manitec.pw"
BASE_URL = "https://mail360.zoho.com"

app = FastAPI()

# Session storage (simple in-memory)
active_sessions = set()

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["GET", "POST", "DELETE"],
    allow_headers=["*"],
)

# Serve static files
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


def is_authenticated(request: Request) -> bool:
    session_token = request.cookies.get("session")
    return session_token in active_sessions


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
        .login-header {
            text-align: center;
            margin-bottom: 30px;
        }
        .login-header h1 {
            font-size: 28px;
            margin-bottom: 10px;
            color: #3b82f6;
        }
        .login-header p {
            color: #94a3b8;
            font-size: 14px;
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
        input[type="password"] {
            width: 100%;
            padding: 12px 16px;
            background: #1e293b;
            border: 1px solid #475569;
            border-radius: 8px;
            color: #f1f5f9;
            font-size: 16px;
            transition: all 0.2s;
        }
        input[type="password"]:focus {
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
        <div id="error" class="error">Invalid password</div>
        <form id="loginForm">
            <div class="form-group">
                <label for="password">Password</label>
                <input type="password" id="password" name="password" placeholder="Enter password" required autofocus>
            </div>
            <button type="submit">Login</button>
        </form>
    </div>
    <script>
        document.getElementById('loginForm').addEventListener('submit', async (e) => {
            e.preventDefault();
            const password = document.getElementById('password').value;
            const formData = new FormData();
            formData.append('password', password);
            try {
                const resp = await fetch('/login', { method: 'POST', body: formData });
                if (resp.ok) {
                    window.location.href = '/';
                } else {
                    document.getElementById('error').classList.add('show');
                    document.getElementById('password').value = '';
                    document.getElementById('password').focus();
                }
            } catch (err) {
                document.getElementById('error').textContent = 'Error: ' + err.message;
                document.getElementById('error').classList.add('show');
            }
        });
    </script>
</body>
</html>"""


@app.get("/login")
def login_page():
    return HTMLResponse(content=LOGIN_HTML)


@app.post("/login")
def do_login(password: str = Form(...)):
    if password == APP_PASSWORD:
        session_token = secrets.token_urlsafe(32)
        active_sessions.add(session_token)
        
        response = RedirectResponse(url="/", status_code=302)
        response.set_cookie(
            key="session",
            value=session_token,
            httponly=True,
            secure=False,
            samesite="lax",
            max_age=86400
        )
        return response
    else:
        raise HTTPException(status_code=401, detail="Invalid password")


@app.get("/logout")
def logout(request: Request):
    session_token = request.cookies.get("session")
    if session_token in active_sessions:
        active_sessions.remove(session_token)
    response = RedirectResponse(url="/login", status_code=302)
    response.delete_cookie("session")
    return response


@app.get("/")
def read_root(request: Request):
    if not is_authenticated(request):
        return RedirectResponse(url="/login", status_code=302)
    return FileResponse("static/index.html")


@app.get("/inbox")
def get_inbox(request: Request, limit: int = 10):
    if not is_authenticated(request):
        raise HTTPException(status_code=401, detail="Not authenticated")
    
    token = get_access_token()
    url = f"{BASE_URL}/api/accounts/{ACCOUNT_KEY}/messages"
    headers = {"Authorization": f"Zoho-oauthtoken {token}"}
    params = {"searchKey": "in:inbox", "limit": limit}
    resp = httpx.get(url, headers=headers, params=params)
    resp.raise_for_status()
    return resp.json()["data"]


@app.get("/message/{message_id}")
def get_message_content(request: Request, message_id: str):
    if not is_authenticated(request):
        raise HTTPException(status_code=401, detail="Not authenticated")
    
    token = get_access_token()
    url = f"{BASE_URL}/api/accounts/{ACCOUNT_KEY}/messages/{message_id}/content"
    headers = {"Authorization": f"Zoho-oauthtoken {token}"}
    params = {"includeBlockContent": "true"}
    resp = httpx.get(url, headers=headers, params=params)
    resp.raise_for_status()
    return resp.json()["data"]


@app.post("/send")
def send_email(request: Request, req: SendRequest):
    if not is_authenticated(request):
        raise HTTPException(status_code=401, detail="Not authenticated")
    
    token = get_access_token()
    url = f"{BASE_URL}/api/accounts/{ACCOUNT_KEY}/messages"
    headers = {"Authorization": f"Zoho-oauthtoken {token}"}
    payload = {
        "fromAddress": FROM_ADDRESS,
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
    if not is_authenticated(request):
        raise HTTPException(status_code=401, detail="Not authenticated")
    
    token = get_access_token()
    url = f"{BASE_URL}/api/accounts/{ACCOUNT_KEY}/messages/{message_id}"
    headers = {"Authorization": f"Zoho-oauthtoken {token}"}
    resp = httpx.delete(url, headers=headers)
    resp.raise_for_status()
    return {"status": "deleted"}


@app.post("/reply/{message_id}")
def reply_to_message(request: Request, message_id: str, req: SendRequest):
    if not is_authenticated(request):
        raise HTTPException(status_code=401, detail="Not authenticated")
    
    token = get_access_token()
    url = f"{BASE_URL}/api/accounts/{ACCOUNT_KEY}/messages/{message_id}"
    headers = {"Authorization": f"Zoho-oauthtoken {token}"}
    payload = {
        "action": "reply",
        "fromAddress": FROM_ADDRESS,
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
    if not is_authenticated(request):
        raise HTTPException(status_code=401, detail="Not authenticated")
    
    token = get_access_token()
    url = f"{BASE_URL}/api/accounts/{ACCOUNT_KEY}/messages"
    headers = {"Authorization": f"Zoho-oauthtoken {token}"}
    
    full_content = f"{req.content}\n\n--- Forwarded message ---\n{req.original_content}"
    
    payload = {
        "fromAddress": FROM_ADDRESS,
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
