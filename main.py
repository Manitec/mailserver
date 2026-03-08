from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from pydantic import BaseModel
from dotenv import load_dotenv
import os
import httpx

# Load credentials
load_dotenv()
CLIENT_ID = os.getenv("CLIENT_ID")
CLIENT_SECRET = os.getenv("CLIENT_SECRET")
REFRESH_TOKEN = os.getenv("REFRESH_TOKEN")

# Account config
ACCOUNT_KEY = "I7k71md8l03w9"
FROM_ADDRESS = "justin.lavey@manitec.pw"
BASE_URL = "https://mail360.zoho.com"

app = FastAPI()

# CORS for development (restrict in production)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["GET", "POST", "DELETE"],
    allow_headers=["*"],
)

# Serve static files (HTML, CSS, JS)
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


@app.get("/")
def read_root():
    return FileResponse("static/index.html")


@app.get("/inbox")
def get_inbox(limit: int = 10):
    token = get_access_token()
    url = f"{BASE_URL}/api/accounts/{ACCOUNT_KEY}/messages"
    headers = {"Authorization": f"Zoho-oauthtoken {token}"}
    params = {"searchKey": "in:inbox", "limit": limit}
    resp = httpx.get(url, headers=headers, params=params)
    resp.raise_for_status()
    return resp.json()["data"]


@app.get("/message/{message_id}")
def get_message_content(message_id: str):
    token = get_access_token()
    url = f"{BASE_URL}/api/accounts/{ACCOUNT_KEY}/messages/{message_id}/content"
    headers = {"Authorization": f"Zoho-oauthtoken {token}"}
    params = {"includeBlockContent": "true"}
    resp = httpx.get(url, headers=headers, params=params)
    resp.raise_for_status()
    return resp.json()["data"]


@app.post("/send")
def send_email(req: SendRequest):
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
def delete_message(message_id: str):
    token = get_access_token()
    url = f"{BASE_URL}/api/accounts/{ACCOUNT_KEY}/messages/{message_id}"
    headers = {"Authorization": f"Zoho-oauthtoken {token}"}
    resp = httpx.delete(url, headers=headers)
    resp.raise_for_status()
    return {"status": "deleted"}


@app.post("/reply/{message_id}")
def reply_to_message(message_id: str, req: SendRequest):
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
def forward_message(req: ForwardRequest):
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
