# ─────────────────────────────────────────────────────────────────────────────
# recovery_routes.py — Manitec Mail Server
# Password recovery endpoints — register this router in main.py
#
# Setup:
#   1. Add RECOVERY_KEY to your Render env vars (a long passphrase you won't forget)
#   2. In main.py:
#        from recovery_routes import router as recovery_router
#        app.include_router(recovery_router)
#   3. Add a route to serve the forgot-password page:
#        from fastapi.responses import FileResponse
#        @app.get("/forgot-password")
#        def forgot_password_page():
#            return FileResponse("static/forgot_password.html")
# ─────────────────────────────────────────────────────────────────────────────

import os
import bcrypt
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from db import get_db_conn  # adjust if your db import differs

router = APIRouter(prefix="/recovery", tags=["recovery"])

RECOVERY_KEY = os.getenv("RECOVERY_KEY", "")


class VerifyRequest(BaseModel):
    username: str
    recovery_key: str


class ResetRequest(BaseModel):
    username: str
    new_password: str


@router.post("/verify")
def verify_recovery(req: VerifyRequest):
    """Step 1 — confirm the user exists and the recovery key is correct."""
    if not RECOVERY_KEY:
        raise HTTPException(status_code=503, detail="Recovery not configured on this server.")
    if req.recovery_key.strip() != RECOVERY_KEY:
        raise HTTPException(status_code=401, detail="Invalid username or recovery key.")

    conn = get_db_conn()
    user = conn.execute(
        "SELECT id FROM users WHERE username = ?",
        (req.username.strip().lower(),)
    ).fetchone()
    conn.close()

    if not user:
        raise HTTPException(status_code=401, detail="Invalid username or recovery key.")
    return {"ok": True}


@router.post("/reset")
def reset_password(req: ResetRequest):
    """Step 2 — update the bcrypt password hash after identity is verified."""
    if len(req.new_password) < 8:
        raise HTTPException(status_code=400, detail="Password must be at least 8 characters.")

    new_hash = bcrypt.hashpw(req.new_password.encode(), bcrypt.gensalt()).decode()

    conn = get_db_conn()
    result = conn.execute(
        "UPDATE users SET password_hash = ? WHERE username = ?",
        (new_hash, req.username.strip().lower())
    )
    conn.commit()
    conn.close()

    if result.rowcount == 0:
        raise HTTPException(status_code=404, detail="User not found.")
    return {"ok": True, "message": "Password updated successfully."}
