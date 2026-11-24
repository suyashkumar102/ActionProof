"""Deliberately small simulated MCP-style email tool. Never use for real email."""
from __future__ import annotations

import os
import sqlite3
import uuid
from datetime import datetime, timezone
from pathlib import Path

from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel


ROOT = Path(__file__).resolve().parent
DB_PATH = ROOT / "data" / "mailbox.db"
GATEWAY_KEY = os.getenv("ACTIONPROOF_GATEWAY_KEY", "local-gateway-only-key")
app = FastAPI(title="Simulated Email MCP Server", version="1.0.0")


class Email(BaseModel):
    to: str
    subject: str
    body: str
    attachment: str


def db() -> sqlite3.Connection:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(DB_PATH)
    connection.row_factory = sqlite3.Row
    connection.execute("CREATE TABLE IF NOT EXISTS sent_messages (id TEXT PRIMARY KEY, to_address TEXT, subject TEXT, body TEXT, attachment TEXT, sent_at TEXT)")
    return connection


def require_gateway(key: str | None) -> None:
    if key != GATEWAY_KEY:
        raise HTTPException(status_code=403, detail="Direct calls are blocked; use the ActionProof gateway")


@app.post("/mcp/send_email")
def send_email(email: Email, x_actionproof_gateway_key: str | None = Header(default=None)):
    require_gateway(x_actionproof_gateway_key)
    message = {"id": f"mail_{uuid.uuid4().hex[:12]}", **email.model_dump(), "sent_at": datetime.now(timezone.utc).isoformat()}
    with db() as connection:
        connection.execute(
            "INSERT INTO sent_messages VALUES (:id, :to, :subject, :body, :attachment, :sent_at)",
            message,
        )
    return {"accepted": True, "message": message}


@app.get("/mcp/mailbox/sent")
def sent_messages():
    with db() as connection:
        rows = connection.execute("SELECT id, to_address AS 'to', subject, body, attachment, sent_at FROM sent_messages ORDER BY sent_at DESC").fetchall()
    return {"messages": [dict(row) for row in rows]}


@app.post("/mcp/reset")
def reset(x_actionproof_gateway_key: str | None = Header(default=None)):
    require_gateway(x_actionproof_gateway_key)
    with db() as connection:
        connection.execute("DELETE FROM sent_messages")
    return {"ok": True}
