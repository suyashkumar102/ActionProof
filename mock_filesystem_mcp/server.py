"""
Simulated Filesystem MCP Server.
Provides read_file, write_file, list_directory tools with:
- Gateway-only access (X-ActionProof-Gateway-Key header required for writes)
- Path sandboxing (all paths resolved within SANDBOX_ROOT)
- File data labels (private/internal/public) returned with reads
Never use for real filesystem access outside a sandbox.
"""
from __future__ import annotations

import os
from pathlib import Path

from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel

ROOT = Path(__file__).resolve().parent
SANDBOX_ROOT = ROOT / "sandbox"
GATEWAY_KEY = os.getenv("ACTIONPROOF_GATEWAY_KEY", "local-gateway-only-key")

app = FastAPI(title="Simulated Filesystem MCP Server", version="1.0.0")

# Data labels for sandboxed files
FILE_LABELS: dict[str, str] = {
    "confidential_q4.pdf": "confidential",
    "strategy_2027.pdf":   "confidential",
    "meeting_notes.pdf":   "internal",
    "readme.txt":          "public",
    "public_report.pdf":   "public",
}


class WriteRequest(BaseModel):
    path: str
    content: str


def _sandbox(path: str) -> Path:
    """Resolve path inside sandbox and reject traversal attempts."""
    SANDBOX_ROOT.mkdir(parents=True, exist_ok=True)
    resolved = (SANDBOX_ROOT / path.lstrip("/")).resolve()
    try:
        resolved.relative_to(SANDBOX_ROOT.resolve())
    except ValueError:
        raise HTTPException(status_code=403, detail="Path traversal blocked — path must be within sandbox")
    return resolved


def require_gateway(key: str | None) -> None:
    if key != GATEWAY_KEY:
        raise HTTPException(status_code=403, detail="Direct calls to filesystem are blocked; use the ActionProof gateway")


def _seed_sandbox() -> None:
    """Create sandbox files on startup."""
    SANDBOX_ROOT.mkdir(parents=True, exist_ok=True)
    files = {
        "readme.txt":          "Welcome to the ActionProof sandbox filesystem.",
        "meeting_notes.pdf":   "[INTERNAL] Q4 planning meeting notes. Distribution: all staff.",
        "public_report.pdf":   "[PUBLIC] Annual summary report available for external sharing.",
        "confidential_q4.pdf": "[CONFIDENTIAL] Q4 earnings data. RESTRICTED — internal eyes only.",
        "strategy_2027.pdf":   "[CONFIDENTIAL] 2027 product strategy. RESTRICTED — do not distribute.",
    }
    for name, content in files.items():
        p = SANDBOX_ROOT / name
        if not p.exists():
            p.write_text(content, encoding="utf-8")


@app.get("/mcp/list_directory")
def list_directory(path: str = "/"):
    """List files in a sandboxed directory. No gateway key required (read-only metadata)."""
    resolved = _sandbox(path)
    if not resolved.exists():
        raise HTTPException(status_code=404, detail=f"Path not found: {path}")
    if resolved.is_file():
        name = resolved.name
        return {"entries": [{"name": name, "type": "file",
                              "label": FILE_LABELS.get(name, "unclassified"),
                              "size": resolved.stat().st_size}]}
    entries = []
    for child in sorted(resolved.iterdir()):
        entry = {"name": child.name, "type": "file" if child.is_file() else "directory",
                 "label": FILE_LABELS.get(child.name, "unclassified")}
        if child.is_file():
            entry["size"] = child.stat().st_size
        entries.append(entry)
    return {"entries": entries, "path": path}


@app.get("/mcp/read_file")
def read_file(path: str, x_actionproof_gateway_key: str | None = Header(default=None)):
    """Read a sandboxed file. Gateway key required — reading is a sensitive action."""
    require_gateway(x_actionproof_gateway_key)
    resolved = _sandbox(path)
    if not resolved.exists() or not resolved.is_file():
        raise HTTPException(status_code=404, detail=f"File not found: {path}")
    content = resolved.read_text(encoding="utf-8")
    name = resolved.name
    label = FILE_LABELS.get(name, "unclassified")
    return {"path": path, "content": content, "label": label,
            "size": len(content), "name": name}


@app.post("/mcp/write_file")
def write_file(req: WriteRequest, x_actionproof_gateway_key: str | None = Header(default=None)):
    """Write a sandboxed file. Gateway key required."""
    require_gateway(x_actionproof_gateway_key)
    resolved = _sandbox(req.path)
    resolved.parent.mkdir(parents=True, exist_ok=True)
    resolved.write_text(req.content, encoding="utf-8")
    return {"ok": True, "path": req.path, "size": len(req.content)}


@app.get("/mcp/file_label")
def file_label(path: str):
    """Return the data label of a file without reading its content."""
    name = Path(path).name
    return {"path": path, "label": FILE_LABELS.get(name, "unclassified")}


@app.on_event("startup")
def startup() -> None:
    _seed_sandbox()
