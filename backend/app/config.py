from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


@dataclass(frozen=True)
class Settings:
    secret: str = os.getenv("ACTIONPROOF_SECRET", "demo-secret-change-before-deployment")
    gateway_key: str = os.getenv("ACTIONPROOF_GATEWAY_KEY", "local-gateway-only-key")
    email_mcp_url: str = os.getenv("ACTIONPROOF_EMAIL_MCP_URL", "http://127.0.0.1:8001")
    db_path: Path = Path(os.getenv("ACTIONPROOF_DB_PATH", str(ROOT / "data" / "actionproof.db")))
    approval_seconds: int = int(os.getenv("ACTIONPROOF_APPROVAL_SECONDS", "300"))
    policy_version: str = "v1"


settings = Settings()

