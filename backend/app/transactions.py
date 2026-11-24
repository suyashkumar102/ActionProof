from __future__ import annotations

import json
import secrets
import uuid
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from .clients.email_mcp_client import EmailMCPClient
from .config import Settings
from .db import connect
from .models import DecisionResponse, Invocation
from .policy import evaluate
from .security.canonical import canonical_json
from .security.fingerprint import make_fingerprint, sha256_prefixed
from .security.tokens import TokenError, sign, verify


class ServiceError(Exception):
    def __init__(self, status_code: int, code: str, message: str, changed_fields: list[str] | None = None):
        super().__init__(message)
        self.status_code = status_code
        self.code = code
        self.message = message
        self.changed_fields = changed_fields or []


def now() -> datetime:
    return datetime.now(timezone.utc)


def iso(value: datetime | None = None) -> str:
    return (value or now()).isoformat()


class TransactionService:
    def __init__(self, settings: Settings, email_client: EmailMCPClient):
        self.settings = settings
        self.email_client = email_client

    def _connection(self):
        return connect(self.settings.db_path)

    @contextmanager
    def _session(self):
        """Commit and close every SQLite connection, preventing stale local locks."""
        db = self._connection()
        try:
            yield db
            db.commit()
        except Exception:
            db.rollback()
            raise
        finally:
            db.close()

    def seed_tool_registry(self) -> None:
        definition_path = Path(__file__).resolve().parents[2] / "mock_email_mcp" / "tool_definition.json"
        definition = json.loads(definition_path.read_text(encoding="utf-8"))
        definition_hash = sha256_prefixed(definition)
        with self._session() as db:
            db.execute(
                "INSERT OR IGNORE INTO tool_registry VALUES (?, ?, ?, ?, ?)",
                ("mock-email-v1", "send_email", canonical_json(definition), definition_hash, iso()),
            )

    def _tool_hash(self, db, invocation: Invocation) -> str:
        row = db.execute(
            "SELECT definition_hash, definition_json FROM tool_registry WHERE server_id=? AND tool_name=?",
            (invocation.server_id, invocation.tool_name),
        ).fetchone()
        if not row:
            raise ServiceError(403, "UNPINNED_TOOL", "Tool is not pinned in the reviewed registry")
        # Verify the pinned definition still matches the on-disk approved definition.
        definition_path = Path(__file__).resolve().parents[2] / "mock_email_mcp" / "tool_definition.json"
        approved_definition = json.loads(definition_path.read_text(encoding="utf-8"))
        approved_hash = sha256_prefixed(approved_definition)
        if row["definition_hash"] != approved_hash:
            raise ServiceError(
                409,
                "REGISTRY_DRIFT",
                f"Tool definition has changed since it was last approved. "
                f"Current hash {row['definition_hash'][:20]}… does not match approved hash {approved_hash[:20]}…. "
                "Re-approve the updated definition before it can be used.",
            )
        return row["definition_hash"]

    def _audit(self, db, transaction_id: str, event_type: str, message: str, metadata: dict[str, Any] | None = None) -> None:
        db.execute(
            "INSERT INTO audit_events(transaction_id, event_type, message, metadata_json, created_at) VALUES (?, ?, ?, ?, ?)",
            (transaction_id, event_type, message, canonical_json(metadata or {}), iso()),
        )

    @staticmethod
    def _response(row, approval_request: dict[str, Any] | None = None, changed_fields: list[str] | None = None) -> DecisionResponse:
        decision = row["decision"] if row["status"] not in {"BLOCKED", "REJECTED"} else "BLOCKED"
        return DecisionResponse(
            transaction_id=row["id"], decision=decision, policy_id=row["policy_id"], reason=row["reason"],
            fingerprint=row["fingerprint"], status=row["status"], approval_request=approval_request,
            changed_fields=changed_fields or [],
        )

    def propose(self, invocation: Invocation) -> DecisionResponse:
        result = evaluate(invocation)
        transaction_id = f"txn_{uuid.uuid4().hex[:16]}"
        with self._session() as db:
            tool_hash = self._tool_hash(db, invocation)
            fingerprint = make_fingerprint(invocation.fingerprint_payload(), tool_hash, self.settings.policy_version)
            status = {"ALLOW": "AUTHORIZED", "REQUIRE_APPROVAL": "AWAITING_APPROVAL", "DENY": "BLOCKED"}[result.decision]
            db.execute(
                "INSERT INTO transactions VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL)",
                (transaction_id, invocation.server_id, invocation.tool_name, canonical_json(invocation.fingerprint_payload()["arguments"]),
                 fingerprint, tool_hash, result.decision, result.policy_id, result.reason, status, iso()),
            )
            self._audit(db, transaction_id, "PROPOSED", "Agent requested an action. Nothing has executed.", {"decision": result.decision})
            self._audit(db, transaction_id, result.decision, result.reason)
            row = db.execute("SELECT * FROM transactions WHERE id=?", (transaction_id,)).fetchone()
        request = None
        if result.decision == "REQUIRE_APPROVAL":
            request = {"expires_in_seconds": self.settings.approval_seconds, "arguments": invocation.fingerprint_payload()["arguments"]}
        return self._response(row, request)

    def get_transaction(self, transaction_id: str) -> dict[str, Any]:
        with self._session() as db:
            row = db.execute("SELECT * FROM transactions WHERE id=?", (transaction_id,)).fetchone()
            if not row:
                raise ServiceError(404, "NOT_FOUND", "Transaction not found")
            data = dict(row)
            data["arguments"] = json.loads(data.pop("arguments_json"))
            data["approval"] = None
            approval = db.execute("SELECT id, expires_at, used_at, rejected_at FROM approvals WHERE transaction_id=?", (transaction_id,)).fetchone()
            if approval:
                data["approval"] = dict(approval)
            return data

    def audit(self, transaction_id: str) -> list[dict[str, Any]]:
        with self._session() as db:
            if not db.execute("SELECT 1 FROM transactions WHERE id=?", (transaction_id,)).fetchone():
                raise ServiceError(404, "NOT_FOUND", "Transaction not found")
            rows = db.execute("SELECT id, event_type, message, metadata_json, created_at FROM audit_events WHERE transaction_id=? ORDER BY id", (transaction_id,)).fetchall()
        return [{**dict(row), "metadata": json.loads(row["metadata_json"])} for row in rows]

    def approve(self, transaction_id: str) -> dict[str, Any]:
        with self._session() as db:
            tx = db.execute("SELECT * FROM transactions WHERE id=?", (transaction_id,)).fetchone()
            if not tx:
                raise ServiceError(404, "NOT_FOUND", "Transaction not found")
            if tx["status"] != "AWAITING_APPROVAL":
                raise ServiceError(409, "NOT_AWAITING_APPROVAL", "This transaction is not awaiting approval")
            approval_id = f"apr_{uuid.uuid4().hex[:16]}"
            expires_at = now() + timedelta(seconds=self.settings.approval_seconds)
            nonce = secrets.token_urlsafe(16)
            payload = {"approval_id": approval_id, "transaction_id": transaction_id, "fingerprint": tx["fingerprint"], "expires_at": iso(expires_at), "nonce": nonce}
            db.execute("INSERT INTO approvals VALUES (?, ?, ?, ?, NULL, NULL, ?)", (approval_id, transaction_id, tx["fingerprint"], payload["expires_at"], nonce))
            db.execute("UPDATE transactions SET status='APPROVED' WHERE id=?", (transaction_id,))
            self._audit(db, transaction_id, "APPROVED", "Approved once. Any edit will invalidate it.", {"expires_at": payload["expires_at"]})
        return {"approval_id": approval_id, "token": sign(payload, self.settings.secret), "expires_at": payload["expires_at"], "fingerprint": tx["fingerprint"]}

    def reject(self, transaction_id: str) -> dict[str, bool]:
        with self._session() as db:
            tx = db.execute("SELECT * FROM transactions WHERE id=?", (transaction_id,)).fetchone()
            if not tx:
                raise ServiceError(404, "NOT_FOUND", "Transaction not found")
            if tx["status"] != "AWAITING_APPROVAL":
                raise ServiceError(409, "NOT_AWAITING_APPROVAL", "This transaction is not awaiting approval")
            db.execute("UPDATE transactions SET status='REJECTED' WHERE id=?", (transaction_id,))
            self._audit(db, transaction_id, "REJECTED", "User rejected this transaction")
        return {"ok": True}

    @staticmethod
    def _diff(approved: dict[str, Any], attempted: dict[str, Any]) -> list[str]:
        return sorted(key for key in set(approved) | set(attempted) if approved.get(key) != attempted.get(key))

    def _block(self, db, tx, code: str, message: str, changed_fields: list[str] | None = None) -> None:
        db.execute("UPDATE transactions SET status='BLOCKED', reason=? WHERE id=?", (message, tx["id"]))
        self._audit(db, tx["id"], code, message, {"changed_fields": changed_fields or []})

    async def execute(self, transaction_id: str, invocation: Invocation, token: str | None) -> dict[str, Any]:
        with self._session() as db:
            tx = db.execute("SELECT * FROM transactions WHERE id=?", (transaction_id,)).fetchone()
            if not tx:
                raise ServiceError(404, "NOT_FOUND", "Transaction not found")
            if tx["status"] in {"BLOCKED", "REJECTED", "EXECUTED"}:
                raise ServiceError(409, "TERMINAL_TRANSACTION", "Transaction is already in a terminal state")
            if tx["server_id"] != invocation.server_id or tx["tool_name"] != invocation.tool_name:
                self._block(db, tx, "TOOL_MISMATCH", "Blocked: attempted tool differs from proposed tool")
                raise ServiceError(409, "TOOL_MISMATCH", "Blocked: attempted tool differs from proposed tool")
            current_policy = evaluate(invocation)
            if current_policy.decision == "DENY":
                self._block(db, tx, "POLICY_DENY", current_policy.reason)
                raise ServiceError(403, "POLICY_DENY", current_policy.reason)
            tool_hash = self._tool_hash(db, invocation)
            fresh = make_fingerprint(invocation.fingerprint_payload(), tool_hash, self.settings.policy_version)
            approved_args = json.loads(tx["arguments_json"])
            if tx["decision"] == "REQUIRE_APPROVAL":
                if not token:
                    raise ServiceError(401, "MISSING_TOKEN", "Approval token is required")
                try:
                    payload = verify(token, self.settings.secret)
                except TokenError as error:
                    self._block(db, tx, "INVALID_TOKEN", "Blocked: invalid approval token")
                    raise ServiceError(401, "INVALID_TOKEN", str(error)) from error
                approval = db.execute("SELECT * FROM approvals WHERE id=?", (payload.get("approval_id"),)).fetchone()
                if not approval or payload.get("transaction_id") != transaction_id or approval["transaction_id"] != transaction_id:
                    self._block(db, tx, "WRONG_TRANSACTION", "Blocked: approval token belongs to a different transaction")
                    raise ServiceError(409, "WRONG_TRANSACTION", "Blocked: approval token belongs to a different transaction")
                if datetime.fromisoformat(approval["expires_at"]) <= now():
                    self._block(db, tx, "TOKEN_EXPIRED", "Blocked: approval has expired")
                    raise ServiceError(409, "TOKEN_EXPIRED", "Blocked: approval has expired")
                if approval["used_at"]:
                    self._block(db, tx, "TOKEN_REPLAY", "Blocked: this approval has already been consumed")
                    raise ServiceError(409, "TOKEN_REPLAY", "Blocked: this approval has already been consumed")
                if payload.get("fingerprint") != approval["fingerprint"] or fresh != approval["fingerprint"]:
                    changed = self._diff(approved_args, invocation.fingerprint_payload()["arguments"])
                    self._block(db, tx, "FINGERPRINT_MISMATCH", "Blocked: approval was for a different transaction", changed)
                    raise ServiceError(409, "FINGERPRINT_MISMATCH", "Blocked: approval was for a different transaction", changed)
            elif fresh != tx["fingerprint"]:
                changed = self._diff(approved_args, invocation.fingerprint_payload()["arguments"])
                self._block(db, tx, "FINGERPRINT_MISMATCH", "Blocked: attempted action differs from authorized action", changed)
                raise ServiceError(409, "FINGERPRINT_MISMATCH", "Blocked: attempted action differs from authorized action", changed)

        # The downstream request happens only after every verification has committed successfully.
        response = await self.email_client.send_email(invocation.fingerprint_payload()["arguments"])
        with self._session() as db:
            db.execute("UPDATE transactions SET status='EXECUTED', executed_at=? WHERE id=?", (iso(), transaction_id))
            if tx["decision"] == "REQUIRE_APPROVAL":
                db.execute("UPDATE approvals SET used_at=? WHERE transaction_id=?", (iso(), transaction_id))
            self._audit(db, transaction_id, "EXECUTED", "Verified: the simulated email server accepted the exact approved action.")
        return {"ok": True, "decision": "ALLOW", "status": "EXECUTED", "transaction_id": transaction_id, "fingerprint": fresh, "downstream": response}

    def tools(self) -> list[dict[str, Any]]:
        with self._session() as db:
            return [dict(row) for row in db.execute("SELECT server_id, tool_name, definition_hash, approved_at FROM tool_registry")]

    async def reset(self) -> None:
        with self._session() as db:
            db.execute("DELETE FROM audit_events")
            db.execute("DELETE FROM approvals")
            db.execute("DELETE FROM transactions")
        await self.email_client.reset()
