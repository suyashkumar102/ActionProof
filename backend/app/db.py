from __future__ import annotations

import sqlite3
from pathlib import Path


SCHEMA = """
PRAGMA foreign_keys = ON;
PRAGMA journal_mode = WAL;

CREATE TABLE IF NOT EXISTS transactions (
  id TEXT PRIMARY KEY, server_id TEXT NOT NULL, tool_name TEXT NOT NULL,
  arguments_json TEXT NOT NULL, fingerprint TEXT NOT NULL, definition_hash TEXT NOT NULL,
  decision TEXT NOT NULL, policy_id TEXT NOT NULL, reason TEXT NOT NULL,
  status TEXT NOT NULL, created_at TEXT NOT NULL, executed_at TEXT
);

CREATE TABLE IF NOT EXISTS approvals (
  id TEXT PRIMARY KEY, transaction_id TEXT NOT NULL UNIQUE, fingerprint TEXT NOT NULL,
  expires_at TEXT NOT NULL, used_at TEXT, rejected_at TEXT, token_nonce TEXT NOT NULL,
  FOREIGN KEY(transaction_id) REFERENCES transactions(id)
);

CREATE TABLE IF NOT EXISTS audit_events (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  transaction_id TEXT NOT NULL,
  event_type TEXT NOT NULL,
  message TEXT NOT NULL,
  metadata_json TEXT NOT NULL,
  created_at TEXT NOT NULL,
  event_hash TEXT NOT NULL DEFAULT '',
  previous_hash TEXT NOT NULL DEFAULT '',
  FOREIGN KEY(transaction_id) REFERENCES transactions(id)
);

CREATE TABLE IF NOT EXISTS tool_registry (
  server_id TEXT NOT NULL, tool_name TEXT NOT NULL, definition_json TEXT NOT NULL,
  definition_hash TEXT NOT NULL, approved_at TEXT NOT NULL,
  PRIMARY KEY(server_id, tool_name)
);

CREATE TABLE IF NOT EXISTS policies (
  id TEXT PRIMARY KEY,
  version TEXT NOT NULL,
  name TEXT NOT NULL,
  description TEXT NOT NULL,
  priority INTEGER NOT NULL DEFAULT 100,
  tool_name TEXT,
  condition_field TEXT,
  condition_op TEXT,
  condition_value TEXT,
  attachment_label TEXT,
  decision TEXT NOT NULL,
  policy_id TEXT NOT NULL,
  reason TEXT NOT NULL,
  active INTEGER NOT NULL DEFAULT 1,
  created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS data_labels (
  id TEXT PRIMARY KEY,
  resource_pattern TEXT NOT NULL,
  label TEXT NOT NULL,
  description TEXT NOT NULL,
  created_at TEXT NOT NULL
);
"""

DEFAULT_POLICIES = [
    {
        "id": "pol_deny_001",
        "version": "v1",
        "name": "Block confidential file exfiltration",
        "description": "Deny any attempt to send confidential_q4.pdf outside the approved domain",
        "priority": 10,
        "tool_name": "send_email",
        "condition_field": "attachment",
        "condition_op": "eq",
        "condition_value": "confidential_q4.pdf",
        "attachment_label": "confidential",
        "decision": "DENY",
        "policy_id": "P-DENY-001",
        "reason": "Protected attachment may not leave approved domain",
    },
    {
        "id": "pol_allow_001",
        "version": "v1",
        "name": "Allow internal non-sensitive email",
        "description": "Auto-allow emails to @company.test with non-sensitive attachments",
        "priority": 20,
        "tool_name": "send_email",
        "condition_field": "to_domain",
        "condition_op": "eq",
        "condition_value": "company.test",
        "attachment_label": None,
        "decision": "ALLOW",
        "policy_id": "P-ALLOW-001",
        "reason": "Internal, non-sensitive communication",
    },
    {
        "id": "pol_approve_002",
        "version": "v1",
        "name": "Require approval for partner communication",
        "description": "Partner domain emails require explicit user approval",
        "priority": 30,
        "tool_name": "send_email",
        "condition_field": "to_domain",
        "condition_op": "eq",
        "condition_value": "partner.test",
        "attachment_label": None,
        "decision": "REQUIRE_APPROVAL",
        "policy_id": "P-APPROVE-002",
        "reason": "Partner communication requires approval",
    },
    {
        "id": "pol_approve_001",
        "version": "v1",
        "name": "Require approval for external email",
        "description": "Any email to an external domain requires approval",
        "priority": 40,
        "tool_name": "send_email",
        "condition_field": "to_domain",
        "condition_op": "neq",
        "condition_value": "company.test",
        "attachment_label": None,
        "decision": "REQUIRE_APPROVAL",
        "policy_id": "P-APPROVE-001",
        "reason": "External communication requires approval",
    },
]

DEFAULT_LABELS = [
    {
        "id": "lbl_001",
        "resource_pattern": "confidential_q4.pdf",
        "label": "confidential",
        "description": "Q4 financial data — restricted to internal use only",
    },
    {
        "id": "lbl_002",
        "resource_pattern": "meeting_notes.pdf",
        "label": "internal",
        "description": "Internal meeting notes — shareable with approved partners",
    },
]


def connect(path: Path) -> sqlite3.Connection:
    path.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(path, check_same_thread=False, timeout=15)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    connection.execute("PRAGMA journal_mode = WAL")
    connection.execute("PRAGMA busy_timeout = 10000")
    return connection


def initialize(path: Path) -> None:
    with connect(path) as connection:
        connection.executescript(SCHEMA)
        # Seed default policies
        now = __import__('datetime').datetime.now(__import__('datetime').timezone.utc).isoformat()
        for p in DEFAULT_POLICIES:
            connection.execute(
                "INSERT OR IGNORE INTO policies VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,1,?)",
                (p["id"], p["version"], p["name"], p["description"], p["priority"],
                 p.get("tool_name"), p.get("condition_field"), p.get("condition_op"),
                 p.get("condition_value"), p.get("attachment_label"),
                 p["decision"], p["policy_id"], p["reason"], now)
            )
        for lbl in DEFAULT_LABELS:
            connection.execute(
                "INSERT OR IGNORE INTO data_labels VALUES (?,?,?,?,?)",
                (lbl["id"], lbl["resource_pattern"], lbl["label"], lbl["description"], now)
            )
        connection.commit()
