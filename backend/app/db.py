from __future__ import annotations

import sqlite3
from pathlib import Path


SCHEMA = """
PRAGMA foreign_keys = ON;
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
  id INTEGER PRIMARY KEY AUTOINCREMENT, transaction_id TEXT NOT NULL, event_type TEXT NOT NULL,
  message TEXT NOT NULL, metadata_json TEXT NOT NULL, created_at TEXT NOT NULL,
  FOREIGN KEY(transaction_id) REFERENCES transactions(id)
);
CREATE TABLE IF NOT EXISTS tool_registry (
  server_id TEXT NOT NULL, tool_name TEXT NOT NULL, definition_json TEXT NOT NULL,
  definition_hash TEXT NOT NULL, approved_at TEXT NOT NULL,
  PRIMARY KEY(server_id, tool_name)
);
"""


def connect(path: Path) -> sqlite3.Connection:
    path.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(path, check_same_thread=False)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    return connection


def initialize(path: Path) -> None:
    with connect(path) as connection:
        connection.executescript(SCHEMA)

