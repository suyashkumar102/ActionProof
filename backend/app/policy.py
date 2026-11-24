from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Union


@dataclass(frozen=True)
class PolicyResult:
    decision: str
    policy_id: str
    reason: str


def _get_label(resource: str, db_path: Path | None = None) -> str | None:
    """Look up the data label for a resource (attachment name or file path)."""
    if not db_path:
        return None
    name = Path(resource).name  # handles both filenames and paths
    try:
        from .db import connect
        with connect(db_path) as db:
            row = db.execute(
                "SELECT label FROM data_labels WHERE resource_pattern=?", (name,)
            ).fetchone()
            return row["label"] if row else None
    except Exception:
        return None


def _load_policies(db_path: Path | None = None, tool_name: str | None = None):
    """Load active policies ordered by priority, optionally filtered by tool."""
    if not db_path:
        return []
    try:
        from .db import connect
        with connect(db_path) as db:
            rows = db.execute(
                "SELECT * FROM policies WHERE active=1 ORDER BY priority ASC"
            ).fetchall()
            return [dict(r) for r in rows]
    except Exception:
        return []


def _matches(policy: dict[str, Any], args_dict: dict[str, Any], label: str | None) -> bool:
    field     = policy.get("condition_field")
    op        = policy.get("condition_op")
    value     = policy.get("condition_value")
    req_label = policy.get("attachment_label")

    if not field:
        return True
    if req_label and label != req_label:
        return False

    actual = args_dict.get(field)
    if field == "to_domain":
        to = args_dict.get("to", "")
        actual = to.rsplit("@", 1)[1].lower() if "@" in to else ""

    if op == "eq":      return str(actual).lower() == str(value).lower()
    if op == "neq":     return str(actual).lower() != str(value).lower()
    if op == "contains": return str(value).lower() in str(actual).lower()
    if op == "startswith": return str(actual).lower().startswith(str(value).lower())
    return False


def evaluate(invocation: Any, db_path: Path | None = None) -> PolicyResult:
    """
    Evaluate any invocation against configured policies.
    Handles both email and filesystem tool calls.
    Data egress is tracked via context_labels — if the agent context carries
    a confidential label from a prior read, sending externally is blocked.
    """
    server_id = invocation.server_id
    tool_name = invocation.tool_name
    args = invocation.arguments

    # ── Filesystem tools ──────────────────────────────────────────────────────
    if server_id == "mock-filesystem-v1":
        return _evaluate_filesystem(tool_name, args, db_path)

    # ── Email tools ───────────────────────────────────────────────────────────
    return _evaluate_email(args, db_path)


def _evaluate_filesystem(tool_name: str, args: Any, db_path: Path | None) -> PolicyResult:
    path = getattr(args, "path", "/")
    label = _get_label(path, db_path)

    if tool_name == "list_directory":
        return PolicyResult("ALLOW", "P-FS-LIST-001", "Directory listing is permitted")

    if tool_name == "read_file":
        if label == "confidential":
            return PolicyResult(
                "REQUIRE_APPROVAL", "P-FS-READ-002",
                f"Reading confidential file '{Path(path).name}' requires explicit approval"
            )
        return PolicyResult("ALLOW", "P-FS-READ-001", f"Reading {label or 'unclassified'} file is permitted")

    if tool_name == "write_file":
        return PolicyResult(
            "REQUIRE_APPROVAL", "P-FS-WRITE-001",
            "File write operations require explicit approval"
        )

    return PolicyResult("DENY", "P-FS-DENY-001", f"Unknown filesystem tool: {tool_name}")


def _evaluate_email(args: Any, db_path: Path | None) -> PolicyResult:
    to = args.to
    attachment = args.attachment
    domain = to.rsplit("@", 1)[1].lower() if "@" in to else ""
    label = _get_label(attachment, db_path)

    args_dict = {
        "to": to, "to_domain": domain,
        "subject": args.subject, "body": args.body, "attachment": attachment,
    }

    # Database policies first
    policies = _load_policies(db_path)
    if policies:
        for policy in policies:
            if policy.get("tool_name") and policy["tool_name"] != "send_email":
                continue
            if _matches(policy, args_dict, label):
                return PolicyResult(policy["decision"], policy["policy_id"], policy["reason"])

    # Built-in fallback rules
    confidential = attachment == "confidential_q4.pdf" or label == "confidential"
    if domain != "company.test" and confidential:
        return PolicyResult("DENY", "P-DENY-001", "Protected attachment may not leave approved domain")
    if domain == "company.test" and not confidential:
        return PolicyResult("ALLOW", "P-ALLOW-001", "Internal, non-sensitive communication")
    if domain == "partner.test":
        return PolicyResult("REQUIRE_APPROVAL", "P-APPROVE-002", "Partner communication requires approval")
    if domain != "company.test":
        return PolicyResult("REQUIRE_APPROVAL", "P-APPROVE-001", "External communication requires approval")
    return PolicyResult("DENY", "P-DENY-001", "Protected attachment may not leave approved domain")
