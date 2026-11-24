from __future__ import annotations

import hashlib
from typing import Any

from .canonical import canonical_json


def sha256_prefixed(value: Any) -> str:
    return "sha256:" + hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


def make_fingerprint(invocation: dict[str, Any], tool_definition_hash: str, policy_version: str) -> str:
    return sha256_prefixed(
        {
            "server_id": invocation["server_id"],
            "tool_name": invocation["tool_name"],
            "tool_definition_hash": tool_definition_hash,
            "arguments": invocation["arguments"],
            "policy_version": policy_version,
        }
    )

