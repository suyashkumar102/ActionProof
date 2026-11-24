from __future__ import annotations

import base64
import hashlib
import hmac
import json
from typing import Any

from .canonical import canonical_json


class TokenError(ValueError):
    pass


def _b64encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _b64decode(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def sign(payload: dict[str, Any], secret: str) -> str:
    body = canonical_json(payload).encode("utf-8")
    signature = hmac.new(secret.encode("utf-8"), body, hashlib.sha256).digest()
    return f"{_b64encode(body)}.{_b64encode(signature)}"


def verify(token: str, secret: str) -> dict[str, Any]:
    try:
        encoded_body, encoded_signature = token.split(".", 1)
        body = _b64decode(encoded_body)
        signature = _b64decode(encoded_signature)
    except (ValueError, TypeError) as error:
        raise TokenError("Malformed approval token") from error
    expected = hmac.new(secret.encode("utf-8"), body, hashlib.sha256).digest()
    if not hmac.compare_digest(signature, expected):
        raise TokenError("Invalid approval token signature")
    try:
        payload = json.loads(body)
    except json.JSONDecodeError as error:
        raise TokenError("Invalid approval token payload") from error
    if not isinstance(payload, dict):
        raise TokenError("Invalid approval token payload")
    return payload

