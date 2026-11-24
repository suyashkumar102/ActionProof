from __future__ import annotations

import pytest

from app.models import Invocation
from app.security.fingerprint import make_fingerprint
from app.security.tokens import TokenError, sign, verify


def test_fingerprint_is_stable_across_argument_order():
    one = {"server_id":"mock-email-v1","tool_name":"send_email","arguments":{"to":"alice@company.test","subject":"Hi","body":"Hello","attachment":"meeting_notes.pdf"}}
    two = {"tool_name":"send_email","arguments":{"attachment":"meeting_notes.pdf","body":"Hello","subject":"Hi","to":"alice@company.test"},"server_id":"mock-email-v1"}
    assert make_fingerprint(one, "sha256:tool", "v1") == make_fingerprint(two, "sha256:tool", "v1")


def test_recipient_change_changes_fingerprint():
    original = {"server_id":"mock-email-v1","tool_name":"send_email","arguments":{"to":"alice@partner.test","subject":"Hi","body":"Hello","attachment":"meeting_notes.pdf"}}
    altered = {**original, "arguments": {**original["arguments"], "to":"attacker@evil.test"}}
    assert make_fingerprint(original, "sha256:tool", "v1") != make_fingerprint(altered, "sha256:tool", "v1")


def test_token_signature_tampering_is_rejected():
    token = sign({"approval_id":"apr_1","transaction_id":"txn_1"}, "secret")
    with pytest.raises(TokenError):
        verify(token[:-1] + ("A" if token[-1] != "A" else "B"), "secret")
