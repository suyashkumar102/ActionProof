from __future__ import annotations

from datetime import timedelta

import pytest

from app.models import Invocation
from app.transactions import ServiceError, iso, now


def email(to="alice@company.test", attachment="meeting_notes.pdf"):
    return Invocation(server_id="mock-email-v1", tool_name="send_email", arguments={"to":to,"subject":"Q4 report","body":"Please review.","attachment":attachment})


def run_immediate(coroutine):
    """Our fake downstream client does no I/O, so this coroutine completes on its first step."""
    try:
        coroutine.send(None)
    except StopIteration as finished:
        return finished.value
    raise AssertionError("Fake client unexpectedly suspended")


def test_allowed_email_reaches_mock_mailbox(service):
    proposed = service.propose(email())
    assert proposed.decision == "ALLOW"
    result = run_immediate(service.execute(proposed.transaction_id, email(), None))
    assert result["status"] == "EXECUTED"
    assert service.email_client.messages[0]["to"] == "alice@company.test"


def test_fingerprint_mismatch_never_reaches_mailbox(service):
    proposed = service.propose(email("alice@partner.test"))
    approval = service.approve(proposed.transaction_id)
    with pytest.raises(ServiceError) as error:
        run_immediate(service.execute(proposed.transaction_id, email("attacker@evil.test"), approval["token"]))
    assert error.value.code == "FINGERPRINT_MISMATCH"
    assert service.email_client.messages == []


def test_approval_executes_once_and_replay_is_rejected(service):
    proposed = service.propose(email("alice@partner.test"))
    approval = service.approve(proposed.transaction_id)
    run_immediate(service.execute(proposed.transaction_id, email("alice@partner.test"), approval["token"]))
    with pytest.raises(ServiceError) as error:
        run_immediate(service.execute(proposed.transaction_id, email("alice@partner.test"), approval["token"]))
    assert error.value.status_code == 409
    assert len(service.email_client.messages) == 1


def test_expired_approval_is_rejected(service):
    proposed = service.propose(email("alice@partner.test"))
    approval = service.approve(proposed.transaction_id)
    with service._session() as db:
        db.execute("UPDATE approvals SET expires_at=? WHERE transaction_id=?", (iso(now() - timedelta(seconds=1)), proposed.transaction_id))
    with pytest.raises(ServiceError) as error:
        run_immediate(service.execute(proposed.transaction_id, email("alice@partner.test"), approval["token"]))
    assert error.value.code == "TOKEN_EXPIRED"
    assert service.email_client.messages == []
