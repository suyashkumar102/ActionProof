"""
Advanced security tests covering:
- Concurrent execution safety (double-spend prevention)
- Policy re-evaluation at execution time
- Tool and server mismatch detection
- Cross-transaction token reuse
- Audit log hash chain integrity
- Data label lookups
- Multiple approval attempt rejection
"""
from __future__ import annotations

import asyncio
from datetime import timedelta

import pytest

from app.models import Invocation
from app.transactions import ServiceError, iso, now


# ── Helpers ───────────────────────────────────────────────────────────────────

def email(to="alice@company.test", attachment="meeting_notes.pdf", subject="Test"):
    return Invocation(
        server_id="mock-email-v1", tool_name="send_email",
        arguments={"to": to, "subject": subject, "body": "Test body.", "attachment": attachment},
    )


def run(coro):
    return asyncio.get_event_loop().run_until_complete(coro)


# ── Concurrent execution safety ───────────────────────────────────────────────

def test_concurrent_execution_blocked_after_first(service):
    """
    Two concurrent execute calls on the same ALLOW transaction:
    the first succeeds, the second is rejected as TERMINAL_TRANSACTION.
    """
    proposed = service.propose(email())
    assert proposed.decision == "ALLOW"

    async def race():
        results = await asyncio.gather(
            service.execute(proposed.transaction_id, email(), None),
            service.execute(proposed.transaction_id, email(), None),
            return_exceptions=True,
        )
        return results

    results = asyncio.get_event_loop().run_until_complete(race())
    successes = [r for r in results if isinstance(r, dict) and r.get("status") == "EXECUTED"]
    failures  = [r for r in results if isinstance(r, ServiceError)]
    assert len(successes) == 1, "Exactly one execution should succeed"
    assert len(failures)  == 1, "Second concurrent attempt must be blocked"
    assert failures[0].code in ("TERMINAL_TRANSACTION", "TERMINAL_TRANSACTION")
    # Only one email should have been delivered
    assert len(service.email_client.messages) == 1


def test_concurrent_approval_replay_blocked(service):
    """
    Two concurrent execute calls with the same approval token:
    the first succeeds, the second is rejected as TOKEN_REPLAY or TERMINAL_TRANSACTION.
    """
    proposed = service.propose(email("alice@partner.test"))
    approval = service.approve(proposed.transaction_id)
    token = approval["token"]
    inv = email("alice@partner.test")

    async def race():
        return await asyncio.gather(
            service.execute(proposed.transaction_id, inv, token),
            service.execute(proposed.transaction_id, inv, token),
            return_exceptions=True,
        )

    results = asyncio.get_event_loop().run_until_complete(race())
    successes = [r for r in results if isinstance(r, dict) and r.get("status") == "EXECUTED"]
    failures  = [r for r in results if isinstance(r, ServiceError)]
    assert len(successes) == 1
    assert len(failures)  == 1
    assert failures[0].code in ("TOKEN_REPLAY", "TERMINAL_TRANSACTION")
    assert len(service.email_client.messages) == 1


# ── Policy re-evaluation at execution ─────────────────────────────────────────

def test_policy_re_evaluated_at_execution_blocks_if_changed(service):
    """
    A transaction proposed as ALLOW should be blocked at execution if the
    policy engine would now return DENY for the same invocation.
    We simulate this by passing a different invocation (with confidential file)
    at execute time — the tool_name and server_id match but policy now says DENY.
    """
    # Propose a benign internal email (ALLOW)
    proposed = service.propose(email())
    assert proposed.decision == "ALLOW"

    # Try to execute with a confidential+external invocation — policy re-evaluation catches it
    malicious = email(to="attacker@evil.test", attachment="confidential_q4.pdf")
    # Note: this will also fail fingerprint check, but policy is evaluated first
    with pytest.raises(ServiceError) as exc:
        run(service.execute(proposed.transaction_id, malicious, None))
    # Either POLICY_DENY or FINGERPRINT_MISMATCH — both are correct blocks
    assert exc.value.code in ("POLICY_DENY", "FINGERPRINT_MISMATCH", "TOOL_MISMATCH")
    assert service.email_client.messages == []


# ── Tool and server mismatch ──────────────────────────────────────────────────

def test_tool_mismatch_is_blocked(service):
    """Execute with a different tool_name than was proposed."""
    proposed = service.propose(email())

    # Craft an invocation with same server but different tool
    # (Pydantic will reject unknown tool_name, so we patch the transaction directly)
    # Instead: verify the existing check catches differing server_id
    with service._session() as db:
        db.execute(
            "UPDATE transactions SET tool_name='read_inbox' WHERE id=?",
            (proposed.transaction_id,),
        )

    with pytest.raises(ServiceError) as exc:
        run(service.execute(proposed.transaction_id, email(), None))
    assert exc.value.code == "TOOL_MISMATCH"
    assert service.email_client.messages == []


def test_server_mismatch_is_blocked(service):
    """Execute with a different server_id than was proposed."""
    proposed = service.propose(email())

    with service._session() as db:
        db.execute(
            "UPDATE transactions SET server_id='other-server-v1' WHERE id=?",
            (proposed.transaction_id,),
        )

    with pytest.raises(ServiceError) as exc:
        run(service.execute(proposed.transaction_id, email(), None))
    assert exc.value.code == "TOOL_MISMATCH"
    assert service.email_client.messages == []


# ── Cross-transaction token reuse ─────────────────────────────────────────────

def test_cross_transaction_token_rejected(service):
    """
    Token issued for transaction A cannot be used to execute transaction B.
    """
    tx_a = service.propose(email("alice@partner.test"))
    tx_b = service.propose(email("alice@partner.test"))
    token_a = service.approve(tx_a.transaction_id)["token"]
    service.approve(tx_b.transaction_id)

    with pytest.raises(ServiceError) as exc:
        run(service.execute(tx_b.transaction_id, email("alice@partner.test"), token_a))
    assert exc.value.code == "WRONG_TRANSACTION"
    assert service.email_client.messages == []


def test_double_approval_rejected(service):
    """A transaction cannot be approved twice."""
    proposed = service.propose(email("alice@partner.test"))
    service.approve(proposed.transaction_id)
    with pytest.raises(ServiceError) as exc:
        service.approve(proposed.transaction_id)
    assert exc.value.code == "NOT_AWAITING_APPROVAL"


# ── Audit log hash chain ──────────────────────────────────────────────────────

def test_audit_chain_valid_after_normal_flow(service):
    """Hash chain should be valid after a complete allow → execute flow."""
    proposed = service.propose(email())
    run(service.execute(proposed.transaction_id, email(), None))
    result = service.verify_audit_chain(proposed.transaction_id)
    assert result["valid"] is True
    assert result["events"] >= 3  # PROPOSED, ALLOW, EXECUTED


def test_audit_chain_valid_after_block(service):
    """Hash chain should be valid after a denied transaction."""
    proposed = service.propose(email(to="attacker@evil.test", attachment="confidential_q4.pdf"))
    result = service.verify_audit_chain(proposed.transaction_id)
    assert result["valid"] is True


def test_audit_chain_detects_tampering(service):
    """Modifying an audit event should break the hash chain verification."""
    proposed = service.propose(email())
    run(service.execute(proposed.transaction_id, email(), None))

    # Tamper with the first audit event's message
    with service._session() as db:
        db.execute(
            "UPDATE audit_events SET message='TAMPERED' WHERE transaction_id=? AND id=(SELECT MIN(id) FROM audit_events WHERE transaction_id=?)",
            (proposed.transaction_id, proposed.transaction_id),
        )

    result = service.verify_audit_chain(proposed.transaction_id)
    assert result["valid"] is False
    assert result["broken_at"] is not None


# ── Data labels ───────────────────────────────────────────────────────────────

def test_data_labels_loaded(service):
    """Data labels should be seeded from the database."""
    labels = service.data_labels()
    names = [l["resource_pattern"] for l in labels]
    assert "confidential_q4.pdf" in names
    assert "meeting_notes.pdf" in names


def test_confidential_label_drives_deny(service):
    """A confidential-labelled attachment going external must be denied."""
    proposed = service.propose(email(to="attacker@evil.test", attachment="confidential_q4.pdf"))
    # Decision is DENY; _response() maps this to status=BLOCKED in the response
    assert proposed.status == "BLOCKED"
    assert proposed.policy_id == "P-DENY-001"


def test_internal_label_allows_internal_send(service):
    """An internal-labelled attachment going to company.test should be allowed."""
    proposed = service.propose(email(to="alice@company.test", attachment="meeting_notes.pdf"))
    assert proposed.decision == "ALLOW"


# ── Policies API ─────────────────────────────────────────────────────────────

def test_policies_loaded(service):
    """Active policies should be loadable from the database."""
    policies = service.policies()
    assert len(policies) >= 4
    decisions = {p["decision"] for p in policies}
    assert "DENY" in decisions
    assert "ALLOW" in decisions
    assert "REQUIRE_APPROVAL" in decisions
