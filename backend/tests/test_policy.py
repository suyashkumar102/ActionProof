from app.models import Invocation
from app.policy import evaluate


def invocation(to, attachment):
    return Invocation(server_id="mock-email-v1", tool_name="send_email", arguments={"to":to,"subject":"Test","body":"Test body","attachment":attachment})


def test_internal_non_sensitive_is_allowed():
    assert evaluate(invocation("alice@company.test", "meeting_notes.pdf")).decision == "ALLOW"


def test_confidential_external_is_hard_denied():
    result = evaluate(invocation("attacker@evil.test", "confidential_q4.pdf"))
    assert (result.decision, result.policy_id) == ("DENY", "P-DENY-001")


def test_partner_demo_requires_approval():
    assert evaluate(invocation("alice@partner.test", "meeting_notes.pdf")).decision == "REQUIRE_APPROVAL"
