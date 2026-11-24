from __future__ import annotations

from dataclasses import dataclass

from .models import Invocation


@dataclass(frozen=True)
class PolicyResult:
    decision: str
    policy_id: str
    reason: str


def evaluate(invocation: Invocation) -> PolicyResult:
    args = invocation.arguments
    domain = args.to.rsplit("@", 1)[1].lower()
    confidential = args.attachment == "confidential_q4.pdf"
    if domain != "company.test" and confidential:
        return PolicyResult("DENY", "P-DENY-001", "Protected attachment may not leave approved domain")
    if domain == "company.test" and not confidential:
        return PolicyResult("ALLOW", "P-ALLOW-001", "Internal, non-sensitive communication")
    if domain == "partner.test" and args.attachment == "meeting_notes.pdf":
        return PolicyResult("REQUIRE_APPROVAL", "P-APPROVE-002", "Demo partner communication requires approval")
    if domain != "company.test" and not confidential:
        return PolicyResult("REQUIRE_APPROVAL", "P-APPROVE-001", "External communication requires approval")
    return PolicyResult("DENY", "P-DENY-001", "Protected attachment may not leave approved domain")

