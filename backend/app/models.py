from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, Field, field_validator


class EmailArguments(BaseModel):
    to: str
    subject: str = Field(min_length=1, max_length=200)
    body: str = Field(min_length=1, max_length=5000)
    attachment: str

    @field_validator("to")
    @classmethod
    def validate_email(cls, value: str) -> str:
        if "@" not in value or value.startswith("@") or value.endswith("@"):
            raise ValueError("to must be an email address")
        return value.lower()


class Invocation(BaseModel):
    server_id: Literal["mock-email-v1"]
    tool_name: Literal["send_email"]
    arguments: EmailArguments

    def fingerprint_payload(self) -> dict[str, Any]:
        return self.model_dump(mode="json")


class ExecuteRequest(BaseModel):
    invocation: Invocation
    approval_token: str | None = None


class DecisionResponse(BaseModel):
    transaction_id: str
    decision: Literal["ALLOW", "REQUIRE_APPROVAL", "DENY", "BLOCKED"]
    policy_id: str
    reason: str
    fingerprint: str
    status: str
    approval_request: dict[str, Any] | None = None
    changed_fields: list[str] = []

