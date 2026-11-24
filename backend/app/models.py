from __future__ import annotations

from typing import Any, Literal, Union

from pydantic import BaseModel, Field, field_validator


# ── Email tool arguments ───────────────────────────────────────────────────────

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


class EmailInvocation(BaseModel):
    server_id: Literal["mock-email-v1"]
    tool_name: Literal["send_email"]
    arguments: EmailArguments

    def fingerprint_payload(self) -> dict[str, Any]:
        return self.model_dump(mode="json")


# ── Filesystem tool arguments ──────────────────────────────────────────────────

class ReadFileArguments(BaseModel):
    path: str = Field(min_length=1, max_length=500)


class WriteFileArguments(BaseModel):
    path: str = Field(min_length=1, max_length=500)
    content: str = Field(min_length=0, max_length=100_000)


class ListDirectoryArguments(BaseModel):
    path: str = Field(default="/", min_length=1, max_length=500)


class FilesystemInvocation(BaseModel):
    server_id: Literal["mock-filesystem-v1"]
    tool_name: Literal["read_file", "write_file", "list_directory"]
    arguments: Union[ReadFileArguments, WriteFileArguments, ListDirectoryArguments]

    def fingerprint_payload(self) -> dict[str, Any]:
        return self.model_dump(mode="json")


# ── Invocation type alias — keep Invocation as the email type for backwards compat ──
Invocation = EmailInvocation

# Union type for type hints (not for instantiation)
AnyInvocation = Union[EmailInvocation, FilesystemInvocation]


def parse_invocation(data: dict[str, Any]) -> Invocation:
    """Parse a raw dict into the correct Invocation type based on server_id."""
    server_id = data.get("server_id", "")
    if server_id == "mock-email-v1":
        return EmailInvocation(**data)
    if server_id == "mock-filesystem-v1":
        return FilesystemInvocation(**data)
    raise ValueError(f"Unknown server_id: {server_id}")


# ── Shared response models ─────────────────────────────────────────────────────

class ExecuteRequest(BaseModel):
    invocation: dict[str, Any]  # Raw dict, parsed by parse_invocation in the service
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
