from __future__ import annotations

from dataclasses import replace

import pytest

from app.clients.email_mcp_client import EmailMCPClient
from app.config import settings
from app.db import initialize
from app.transactions import TransactionService


class FakeEmailClient(EmailMCPClient):
    def __init__(self):
        self.messages = []

    async def send_email(self, arguments):
        message = {"id": f"mail_{len(self.messages)+1}", **arguments}
        self.messages.append(message)
        return {"accepted": True, "message": message}

    async def sent_messages(self):
        return self.messages

    async def reset(self):
        self.messages.clear()


@pytest.fixture
def service(tmp_path):
    configured = replace(settings, db_path=tmp_path / "actionproof.db", secret="test-secret", approval_seconds=300)
    initialize(configured.db_path)
    client = FakeEmailClient()
    instance = TransactionService(configured, client)
    instance.seed_tool_registry()
    return instance

