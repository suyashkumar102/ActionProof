from __future__ import annotations

from typing import Any

import httpx


class EmailMCPClient:
    """Only the gateway owns this authorization header in the demo."""

    def __init__(self, base_url: str, gateway_key: str):
        self.base_url = base_url.rstrip("/")
        self.gateway_key = gateway_key

    async def send_email(self, arguments: dict[str, Any]) -> dict[str, Any]:
        async with httpx.AsyncClient(timeout=5) as client:
            response = await client.post(
                f"{self.base_url}/mcp/send_email",
                json=arguments,
                headers={"X-ActionProof-Gateway-Key": self.gateway_key},
            )
            response.raise_for_status()
            return response.json()

    async def read_inbox(self) -> list[dict[str, Any]]:
        async with httpx.AsyncClient(timeout=5) as client:
            response = await client.get(f"{self.base_url}/mcp/inbox")
            response.raise_for_status()
            return response.json()["messages"]

    async def sent_messages(self) -> list[dict[str, Any]]:
        async with httpx.AsyncClient(timeout=5) as client:
            response = await client.get(f"{self.base_url}/mcp/mailbox/sent")
            response.raise_for_status()
            return response.json()["messages"]

    async def reset(self) -> None:
        async with httpx.AsyncClient(timeout=5) as client:
            response = await client.post(
                f"{self.base_url}/mcp/reset",
                headers={"X-ActionProof-Gateway-Key": self.gateway_key},
            )
            response.raise_for_status()
