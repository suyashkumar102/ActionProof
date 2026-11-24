from __future__ import annotations

from typing import Any

import httpx


class FilesystemMCPClient:
    """Client for the simulated Filesystem MCP server. Only the gateway holds the key."""

    def __init__(self, base_url: str, gateway_key: str):
        self.base_url = base_url.rstrip("/")
        self.gateway_key = gateway_key

    def _headers(self) -> dict[str, str]:
        return {"X-ActionProof-Gateway-Key": self.gateway_key}

    async def list_directory(self, path: str = "/") -> dict[str, Any]:
        async with httpx.AsyncClient(timeout=5) as client:
            r = await client.get(f"{self.base_url}/mcp/list_directory", params={"path": path})
            r.raise_for_status()
            return r.json()

    async def read_file(self, path: str) -> dict[str, Any]:
        async with httpx.AsyncClient(timeout=5) as client:
            r = await client.get(
                f"{self.base_url}/mcp/read_file",
                params={"path": path},
                headers=self._headers(),
            )
            r.raise_for_status()
            return r.json()

    async def write_file(self, path: str, content: str) -> dict[str, Any]:
        async with httpx.AsyncClient(timeout=5) as client:
            r = await client.post(
                f"{self.base_url}/mcp/write_file",
                json={"path": path, "content": content},
                headers=self._headers(),
            )
            r.raise_for_status()
            return r.json()

    async def file_label(self, path: str) -> str:
        """Return just the label string for a file path."""
        async with httpx.AsyncClient(timeout=5) as client:
            r = await client.get(f"{self.base_url}/mcp/file_label", params={"path": path})
            r.raise_for_status()
            return r.json().get("label", "unclassified")

    async def available(self) -> bool:
        try:
            async with httpx.AsyncClient(timeout=2) as client:
                r = await client.get(f"{self.base_url}/mcp/list_directory")
                return r.status_code == 200
        except Exception:
            return False
