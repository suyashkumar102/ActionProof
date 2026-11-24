from __future__ import annotations

import pytest
from fastapi import HTTPException

from mock_email_mcp import server


def test_simulated_server_refuses_direct_calls():
    with pytest.raises(HTTPException) as error:
        server.require_gateway("not-the-gateway-key")
    assert error.value.status_code == 403
