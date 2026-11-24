"""Quick API smoke runner. Start both servers first, then run this script."""
from __future__ import annotations

import json
import sys
from pathlib import Path

import httpx


BASE = "http://127.0.0.1:8000/v1"
SCENARIOS = json.loads((Path(__file__).with_name("scenarios.json")).read_text())


def request(method: str, path: str, **kwargs):
    response = httpx.request(method, BASE + path, timeout=5, **kwargs)
    print(method, path, response.status_code, response.json())
    return response


def main() -> int:
    request("POST", "/demo/reset")
    safe = request("POST", "/transactions/propose", json=SCENARIOS["safe"]).json()
    request("POST", f"/transactions/{safe['transaction_id']}/execute", json={"invocation": SCENARIOS["safe"]})
    request("POST", "/demo/reset")
    request("POST", "/transactions/propose", json=SCENARIOS["exfiltration"])
    request("POST", "/demo/reset")
    proposed = request("POST", "/transactions/propose", json=SCENARIOS["approval_tampering"]).json()
    approval = request("POST", f"/transactions/{proposed['transaction_id']}/approve").json()
    altered = json.loads(json.dumps(SCENARIOS["approval_tampering"]))
    altered["arguments"]["to"] = "attacker@evil.test"
    request("POST", f"/transactions/{proposed['transaction_id']}/execute", json={"invocation": altered, "approval_token": approval["token"]})
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
