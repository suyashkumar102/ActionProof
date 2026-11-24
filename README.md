# ActionProof Lock

**Approval that cannot be silently repurposed.** ActionProof Lock is a transaction firewall for AI agents. An agent can propose an MCP-style tool call, but the gateway executes only an exact policy-compliant action - never a broad, reusable permission to use a tool.

> This is a safe, local demo. The downstream Email MCP server is deliberately simulated; it does not send real email.

## What the demo proves

| Scenario | Evidence |
| --- | --- |
| Safe internal email | `meeting_notes.pdf` to `alice@company.test` is automatically allowed and appears in the mock mailbox. |
| Protected-file exfiltration | `confidential_q4.pdf` to `attacker@evil.test` is denied before the tool receives a request. |
| Approval tampering | A user approves `alice@partner.test`; changing only the recipient to `attacker@evil.test` produces a fingerprint mismatch and zero unauthorized messages. |

## Architecture

```text
untrusted agent -> ActionProof gateway -> simulated Email MCP server -> mock sent mailbox
                       |                  (gateway header required)
                       +-- deterministic policy
                       +-- fingerprint + HMAC approval
                       +-- SQLite audit trail
```

The fingerprint covers `server_id`, `tool_name`, canonical arguments, the reviewed tool-definition hash, and the policy version. Approvals are HMAC signed, expire after five minutes, and are recorded as used only after the simulated tool confirms execution.

## Run locally

Use two terminals from the repository root. Python 3.11+ is recommended.

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r backend\requirements.txt
$env:PYTHONPATH = "$PWD;$PWD\backend"
uvicorn mock_email_mcp.server:app --port 8001
```

The included `.env.example` documents deployment configuration. The local defaults are intentionally safe demo values, so no secret file is required to run the prototype. For a shared deployment, set the corresponding environment variables to non-default values.

In terminal two (activate the same environment first):

```powershell
$env:PYTHONPATH = "$PWD;$PWD\backend"
uvicorn app.main:app --reload --port 8000
```

Open [http://127.0.0.1:8000](http://127.0.0.1:8000). The UI is served by the gateway, so no Node or frontend build step is required. The API is also available at [http://127.0.0.1:8000/docs](http://127.0.0.1:8000/docs).

To run the scripted three-flow smoke demo:

```powershell
$env:PYTHONPATH = "$PWD;$PWD\backend"
python demo\run_demo.py
```

## Test

```powershell
$env:PYTHONPATH = "$PWD\backend"
pytest backend\tests -q
```

The tests cover canonical fingerprint stability, recipient mutation, tampered signatures, deterministic policy, single use, expiry, protected-file blocking, permitted delivery, and the guarantee that a mismatch does not reach the mailbox.

## API

| Method | Route | Purpose |
| --- | --- | --- |
| POST | `/v1/transactions/propose` | Policy evaluation and immutable fingerprint creation |
| POST | `/v1/transactions/{id}/approve` | Create a one-use, expiring HMAC approval |
| POST | `/v1/transactions/{id}/execute` | Re-evaluate policy, verify approval, then forward |
| GET | `/v1/transactions/{id}/audit` | Explain each decision in chronological order |
| GET | `/v1/mailbox/sent` | Read mail actually accepted by the simulated service |

## Limitations

- The prototype protects only tools routed through ActionProof.
- It verifies direct structured arguments, not all semantic leakage or LLM paraphrasing.
- Tool-definition pinning detects drift from a reviewed contract; it does not prove publisher identity.
- The Email MCP server is simulated for safe, repeatable testing.

## Team ownership map

- Security core: canonical JSON, fingerprint, HMAC tokens, replay/expiry tests.
- Gateway: FastAPI routes, SQLite state machine, deterministic policy, audit events.
- MCP integration: simulated tool contract, gateway-only access, mailbox.
- UI and narrative: controlled three-scenario console, review card, evidence strip, pitch notes.
