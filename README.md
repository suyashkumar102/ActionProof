# ActionProof

**Runtime Security, Policy Enforcement and Transaction Verification Gateway for AI Agents**

---

AI agents connected to external tools through protocols like MCP can be manipulated into performing actions the user never authorised — reading private files, sending confidential data to external recipients, or executing destructive operations in response to injected instructions hidden inside emails, documents, or tool outputs.

ActionProof is a security gateway that sits between an AI agent and its connected MCP servers. Every tool invocation passes through ActionProof before it reaches a downstream service. The gateway verifies tool integrity, evaluates the request against deterministic security policies, and enforces cryptographically bound approvals. An agent cannot silently modify a request after a user has reviewed it. A consumed approval cannot be replayed. A tampered tool definition is detected before any transaction is created.

**An AI agent may propose an action. ActionProof determines whether it executes.**

---

## Core Capabilities

### Cryptographically Pinned Tool Registry
ActionProof registers each downstream MCP tool at startup and stores a SHA-256 hash of its definition — name, description, and input schema. Before creating any transaction, the gateway recomputes the hash and compares it against the pinned approved version. If the tool description or schema has changed since registration, the gateway raises a `REGISTRY_DRIFT` error and blocks all calls to that tool until the updated definition has been reviewed and re-approved. This prevents tool-definition poisoning attacks, where an attacker modifies a tool's description to inject instructions into the agent's context.

### Deterministic Policy Enforcement
Every incoming tool invocation is evaluated against a set of security policies before a transaction is created. Policies are deterministic — the same invocation always produces the same decision. There is no probabilistic or model-based component in the enforcement path. Each invocation receives one of three outcomes:

- **ALLOW** — the operation satisfies all configured policies and executes immediately.
- **REQUIRE_APPROVAL** — the operation is sensitive and requires explicit user authorisation before it can proceed.
- **DENY** — the operation violates a security policy and is blocked unconditionally.

Policies are evaluated a second time at execution, not only at proposal, ensuring that a policy change between approval and execution is always enforced.

### Transaction-Bound Approvals
When a policy result is `REQUIRE_APPROVAL`, ActionProof creates an immutable transaction record and presents the exact proposed action to the user for review. The user sees the precise recipient, subject, attachment, server, tool, and a fingerprint of the complete operation.

If the user approves, ActionProof issues an HMAC-SHA256 signed token bound to the cryptographic fingerprint of that specific transaction. The fingerprint is derived from the server identity, tool name, canonicalised arguments, the approved tool-definition hash, and the current policy version. If any argument changes between approval and execution — including a single character in a recipient address — the fingerprint no longer matches and execution is blocked. Approval tokens are single-use and expire after five minutes.

### Approval Tamper Detection
An agent that attempts to change the recipient, attachment, or any other argument after receiving user approval will be blocked at execution time. The gateway recalculates the fingerprint from the submitted arguments and compares it against the fingerprint stored when the transaction was proposed. A mismatch produces a `FINGERPRINT_MISMATCH` error and no request reaches the downstream tool.

### Single-Use Token Enforcement
Each approval token is recorded in the database with a `used_at` timestamp on first consumption. Any subsequent attempt to reuse the same token — whether against the original transaction or a different one — is rejected with a `TOKEN_REPLAY` error. Tokens that belong to a different transaction are rejected with `WRONG_TRANSACTION`. This prevents an agent from accumulating approvals and reusing them across multiple operations.

### Registry Drift Detection
The gateway continuously verifies that every registered tool definition still matches the hash that was reviewed and approved. If a downstream MCP server's tool description is modified after registration — intentionally or as the result of a supply-chain compromise — ActionProof detects the hash mismatch at the next proposal attempt and blocks execution until the new definition is explicitly re-approved by a human operator.

### Gateway-Only Downstream Access
The simulated Email MCP server rejects all direct requests. Access requires a secret gateway key transmitted in the `X-ActionProof-Gateway-Key` header, which only the ActionProof gateway holds. An agent cannot bypass the enforcement layer by calling the downstream tool directly.

### Append-Only Audit Trail
Every event in the lifecycle of a transaction is recorded in a SQLite audit log — proposal, policy decision, approval issuance, execution or block. Events are never deleted. The audit timeline is surfaced in the UI for every transaction, showing each decision in chronological order with the reason it was made.

---

## Attack Scenarios Demonstrated

| # | Scenario | Attack Vector | Gateway Response |
|---|---|---|---|
| 01 | Safe internal email | — | Policy ALLOW; executes immediately; email appears in mock mailbox |
| 02 | Indirect prompt injection | Malicious instructions embedded in an email body direct the agent to exfiltrate `confidential_q4.pdf` to `attacker@evil.test` | Policy DENY (P-DENY-001); blocked before the tool receives any request |
| 03 | Approval tampering | User approves email to `alice@partner.test`; agent changes recipient to `attacker@evil.test` before execution | FINGERPRINT_MISMATCH; zero unauthorised emails delivered |
| 04 | Tool definition poisoning | Attacker modifies the tool description to inject a system override instruction after the tool was registered | REGISTRY_DRIFT; all tool calls blocked until definition is re-approved |
| 05 | Approval token replay | Agent reuses a consumed approval token to attempt a second execution | TOKEN_REPLAY / WRONG_TRANSACTION; blocked; only the legitimate first execution reaches the mailbox |

---

## Architecture

```
Untrusted Agent
       |
       | MCP tool invocation
       v
+---------------------------+
|   ActionProof Gateway     |  port 8000
|                           |
|  +---------+  +--------+  |
|  | Tool    |  | Policy |  |
|  | Registry|  | Engine |  |
|  +---------+  +--------+  |
|       |            |      |
|  Hash |       ALLOW / REQUIRE_APPROVAL / DENY
|  check|            |      |
|       |     +------+---+  |
|       |     | Txn Svc  |  |
|       |     | propose  |  |
|       |     | approve  |  |
|       |     | execute  |  |
|       |     +----------+  |
|            Fingerprint +  |
|            HMAC token     |
|                           |
|       Audit Engine        |
|       (append-only)       |
+---------------------------+
       |
       | Gateway key required
       v
+---------------------------+
|  Simulated Email MCP      |  port 8001
|  (rejects direct calls)   |
+---------------------------+
       |
       v
  Mock sent mailbox
```

---

## Security Properties

| Property | Mechanism |
|---|---|
| Arguments cannot be changed after approval | SHA-256 fingerprint over canonical JSON arguments; recalculated at execute time |
| Approval token cannot be reused | Single-use flag written to `approvals` table on first consumption |
| Approval token cannot be forged | HMAC-SHA256 signed with gateway secret; verified on every execute call |
| Approval token expires | 5-minute server-side expiry checked before execution |
| Tool definition drift is detected | Registry hash compared against approved hash at every `propose` call |
| Agent cannot call downstream tools directly | `X-ActionProof-Gateway-Key` header enforced at the MCP server; 403 without it |
| Policy is enforced at execution, not only at proposal | Policy engine called twice per transaction |
| All decisions are recorded | Append-only SQLite audit events; never modified post-execution |

---

## Technology Stack

| Component | Technology |
|---|---|
| Gateway | Python, FastAPI |
| Policy engine | Custom deterministic rule engine |
| Cryptographic verification | SHA-256, HMAC-SHA256 |
| Approval integrity | Canonical JSON, cryptographic fingerprints |
| Approval tokens | HMAC-signed, base64url encoded, single-use |
| Database | SQLite |
| Frontend | Vanilla HTML, CSS, JavaScript (no build step) |
| MCP integration | Simulated HTTP MCP server |
| Testing | Pytest (11 tests) |

---

## Run Locally

Python 3.11 or later. Two terminals from the repository root.

**Terminal 1 — simulated Email MCP server**

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r backend\requirements.txt
$env:PYTHONPATH = "$PWD;$PWD\backend"
uvicorn mock_email_mcp.server:app --port 8001
```

**Terminal 2 — ActionProof gateway**

```powershell
.\.venv\Scripts\Activate.ps1
$env:PYTHONPATH = "$PWD;$PWD\backend"
uvicorn backend.app.main:app --reload --port 8000
```

Open [http://127.0.0.1:8000](http://127.0.0.1:8000) to access the demo UI.

Interactive API documentation is available at [http://127.0.0.1:8000/docs](http://127.0.0.1:8000/docs).

No Node.js, no build step, no secrets file required. The `.env.example` file documents all configurable environment variables.

---

## Run Tests

```powershell
$env:PYTHONPATH = "$PWD\backend"
pytest backend\tests -q
```

The test suite covers: fingerprint stability across argument ordering, recipient mutation detection, HMAC signature tampering, deterministic policy evaluation, single-use token enforcement, token expiry, protected-file blocking, permitted delivery, and the guarantee that a fingerprint mismatch never causes a request to reach the downstream server.

---

## API Reference

| Method | Route | Description |
|---|---|---|
| `POST` | `/v1/transactions/propose` | Evaluate policy and create an immutable fingerprinted transaction |
| `POST` | `/v1/transactions/{id}/approve` | Issue a one-use HMAC approval token bound to the transaction fingerprint |
| `POST` | `/v1/transactions/{id}/execute` | Verify fingerprint and approval, then forward to the downstream tool |
| `POST` | `/v1/transactions/{id}/reject` | Reject a pending approval |
| `GET` | `/v1/transactions/{id}` | Retrieve current transaction state |
| `GET` | `/v1/transactions/{id}/audit` | Retrieve the full chronological event log for a transaction |
| `GET` | `/v1/mailbox/sent` | List messages accepted by the simulated email server |
| `GET` | `/v1/registry/status` | Current pinned hash, approved hash, and drift status |
| `POST` | `/v1/registry/tamper` | Inject a poisoned tool description to demonstrate drift detection |
| `POST` | `/v1/registry/restore` | Restore the tool definition to its approved hash |
| `POST` | `/v1/demo/reset` | Clear all transactions, approvals, events, and restore the registry |
| `GET` | `/v1/health` | Gateway health check |
