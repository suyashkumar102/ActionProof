# Architecture

```text
Untrusted agent -> ActionProof gateway -> simulated Email MCP server -> mock mailbox
                       |        |
                       |        +-- HMAC approval verifier (expiry + single use)
                       +-- deterministic policy + exact transaction fingerprint
                       +-- SQLite transactions, approvals, audit trail, pinned tool contract
```

The browser never contacts the email server directly. The simulated tool refuses requests that do not carry the gateway-only header. ActionProof computes a SHA-256 fingerprint over the reviewed server, tool, arguments, pinned tool-definition hash, and policy version. A signed approval is bound to that fingerprint and may be consumed only once.

## Threat model

The proposing agent is untrusted: it can be prompt-injected or change its requested arguments after a user review. It cannot cause an email to be stored unless ActionProof permits that exact invocation. The prototype deliberately does not protect tools that bypass the gateway, semantic leakage caused by LLM paraphrase, or publisher identity beyond detecting changed tool definitions.
