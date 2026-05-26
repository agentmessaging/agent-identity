# AID ↔ OWASP Top 10 for Agentic Applications (2026)

This document maps each risk in the [OWASP Top 10 for Agentic Applications 2026](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/) to the specific Agent Identity (AID) controls that address it.

The honest summary: **AID is an identity-layer protocol.** It directly covers the risks that come from agents acting without scoped, attributable identity. It partially covers risks where identity contributes (containment, attribution, isolation). It does not cover risks that belong to the runtime, sandboxing, or policy layers — those compose with AID but aren't its concern.

## Coverage at a glance

| Code | Risk | Coverage | Primary AID controls |
|---|---|---|---|
| ASI01 | Agent Goal Hijacking | **Partial** | Per-agent attribution via introspection; fast revocation |
| ASI02 | Tool Misuse and Exploitation | **Full** | Role-scoped JWTs; scope intersection; real-time introspection |
| ASI03 | Identity and Privilege Abuse | **Full** | Ed25519 per-agent identity; short-lived tokens; per-request proof of possession |
| ASI04 | Agentic Supply Chain Vulnerabilities | **Partial** | Signed discovery (RFC 9728/8414); JWKS-based JWT validation |
| ASI05 | Unexpected Code Execution | **Out of scope** | Sandbox/runtime concern — compose with MS Agent Governance Toolkit |
| ASI06 | Memory and Context Poisoning | **Partial** | Per-agent identity enables tenant isolation; memory model is out of scope |
| ASI07 | Insecure Inter-Agent Communication | **Partial → Full with AMP** | Per-agent Ed25519 keypair; signed messages when paired with AMP |
| ASI08 | Cascading Failures | **Partial** | RFC 7662 introspection enables sub-second suspend; lifecycle management |
| ASI09 | Human-Agent Trust Exploitation | **Partial** | Introspection exposes agent_address / agent_role / agent_status for source attribution |
| ASI10 | Rogue Agents | **Partial** | Comprehensive audit trail; suspend/revoke as kill switch |

**Score**: Full=2 · Partial=7 · Out of scope=1 (of 10)

The two `Full` items (ASI02, ASI03) are exactly the identity-layer risks. They're why AID exists. The seven `Partial` items are risks where identity is a contributor; AID provides the identity-layer building blocks, but full coverage requires composition with runtime governance (MS Agent Governance Toolkit, OPA, Cedar) and inter-agent messaging (AMP). The one `Out of scope` (ASI05) is sandboxing — explicitly not AID's job.

---

## Detailed mapping

### ASI01 — Agent Goal Hijacking — **Partial**

**The risk.** An attacker injects malicious instructions into data the agent reads (emails, documents, web content). The agent can't reliably distinguish instructions from data and is redirected to perform harmful actions using its legitimate tools and credentials.

**AID controls.**
- **Per-agent attribution.** When a goal-hijacked agent does something harmful, AID's introspection response identifies which agent did it (`agent_address`, `agent_id`, `agent_role`). Forensic investigation has a clear principal to investigate.
- **Fast revocation.** `POST /agent_registrations/:unique_id/suspend` blocks the compromised agent's tokens from being validated within seconds (RFC 7662 introspection picks up suspension immediately, no waiting for token expiry).
- **Scoped privileges.** Even a hijacked agent can only act within its registered role's scopes. A read-only agent that gets goal-hijacked can still only read.

**Coverage.** AID does not prevent the hijacking itself — that's a runtime-layer / prompt-defense concern. AID *contains the blast radius* (scope envelope) and *speeds incident response* (attribution + revocation). Pair with content filtering, input sanitization, and policy enforcement at the tool-call layer for full coverage.

**Out of scope (defer to):** input validation, content filtering, prompt-injection defenses.

---

### ASI02 — Tool Misuse and Exploitation — **Full**

**The risk.** Agents use legitimate tools unsafely due to ambiguous prompts or manipulated input — deleting data, exfiltrating information, calling tools outside their intended purpose.

**AID controls.**
- **Strict permission scoping.** Every AID token is bound to a role; the role's scopes are the agent's maximum capability. An agent registered with `tickets:read` cannot call `tickets:delete` regardless of what it's been instructed to do — the auth server rejects the request.
- **Scope intersection.** The `scope` parameter on token requests enables *per-task narrowing*: an agent can request only the scopes needed for the current task, even narrower than its role allows. Excess scopes are rejected with `invalid_scope`.
- **Real-time introspection.** Target APIs that introspect tokens (RFC 7662) catch suspended/revoked agents on the very next call.
- **No long-lived bearer reuse.** AID's 5-minute proof-of-possession window means a stolen token isn't reusable beyond that window without the agent's private key.

**Coverage.** AID's authorization model directly implements the OWASP-recommended mitigations: "Apply strict permission scoping; implement rate limiting and anomaly detection" — the first half is AID by design.

**Out of scope (defer to):** tool-argument validation (application layer), anomaly detection (observability layer, e.g., MS Agent Governance Toolkit).

---

### ASI03 — Identity and Privilege Abuse — **Full**

**The risk.** Agents inherit and reuse high-privilege credentials, session tokens, and delegated access without proper scoping. Auth tokens get cached, shared, or persisted improperly.

**AID controls.** This is the core risk AID exists to address.
- **Per-agent cryptographic identity.** Each agent has its own Ed25519 keypair. No credential inheritance — the agent's identity is the agent's keypair.
- **Short-lived tokens with proof of possession.** Every token request carries a fresh Ed25519 signature over `aid-token-exchange\n<timestamp>\n<oidc_issuer>` with a 5-minute window. A stolen token without the private key is useless after that window.
- **Task-scoped credentials.** The `scope` parameter on `aid-token` lets an agent request only what it needs for the current task, even narrower than its role permits.
- **No token caching beyond expiry buffer.** Client-side cache lives for `expires_in - 60s` and is purged automatically. No persistent token storage in plaintext.
- **Least privilege via role binding.** The admin assigns a specific role at registration; the agent cannot escalate.

**Coverage.** AID's design *is* the mitigation for ASI03. The OWASP-recommended mitigations — "issue short-lived, task-scoped credentials; never allow agents to cache authentication tokens; implement least privilege" — are line-for-line what AID does.

---

### ASI04 — Agentic Supply Chain Vulnerabilities — **Partial**

**The risk.** Dynamically fetched components (tools, plugins, MCP servers) can be compromised at runtime. Malicious or tampered components inherit the agent's privileges.

**AID controls.**
- **Signed discovery.** AID's discovery uses RFC 9728 Protected Resource Metadata + RFC 8414 Authorization Server Metadata over TLS. Endpoint discovery cannot be spoofed without compromising TLS or the server itself.
- **JWKS-based JWT verification.** AID tokens are RS256-signed by the auth server's published JWKS. Target APIs verifying tokens have a cryptographic chain back to the auth server.
- **Token introspection** validates against the live auth server, defeating any cache-based token-replay attack via a tampered intermediary.

**Coverage.** AID hardens the *auth path*. Component verification (signed manifests, pinned versions, integrity hashes for tools/plugins) is the application's responsibility and belongs in the OpenGAP / package-management layer.

**Out of scope (defer to):** signed manifests (OpenGAP), curated tool registries (ACP, MCP), MCP configuration audits.

---

### ASI05 — Unexpected Code Execution — **Out of scope**

**The risk.** Agents generate or execute code unsafely through shell commands, scripts, eval statements. Treat generated code as untrusted; execute in hardened sandboxes.

**AID controls.** None. This is a sandboxing concern, not an identity concern.

**Coverage.** Explicitly out of scope. AID composes with code-execution governance tools (MS Agent Governance Toolkit's container-per-agent model, Docker sandboxes, Firecracker microVMs) but does not solve this risk itself.

**Defer to:** Microsoft Agent Governance Toolkit, container sandboxes, runtime policy engines.

---

### ASI06 — Memory and Context Poisoning — **Partial**

**The risk.** Attackers inject false or malicious information into an agent's long-term memory to influence future decisions. OWASP-recommended mitigations: "Segment memory by tenant and sensitivity; track provenance of memory entries; implement periodic integrity checks."

**AID controls.**
- **Per-agent identity enables tenant segmentation.** When agents have distinct Ed25519 identities and explicit role bindings, "tenant" is unambiguous — the agent's address (`support-bot@acme.local`) is the tenant key. Memory systems can segment cleanly on agent identity.
- **Audit trail via introspection.** Memory writes attributed to a specific agent (rather than a borrowed user identity) make provenance tracking meaningful.

**Coverage.** AID enables memory-layer mitigations by providing strong tenant identity. It does not implement memory itself — that's the runtime / memory-store concern.

**Defer to:** memory system implementations, OpenGAP's `memory/runtime/` convention.

---

### ASI07 — Insecure Inter-Agent Communication — **Partial → Full with AMP**

**The risk.** Multi-agent systems exchange messages without proper authentication or encryption, enabling spoofing and injection. OWASP mitigations: "Require mutual TLS and signed payloads; authenticate every message; implement replay protection."

**AID controls.**
- **Per-agent Ed25519 keypair.** Every AID-identified agent has its own key, suitable for signing inter-agent messages.
- **Per-message signatures.** With the same Ed25519 key, an agent can sign messages it sends to other agents, just as it signs proof-of-possession to its auth server.

**Coverage.**
- **Partial as AID alone:** the keys exist but AID doesn't define the inter-agent message protocol.
- **Full when paired with AMP** ([Agent Messaging Protocol](https://agentmessaging.org)) — AMP is built on the same Ed25519 identity AID issues. Messages are signed with the agent's AID key; recipients verify against the AID-published identity. Replay protection is built into AMP.

**Note.** AID and AMP share the same agent directory (`~/.agent-messaging/agents/`). One key serves both protocols.

---

### ASI08 — Cascading Failures — **Partial**

**The risk.** Errors propagate across interconnected agents, planning layers, downstream systems.

**AID controls.**
- **Sub-second containment.** AID's lifecycle endpoint `POST /agent_registrations/:unique_id/suspend` blocks new tokens immediately. Target APIs that introspect tokens (RFC 7662) refuse the next call from a suspended agent — no waiting for token TTL expiry.
- **Agent-status in introspection** provides explicit lifecycle state (`active`, `suspended`, `deleted`) so downstream systems can recognize a contained agent without out-of-band signaling.

**Coverage.** AID provides the *kill switch* primitive. Circuit breakers, timeouts, rollback, and isolation boundaries are runtime/orchestration concerns.

**Defer to:** runtime orchestration tools (LangGraph state machines, MS Agent Governance Toolkit's containment).

---

### ASI09 — Human-Agent Trust Exploitation — **Partial**

**The risk.** Users over-trust agent outputs. Attackers exploit this by influencing decisions or introducing subtle backdoors.

**AID controls.**
- **Source attribution.** Introspection responses carry `agent_address`, `agent_name`, `agent_role`, `agent_status` — the information UI layers need to display "this action was performed by support-bot, role=tier1-triage, status=active."
- **Provenance.** Every token traces to a specific agent and a specific role; logs cite the principal directly.

**Coverage.** AID provides the *data* for source attribution. UX choices (when to require human confirmation, how to display confidence) are application concerns.

**Defer to:** application UX patterns, MS Agent Governance Toolkit's "human-in-the-loop" approval modes.

---

### ASI10 — Rogue Agents — **Partial**

**The risk.** A compromised or misaligned agent acts harmfully while appearing to function normally.

**AID controls.**
- **Comprehensive audit trail.** Every AID token carries `agent_id`, `agent_address`, `agent_role`. Every introspection call returns the same. Audit logs at every target API trace actions to a specific agent.
- **Kill switch.** `POST /agent_registrations/:unique_id/revoke` permanently invalidates the agent. The `agent_id` cannot be reused. Introspection returns `active: false, reason: agent_not_found`.
- **Suspend before revoke.** For cases where you want to pause an agent for investigation without committing to permanent revocation, `suspend` is reversible.

**Coverage.** AID implements the OWASP-recommended audit logging and kill-switch mitigations. Behavioral monitoring (detecting that an agent is rogue) requires observability tooling.

**Defer to:** behavioral anomaly detection (MS Agent Governance Toolkit, Datadog, observability platforms).

---

## How to use this mapping

**If you're a security reviewer:** AID alone is not a complete agentic-AI security posture. It's the identity layer. Pair it with:
- A runtime governance tool ([MS Agent Governance Toolkit](https://github.com/microsoft/agent-governance-toolkit) is the obvious default — it explicitly covers 10/10 OWASP)
- An inter-agent messaging protocol ([AMP](https://agentmessaging.org), if multi-agent)
- A code-execution sandbox (containers, Firecracker, gVisor)

**If you're an AID implementer:** Make sure your auth server exposes the introspection fields that downstream systems need for attribution: `agent_id`, `agent_address`, `agent_role`, `agent_status`. These are not optional — they enable ASI09 and ASI10 mitigations at the application layer.

**If you're an agent operator:** Use the introspection endpoint actively. Don't rely on JWT expiry alone for revocation — the whole point of suspend/revoke is sub-second containment. Cache introspection results conservatively.

---

## Versioning

This mapping is against [OWASP Top 10 for Agentic Applications 2026](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/), released December 2025. We'll refresh this document annually or whenever OWASP publishes a new version, whichever is sooner.

**Last reviewed:** 2026-05-26

## Sources

- [OWASP Top 10 for Agentic Applications 2026](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/)
- [OWASP GenAI Security Project announcement](https://genai.owasp.org/2025/12/09/owasp-genai-security-project-releases-top-10-risks-and-mitigations-for-agentic-ai-security/)
- [Microsoft Agent Governance Toolkit OWASP compliance map](https://github.com/microsoft/agent-governance-toolkit/blob/main/docs/OWASP-COMPLIANCE.md) (reference structure)
