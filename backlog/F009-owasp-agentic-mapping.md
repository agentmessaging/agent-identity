# F009 — Map AID to OWASP Agentic Top 10

**Status:** Todo
**Type:** Documentation / compliance
**Created:** 2026-05-26
**Priority:** High
**Category:** Enterprise legibility
**Effort:** S-M (3-4 days)

## Description

Publish a `docs/owasp-agentic-mapping.md` document in the agent-identity repo that maps each of the 10 OWASP Agentic AI risks to the specific AID controls that address it, the controls that partially address it, and the risks that are explicitly out of scope.

Include a summary table in the README so security reviewers can see the mapping at a glance.

## Why It's Needed

Microsoft's [Agent Governance Toolkit](https://github.com/microsoft/agent-governance-toolkit) (2.3k stars) maps to "10/10 OWASP Agentic Top 10" and publishes formal compliance docs. That has set the bar for enterprise procurement: security teams now ask for the OWASP mapping by default.

AID either has the mapping documented or it gets dismissed as "another vendor proposal." This is the cheapest way to clear the procurement bar.

## Business Case

- **Enterprise procurement legibility** — security teams have the OWASP list memorized; they want the mapping in 10 rows
- **Audit-ready posture** — SOC 2 / NIST AI RMF / EU AI Act readiness flows from OWASP coverage
- **Honest gaps win trust** — being explicit about what AID doesn't cover (prompt injection, supply chain, etc.) makes the claims about what it *does* cover more credible
- **Differentiation from peers** — no other agent-auth proposal in our research folder publishes an OWASP mapping yet

## Implementation Plan

### Phase 1 — Read the OWASP Agentic Top 10 (1 day)
- Fetch the latest version from [owasp.org](https://owasp.org/www-project-agentic-ai-top-10/) or the OWASP repo
- The list is structured roughly: agent identity, tool abuse, prompt injection, output handling, supply chain, etc.
- Read Microsoft's [OWASP-COMPLIANCE.md](https://github.com/microsoft/agent-governance-toolkit/blob/main/docs/OWASP-COMPLIANCE.md) for reference structure

### Phase 2 — Draft the mapping (1-2 days)
For each of the 10 risks, write three sections:
1. **The risk** (one paragraph)
2. **AID controls** — which AID mechanisms address it (Ed25519 identity, proof of possession, role-scoped tokens, audit trail via introspection, suspend/revoke, etc.)
3. **Coverage** — `Full`, `Partial`, or `Out of scope` with honest reasoning

For `Out of scope` items, point to what *does* address it (e.g., "Microsoft Agent Governance Toolkit handles this at the policy layer")

### Phase 3 — Publish (1 day)
- Add `docs/owasp-agentic-mapping.md` to the repo
- Add a summary table to README under a new "Compliance" section
- Update [SKILL.md](../skills/agent-identity/SKILL.md) with a short reference
- Blog post on agentids.org announcing the mapping (~600 words)

## Risks

- **Some risks AID legitimately can't address** (e.g., prompt injection — that's the runtime layer's problem, not auth's). Honest "Out of scope" rows are correct, not a weakness — but the framing matters.
- **OWASP list may evolve.** Snapshot the version we mapped against; commit to refresh annually.
- **Microsoft's existing mapping might set framing we have to address.** Read theirs first to position ours.

## Definition of Done

- `docs/owasp-agentic-mapping.md` published
- README has a summary table linking to the doc
- Blog post announcing the mapping is live
- README's "For Auth Server Implementers" section references the mapping

## Sources / references

- [OWASP Agentic AI Top 10](https://owasp.org/www-project-agentic-ai-top-10/) (verify latest URL)
- [Microsoft Agent Governance Toolkit OWASP compliance](https://github.com/microsoft/agent-governance-toolkit/blob/main/docs/OWASP-COMPLIANCE.md)
- Internal research: [`research/microsoft-agent-governance.md`](../research/microsoft-agent-governance.md)
