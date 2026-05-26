# F008 — Propose AID as an auth.md assertion_type

**Status:** Todo
**Type:** Feature (strategic / external)
**Created:** 2026-05-26
**Priority:** High
**Category:** Composition with WorkOS auth.md
**Effort:** S (1-2 days)

## Description

Open a PR on [`workos/auth.md`](https://github.com/workos/auth.md) adding `urn:aid:agent-identity` to `identity_assertion.assertion_types_supported` in the `agent_auth` discovery block. This makes AID a first-class assertion type that agents can present inside the auth.md registration flow.

The composition story: an agent that already has its own Ed25519 identity (via AID) can present that identity directly to an auth.md-implementing service, instead of relying solely on the agent-provider ID-JAG model.

## Why It's Needed

The blog post [auth.md and AID: Complementary Layers, Not Competitors](https://agentids.org/blog/auth-md-vs-aid-complementary-layers/) ends with this exact pitch. Materializing it as an actual PR turns the claim into a deployable artifact.

It also closes the most visible architectural gap in auth.md: the agent has no identity of its own. Adding AID as an assertion_type fixes that for any service that wants per-agent identity without abandoning auth.md's discovery flow.

## Business Case

- **Composition over competition** narrative becomes concrete, not theoretical
- **Distribution**: WorkOS's auth.md is positioned to be the dominant consumer-AI registration mechanism; landing inside it puts AID in front of every auth.md implementer
- **Cheap**: a single PR with spec changes and a sample registration request
- **Credibility**: being recognized as an assertion_type in someone else's spec is a stronger signal than self-published standards

## Implementation Plan

### Phase 1 — Outreach (before opening the PR)
- Email `authmd@workos.com` referencing the [comparison blog post](https://agentids.org/blog/auth-md-vs-aid-complementary-layers/)
- Frame as additive composition, not a competing claim
- Brief Garrett on the goal — confirm WorkOS is open to additional assertion types
- **Owner:** Juan

### Phase 2 — Spec PR
- Fork `workos/auth.md`
- Add `urn:aid:agent-identity` to `identity_assertion.assertion_types_supported` in the `agent_auth` discovery example
- Add a new section to `AUTH.md` (or wherever assertion_types are documented) explaining the AID assertion shape
- Reference the AID spec at agentids.org
- **Effort:** 4 hours

### Phase 3 — Sample request
- In the same PR, add an example `/agent/auth` request body where the agent presents an AID Agent Identity document instead of an ID-JAG JWT:
  ```json
  {
    "type": "identity_assertion",
    "assertion_type": "urn:aid:agent-identity",
    "assertion": "<base64url-encoded-signed-agent-identity>",
    "proof": "<base64url-encoded-proof-of-possession>",
    "requested_credential_type": "access_token"
  }
  ```
- Reference the AID canonical-JSON signing requirement
- **Effort:** 2 hours

### Phase 4 — Reference implementation hint
- Add a note that auth.md services can accept AID assertions either:
  - By validating the Agent Identity signature directly (if the agent is registered with this auth server via AID), OR
  - By federating to an upstream AID auth server via introspection
- **Effort:** 2 hours

## Risks

- **Garrett rejects entirely.** Mitigation: frame as additive, offer to maintain it as an optional extension rather than core.
- **WorkOS wants a richer spec change than a single PR.** Be ready to draft a longer proposal or split into multiple PRs.
- **The `agent_auth` block has internal conventions we don't know.** Read the existing spec carefully before drafting; ask in an issue first if uncertain.

## Definition of Done

PR is merged on `workos/auth.md`, OR a recorded conversation exists explaining why not. Blog post or thread announcing the composition once merged.

## References

- [auth.md repo](https://github.com/workos/auth.md)
- [auth.md app implementer guide](https://workos.com/auth-md/docs/apps)
- [Our comparison post](https://agentids.org/blog/auth-md-vs-aid-complementary-layers/)
- Contact: `authmd@workos.com`
