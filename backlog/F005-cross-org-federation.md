# F005 — Cross-Organization Federation

**Status:** In progress (relying-party profile and reference verifier drafted; issuer work and token exchange not started)
**Type:** Feature
**Created:** 2026-05-20
**Priority:** Medium
**Category:** Protocol

## Description

Enable trust between AID auth servers so agents registered on one server can authenticate with another. An agent registered at `auth.acme.com` should be able to request tokens from `auth.partner.com` if a federation trust exists between them.

## Why It's Needed

AID currently works within one auth server. Microsoft Entra Agent ID is also single-tenant. Google A2A and W3C DIDs address cross-org trust. For AID to serve multi-organization agent ecosystems, federation is essential.

## Business Case

- **Market expansion**: Cross-org federation is the #1 unsolved problem in agent identity. Being first to solve it is a massive differentiator.
- **Enterprise demand**: Large organizations have multiple tenants and partners that need agent interoperability.

## Implementation Plan

- Define federation trust establishment protocol (mutual JWKS exchange)
- Add `trusted_issuers` configuration to auth server
- Cross-server token exchange: agent presents token from Server A, Server B validates via Server A's JWKS and issues local token
- Effort: L+ (multi-cycle, requires security review)

## Update 2026-10-24: split into two slices

The need that matters first is not agent-to-server federation but a **company that does not run its own agent identity server** (Acme) trusting an AID issuer (23blocks) for its own agents and for agents it has authorized to work in it.

1. **F005a, relying-party profile and reference verifier (drafted).** [`docs/federation.md`](../docs/federation.md) and [`verifier/`](../verifier): the relying party trusts issuers directly, keeps the final decision (its own scope mapping, grants with a sponsor, deny by default), and checks freshness by introspection and status events. It works today against a tenant's own agents; for external agents it needs the issuer work below.
2. **F005b, cross-issuer token exchange** (the original plan above): later, shaped as an ID-JAG-style assertion.

### Issuer work this needs (the 23blocks gateway, tracked in its own repo)

R1 an audience specific to the service (RFC 8707 `resource`); R2 a `scope` string claim; R3 introspection that authenticates its caller; R4 status events to registered relying parties; R5 key rotation with an overlap; R6 the agent's role and the person who registered it in the introspection answer. Details and the current state of each are in [`docs/federation.md` §7](../docs/federation.md#7-what-an-issuer-must-add).
