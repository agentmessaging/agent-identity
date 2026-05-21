# F005 — Cross-Organization Federation

**Status:** Todo
**Type:** Feature
**Created:** 2026-05-20
**Priority:** Low
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
