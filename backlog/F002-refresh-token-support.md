# F002 — Add Refresh Token Support

**Status:** Todo
**Type:** Feature
**Created:** 2026-05-20
**Priority:** Medium
**Category:** Protocol

## Description

Add OAuth 2.0 refresh token support so agents don't need to re-prove their identity (full Ed25519 proof of possession) for every token renewal. When an agent's access token expires, it should be able to exchange a refresh token for a new access token without the full cryptographic handshake.

## Why It's Needed

Currently, when an agent's JWT expires, it must perform the full `aid-token` flow: construct Agent Identity, sign proof of possession, send to `/oauth/token`. This is unnecessary overhead for token renewal — the agent has already proven its identity.

Every major OAuth 2.0 implementation supports refresh tokens. MCP mandates them. Not having them makes AID look incomplete to security reviewers and adds unnecessary load on both agent and auth server.

## Business Case

- **Parity with standards**: OAuth 2.0, MCP, and Entra all support refresh tokens. Missing this makes AID look immature.
- **Performance**: Reduces cryptographic operations on both sides for routine token renewals.
- **Developer experience**: Agents can maintain long-running sessions without re-authentication complexity.

## Implementation Plan

- Add `refresh_token` field to token response
- Add `grant_type=refresh_token` support to `/oauth/token` endpoint
- Refresh tokens should be bound to the agent's fingerprint (not transferable)
- Refresh token rotation: issue new refresh token with each use, invalidate old one
- Configurable refresh token TTL (default: 7 days)
- Key files: `aid-token.sh`, Auth API `oauth_controller.rb`
- Effort: M (2-3 days)
