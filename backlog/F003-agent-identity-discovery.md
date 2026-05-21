# F003 — Agent Identity Discovery Endpoint

**Status:** Todo
**Type:** Feature
**Created:** 2026-05-20
**Priority:** Medium
**Category:** Protocol

## Description

Add a `/.well-known/agent-identity.json` discovery endpoint, similar to Google A2A's `/.well-known/agent.json` (Agent Card). This allows other agents and systems to discover an agent's identity metadata, capabilities, and auth server without out-of-band configuration.

## Why It's Needed

Google A2A has Agent Cards. OIDC has discovery documents. AID has no way for an agent to advertise its identity or capabilities. This gap means AID agents can't participate in automated discovery flows — everything requires manual configuration.

## Business Case

- **A2A interoperability**: Positions AID as complementary to A2A by enabling cross-protocol agent discovery.
- **MCP integration story**: "AID is the identity layer underneath MCP and A2A" becomes tangible when agents can be discovered.
- **Strategic positioning**: Demonstrates AID is a complete identity framework, not just a token exchange.

## Implementation Plan

- Define `/.well-known/agent-identity.json` schema (name, address, fingerprint, public_key, auth_server, capabilities)
- Add `aid-card` command to generate/serve the discovery document
- Auth server can optionally host agent cards for registered agents
- Effort: M (2-3 days)
