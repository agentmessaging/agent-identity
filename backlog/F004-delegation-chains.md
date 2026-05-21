# F004 — Delegation Chains for Sub-Agents

**Status:** Todo
**Type:** Feature
**Created:** 2026-05-20
**Priority:** Low
**Category:** Protocol

## Description

Add `act` (actor) claims to AID-issued JWTs when an agent spawns sub-agents, enabling cryptographic delegation chains. When Agent A requests Agent B to perform a task, Agent B's token should carry both its own identity and Agent A's delegation context.

Follows the pattern in IETF `draft-oauth-ai-agents-on-behalf-of-user-02`.

## Why It's Needed

As AI agent ecosystems grow, agents increasingly delegate to sub-agents (e.g., a coordinator agent spawns specialist agents). Without delegation chains, there's no way to audit who authorized what — only the last agent in the chain is visible.

## Business Case

- **Audit trail**: Enterprise compliance requires knowing the full authorization chain.
- **IETF alignment**: The `on-behalf-of` draft is gaining traction. Supporting `act` claims positions AID as compatible.
- **Security**: Prevents privilege escalation when sub-agents inherit parent permissions.

## Implementation Plan

- Add `act` claim support to JWT token generation
- Define delegation depth limits (prevent infinite nesting)
- Add `--delegate-from` flag to `aid-token` for agent-to-agent delegation
- Effort: L (full cycle)
