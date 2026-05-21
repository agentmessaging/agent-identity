# F006 — Transaction Tokens

**Status:** Todo
**Type:** Feature
**Created:** 2026-05-20
**Priority:** Low
**Category:** Protocol

## Description

Add transaction token support (inspired by WIMSE) to scope an agent's token to a specific operation or request. A transaction token is a short-lived, single-use token derived from the agent's access token, constrained to one specific action.

## Why It's Needed

Current AID tokens grant all scopes for the token's lifetime. If an agent needs to call a sensitive endpoint once, it holds broad permissions for the full TTL. Transaction tokens enable least-privilege per-operation authorization.

## Business Case

- **Security**: Prevents lateral movement — even if a transaction token is intercepted, it's single-use and operation-scoped.
- **WIMSE alignment**: The IETF WIMSE working group is standardizing transaction tokens. Early adoption signals protocol maturity.
- **Compliance**: Fine-grained authorization helps with SOC 2 and HIPAA audit requirements.

## Implementation Plan

- Define transaction token format (JWT with `txn` claim, operation scope, single-use)
- Add `POST /oauth/transaction-token` endpoint
- Token binding: transaction token is cryptographically bound to the parent access token
- Effort: L (full cycle)
