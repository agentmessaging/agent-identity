# F014 — DPoP-align proof-of-possession (RFC 9449) / sender-constrained agent tokens

**Status:** Todo
**Type:** Feature
**Created:** 2026-07-02
**Priority:** Medium
**Category:** Protocol / Security

## Description

Make AID agent tokens **sender-constrained**, aligned with **RFC 9449 (DPoP — Demonstrating Proof-of-Possession at the Application Layer for OAuth 2.0)**.

Two artifacts must not be confused:

- **The proof** — the ephemeral Ed25519-signed blob (`scripts/aid-token.sh:319`), ~5 min lifetime, sent **once, only to the token endpoint**.
- **The issued token** — the RS256 JWT, lives for its full TTL, presented **at resource servers**.

Today the proof protects *minting* a token, but the issued JWT is a plain **bearer** token. Anyone who obtains it (logs, proxy, a compromised resource server, the on-disk `tokens/` cache) can replay it against APIs until it expires.

**The goal of this item is to protect the issued token**, by binding it to the agent's key:

- Auth server issues tokens carrying `cnf.jkt` = SHA-256 thumbprint of the agent's public key (JWK).
- Client presents a fresh DPoP proof JWT on **every** resource-server call: header `typ: dpop+jwt` / `alg` / inline `jwk`; claims `jti`, `htm`, `htu`, `iat`, optional server `nonce`, and `ath` (access-token hash).
- Each resource server validates that proof and checks it matches the token's `cnf.jkt`.

A stolen token alone then becomes worthless — replaying it requires the Ed25519 private key.

## Why It's Needed

Agents run in more-exposed environments than human users — cached tokens on disk, MCP proxies, shared CI, third-party resource servers. A leaked agent bearer token is a high-value, fully-replayable credential for its entire TTL. AID's current PoP protects *issuance* but not *use*; sender-constraining the issued token is the only thing that defends the actual high-value target.

## Rejected alternative — proof-only hardening (do not re-propose)

An earlier draft proposed a cheaper "Level 1": add `jti` (single-use) and a target-URL (`htu`) binding to the *proof* only, without touching the issued token. This was analyzed and **rejected as marginal** — documented here so it isn't re-suggested:

- **URL/`htu` binding buys nothing at the proof layer.** An AID proof has exactly one destination — the token endpoint. Unlike DPoP (where proofs hit many resource servers), there is no second endpoint to replay it to. `htu` only earns its keep once proofs are presented per-call at resource servers — i.e. as part of the full work below, not as a standalone step.
- **`jti` single-use adds little over the existing 5-min window.** To replay a proof an attacker must capture the request — but whoever captures the request almost always captures the response, which already contains the issued token directly, so replaying the proof yields nothing new. The only gap `jti` closes is "request body logged, response body not, and read within 5 minutes" — which the 5-minute window already largely defeats, since log-based attacks are rarely real-time.

Conclusion: `jti`/`htu` are sub-components of the sender-constrained-token work, not an independently shippable win. Ship the whole thing or nothing.

## Business Case

- **Risk mitigation (security):** eliminates the stolen-bearer-token replay class — the highest-leverage attack against a deployed agent. Strengthens the AID story for the OWASP Agentic Top 10 (see [F009](./F009-owasp-agentic-mapping.md)).
- **Standards credibility:** AID PoP is effectively a pre-DPoP design. Adopting the ratified RFC 9449 format signals maturity, interoperates with existing OAuth tooling, and strengthens the IETF Internet-Draft ([F001](./F001-ietf-internet-draft-submission.md)) Security Considerations.
- **Composes with least-privilege work:** pairs with transaction tokens ([F006](./F006-transaction-tokens.md)) — sender-constraint + per-operation scope is the full defense-in-depth picture.

## Implementation Plan

- **Client (`scripts/aid-token.sh` + a per-call proof helper):** build the DPoP proof JWT — base64url header + claims + Ed25519 signature — via `$OPENSSL_BIN` and `jq -cS`. Reuse existing `sign_message` (tempfile-based, avoids the OpenSSL 3 Ed25519+stdin bug). Emit a proof per resource-server request, not just at issuance.
- **Server-side (blocks-auth-api + every resource server):** auth server adds `cnf.jkt` to issued tokens; each resource server requires and validates a fresh DPoP proof per call and checks it against `cnf.jkt`. This is the bulk of the effort and spans repos — file a companion issue on `blocks-auth-api` as with F007.
- **Docs:** update the "Token request wire format" section of `README.md` and the AID protocol spec in lockstep (spec-implementation parity convention). Keep the issued credential in the standard `access_token` response field regardless of type (consistency with F007).
- **Open questions / risks:**
  - **Multi-repo rollout is the hard part** — sender-constraint is only real once resource servers enforce it. Sequence: auth server emits `cnf.jkt` → resource servers begin validating → deprecate plain bearer.
  - **Backward compatibility:** negotiate via auth-server metadata (advertise DPoP support) so legacy bearer flow still works during migration.
  - **Replay cache** for proof `jti` must be **shared across auth/resource-server instances** (e.g. Redis, not in-process memory), or a load-balanced deployment lets a replay land on a node that hasn't seen the `jti`.
  - Server-issued `nonce` is optional in RFC 9449 — decide whether to require it.
- **Effort:** L (full cycle, multi-repo). No smaller independently-valuable slice exists (see rejected alternative).
- **Suggested slot:** feeds the v2.0 "Standards release" alongside F001; can start once F012 conformance harness gives a regression baseline.
