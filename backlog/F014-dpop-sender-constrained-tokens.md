# F014 — DPoP-align proof-of-possession (RFC 9449) / sender-constrained agent tokens

**Status:** Todo
**Type:** Feature
**Created:** 2026-07-02
**Priority:** Medium
**Category:** Protocol / Security

## Description

Align AID's proof-of-possession with **RFC 9449 (DPoP — Demonstrating Proof-of-Possession at the Application Layer for OAuth 2.0)** so that agent tokens become **sender-constrained end-to-end**, not just at issuance.

Today `aid-token.sh` proves possession only at the **token endpoint**. The sign input is a bespoke line-delimited blob (`scripts/aid-token.sh:319`):

```
aid-token-exchange
<unix_ts>
<oidc_issuer>          ← Ed25519-signed, 5-min window
```

Once the RS256 JWT is issued it is a plain **bearer** token — anyone who obtains it (logs, proxy, a compromised resource server, the on-disk `tokens/` cache) can replay it against APIs until it expires. DPoP closes this by binding the issued token to the agent's key (`cnf.jkt` thumbprint claim) and requiring a fresh key-signed proof on **every** resource-server call.

This is conceptually the same PoP mechanism AID already has — extended from issuance to every API request, and re-expressed in the standard JWT format OAuth infrastructure understands.

Deliver in two levels (level 1 shippable independently):

**Level 1 — cheap hardening, stay custom (S):**
- Add a unique `jti` (nonce) to the proof → closes intra-window replay (proof currently reusable for the full 5 minutes).
- Add the target endpoint URL (analogue of DPoP `htu`/`htm`) to the sign input → binds the proof to the actual request target, not just `oidc_issuer`.
- One-line-ish change to `SIGN_INPUT` on client + matching server validation.

**Level 2 — full RFC 9449 alignment (L):**
- Client emits a real DPoP proof JWT: header `typ: dpop+jwt` / `alg` / inline `jwk`; claims `jti`, `htm`, `htu`, `iat`, optional server `nonce`, and `ath` (access-token hash) for resource-server calls.
- Auth server issues sender-constrained tokens carrying `cnf.jkt` = SHA-256 thumbprint of the JWK.
- Every resource server requires and validates a fresh DPoP proof per call.

## Why It's Needed

Agents run in more-exposed environments than human users — cached tokens on disk, MCP proxies, shared CI, third-party resource servers. A leaked agent bearer token is a high-value, fully-replayable credential for its entire TTL. AID's current PoP protects *minting* a token but not *using* one. Sender-constraining the token makes a leaked token alone worthless without the Ed25519 private key.

Secondary gaps level 1 fixes: the proof isn't bound to the request target (`oidc_issuer` is only a partial substitute), and replay defense is purely the 5-minute timestamp window with no single-use guarantee.

## Business Case

- **Risk mitigation (security):** eliminates the stolen-bearer-token replay class — the highest-leverage attack against a deployed agent. Directly strengthens the AID story for OWASP Agentic Top 10 (see [F009](./F009-owasp-agentic-mapping.md)).
- **Strategic positioning / standards credibility:** AID PoP is effectively a pre-DPoP design. Adopting the ratified RFC 9449 format signals maturity and interoperates with existing OAuth tooling — strengthens the IETF Internet-Draft ([F001](./F001-ietf-internet-draft-submission.md)) Security Considerations.
- **Composes with least-privilege work:** pairs naturally with transaction tokens ([F006](./F006-transaction-tokens.md)) — sender-constraint + per-operation scope is the full defense-in-depth picture.

## Implementation Plan

- **Client (`scripts/aid-token.sh`):**
  - Level 1: extend `SIGN_INPUT` with `jti` + target URL; keep pure-Bash. Bump the documented proof format in `README.md` in lockstep (spec-implementation parity convention).
  - Level 2: build the DPoP proof JWT — base64url header + claims + Ed25519 signature — via `$OPENSSL_BIN` and `jq -cS`. Reuse existing `sign_message` (tempfile-based, avoids the OpenSSL 3 Ed25519+stdin bug).
- **Server-side (blocks-auth-api + every resource server):** validate the proof, add `cnf.jkt` to issued tokens, enforce per-call DPoP at resource servers. This is the bulk of level-2 effort and spans repos — file a companion issue on `blocks-auth-api` as with F007.
- **Docs:** update the "Token request wire format" section of `README.md` and the AID protocol spec; note backward-compat / negotiation so minimal servers still work.
- **Open questions / risks:**
  - Backward compatibility: level 2 requires coordinated resource-server rollout. Negotiate via metadata (advertise DPoP support) so legacy bearer flow still functions during migration.
  - Server-issued `nonce` support is optional in RFC 9449 — decide whether to require it.
  - Keep the issued credential in the standard `access_token` response field regardless of type (consistency with F007).
- **Effort:** Level 1 = S (client + minimal server). Level 2 = L (full cycle, multi-repo).
- **Suggested slot:** Level 1 into v1.3 "Credibility release" alongside F012; Level 2 as its own item feeding the v2.0 standards work.
