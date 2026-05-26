# F007 — Opaque API key credential type

**Status:** Spec + client shipped (2026-05-26); awaiting auth-api server implementation
**Type:** Feature
**Created:** 2026-05-22

## Description

Today AID issues only RS256 JWT access tokens. Add support for the agent to request an opaque, server-side-validated bearer credential (an "API key") as an alternative credential format.

Wire-level changes:
- Add `requested_credential_type` to the token request form body (values: `access_token` (default, JWT), `api_key`).
- Response gains `credential_type` field; existing `access_token` field is reused for the opaque value when `credential_type == "api_key"`.
- Discovery: `aid_grant.credential_types_supported` advertises which formats the server issues.

## Why It's Needed

JWT validation requires JWKS fetching and signature verification at every target API. Smaller services, internal tools, and services without an OIDC stack often prefer opaque tokens validated server-side via introspection. WorkOS auth.md supports both formats and treats them equivalently; AID should match that flexibility to lower the bar for adoption.

Real-world drivers:
- Lambda/edge functions where importing a JWKS verifier is heavy
- Customers integrating AID with services that already speak API keys
- Long-lived service credentials where JWT rotation is unnecessary overhead

## Business Case

- **Adoption breadth**: Removes the "we don't have JWKS infrastructure" objection for prospective auth-server implementers.
- **Parity with auth.md**: One of the few capability gaps the comparison post will surface. Closing it is cheap insurance.
- **Strategic**: Keeps AID viable in the long-lived-service-credential niche, not just session-style access tokens.

## Implementation Plan

Spec-level (this repo):
- Update README "OAuth 2.0 Grant Type" section to document `requested_credential_type`.
- Update README discovery section to flesh out `credential_types_supported`.
- Update SKILL.md token request docs.

Client-level (scripts):
- `aid-token.sh` — add `--credential-type|-c {access_token|api_key}` flag, default `access_token`. Add to form body when present.
- Token cache: include credential_type in cache key so requesting both formats from the same agent doesn't collide.

Server-side (out of scope for this repo):
- Auth server must accept the parameter, issue an opaque key, and validate it via introspection. Requires coordination with the auth-api reference implementation.

**Effort:** S for the client + spec; M for the reference server.
**Risks:** Cache invalidation if a server changes default credential type. Opaque keys need a revocation story orthogonal to JWT `exp` (covered by RFC 7662 introspection).
**Open question:** Should `api_key` credentials have a default expiration, or be long-lived until explicitly revoked?
