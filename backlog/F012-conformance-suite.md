# F012 — AID conformance suite v1

**Status:** Todo
**Type:** Feature (infrastructure)
**Created:** 2026-05-26
**Priority:** High
**Category:** Standards credibility
**Effort:** L (4-6 weeks for v1)

## Description

Build a runnable conformance test suite that any AID auth server can execute to prove compliance. Publish as a separate repo (`agentmessaging/aid-conformance`) so it's independently versioned and runnable against any implementation.

The suite produces a structured report (`server X is N/120 conformant`) that implementers can publish and consumers can check.

## Why It's Needed

Microsoft's Agent Governance Toolkit publishes **992 conformance tests across 10 specs**. That has reset the bar for what "this is a real standard" looks like. AID currently has zero conformance infrastructure. "AID-conformant" today is a marketing claim, not a verifiable property.

For F001 (IETF Internet-Draft) to credibly progress to WG-adoption, having a conformance suite that can validate multiple independent implementations is essentially mandatory.

## Business Case

- **Standards credibility multiplier** — direct prerequisite for taking F001 seriously
- **Enterprise procurement** — security teams ask for conformance test results
- **Interop guarantee** — catches drift between implementations early
- **Marketing leverage** — every conformance report is a public artifact citing AID by name

## Implementation Plan

### Coverage areas (target ~100-120 tests for v1)

1. **Registration (admin-initiated)** — ~20 tests
   - POST with admin JWT + role_id succeeds, returns expected fields
   - POST without admin JWT rejected (401)
   - POST with invalid role_id rejected
   - Duplicate fingerprint handling
   - Idempotency

2. **Registration (agent-initiated)** — ~20 tests
   - POST /agent_registrations/request returns 202 + authorization_url + user_code + expires_in + interval
   - Polling returns RFC 8628 errors correctly (authorization_pending, slow_down, expired_token, access_denied)
   - Approval flow assigns role
   - Code resolution endpoint returns the right agent details
   - Code expiry behavior

3. **Token issuance** — ~25 tests
   - urn:aid:agent-identity grant type accepted
   - Canonical JSON signing validated (sorted keys, compact)
   - Proof of possession 5-minute window enforced
   - oidc_issuer used (not just auth URL)
   - Audience binding correct
   - Scope intersection enforced (invalid_scope returned for excess scopes)
   - Cached vs fresh token semantics
   - Expired identity rejection

4. **Discovery** — ~15 tests
   - /.well-known/oauth-protected-resource shape (RFC 9728)
   - /.well-known/oauth-authorization-server has urn:aid:agent-identity in grant_types_supported
   - aid_grant block has all required fields
   - aid_grant fields point to working endpoints

5. **Introspection (RFC 7662)** — ~15 tests
   - active=true for valid tokens
   - All required agent-* fields present
   - Suspended agent returns active=false + reason
   - Deleted agent returns active=false + reason
   - jti uniqueness

6. **Lifecycle** — ~10 tests
   - Suspend endpoint blocks new tokens
   - Suspend invalidates via introspection immediately
   - Reactivate restores
   - Revoke is terminal (cannot reactivate)

7. **Error handling** — ~10 tests
   - All documented error codes return correctly
   - HTTP status codes match (401, 403, 410, 422, 429)
   - Error response shape consistent

### Phase 1 — Scaffold (1 week)
- New repo `agentmessaging/aid-conformance`
- Bash + curl + jq runner (dogfood our own stack)
- Test format: each test is a `.sh` file in a category directory
- Runner outputs JSON report + colored CLI summary
- Initial 15-20 tests covering registration and token issuance happy paths

### Phase 2 — Coverage (3 weeks)
- Fill out all 7 areas to target counts above
- Each test should be:
  - Self-contained (creates its own agent, cleans up)
  - Deterministic (no time-dependent assertions except expiry tests)
  - Implementation-agnostic (no auth-api-specific behavior)
- Add a `--verbose` mode that prints request/response for debugging

### Phase 3 — Validate against second implementation (1-2 weeks)
- Run the suite against auth-api (the reference)
- Find a willing second-party implementer (Microsoft toolkit team? open-source enthusiast?) to run it against their impl
- Iterate on tests that fail differently between implementations — those are spec ambiguities, not bugs
- This step is where the suite earns its credibility

### Phase 4 — Public report format
- `aid-conformance run --output report.json` produces a structured report
- Include version of suite, version of impl, timestamp, per-test pass/fail/skip
- Define a "conformant" threshold (e.g., 95% of MUST tests, 80% of SHOULD tests)
- Document in the conformance repo's README

## Risks

- **One-implementation suite is theater.** This is the biggest risk. The suite must validate against ≥2 implementations before being publicly cited.
- **Spec ambiguities surface as test conflicts.** That's actually the point — but it means we'll be patching the AID spec mid-suite-development.
- **Maintenance burden.** ~120 tests need ongoing care as the spec evolves. Worth it, but acknowledge it.

## Definition of Done

- `agentmessaging/aid-conformance` repo public
- ≥100 tests covering all 7 areas
- Suite passes ≥95% against the auth-api reference implementation
- Suite has been run against at least one independent second implementation
- Public conformance report published for auth-api
- AID spec README references the conformance suite

## Sources

- [Microsoft Agent Governance Toolkit conformance tests](https://github.com/microsoft/agent-governance-toolkit) — 992 tests, 10 specs
- AID spec: [`agent-identity/README.md`](../README.md)
- Reference impl: [`23blocks-org/auth-api`](https://github.com/23blocks-org/auth-api)
- Internal research: [`research/microsoft-agent-governance.md`](../research/microsoft-agent-governance.md)
