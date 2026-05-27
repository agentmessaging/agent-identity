# F010 — SPIFFE federation for CNCF zero-trust environments

**Status:** Phase 1 complete (research done 2026-05-27). Phase 2 scope refined and pending kickoff.
**Type:** Research → Feature (partial go)
**Created:** 2026-05-26
**Updated:** 2026-05-27 after research findings
**Priority:** Medium
**Category:** CNCF / Istio / SPIRE interop
**Effort:** M (Phase 2 estimated ~2 weeks)

## Description

Make AID-issued credentials valid in SPIFFE-governed environments by:
1. Emitting **JWT-SVIDs** as an optional credential type
2. Publishing a **SPIFFE federation bundle endpoint** alongside JWKS
3. Advertising the trust domain in the `aid_grant` discovery block

This enables AID-authenticated agents to call into Istio service meshes, SPIRE-governed Kubernetes clusters, and any other CNCF zero-trust deployment without AID itself becoming a SPIRE server.

## Phase 1 — Research findings (complete)

The research is documented in [`research/spiffe-fit.md`](../research/spiffe-fit.md) (gitignored). Key findings:

| Question | Finding |
|---|---|
| Attestation model incompatibility? | Doesn't block federation. We're a federation peer, not a SPIRE Server. |
| X.509-SVID emission viable? | Yes via CSR-and-sign, but high overhead, narrow value. **Skip for now.** |
| JWT-SVID emission viable? | **Yes — clean, additive, cheap.** Adopted as the primary integration. |
| Federation bundle endpoint viable? | **Yes — `/.well-known/spiffe-bundle` mirroring JWKS.** Adopted. |
| Microsoft AGENTMESH via SPIFFE? | **No — wrong bridge.** AGENTMESH isn't SPIFFE-native; their identity is `did:mesh:` + Ed25519. **Moved to F013 (separate Ed25519/DID bridge work).** |

**Decision: PARTIAL go.** SPIFFE compatibility ships as an optional credential format with two narrow additions to the auth server. AGENTMESH integration is independent work tracked in F013.

## Why It's Needed (refined)

The original framing assumed SPIFFE federation = the bridge into Microsoft-governed environments. That's not how Microsoft AGENTMESH actually works (they're DID-based, not SPIFFE-native — see F013).

But SPIFFE itself is still strategically important: it's the CNCF-graduated workload identity standard, used by Istio, SPIRE, Linkerd, and most cloud-native zero-trust deployments. An AID agent that can present a valid JWT-SVID becomes a first-class identity in those environments — without giving up its AID identity or running SPIRE infrastructure.

## Business Case

- **CNCF zero-trust interop** — Istio, SPIRE, Linkerd ecosystems
- **Standards-aligned** — JWT-SVID is RFC 7517-shaped, federation is a CNCF graduated standard
- **Low cost** — JWT-SVID is ~80% the same shape as AID's existing JWTs; mostly subject-format change + new bundle endpoint
- **Defensive** — SPIFFE adoption is rising; not being interoperable becomes a procurement blocker for some buyers

## Implementation Plan (refined v2 scope)

### Phase 2 — Spec + client + server (Phase 2 v2 — ~2 weeks)

#### 2a. Spec additions (2-3 days)

- Add `spiffe_trust_domain` field to the `aid_grant` discovery block (string, e.g. `"acme.local"`)
- Add `spiffe_jwt_svid` to `credential_types_supported` as a valid value
- Document the JWT-SVID format in the README:
  - `sub` claim is `spiffe://<trust-domain>/agent/<address>` (not the agent UUID)
  - `aud` is the resource URL of the target
  - `iss`, `exp`, `iat` standard
  - Algorithm: RS256 (matches our existing default)
- Document `/.well-known/spiffe-bundle` endpoint shape per the [SPIFFE Trust Domain and Bundle spec](https://github.com/spiffe/spiffe/blob/main/standards/SPIFFE_Trust_Domain_and_Bundle.md):
  - Returns JSON bundle with `spiffe_refresh_hint`, `spiffe_sequence`, `keys` array
  - Each key annotated with `use: jwt-svid` (or `use: x509-svid` if we add that later)
  - Public keys are the same RS256 keys served at `/.well-known/jwks.json`

#### 2b. Client changes (2-3 days)

- `aid-token --credential-type spiffe-jwt-svid` — request a JWT-SVID instead of a vanilla access token
- Cache key already includes credential_type (F007 work) — no further change needed there
- Update help text + SKILL.md

#### 2c. Server-side coordination (filed separately on auth-api)

- Open a tracking issue on `23blocks/blocks-auth-api` (like F007's issue #43) for the server implementation
- Server scope:
  - Accept `requested_credential_type=spiffe-jwt-svid` and emit a JWT with `spiffe://` subject
  - Serve `/.well-known/spiffe-bundle` reflecting the JWKS
  - Configure `aid_grant.spiffe_trust_domain` per tenant

#### 2d. Conformance tests (in `agentmessaging/aid-conformance`)

- New category `tests/07-spiffe-interop/`
- Tests:
  - JWT-SVID subject format (`spiffe://...`)
  - JWT-SVID required claims (sub, aud, exp)
  - Bundle endpoint shape
  - Bundle keys annotated with `use: jwt-svid`
  - `spiffe_trust_domain` advertised in `aid_grant`
- Estimated ~8-10 tests for v1

#### 2e. Validation against real SPIRE (1 week)

- Stand up local SPIRE (server + agent + workload simulator)
- Configure SPIRE to federate with AID's trust domain via the bundle endpoint
- End-to-end test: AID-issued JWT-SVID validates inside a SPIRE-federated workload
- Document any spec ambiguities found

## What's NOT in this phase

- **X.509-SVID emission.** Viable via CSR-and-sign but high overhead. Defer until a customer asks.
- **SPIRE Server impersonation.** We're not running SPIRE machinery; we federate.
- **OIDC federation paths.** SPIFFE has an AWS OIDC integration but it's orthogonal to our work.

## Risks

- **JWT-SVID adoption is narrower than X.509-SVID** in the SPIRE ecosystem. Most SPIRE-governed workloads use X.509 SVIDs for mTLS. The value of JWT-SVID is greater for SPIFFE-aware non-mTLS callers (gRPC with token auth, HTTP services).
- **Trust domain naming** is a one-way decision. Pick `<tenant>.local` (matching agent_address suffix) for symmetry, but lock it in early.
- **Bundle endpoint freshness.** SPIFFE peers cache for `spiffe_refresh_hint` seconds (default 5min). Key rotation needs explicit refresh-hint reduction during rotation windows.

## Definition of Done

- Spec section in README documenting `spiffe_jwt_svid` credential type and `/.well-known/spiffe-bundle` endpoint
- Client supports `--credential-type spiffe-jwt-svid` (server-dependent for actual issuance)
- Tracking issue filed on `23blocks/blocks-auth-api`
- New conformance test category covering JWT-SVID format + bundle shape
- One successful end-to-end validation against a real SPIRE deployment

## Out of scope (tracked separately)

- **Microsoft AGENTMESH integration** → see [F013](./F013-agentmesh-did-bridge.md). Different protocol, different bridge.

## Sources

- [SPIFFE / SPIRE](https://spiffe.io/)
- [JWT-SVID spec](https://github.com/spiffe/spiffe/blob/main/standards/JWT-SVID.md)
- [SPIFFE Federation spec](https://github.com/spiffe/spiffe/blob/main/standards/SPIFFE_Federation.md)
- Research: [`research/spiffe-fit.md`](../research/spiffe-fit.md)
- Cross-reference: [F013 — AGENTMESH bridge](./F013-agentmesh-did-bridge.md)
