# F010 — SPIFFE federation research and (conditional) prototype

**Status:** Todo
**Type:** Research → conditional Feature
**Created:** 2026-05-26
**Priority:** Medium (research) / TBD (implementation)
**Category:** Microsoft governance bridge
**Effort:** M (2-3 weeks total; 1 week research + 2 weeks prototype if go)

## Description

Phase 1: investigate whether AID identities can map cleanly to SPIFFE SVIDs (X.509 or JWT) for federation with workload-identity-based systems like Microsoft's AgentMesh.

Phase 2 (only if Phase 1 = go): prototype `aid-token --credential-type=spiffe-svid` that emits a valid X.509 SVID compatible with SPIRE-based environments.

## Why It's Needed

Microsoft's [Agent Governance Toolkit](https://github.com/microsoft/agent-governance-toolkit) uses [SPIFFE](https://spiffe.io/) DIDs + mTLS for zero-trust agent identity at the workload level. Its [AGENTMESH-IDENTITY-TRUST-1.0 spec](https://github.com/microsoft/agent-governance-toolkit/blob/main/docs/specs/AGENTMESH-IDENTITY-TRUST-1.0.md) has 135 conformance tests — it's a serious bar.

AID currently has no story for SPIFFE-governed environments. If we can issue AID identities as SVIDs (or federate AID auth servers as SPIFFE trust domains), we become the natural identity provider in Microsoft-governed deployments. If we can't, we cede that whole environment.

## Business Case

- **Strategic bridge** into the Microsoft-governed agent ecosystem (very large enterprise footprint)
- **SPIFFE is CNCF-graduated** — adopting it is risk-free standards-wise; it's the cloud-native workload identity default
- **Defensive** — SPIFFE federation is going to be how AID composes with other zero-trust workload identity systems regardless of Microsoft

## Implementation Plan

### Phase 1 — Research (1 week)

Deliverable: `research/spiffe-fit.md`

Questions to answer:
1. **Identity model fit.** SPIFFE assumes the workload is *attested* by a trusted SPIRE agent. AID's "agent registers itself, admin approves" model isn't attestation-shaped. Does that block native fit?
2. **SVID format fit.** Can AID emit an X.509 SVID with the agent's address as the SPIFFE ID (`spiffe://<trust-domain>/agent/<address>`)?
3. **JWT-SVID alternative.** SPIFFE also supports JWT-SVIDs. AID already issues RS256 JWTs. Is the JWT-SVID format a superset we can emit?
4. **Trust domain federation.** SPIFFE supports trust-domain federation via bundle exchange. Can an AID auth server publish a federation bundle?
5. **What does Microsoft AgentMesh actually require?** Read the AGENTMESH-IDENTITY-TRUST spec carefully — what shape of identity input does it consume?

Go/no-go decision criteria:
- **Go:** SPIFFE compatibility can be added as an optional credential format without breaking AID's identity model
- **Partial:** Federation works (bundle exchange) but native SVID emission requires major rework — pursue federation only
- **No-go:** SPIFFE's attestation model is fundamentally incompatible with AID's registration model — document why, close the thread

### Phase 2 — Prototype (2 weeks, only if Phase 1 = go)

Deliverable: working `aid-token --credential-type=spiffe-svid` or equivalent

- Add `spiffe-svid` to `credential_types_supported` in the `aid_grant` discovery block
- Implement SVID issuance in the auth-api reference server
- Validate against SPIRE locally
- Document in README + spec

## Risks

- **SPIFFE's attestation model.** SPIRE agents typically attest workloads via Kubernetes service accounts, AWS IAM, etc. AID's admin-approval model doesn't map cleanly. The honest answer might be "AID auth servers can federate with SPIRE as trust-domain peers, but not emit native SVIDs."
- **Effort underestimation.** SPIFFE is a deep ecosystem. The 2-week prototype estimate assumes we don't hit unexpected complexity.
- **Microsoft's spec may be MS-specific.** AgentMesh might depart from vanilla SPIFFE in ways that constrain interop.

## Definition of Done

Phase 1: research doc published with a clear go/no-go/partial decision.
Phase 2: only if go — prototype shipped, documented, validated against SPIRE.

## Sources

- [SPIFFE / SPIRE](https://spiffe.io/)
- [Microsoft AGENTMESH-IDENTITY-TRUST-1.0 spec](https://github.com/microsoft/agent-governance-toolkit/blob/main/docs/specs/AGENTMESH-IDENTITY-TRUST-1.0.md)
- Internal research: [`research/microsoft-agent-governance.md`](../research/microsoft-agent-governance.md)
