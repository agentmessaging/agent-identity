# F013 — Microsoft AGENTMESH bridge via Ed25519/DID format conversion

**Status:** Todo
**Type:** Feature (composition / bridge)
**Created:** 2026-05-27
**Priority:** Medium-High
**Category:** Microsoft governance integration
**Effort:** S-M (~1 week)

## Description

Ship a thin format-conversion bridge between AID identities and Microsoft AGENTMESH (`did:mesh:`) identities. Both protocols use Ed25519 as the cryptographic substrate, so a clean one-time bootstrap is possible: AID exports a W3C-compliant DID Document for any registered agent, AGENTMESH ingests it via its existing JWK import flow.

This work is **independent of F010 (SPIFFE)** despite being motivated by the same goal (compatibility with Microsoft-governed environments). The pivot is documented in [`research/spiffe-fit.md`](../research/spiffe-fit.md) (gitignored).

## Why It's Needed

The initial F010 thesis assumed SPIFFE federation would be the bridge into Microsoft Agent Governance Toolkit. After reading the [AGENTMESH-IDENTITY-TRUST-1.0 spec](https://github.com/microsoft/agent-governance-toolkit/blob/main/docs/specs/AGENTMESH-IDENTITY-TRUST-1.0.md) carefully:

- AGENTMESH is **not SPIFFE-native**. Its identity primitives are `did:mesh:<unique-id>` + Ed25519 public key + sponsor email.
- SPIFFE appears in AGENTMESH only as an *integration layer for mTLS transport*, not as the identity substrate.
- AGENTMESH is a **closed-mesh model** with default trust domain `agentmesh.local`. It has no federation path for external identity providers.
- However, AGENTMESH **does** accept Ed25519 JWK imports (Section 20.4-20.5 of their spec) for one-time identity provisioning.

Both AID and AGENTMESH share Ed25519 as the substrate. A direct format-conversion bridge is meaningfully cheaper than a federation protocol and lands the same outcome: an AID-registered agent can be ingested into an AGENTMESH deployment.

## Business Case

- **Direct path into Microsoft-governed environments** without taking on SPIFFE-server obligations
- **Lower effort** than the original SPIFFE thesis (~1 week vs ~3-4 weeks)
- **Defensive** — closes an interop gap before someone else writes a less-aligned converter
- **Composable with other DID-based agent systems** — any future protocol using `did:` + Ed25519 (the W3C DID model is generic) can use the same export

## Implementation Plan

### Phase 1 — DID format mapping (1-2 days)
Decide the deterministic mapping from AID identities to `did:mesh:` identifiers. Options:
- **Option A:** `did:mesh:<sha256-of-public-key>` — deterministic from key material, no AID-side state
- **Option B:** `did:mesh:<sha256-of-agent-address>` — deterministic from address, stable across key rotation
- **Option C:** `did:mesh:<uuid>` — fresh per export, requires AID to remember the mapping

Option A is simplest and matches the cryptographic-binding principle that AGENTMESH itself uses. Document the choice with rationale.

### Phase 2 — `aid-export` command (2-3 days)
New script: `scripts/aid-export.sh`

```bash
aid-export --format=agentmesh-did            # emit DID Document for the default agent
aid-export --format=agentmesh-did --id <uuid>  # specific agent
aid-export --format=agentmesh-did --output did.json  # write to file
```

Output: W3C DID Document (JSON-LD) conforming to AGENTMESH's expected import format:

```json
{
  "@context": "https://www.w3.org/ns/did/v1",
  "id": "did:mesh:<computed>",
  "verificationMethod": [
    {
      "id": "did:mesh:<computed>#key-1",
      "type": "Ed25519VerificationKey2020",
      "controller": "did:mesh:<computed>",
      "publicKeyMultibase": "<multibase-encoded-Ed25519-public-key>"
    }
  ],
  "authentication": ["did:mesh:<computed>#key-1"],
  "assertionMethod": ["did:mesh:<computed>#key-1"],
  "service": [
    {
      "id": "did:mesh:<computed>#aid",
      "type": "AgentIdentityProtocol",
      "serviceEndpoint": "<auth-server-url>",
      "agentAddress": "support-bot@acme.local"
    }
  ]
}
```

The `service` block is the bridge back to AID: an AGENTMESH-governed environment that wants to validate a token from this agent can fetch the auth-server URL and call introspection.

### Phase 3 — Documentation + example (1-2 days)
- New `examples/agentmesh-import/` directory with a sample DID Document, a one-page README explaining the bootstrap flow
- README section in the main repo explaining AGENTMESH composition (sibling to the existing auth.md composition section)
- Cross-link from F010 spiffe-fit research

### Phase 4 — Validation against AGENTMESH (1 week, conditional)
- Stand up a local AGENTMESH instance from the Microsoft Agent Governance Toolkit
- Run a real end-to-end test: AID-export → AGENTMESH-import → confirm the agent shows up in AGENTMESH's registry with the right Ed25519 key
- Document any spec ambiguities found
- Optionally open a follow-up issue on `microsoft/agent-governance-toolkit` proposing standardization of the import format

## Risks

- **AGENTMESH spec is v1.0** and may evolve. Pin to a specific spec version in our export; refresh annually.
- **Microsoft's JWK import format** may have undocumented constraints we don't catch from reading the spec. Phase 4 (validation) is where we find out.
- **AGENTMESH provisions its own keys** after import. Our DID Document is a *seed*, not an ongoing federated trust — the actual AGENTMESH identity is independent post-bootstrap. This limits the value proposition; document honestly.
- **Naming collision.** `did:mesh:` is Microsoft's namespace. We should use it exactly as their spec defines, not invent a parallel `did:aid:` (which would be a separate larger project).

## Definition of Done

- `scripts/aid-export.sh` exists, supports `--format=agentmesh-did`, emits W3C DID Documents
- `examples/agentmesh-import/` reference example with a runnable sample
- README has an "AGENTMESH bridge" composition section
- Tested end-to-end against a real AGENTMESH instance (phase 4)

## Related work

- **F010 (SPIFFE)** — parallel composition path for SPIRE/CNCF environments, independent of F013
- **F008 (auth.md PR)** — same "compose, don't compete" pattern at a different layer
- **F011 (OpenGAP block)** — same pattern at the agent-definition layer

The four together form the AID composition story: gitagent for definition (F011), auth.md for delegation (F008), SPIFFE for CNCF interop (F010), AGENTMESH for Microsoft interop (F013).

## Sources

- [AGENTMESH-IDENTITY-TRUST-1.0](https://github.com/microsoft/agent-governance-toolkit/blob/main/docs/specs/AGENTMESH-IDENTITY-TRUST-1.0.md)
- [Microsoft Agent Governance Toolkit](https://github.com/microsoft/agent-governance-toolkit)
- [W3C DID Core](https://www.w3.org/TR/did-core/)
- Research: [`research/spiffe-fit.md`](../research/spiffe-fit.md) — documents the pivot from SPIFFE-federation thesis to direct-DID thesis
