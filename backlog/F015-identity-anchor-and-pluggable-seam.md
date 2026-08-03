# F015 — Identity anchor (key-derived DID) + pluggable attestation seam

**Status:** In Progress
**Type:** Feature (foundational — re-scopes F004/F005/F014)
**Created:** 2026-08-02
**Related:** F004, F005, F013, F014; AMP spec `02-identity`, `06-federation`, `07-security`

## Description

Establish the foundational identity architecture for AID + AMP: **layered independence
with optional enrichment and a pluggable identity slot.** AID and AMP remain independent
products that compose without coupling. Three decisions:

1. **Shared anchor — a key-derived DID.** An agent's canonical identifier becomes a
   **`did:key`** (self-certifying default; the id *is* the key, so it can never drift from
   the key material) with **`did:web`** as an option for org-domain-rooted identities. Use
   only the *thin* DID methods — `did:key` is the public key in a standard multibase wrapper,
   `did:web` is a `.well-known` URL — explicitly **not** the heavy blockchain SSI stack.
   AMP's existing Agent Card is already ~80% a DID-document + VC; its canonical id becomes
   this DID. This replaces AID's current server-assigned UUID as *the* principal.

2. **Credentials *about* the DID (not a parallel identity).** AID (and any IdP) issues
   membership/role credentials whose **`subject` is the agent's DID**, bound by
   proof-of-possession — not a separate server-minted UUID + copyable bearer token. The
   badge is stamped with the agent's "passport number" (its DID) and only works when
   presented by the key-holder.

3. **Pluggable attestation seam (companion AMP change).** AMP is identity-provider-
   agnostic: it defines a thin carriage slot + a verification contract, and carries a
   **standard W3C VC / SD-JWT VC** — it does *not* invent a credential format. AID is one
   issuer among many (Entra Agent ID, SPIFFE, corporate IdP, any VC issuer).

### The four deployment modes this preserves
| Mode | Identity source | Valid? |
|---|---|---|
| AMP only | AMP DID + Agent Card (TOFU, key-swap detection) | ✅ |
| AID only | AID membership + role; no messaging | ✅ |
| AMP + AID | AMP carries AID-issued, revocable org credentials | ✅ |
| AMP + any IdP | any IdP vouches for the DID | ✅ |

Analogy: **AMP = email/Exchange, AID = directory/LDAP, the agent's DID = the shared
credential both recognize.**

## Why It's Needed

- **The identity is currently copyable and drift-prone.** Today the principal is a
  server-assigned UUID + a **bearer JWT** ("protects issuance but not use" — F014), and the
  address is self-asserted. On all five identity invariants the shipped design *permits* an
  agent's identity being copied or shared. A downstream implementer (AI Maestro) hit exactly
  this — 71 agents collapsed to one shared keypair — because nothing bound id↔key or made
  identity non-copyable. A key-derived DID makes id↔key drift **unrepresentable**;
  VC-about-the-DID + proof-of-possession makes the credential **non-transferable**.
- **The product vision is not expressible today.** "Agents that join organizations on
  demand, work remotely, and are outsourced across orgs" *is* portable identity + issued
  credentials + cross-org trust. Those live in F004/F005/F010/F013 as **Low-priority
  backlog** — i.e., the core of the vision is currently deprioritized.

## Business Case

- **Strategic positioning:** a portable, self-certifying agent identity that *any* IdP can
  enrich is the defensible standards-track bet (W3C DID + VC, SD-JWT VC), aligning with
  where the ecosystem is going (Google A2A Agent Cards, Microsoft Entra Agent ID, SPIFFE)
  while keeping AID usable standalone. This is AID's differentiator.
- **Risk mitigation:** closes the copyable-identity class that already caused a fleet-wide
  identity contamination in a shipping implementation.
- **Unblocks partners/customers:** cross-org membership + delegation is the prerequisite
  for outsourcing / marketplace / multi-tenant scenarios.

## Implementation Plan

**AID (this repo):**
- [x] `did:key` derivation from the existing Ed25519 key (`scripts/aid-helper.sh:derive_did_key`,
  multicodec `0xed01` + base58btc/`z` multibase). *(v0.1 — this commit)*
- [ ] Surface the DID in `aid-init.sh` / `aid-status.sh` and store it in `config.json`
  (`agent.did`) as the canonical id; keep the UUID as a legacy alias during migration.
- [ ] `did:web` document at a `.well-known` path for org-domain-rooted identities.
- [ ] Issue credentials as **VCs with `subject = did`**, bound via the existing PoP proof
  (`aid-token.sh`); supersede the parallel-UUID model.
- [ ] **Promote to core:** F014 (sender-constrained / DPoP), F004 (delegation),
  F005 (cross-org / trust root). F013 (`did:aid`) folds in as the DID-method decision.
- [ ] Harden key custody from the descriptive `README:725` bullet to a normative MUST +
  threat model; make live-revocation enforcement mandatory for security-relevant scopes.

**Companion AMP spec changes (`agentmessaging/protocol`):**
- Make the Agent Card's canonical id a DID (`02-identity`).
- Define the **attestation slot** (optional envelope field), the **verification contract**
  (issuer discovery → issuer key → revocation/expiry → trust tier), an **`org-verified`**
  trust tier extending `verified`/`external`/`untrusted` (`07-security`), and the rule that
  the attestation **subject MUST be the sender's DID**. Carry a standard VC / SD-JWT VC.

**Effort:** L (multi-repo: AID + AMP spec + reference server + F012 conformance). Sequence:
DID anchor + VC-about-DID first (unblocks everything), then the AMP seam, then F014/F004/F005.

**Open questions / risks:**
- **Issuer trust root** — how a verifier decides which issuers may vouch for which orgs
  (allowlist / discovery / trust registry). The one genuinely hard problem; solve once
  (reuse F005/F010 direction).
- DID method scope — `did:key` + `did:web` only, or also `did:aid` (F013)?
- Migration for existing UUID-based agents (dual-identifier window).
- `derive_did_key` uses python3 for base58btc; acceptable for the reference client, note as
  a dependency for the DID feature.
- Update F012 conformance suite: id↔key binding, credential subject = DID, non-replayable
  (sender-constrained) credentials.
