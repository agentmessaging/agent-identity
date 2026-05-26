# F001 — Submit AID as IETF Internet-Draft

**Status:** Todo
**Type:** Feature
**Created:** 2026-05-20
**Priority:** High
**Category:** Strategic

## Description

Submit the Agent Identity (AID) protocol as an IETF Internet-Draft (`draft-agentmessaging-aid-XX`). This formalizes the protocol in the standards ecosystem alongside existing agent auth drafts and gives AID credibility with enterprise security teams.

The draft should cover:
- The `urn:aid:agent-identity` custom OAuth 2.0 grant type
- Agent-initiated registration flow (aligned with RFC 8628 Device Authorization)
- Authorization URL with opaque codes and user_code
- Proof of possession mechanism (Ed25519)
- Token introspection extensions (agent-specific fields)
- Agent lifecycle management (suspend/reactivate)
- Scope intersection rules

## Why It's Needed

Four competing IETF drafts already exist for AI agent authentication:
1. `draft-oauth-ai-agents-on-behalf-of-user-02` — delegation chains
2. `draft-rosenberg-oauth-aauth-00` — voice/text channel agent auth
3. `draft-klrc-aiagent-auth-00` — WIMSE + SPIFFE + OAuth composition
4. `draft-song-oauth-ai-agent-authorization-00` — agent metadata in OAuth

AID is the only protocol with a production reference implementation (23blocks Auth API), agent-initiated registration, and three-command CLI onboarding. Without an IETF draft, AID remains a solo project rather than a recognized standard candidate.

NIST launched the AI Agent Standards Initiative in February 2026. Standards bodies are actively looking for input. The window for establishing AID's position is now.

## Business Case

- **Strategic positioning**: An IETF draft signals seriousness to enterprise buyers, security auditors, and potential partners. "We submitted an IETF draft" is a credibility multiplier.
- **Competitive moat**: Even if the draft never becomes an RFC, being in the conversation at IETF prevents AID from being designed out of future standards.
- **Partnership leverage**: Standards body participation opens doors to collaboration with CNCF (SPIFFE), Linux Foundation (A2A), and OAuth WG members.
- **Media/content**: The submission itself is a content event — blog post, press coverage, community discussion.

## Prerequisites (must land before formal submission)

Refined 2026-05-26 after the agent-auth landscape evaluation. The goal is **WG-adoption**, not just publication as an Individual Submission. The Individual Submission path (AGTP, AAuth) gets you an RFC but not a standard. ID-JAG proves the opposite path works.

1. **F007 (opaque credentials)** must be either shipped or explicitly punted from the v1.0 spec. Otherwise the I-D gets reshaped mid-flight by post-submission feedback.
2. **F009 (OWASP mapping)** should land first so the Security Considerations section can cite it.
3. **F012 (conformance suite)** should be in progress with ≥1 second-party implementation lined up. WG-adoption almost requires interop evidence.
4. **F008 (auth.md composition PR)** in flight or merged — shows AID isn't being designed in isolation.

## Implementation Plan

### Phase 1 — Toolchain + spec prose (1 week)
- Set up `kramdown-rfc` or `xml2rfc` locally
- Convert README normative sections to RFC-shaped Markdown / XML
- Apply RFC 2119 MUST/SHOULD/MAY language consistently
- Add Security Considerations citing OWASP mapping (F009)
- Add IANA Considerations:
  - Register `urn:aid:agent-identity` grant type
  - Register `aid_grant` metadata block fields under RFC 8414
  - Define agent introspection fields extension to RFC 7662

### Phase 2 — OAuth WG mailing list pre-feedback (2 weeks)
**Critical step — do this before formal submission.**

- Post a "we're working on this, looking for feedback" message to `oauth@ietf.org`
- Reference our complementarity story with ID-JAG (which is already WG-adopted)
- Listen to objections and incorporate before v0
- Probable critiques to prepare for:
  - "Why not just extend ID-JAG?" — Answer: ID-JAG carries user identity; AID carries agent identity. Compose, don't conflate.
  - "Custom grant type is heavy" — Answer: same shape as RFC 8693 token-exchange grant. Precedent exists.
  - "RFC 8628 device-grant is already this" — Answer: device-grant is for end-user devices; AID is for autonomous agents with persistent identity.

### Phase 3 — Formal submission (1 week)
- Create IETF datatracker account
- Upload v0 as `draft-pelaez-oauth-agent-identity-00` (Individual Submission stream initially)
- Announce on `oauth@ietf.org`
- Submit to OAuth WG for adoption consideration

### Phase 4 — WG-adoption push (2-4 months calendar)
- Engage actively in WG discussion
- Iterate to `-01`, `-02` based on feedback
- Goal: become `draft-ietf-oauth-agent-identity-00` (WG-adopted)
- Present at the next IETF meeting (IETF 124 in Madrid or IETF 125)

## Open questions

- **Co-authors.** Aaron Parecki (ID-JAG primary author) is the natural co-author for an agent-identity draft that composes with ID-JAG. Worth a direct outreach before phase 2.
- **IANA grant-type registration.** Can be done independently of the I-D via the existing OAuth Grant Type Registry. Worth pursuing in parallel to lock in the URN.
- **Security audit.** Recommended before WG-adoption push (phase 4). Trail of Bits / NCC Group are obvious candidates.

## Risks

- **The Individual Submission trap.** AGTP and AAuth are cautionary tales — published but explicitly "not endorsed by the IETF." If we don't get WG-adoption, we end up there. The mitigation is phase 2 (pre-feedback) before phase 3 (submission).
- **WG-adoption is slow.** Realistic timeline is 6-12 months from first submission to adoption. Plan accordingly.
- **Spec drift during phase 4.** Adoption negotiations will reshape the spec. Code freezes during this period help.

## Definition of Done

- Posted to `oauth@ietf.org` with pre-feedback received and addressed
- `draft-pelaez-oauth-agent-identity-00` submitted to datatracker
- WG-adoption proposal submitted
- Stretch goal: `draft-ietf-oauth-agent-identity-00` exists (WG-adopted)

## References

- [ID-JAG (WG-adopted, our proof point)](https://datatracker.ietf.org/doc/draft-ietf-oauth-identity-assertion-authz-grant/)
- [OAuth WG](https://datatracker.ietf.org/wg/oauth/about/)
- [IETF Datatracker](https://datatracker.ietf.org/)
- [kramdown-rfc](https://github.com/cabo/kramdown-rfc)
- Internal: [`research/id-jag.md`](../research/id-jag.md) — explains why WG adoption matters
