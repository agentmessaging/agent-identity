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

## Implementation Plan

1. **Review IETF submission requirements** at datatracker.ietf.org
   - Internet-Drafts use RFC XML format (xml2rfc toolchain)
   - Individual submissions don't require WG sponsorship
   - Effort: S (1 day research)

2. **Format AID spec as Internet-Draft**
   - Convert README.md protocol sections to RFC XML
   - Add formal MUST/SHOULD/MAY language per RFC 2119
   - Include security considerations section
   - Include IANA considerations (grant type registration)
   - Effort: L (full cycle)

3. **Identify target working group**
   - OAuth WG is the most natural fit (custom grant type)
   - Alternative: propose a new BOF (Birds of a Feather) session for agent auth
   - The `draft-klrc-aiagent-auth` authors may be allies — they compose existing standards
   - Effort: S (outreach)

4. **Submit via datatracker**
   - Create account, upload XML, get `draft-agentmessaging-aid-00` identifier
   - Effort: S (1 day)

5. **Present at next IETF meeting**
   - IETF 121 (November 2026, Dublin) or IETF 122 (March 2027)
   - Prepare slides, attend OAuth WG session
   - Effort: M (prep + travel)

**Total estimate:** L (full 6-day cycle for the draft, plus ongoing IETF engagement)

**Open questions:**
- Should we co-author with anyone? (e.g., the `draft-klrc` authors who already advocate for composition)
- Should we register the `urn:aid:agent-identity` grant type with IANA proactively?
- Do we need a formal security audit before submission?

**Reference:** `docs/internal/AID_COMPETITIVE_STRATEGY.md` in the 23blocks Auth API repo
