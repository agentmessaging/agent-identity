# Draft email to Garrett Galow / WorkOS

**To:** authmd@workos.com (also CC garrett@workos.com if you have it)
**From:** juan@23blocks.com (or your preferred address)
**Subject:** AID + auth.md — proposing composition via `assertion_types_supported`

---

Hi Garrett,

Congrats on the auth.md launch. I've spent the last few days reading the spec and the reference repo end-to-end — it's a thoughtful design and it hits something the OAuth/agent space has been missing.

I write to propose a small composition between auth.md and a protocol we ship at 23blocks called Agent Identity (AID). AID is an OAuth 2.0 custom grant type (`urn:aid:agent-identity`) where each agent has its own Ed25519 keypair and a role-scoped registration — the agent itself is the principal, not a session inside someone else's. Our angle is the opposite of auth.md's user-delegation model: where auth.md answers "how does Claude-acting-for-Jane register with my service?", AID answers "how does support-bot, a long-lived autonomous agent, authenticate to my service?".

Reading the auth.md spec, the two are stackable rather than competitive. The cleanest composition is to list `urn:aid:agent-identity` as one of `identity_assertion.assertion_types_supported` in the `agent_auth` block. A service that publishes both an `agent_auth` block (auth.md) and an `aid_grant` block (AID's discovery extension) supports both protocols cleanly — and an agent that has both a user-delegation context and its own Ed25519 identity can present whichever fits the request.

I wrote up the longer version of this thinking here: https://agentids.org/blog/auth-md-vs-aid-complementary-layers/

Before I draft a PR I wanted to ask:

1. **Is auth.md open to accepting additional `assertion_types`?** I read the spec as designed to accommodate this (ID-JAG and verified_email are both listed; no closure language), but I'd rather confirm than assume.

2. **Does the integration story land for you?** Specifically: an AID-registered agent presents its signed Agent Identity document as the `assertion` field, the auth.md service verifies the signature directly (if registered locally with AID) or via introspection to the agent's AID auth server (if federated).

3. **Anything in the framing you'd push back on** before we materialize it as a PR?

I'm not trying to win a protocol war. I think auth.md is the right answer for consumer-AI delegation flows, and I think AID is the right answer for autonomous agents with persistent identity. They want to coexist in the same auth servers.

If this resonates, I'll open a PR on workos/auth.md with the spec change and a sample registration request. If not, I'd love to understand the philosophical objection so I can sharpen the AID positioning instead.

Happy to jump on a call, do this entirely async, or just hash it out in a PR thread — whatever works.

Thanks for shipping good open protocols. We need more of this.

— Juan Peláez
  23blocks · agentids.org
  @jkpelaez on X
