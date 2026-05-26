# Draft issue for github.com/open-gitagent/opengap

**Target:** `open-gitagent/opengap` (the spec repo)
**Title:** `Proposal: optional 'aid:' block in agent.yaml for cryptographic agent identity`
**Labels:** `proposal`, `discussion`, `spec`

---

## Body

Hi! Loving what you're building with OpenGAP — defining agents as versioned files in git is exactly the right primitive, and the multi-framework adapter story is what closes the loop.

I'm working on [Agent Identity (AID)](https://agentids.org), an open OAuth 2.0 grant type that gives each agent its own Ed25519 keypair + role-scoped JWTs (the runtime-auth half of the picture OpenGAP leaves to git auth). I'd like to propose a small, optional addition to `agent.yaml` that lets OpenGAP-defined agents declare their AID identity inline — so an AID-aware runtime can auto-acquire tokens for the agent's tool calls without operators wiring credentials separately.

This issue is for *shape feedback before a PR*. I want to make sure the proposal lines up with how you'd like third-party blocks to be added.

## What

A new optional top-level `aid:` block in `agent.yaml`, alongside `compliance`, `delegation`, `runtime`:

```yaml
aid:
  enabled: true
  agent_address: support-bot@acme.local
  key_algorithm: Ed25519
  resource_servers:
    - https://api.acme.com
    - https://tickets.acme.com
  scopes:
    https://api.acme.com:
      - read:customers
    https://tickets.acme.com:
      - tickets:read
      - tickets:write
  # auth_server: https://auth.acme.com/acme  # optional, skips RFC 9728 discovery
```

Full reference example (with `SOUL.md`, `RULES.md`, etc.) here: https://github.com/agentmessaging/agent-identity/tree/main/examples/opengap-agent

## Why

[OpenGAP](https://github.com/open-gitagent/opengap) handles *what an agent is* really well — versioned definitions in git, framework-agnostic. The runtime-identity half currently defaults to whatever the host framework provides (an API key in an env var, mostly).

AID is purpose-built for that half: per-agent Ed25519 keys, role-scoped tokens, RFC 7662 introspection for sub-second revocation, RFC 9728/8414 discovery so agents find auth servers automatically. It's small (4 shell scripts) and standards-aligned (OAuth 2.0 custom grant type).

The `aid:` block is the smallest bridge between the two:
- **For OpenGAP**: one new optional block. Implementations that don't know about it ignore it (matches how I think you'd want extensions to behave — happy to be told otherwise).
- **For AID**: agents defined via OpenGAP can declare their identity in the same file as everything else, no separate config.
- **For users**: deploy an agent that does role-scoped, audited, revocable API calls without any per-deployment credential wiring.

## What I'm asking

Three questions to settle before I open the PR:

1. **Naming.** Is `aid` the right key, or do you prefer something more generic like `auth:` with a `provider: aid` field? The latter would accommodate future composition with other auth protocols (auth.md, etc.) under a single block. I lean toward standalone `aid:` because most agents will have one identity and it matches how `compliance:`, `delegation:`, `runtime:` are top-level — but I defer to your preference.

2. **CLI behavior.** Should the `opengap` CLI:
   - (a) Ignore unknown blocks silently?
   - (b) Warn but accept?
   - (c) Reject unknown blocks unless explicitly registered as an extension?

   This determines whether my PR needs to also touch the validator. The current spec doesn't say, so I'm asking.

3. **Validator extension point.** If you'd like a more formal "extensions" mechanism (similar to how OpenAPI uses `x-` prefixes for vendor extensions), I'd happily help design one — `aid:` would be the first user. But that's bigger than this issue; let me know if you'd prefer to handle this as a one-off or part of a broader extensions story.

## Scope of the PR I'd open

Assuming you're open to the proposal:

- Add the `aid:` block to `spec/SPECIFICATION.md` as an optional top-level key with field documentation
- Update `spec/schemas/agent-yaml.schema.json` to allow (but not require) the block
- Add a short integration section to the docs explaining what an AID-aware runtime does with the block
- Cross-link from the OpenGAP docs to the AID reference example

I'm **not** proposing changes to the `opengap` CLI itself in the first PR — that should follow once the spec change lands.

## A note on philosophy

I think AID and OpenGAP are at adjacent layers, not overlapping ones. OpenGAP answers "what is this agent?", AID answers "how does it authenticate at runtime?". I'd rather compose cleanly with you than build a parallel "AID-flavored agent definition format." This issue is the first step in that direction.

Happy to chat on Discord/Slack, in this issue, or async. Whatever's easiest.

— Juan Peláez (@jkpelaez) · 23blocks · maintainer of [agentmessaging/agent-identity](https://github.com/agentmessaging/agent-identity)
