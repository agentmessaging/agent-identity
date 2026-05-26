# F011 — Add `aid:` block to OpenGAP `agent.yaml`

**Status:** Todo
**Type:** Feature (external composition)
**Created:** 2026-05-26
**Priority:** High
**Category:** Gitagent ecosystem distribution
**Effort:** S (1-2 days)

## Description

Propose and ship an optional `aid:` block in OpenGAP's `agent.yaml` schema. Any agent defined via the [OpenGAP / gitagent](https://github.com/open-gitagent/opengap) convention can declare its AID identity inline.

When the `opengap` CLI runs an agent, it could automatically run `aid-discover --resource <api>` and `aid-token --resource <api>` against the declared resource servers, threading the resulting tokens into the agent's tool calls.

## Why It's Needed

OpenGAP has 2,800 stars and is the de facto standard for "agent definition as files in a git repo." It's positioned to be where agents *come from* in the next 12-24 months. AID needs to be discoverable in that ecosystem — otherwise the default for git-defined agents will be "no auth" or "API key in a env var."

This is the cheapest distribution surface in the entire landscape: a single PR onto a 2.8k-star repo gets AID listed in front of every developer who defines an agent in git.

## Business Case

- **Distribution leverage** — instant access to the OpenGAP developer audience
- **Cheap** — single PR, schema addition + reference example
- **Composition story** — concretely shows AID composes with how developers actually define agents today
- **Defensive** — if we don't propose a shape, OpenGAP maintainers will define one for us (probably more generic, less aligned)

## Implementation Plan

### Phase 1 — Read OpenGAP's spec conventions (2 hours)
- Read [`open-gitagent/opengap/spec/SPECIFICATION.md`](https://github.com/open-gitagent/opengap/blob/main/spec/SPECIFICATION.md)
- Confirm how third-party blocks are namespaced
- Check whether existing optional blocks (compliance, hooks) follow a convention we should mirror

### Phase 2 — Open an issue first (1 day turnaround)
Before the PR, open an issue on `open-gitagent/opengap` outlining the proposed `aid:` block and asking for feedback on placement / naming. Avoids the PR being rejected for shape reasons.

### Phase 3 — Draft the schema (2 hours)

```yaml
# agent.yaml additions

aid:
  enabled: true
  agent_address: support-bot@acme.local
  key_algorithm: Ed25519  # default
  resource_servers:
    - https://api.acme.com
    - https://files.acme.com
  # optional: explicit auth server URL (skip discovery)
  # auth_server: https://auth.acme.com/zoom
  # optional: scopes per resource
  # scopes:
  #   https://api.acme.com:
  #     - tickets:read
  #     - tickets:write
```

### Phase 4 — Reference example in AID repo
Add `examples/opengap-agent/` with:
- `agent.yaml` containing the `aid:` block
- `SOUL.md`, `RULES.md` (OpenGAP-required)
- A README explaining how to run it: `opengap run` should auto-acquire AID tokens

### Phase 5 — PR on OpenGAP
- Spec PR adding the `aid:` block to `SPECIFICATION.md`
- Validator change in the `opengap` CLI to recognize the block (optional — depends on how OpenGAP handles unknown blocks; ideally they're allowed)
- Reference example linked from OpenGAP docs

### Phase 6 — (Stretch) CLI hook
If maintainers are open: a hook in `opengap run` that calls `aid-token` and threads the result into the agent's environment. This is the highest-impact composition piece.

## Risks

- **Maintainers want a different shape.** Open an issue first; iterate on the proposal before the PR.
- **They prefer a generic `auth:` block.** Be ready to negotiate — `auth.aid:` or `auth: { provider: aid, ... }` are acceptable alternatives.
- **CLI hook gets pushed back.** Schema-only addition is still a win even without the runtime hook.

## Definition of Done

- PR merged on `open-gitagent/opengap` (or a clear alternative shape agreed upon)
- Reference example exists in `agent-identity/examples/opengap-agent/`
- AID README links to the OpenGAP integration example
- If CLI hook ships, end-to-end test: an OpenGAP agent runs and gets an AID token without manual `aid-token` calls

## Sources

- [OpenGAP spec](https://github.com/open-gitagent/opengap/blob/main/spec/SPECIFICATION.md)
- [gitagent.sh](https://gitagent.sh)
- Internal research: [`research/gitagent.md`](../research/gitagent.md)
