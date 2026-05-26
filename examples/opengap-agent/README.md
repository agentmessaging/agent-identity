# opengap-agent example

A reference agent definition combining the [OpenGAP / gitagent](https://github.com/open-gitagent/opengap) file convention with an [AID](https://agentids.org) `aid:` block for runtime authentication.

This is what the proposed composition looks like in practice: agent definition lives in version-controlled files (gitagent's strength), runtime identity and tokens come from AID (AID's strength). Each protocol stays in its lane.

## Files

```
opengap-agent/
├── agent.yaml      ← OpenGAP manifest + aid: block (proposed)
├── SOUL.md         ← OpenGAP identity / personality
├── RULES.md        ← OpenGAP hard constraints
└── README.md       ← this file
```

## The `aid:` block (proposed extension)

The `aid:` block in `agent.yaml` is an **optional** extension proposed in [F011 of the AID backlog](../../backlog/F011-opengap-aid-block.md) and tracked on the [OpenGAP repo](https://github.com/open-gitagent/opengap/issues). OpenGAP implementations that don't know about it MUST ignore it — no breaking change.

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
```

### Fields

| Field | Required | Description |
|---|---|---|
| `enabled` | yes | Master toggle. If `false`, the runtime skips AID entirely. |
| `agent_address` | yes | The agent's AID address (`<name>@<tenant>.local`). MUST match the address bound to the agent's keypair at `aid-init` time. |
| `key_algorithm` | no | Defaults to `Ed25519` (currently the only supported value). |
| `resource_servers` | yes | List of protected resource URLs the agent expects to call. Each will be discovered via RFC 9728 / RFC 8414. |
| `scopes` | no | Optional per-resource scope narrowing. Omitted = use all role scopes. |
| `auth_server` | no | Skip discovery; use this auth server URL directly. |

## How an AID-aware OpenGAP runtime uses this block

1. **At bootstrap**: verify the agent has an AID identity (`aid-status` succeeds). If not, fail fast with a clear error.
2. **For each `resource_servers[i]`**: run `aid-discover --resource <url>` once (results can be cached). Confirm `urn:aid:agent-identity` is advertised.
3. **Before each tool call against a resource server**: run `aid-token --resource <url> [--scope ...]` and inject the token as `Authorization: Bearer <token>`.
4. **On 401/403 from a resource server**: do not retry. The agent has been suspended/revoked. Surface the error to the operator.

## Running this example manually (no OpenGAP runtime required)

The example works today without any OpenGAP-runtime changes — the `aid:` block is just metadata until the OpenGAP CLI knows about it. You can run the AID half manually:

```bash
# Initialize identity (once per agent)
aid-init --name support-bot --tenant acme

# Discover the auth server for each resource
aid-discover --resource https://api.acme.com
aid-discover --resource https://tickets.acme.com

# Register (admin-initiated for this example; agent-initiated also works)
aid-register \
  --resource https://api.acme.com \
  --token <ADMIN_JWT> \
  --role-id <support-tier1-role-id>

# Get a token and call the API
TOKEN=$(aid-token --resource https://tickets.acme.com --quiet)
curl -H "Authorization: Bearer $TOKEN" https://tickets.acme.com/v1/tickets/open
```

## Why this composition matters

[OpenGAP](https://github.com/open-gitagent/opengap) defines *what an agent is* — versioned files in a repo. [AID](https://agentids.org) defines *how an agent authenticates* — Ed25519 identity, role-scoped JWTs, lifecycle management.

A single agent should be both:
- **Defined** in git so prompts and rules are auditable engineering artifacts
- **Authenticated** cryptographically so its runtime actions are attributable to a specific agent, not to the user who deployed it or to a shared API key

The `aid:` block is the smallest bridge between these two. One field in `agent.yaml` and the agent gains per-action audit trails, role-scoped tokens, and sub-second revocation — without giving up the OpenGAP definition model.

## See also

- [F011 backlog item](../../backlog/F011-opengap-aid-block.md) — implementation plan
- [OpenGAP specification](https://github.com/open-gitagent/opengap/blob/main/spec/SPECIFICATION.md)
- [AID protocol docs](../../README.md)
