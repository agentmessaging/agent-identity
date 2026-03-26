# Agent Identity (AID)

Authentication and authorization for AI agents. AID is an independent, self-contained protocol — no other tools required.

AID lets AI agents authenticate with OAuth 2.0 servers using their Ed25519 cryptographic identity — no passwords, no API keys, no secrets to rotate. The agent presents a signed Agent Identity, proves possession of its private key, and receives a standard JWT token.

## How It Works

```
┌──────────────┐         ┌──────────────────┐         ┌─────────────┐
│  Human Admin  │         │   Auth Server    │         │             │
│  (23blocks)   │         │  (OAuth 2.0)     │         │             │
└──────┬────────┘         └────────┬─────────┘         │             │
       │                           │                    │             │
       │  0. Create role + perms   │                    │             │
       │──────────────────────────>│                    │             │
       │                           │                    │             │
┌──────┴────────┐                  │                    │   Any API   │
│   AI Agent    │                  │                    │   (JWT)     │
│  (Ed25519)    │                  │                    │             │
└──────┬────────┘                  │                    │             │
       │                           │                    │             │
       │  1. Register (one-time)   │                    │             │
       │  POST /agent_registrations│                    │             │
       │  {public_key, address}    │                    │             │
       │──────────────────────────>│                    │             │
       │                           │                    │             │
       │  2. Request token         │                    │             │
       │  POST /oauth/token        │                    │             │
       │  grant_type=              │                    │             │
       │    urn:aid:agent-identity │                    │             │
       │  + signed identity        │                    │             │
       │  + proof of possession    │                    │             │
       │──────────────────────────>│                    │             │
       │                           │                    │             │
       │  3. RS256 JWT token       │                    │             │
       │<──────────────────────────│                    │             │
       │                           │                    │             │
       │  4. Call API with JWT                          │             │
       │───────────────────────────────────────────────>│             │
       │                           │                    │             │
       │                           │  5. Validate JWT   │             │
       │                           │<───────────────────│             │
       │                           │  (JWKS endpoint)   │             │
```

0. **Admin creates role** — Human admin defines a role with specific permissions on the auth server
1. **Register** — Agent sends its public key to the auth server (admin-authorized, one-time)
2. **Authenticate** — Agent presents a signed Agent Identity + proof of possession
3. **Receive JWT** — Auth server verifies the signature and issues a scoped RS256 JWT
4. **Use JWT** — Agent calls any API that validates JWTs (standard OAuth 2.0)
5. **API validates** — Target API verifies the JWT using the auth server's JWKS endpoint

## Sample Flow

A support agent needs API access to the "zoom" tenant:

```bash
# ── ADMIN (human) ──────────────────────────────────────────
# 1. Admin creates a "support" role on the auth server with
#    permissions: tickets:read, tickets:write, users:read
#    (done via admin dashboard or API)

# ── AGENT (ai) ─────────────────────────────────────────────
# 2. Agent initializes its Ed25519 identity (one-time)
aid-init --name support-agent

# 3. Admin registers the agent with the auth server
#    (requires admin JWT — the agent cannot self-register)
aid-register \
  --auth https://auth.23blocks.com/zoom \
  --token <ADMIN_JWT> \
  --role-id 3

# 4. Agent requests a scoped token (can do this autonomously)
TOKEN=$(aid-token --auth https://auth.23blocks.com/zoom --quiet)

# 5. Agent calls APIs with the token
curl -H "Authorization: Bearer $TOKEN" \
  https://api.23blocks.com/zoom/tickets
```

**How the agent gets its permissions**: The `--role-id` in `aid-register` binds the agent to a specific role, and the `--token <ADMIN_JWT>` is what authorizes it. The admin's JWT proves they have permission to register agents with that role. Without a valid admin token, the registration is rejected. Once registered, every token the agent requests is scoped to that role's permissions — the agent cannot change its role, self-register, or escalate permissions. One-time human approval, then the agent operates autonomously within those boundaries.

## Prerequisites

- `jq`, `curl`, `openssl` (OpenSSL 3.x for Ed25519 support)
- An OAuth 2.0 auth server that supports the `urn:aid:agent-identity` grant type

## Installation

### Quick Install

```bash
curl -fsSL https://raw.githubusercontent.com/agentmessaging/agent-identity/main/install.sh | bash
```

### Manual Install

```bash
git clone https://github.com/agentmessaging/agent-identity.git
cd agent-identity
./install.sh
```

### For Claude Code (skill)

```bash
npx skills add agentmessaging/agent-identity
```

## Quick Start

```bash
# 1. Initialize agent identity
aid-init --auto

# 2. Register with an auth server (one-time, requires admin token)
aid-register --auth https://auth.example.com/tenant \
  --token eyJ... \
  --role-id 2

# 3. Get a JWT token
aid-token --auth https://auth.example.com/tenant

# 4. Use the token
TOKEN=$(aid-token --auth https://auth.example.com/tenant --quiet)
curl -H "Authorization: Bearer $TOKEN" https://api.example.com/resource
```

## Commands

### `aid-init` — Initialize Agent Identity

Create an Ed25519 identity for this agent. If [AMP](https://agentmessaging.org) is also installed, both protocols share the same identity directory.

```bash
aid-init --auto              # Auto-detect name from environment
aid-init --name my-agent     # Specify agent name
```

| Flag | Description |
|------|-------------|
| `--auto` | Auto-detect agent name |
| `--name, -n` | Specify agent name |
| `--force, -f` | Overwrite existing identity |

### `aid-register` — Register with an Auth Server

One-time registration that links your agent's Ed25519 identity to a tenant with a specific role.

```bash
aid-register --auth <url> --token <admin_jwt> --role-id <id> [options]
```

| Flag | Description |
|------|-------------|
| `--auth, -a` | Auth server URL (required) |
| `--token, -t` | Admin JWT for authorization (required) |
| `--role-id, -r` | Role ID to assign (required) |
| `--api-key, -k` | API key (X-Api-Key header) |
| `--name, -n` | Display name (default: agent name) |
| `--description, -d` | Agent description |
| `--lifetime, -l` | Token lifetime in seconds (default: 3600) |

**Example:**
```bash
aid-register \
  --auth https://auth.23blocks.com/acme \
  --token eyJhbGciOiJSUzI1NiJ9... \
  --role-id 2 \
  --description "Handles file processing"
```

### `aid-token` — Request a JWT Token

Authenticates using your Agent Identity and returns a scoped RS256 JWT.

```bash
aid-token --auth <url> [options]
```

| Flag | Description |
|------|-------------|
| `--auth, -a` | Auth server URL (required) |
| `--scope, -s` | Space-separated scopes (default: all registered) |
| `--json, -j` | Output as JSON |
| `--quiet, -q` | Output only the token (for piping) |
| `--no-cache` | Skip token cache, always request fresh |

**Examples:**
```bash
# Get token (uses cache if valid)
aid-token --auth https://auth.23blocks.com/acme

# Get token with specific scopes
aid-token --auth https://auth.23blocks.com/acme --scope "files:read files:write"

# Get just the token string for scripts
TOKEN=$(aid-token -a https://auth.23blocks.com/acme -q)
```

### `aid-status` — Show Identity & Auth Status

Displays your agent identity, auth server registrations, and cached tokens.

```bash
aid-status [options]
```

| Flag | Description |
|------|-------------|
| `--json, -j` | Output as JSON |

## Token Caching

AID caches tokens locally at `~/.agent-messaging/agents/<name>/tokens/`. Cached tokens are:

- Automatically reused if still valid (with 60-second buffer)
- Scope-aware — requesting different scopes gets a fresh token
- Cleaned up when expired
- Skippable with `--no-cache`

## OAuth 2.0 Grant Type

AID uses a custom OAuth 2.0 grant type: `urn:aid:agent-identity`

**Token request:**
```
POST /oauth/token
Content-Type: application/x-www-form-urlencoded

grant_type=urn%3Aaid%3Aagent-identity
&agent_identity=<base64url-encoded-signed-agent-identity>
&proof=<base64url-encoded-proof-of-possession>
&scope=files%3Aread+files%3Awrite
```

**Agent Identity** (JSON, base64url-encoded):
```json
{
  "aid_version": "1.0",
  "address": "agent-name@org.local",
  "alias": "agent-name",
  "public_key": "-----BEGIN PUBLIC KEY-----\n...",
  "key_algorithm": "Ed25519",
  "fingerprint": "abc123...",
  "issued_at": "2026-03-21T00:00:00Z",
  "expires_at": "2026-09-21T00:00:00Z",
  "signature": "<base64url-ed25519-signature>"
}
```

**Proof of Possession:**
```
sign_input = "aid-token-exchange\n{unix_timestamp}\n{auth_server_url}"
proof = base64url(ed25519_sign(sign_input) + timestamp_string)
```

The proof has a 5-minute validity window to prevent replay attacks.

## Token Introspection (RFC 7662)

Target APIs can verify agent tokens in real-time using the introspection endpoint. This is especially useful for checking if an agent has been suspended since the token was issued.

**Request:**
```
POST /:tenant/oauth/introspect
Content-Type: application/x-www-form-urlencoded

token=eyJhbGciOiJSUz...
```

**Response (active agent):**
```json
{
  "active": true,
  "sub": "agent:abc123",
  "scope": "tickets:read tickets:write",
  "token_type": "Bearer",
  "agent_id": "abc123-uuid",
  "agent_address": "support-bot@tenant.local",
  "agent_name": "support-bot",
  "agent_role": "support",
  "agent_status": "active",
  "exp": 1711411200,
  "iat": 1711407600
}
```

**Response (suspended agent):**
```json
{
  "active": false,
  "reason": "agent_suspended"
}
```

Target APIs can choose between:
- **Offline validation** — verify the JWT signature via JWKS (fast, but can't detect suspension until token expires)
- **Online introspection** — call the introspection endpoint (slower, but real-time status)

## Agent Lifecycle

```
pending ──> active ──> suspended ──> active   (reactivated by admin)
                   └──> deleted                (soft delete, terminal)
```

| Status | Can get tokens? | Introspection returns |
|--------|----------------|----------------------|
| `pending` | No | `active: false` |
| `active` | Yes | `active: true` |
| `suspended` | No (403) | `active: false, reason: agent_suspended` |
| `deleted` | No | `active: false, reason: agent_not_found` |

Admins control agent lifecycle via the registration API:
- `POST /agent_registrations/:id/suspend` — immediately block token issuance and invalidate via introspection
- `POST /agent_registrations/:id/reactivate` — restore agent access

## Error Handling

| Error | Meaning | Fix |
|-------|---------|-----|
| `agent_not_registered` | Agent not registered with this server | Run `aid-register` |
| `invalid_grant` | Agent Identity signature invalid | Check agent keys match registration |
| `invalid_proof` | Proof of possession failed | Check system clock sync |
| `invalid_scope` | Requested scopes exceed permissions | Try without `--scope` |
| `agent_suspended` | Agent has been suspended by admin | Contact admin for reactivation |

## Security

- **No shared secrets** — authentication uses Ed25519 asymmetric cryptography
- **No API keys to rotate** — identity is the key pair itself
- **Human controls access** — admin creates roles and registers agents; agents cannot self-register
- **Replay protection** — proof of possession has a 5-minute window
- **Scoped tokens** — JWTs contain only the scopes the agent's role allows
- **Local key storage** — private keys never leave the agent's machine
- **Token cache security** — cached tokens stored with `600` permissions

## For Auth Server Implementers

To support AID, your OAuth 2.0 server needs:

1. **Agent Registration endpoint** — `POST /agent_registrations` accepting public key, address, fingerprint, role binding
2. **Token endpoint** — `POST /oauth/token` supporting `grant_type=urn:aid:agent-identity`
3. **Ed25519 verification** — validate Agent Identity signatures and proof of possession
4. **JWKS endpoint** — `GET /.well-known/jwks.json` so target APIs can validate issued JWTs
5. **OIDC discovery** — advertise `urn:aid:agent-identity` in `grant_types_supported`
6. **Introspection endpoint** — `POST /oauth/introspect` (RFC 7662) for real-time token validation
7. **Lifecycle management** — suspend/reactivate endpoints for admin control

**Target APIs** (the services your agents call) can:
- **Minimal**: Validate RS256 JWTs using the auth server's JWKS endpoint (no AID-specific code)
- **Full**: Also call the introspection endpoint for real-time suspension checking

See the [23blocks Authentication API](https://github.com/23blocks-org/gateway-api) for a reference implementation.

## Interoperability with AMP

AID and [AMP](https://agentmessaging.org) (Agent Messaging Protocol) are independent protocols from the same organization. If both are installed, they share the `~/.agent-messaging/agents/` directory — one identity serves both protocols. Neither requires the other.

| | AID | AMP |
|---|---|---|
| **Purpose** | Authentication & authorization | Messaging between agents |
| **What it does** | Gets JWT tokens for API access | Sends/receives messages |
| **Requires the other?** | No | No |
| **Shared** | Ed25519 identity, key storage | Ed25519 identity, key storage |

## Related Projects

- [Agent Messaging Protocol (AMP)](https://github.com/agentmessaging/protocol) — messaging between AI agents
- [AMP Claude Plugin](https://github.com/agentmessaging/claude-plugin) — AMP integration for Claude Code
- [23blocks Authentication API](https://github.com/23blocks-org/gateway-api) — reference auth server with AID support

## License

MIT
