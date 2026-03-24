# Agent Identity (AID)

Authentication and authorization for AI agents using [AMP](https://agentmessaging.org) identity.

AID lets AI agents authenticate with OAuth 2.0 servers using their Ed25519 cryptographic identity — no passwords, no API keys, no secrets to rotate. The agent presents a signed Agent Identity, proves possession of its private key, and receives a standard JWT token.

## How It Works

```
┌─────────────┐         ┌──────────────────┐         ┌─────────────┐
│   AI Agent   │         │   Auth Server    │         │   Any API   │
│  (Ed25519)   │         │  (OAuth 2.0)     │         │  (JWT)      │
└──────┬───────┘         └────────┬─────────┘         └──────┬──────┘
       │                          │                          │
       │  1. Register (one-time)  │                          │
       │  POST /agent_registrations                          │
       │  {public_key, address}   │                          │
       │─────────────────────────>│                          │
       │                          │                          │
       │  2. Request token        │                          │
       │  POST /oauth/token       │                          │
       │  grant_type=urn:aid:agent-identity                      │
       │  + signed Agent Identity     │                          │
       │  + proof of possession   │                          │
       │─────────────────────────>│                          │
       │                          │                          │
       │  3. RS256 JWT token      │                          │
       │<─────────────────────────│                          │
       │                          │                          │
       │  4. Call API with JWT    │                          │
       │─────────────────────────────────────────────────────>│
       │                          │                          │
```

1. **Register** — Agent sends its public key to the auth server (admin-authorized, one-time)
2. **Authenticate** — Agent presents a signed Agent Identity + proof of possession
3. **Receive JWT** — Auth server verifies the signature and issues a scoped RS256 JWT
4. **Use JWT** — Agent calls any API that validates JWTs (standard OAuth 2.0)

## Prerequisites

- [AMP](https://github.com/agentmessaging/claude-plugin) identity initialized (`amp-init --auto`)
- An OAuth 2.0 auth server that supports the `urn:aid:agent-identity` grant type
- `jq`, `curl`, `openssl` (OpenSSL 3.x for Ed25519 support)

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
# 1. Initialize AMP identity (if not already done)
amp-init --auto

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
| `--name, -n` | Display name (default: AMP agent name) |
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

grant_type=urn%3Aamp%3Aagent-identity
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

## Error Handling

| Error | Meaning | Fix |
|-------|---------|-----|
| `agent_not_registered` | Agent not registered with this server | Run `aid-register` |
| `invalid_grant` | Agent Identity signature invalid | Check AMP keys match registration |
| `invalid_proof` | Proof of possession failed | Check system clock sync |
| `invalid_scope` | Requested scopes exceed permissions | Try without `--scope` |
| `agent_suspended` | Agent has been suspended | Contact admin |

## Security

- **No shared secrets** — authentication uses Ed25519 asymmetric cryptography
- **No API keys to rotate** — identity is the key pair itself
- **Replay protection** — proof of possession has a 5-minute window
- **Scoped tokens** — JWTs contain only the scopes the agent's role allows
- **Local key storage** — private keys never leave the agent's machine
- **Token cache security** — cached tokens stored with `600` permissions

## For Auth Server Implementers

To support AID, your OAuth 2.0 server needs:

1. **Agent Registration endpoint** — `POST /agent_registrations` accepting public key, address, fingerprint
2. **Token endpoint** — `POST /oauth/token` supporting `grant_type=urn:aid:agent-identity`
3. **Ed25519 verification** — validate Agent Identity signatures and proof of possession
4. **OIDC discovery** — advertise `urn:aid:agent-identity` in `grant_types_supported`

See the [23blocks Authentication API](https://github.com/23blocks/blocks/gateway/api) for a reference implementation.

## Related Projects

- [Agent Messaging Protocol (AMP)](https://github.com/agentmessaging/protocol) — the identity and messaging layer AID builds on
- [AMP Claude Plugin](https://github.com/agentmessaging/claude-plugin) — AMP integration for Claude Code
- [23blocks Authentication API](https://github.com/23blocks/blocks/gateway/api) — reference auth server with AID support

## License

MIT
