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

## Registration

AID supports two registration flows. Both require human approval — agents can never grant themselves permissions.

### Admin-Initiated Registration

The admin has the agent's public key and registers it directly:

```bash
# ── AGENT ─────────────────────────────────────────────────
aid-init --name support-agent

# ── ADMIN ─────────────────────────────────────────────────
# Admin registers the agent (requires admin JWT + role assignment)
aid-register \
  --auth https://auth.23blocks.com/zoom \
  --token <ADMIN_JWT> \
  --role-id 3

# ── AGENT ─────────────────────────────────────────────────
# Agent can now get tokens immediately
TOKEN=$(aid-token --auth https://auth.23blocks.com/zoom --quiet)
```

The `--role-id` binds the agent to a specific role, and the `--token <ADMIN_JWT>` authorizes it. Once registered, every token the agent requests is scoped to that role's permissions — the agent cannot change its role or escalate permissions.

### Agent-Initiated Registration

The agent requests access on its own. An admin approves it later.

```
┌──────────────┐                    ┌──────────────────┐
│   AI Agent    │                    │   Auth Server    │
│  (Ed25519)    │                    │  (OAuth 2.0)     │
└──────┬────────┘                    └────────┬─────────┘
       │                                      │
       │  1. POST /agent_registrations/request│
       │  {public_key, address, fingerprint}  │
       │─────────────────────────────────────>│
       │                                      │
       │  2. 202 Accepted                      │
       │  {status: pending,                   │
       │   authorization_url: https://...}    │
       │<─────────────────────────────────────│
       │                                      │
       │  2b. Agent shows authorization_url   │
       │      to human admin                  │
       │                                      │
       │         ┌──────────────┐             │
       │         │  Human Admin  │             │
       │         └──────┬────────┘             │
       │                │                      │
       │                │  3. Visit URL +      │
       │                │     approve          │
       │                │  POST /agent_registrations/:unique_id/approve
       │                │  {role_id: 3}        │
       │                │─────────────────────>│
       │                                      │
       │  4. Poll status                      │
       │  POST /agent_registrations/:unique_id/status│
       │─────────────────────────────────────>│
       │                                      │
       │  5. 200 OK (status: active)          │
       │<─────────────────────────────────────│
       │                                      │
       │  6. POST /oauth/token                │
       │  grant_type=urn:aid:agent-identity   │
       │─────────────────────────────────────>│
```

```bash
# ── AGENT ─────────────────────────────────────────────────
# 1. Initialize identity
aid-init --name support-agent

# 2. Request registration (no admin token needed)
aid-request --auth https://auth.23blocks.com/zoom \
  --description "Handles customer support ticket triage"
# → Returns authorization_url for admin approval
# → e.g. https://app.23blocks.com/agents/authorize?code=kX9mP2vL7qR4wY6t...

# ── ADMIN ─────────────────────────────────────────────────
# 3. Admin visits the authorization_url, reviews the agent, and approves
#    (or via API: POST /agent_registrations/:unique_id/approve { role_id: 3 })

# ── AGENT ─────────────────────────────────────────────────
# 4. Check if approved
aid-request --auth https://auth.23blocks.com/zoom --poll

# 5. Once approved, get tokens
TOKEN=$(aid-token --auth https://auth.23blocks.com/zoom --quiet)
```

#### Authorization URL

When an agent-initiated registration is created, the auth server MUST return an `authorization_url` in the response. This is the URL the agent shows to a human admin so they can review and approve the request — similar to OAuth 2.0 Device Authorization (RFC 8628).

**Standard path**: Auth server implementers SHOULD serve the agent authorization UI at a well-known path:

```
/agents/authorize?code={authorization_code}
```

This allows agents to predict the authorization URL from just the domain, without needing per-provider configuration.

**Authorization code**: The `code` parameter MUST be a temporary, opaque token — NOT the agent's `unique_id` or any other permanent identifier. This prevents leaking system information when the URL is shared via email, Slack, or logs. The code SHOULD:
- Be cryptographically random (e.g., 32 bytes, URL-safe base64)
- Expire after a reasonable period (RECOMMENDED: 24 hours)
- Be single-use or regenerated on each request
- Resolve to the agent registration only via a server-side lookup

**Response fields:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `authorization_url` | string | MUST | Full URL with pre-filled code (equivalent to RFC 8628's `verification_uri_complete`) |
| `user_code` | string | MUST | Short, human-readable code (RECOMMENDED format: `XXXX-XXXX`, e.g., `ABCD-1234`). The admin can visit the base authorization URL and type this code manually instead of clicking the full URL. |
| `expires_in` | integer | MUST | Seconds until the authorization code expires. Agents MUST stop polling after this period. |
| `interval` | integer | MUST | Minimum seconds between polling requests (default: 5). Auth server SHOULD return HTTP 429 if agent polls faster. |

**Response example:**
```json
{
  "data": {
    "type": "agent_registration",
    "id": "4e6aa83e-e4d4-4b31-b519-1b493855c28d",
    "attributes": {
      "status": "pending",
      "authorization_url": "https://acme.example.com/agents/authorize?code=kX9mP2vL7qR4wY6tN8sA...",
      "user_code": "ABCD-1234",
      "expires_in": 86400,
      "interval": 5
    }
  }
}
```

**Base Authorization URL**: Auth servers SHOULD expose a base authorization page at `/agents/authorize` (no query parameters). This is the equivalent of RFC 8628's `verification_uri` — a page where admins can manually type the `user_code` to look up and approve agent requests. The full `authorization_url` with `?code=xxx` is the pre-filled version (equivalent to RFC 8628's `verification_uri_complete`), allowing one-click approval when shared via email, Slack, or logs.

**Resolving the code**: The auth server MUST provide an endpoint to resolve the authorization code into the full agent registration:

```
GET /agent_registrations/resolve?code={authorization_code}
```

This endpoint requires admin authentication (`agent_registrations:read` scope) and returns the agent registration details if the code is valid and not expired. Returns 404 if the code is invalid or expired.

**How the URL is resolved:**

The auth server builds the URL from the tenant's configured frontend domain. In multi-tenant architectures, each tenant may have their own admin UI:

| Scenario | Authorization URL |
|----------|------------------|
| Tenant has custom domain | `https://acme.example.com/agents/authorize?code={code}` |
| Tenant uses platform default | `https://platform.example.com/agents/authorize?code={code}` |

The authorization page MUST:
1. Call the resolve endpoint to look up the agent by authorization code
2. Display the agent's name, address, and fingerprint for admin verification
3. Allow the admin to select a role for the agent
4. Call `POST /agent_registrations/:unique_id/approve` with the selected `role_id`
5. Require the admin to be authenticated with `agent_registrations:write` scope

**Security**: The agent-initiated flow does NOT bypass human approval. The agent submits its public key and a description of why it needs access. The registration is created in `pending` status — the agent cannot get tokens until an admin approves the request and assigns a role. The admin controls which role (and therefore which scopes) the agent receives. The agent never chooses its own permissions.

## Sample Flow

A support agent needs API access to the "zoom" tenant:

```bash
# Agent-initiated (agent requests, admin approves)
aid-init --name support-agent
aid-request --auth https://auth.23blocks.com/zoom \
  --description "Tier-1 support ticket triage"

# ... admin approves via dashboard ...

TOKEN=$(aid-token --auth https://auth.23blocks.com/zoom --quiet)
curl -H "Authorization: Bearer $TOKEN" \
  https://api.23blocks.com/zoom/tickets
```

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

# 2a. Request registration (agent-initiated, no admin token needed)
aid-request --auth https://auth.example.com/tenant
# ... wait for admin approval ...
aid-request --auth https://auth.example.com/tenant --poll

# 2b. Or: admin-initiated registration (requires admin token)
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

### `aid-request` — Request Registration (Agent-Initiated)

Submit a registration request without an admin token. The request is created in `pending` status and must be approved by an admin before the agent can get tokens.

```bash
aid-request --auth <url> [options]
```

| Flag | Description |
|------|-------------|
| `--auth, -a` | Auth server URL (required) |
| `--api-key, -k` | API key (X-Api-Key header) |
| `--name, -n` | Display name (default: agent name) |
| `--description, -d` | Why this agent needs access |
| `--poll, -p` | Check status of a pending request |

**Examples:**
```bash
# Request registration
aid-request --auth https://auth.23blocks.com/acme \
  --description "Handles customer support ticket triage"

# Check if request has been approved
aid-request --auth https://auth.23blocks.com/acme --poll
```

**What it does:**
1. Reads the agent's Ed25519 public key and identity
2. POSTs to `POST /agent_registrations/request` (no auth token required)
3. Server creates a `pending` registration and returns an `authorization_url`
4. Displays the `authorization_url` for the admin to visit and approve
5. Stores the registration ID locally for polling
6. With `--poll`, checks the current status of the pending request

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

### Scope Resolution

When the `scope` parameter is included in the token request, the auth server MUST apply scope intersection:

1. Let `registered_scopes` = the set of scopes available to the agent via its assigned role
2. Let `requested_scopes` = the scopes in the `scope` parameter (space-separated)
3. If `requested_scopes` is empty or omitted, grant all `registered_scopes`
4. If any scope in `requested_scopes` is NOT in `registered_scopes`, the server MUST reject the request with `invalid_scope`
5. Otherwise, grant exactly `requested_scopes` (which is a subset of `registered_scopes`)

This prevents scope escalation — an agent cannot request permissions beyond what its role allows. It also enables least-privilege token requests, where an agent requests only the scopes it needs for a specific task.

**Error response for invalid scopes:**
```json
{
  "error": "invalid_scope",
  "error_description": "Requested scopes not permitted: admin:write, users:delete"
}
```

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

### Required Introspection Fields

When introspecting an agent token, the auth server MUST include these agent-specific fields alongside the standard RFC 7662 fields:

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `active` | boolean | MUST | Whether the token is valid AND the agent is active |
| `sub` | string | MUST | Agent's subject identifier |
| `scope` | string | MUST | Space-separated granted scopes |
| `token_type` | string | MUST | Always `"Bearer"` |
| `agent_id` | string | MUST | Agent's unique identifier (from registration) |
| `agent_address` | string | MUST | Agent's address (e.g., `name@org.provider`) |
| `agent_name` | string | MUST | Agent's human-readable display name |
| `agent_role` | string | MUST | Name of the role assigned to this agent |
| `agent_status` | string | MUST | Current lifecycle status: `pending`, `active`, `suspended`, or `deleted` |
| `exp` | integer | MUST | Token expiration (Unix timestamp) |
| `iat` | integer | MUST | Token issued-at (Unix timestamp) |
| `iss` | string | SHOULD | Issuer URL |
| `jti` | string | SHOULD | Unique token identifier |

These fields allow target APIs to make authorization decisions based on agent identity, not just token validity. For example, an API can log which agent made each request, or apply per-agent rate limits.

**Response (suspended agent):**
```json
{
  "active": false,
  "reason": "agent_suspended"
}
```

When `active` is `false`, the `reason` field SHOULD indicate why: `agent_suspended`, `agent_not_found`, `token_expired`, or `invalid_token`.

Target APIs can choose between:
- **Offline validation** — verify the JWT signature via JWKS (fast, but can't detect suspension until token expires)
- **Online introspection** — call the introspection endpoint (slower, but real-time status)

## Agent Lifecycle

```
                            ┌───────────────────────────────────────┐
                            │                                       v
aid-request ──> pending ──> active ──> suspended ──> active   (reactivated)
                   │                           └──> deleted   (terminal)
                   └──> rejected                              (terminal)
```

| Status | Can get tokens? | Introspection returns |
|--------|----------------|----------------------|
| `pending` | No | `active: false, reason: registration_pending` |
| `active` | Yes | `active: true` |
| `suspended` | No (403) | `active: false, reason: agent_suspended` |
| `rejected` | No | `active: false, reason: agent_not_found` |
| `deleted` | No | `active: false, reason: agent_not_found` |

Admins control agent lifecycle via the registration API:
- `POST /agent_registrations/:unique_id/approve` — approve a pending request and assign a role
- `POST /agent_registrations/:unique_id/reject` — reject a pending request
- `POST /agent_registrations/:unique_id/suspend` — immediately block token issuance and invalidate via introspection
- `POST /agent_registrations/:unique_id/reactivate` — restore agent access

## Error Handling

| Error | Meaning | Fix |
|-------|---------|-----|
| `agent_not_registered` | Agent not registered with this server | Run `aid-request` or `aid-register` |
| `registration_pending` | Registration awaiting admin approval | Run `aid-request --poll` to check status |
| `invalid_grant` | Agent Identity signature invalid | Check agent keys match registration |
| `invalid_proof` | Proof of possession failed | Check system clock sync |
| `invalid_scope` | Requested scopes exceed permissions | Try without `--scope` |
| `agent_suspended` | Agent has been suspended by admin | Contact admin for reactivation |

### Polling Error Responses (RFC 8628)

When an agent polls for registration status, the auth server MUST return one of the following error codes aligned with [RFC 8628 Section 3.5](https://datatracker.ietf.org/doc/html/rfc8628#section-3.5):

| Error | HTTP Status | Meaning | Agent Action |
|-------|-------------|---------|--------------|
| `authorization_pending` | 200 | Registration not yet approved | Keep polling at the specified `interval` |
| `slow_down` | 429 | Agent is polling too frequently | Increase polling interval by 5 seconds |
| `expired_token` | 410 | Authorization code has expired | Submit a new registration request with `aid-request` |
| `access_denied` | 403 | Admin rejected the registration request | Do not retry; contact admin or submit a new request |

**Example error response:**
```json
{
  "error": "slow_down",
  "error_description": "Polling too frequently. Increase interval to 10 seconds."
}
```

## Security

- **No shared secrets** — authentication uses Ed25519 asymmetric cryptography
- **No API keys to rotate** — identity is the key pair itself
- **Human controls access** — agents can request registration, but only an admin can approve and assign roles
- **Replay protection** — proof of possession has a 5-minute window
- **Scoped tokens** — JWTs contain only the scopes the agent's role allows
- **Local key storage** — private keys never leave the agent's machine
- **Token cache security** — cached tokens stored with `600` permissions

## For Auth Server Implementers

To support AID, your OAuth 2.0 server needs:

1. **Agent Registration endpoint** — `POST /agent_registrations` (admin-initiated) and `POST /agent_registrations/request` (agent-initiated, creates `pending` registration)
1. **Registration approval** — `POST /agent_registrations/:unique_id/approve` with role assignment, `POST /agent_registrations/:unique_id/reject`
1. **Authorization URL** — return `authorization_url` with a temporary opaque code in agent-initiated registration responses, and a `GET /agent_registrations/resolve?code={code}` endpoint for the admin UI to resolve it
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
