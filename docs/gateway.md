# AID hosted gateway (reference implementation, kind B)

A gateway for old systems that have an API with their own credentials but cannot check an outside token. The agent calls the gateway with its AID token. The gateway checks the token, checks the request against a permission catalog the company wrote, swaps in the credential of the agent's own user in the old system, forwards the request, and writes an audit record. The agent never sees a credential of the old system.

Code: [`gateway/`](../gateway/). Demo: [`examples/gateway-demo/`](../examples/gateway-demo/) (`node examples/gateway-demo/run-demo.js`). Profile it builds on: [federation.md](federation.md). Status: **reference implementation, not independently reviewed** (see the [security checklist](#security-checklist)).

## What this is, and what it is not

| Kind of system (see [Which systems this works with](federation.md#which-systems-this-works-with)) | Gateway? |
|---|---|
| **A**: can be told to trust an outside OIDC/OAuth identity provider on its API | **No.** It takes the token itself and maps it to the agent's user. Adding a gateway only adds a hop. |
| **B**: has an API with its own credentials (API key, basic auth, its own OAuth client) but cannot check an outside token | **Yes. This is what this is for.** |
| **C**: no API (screen-only, files, a database nobody should touch) | **Not covered.** Nothing here helps. |

It is also not:

- **An authorization system for the old system.** The old system's own permissions for the agent's user are the ceiling. The gateway can only narrow: a request has to pass the token, the scope map, the grant ceiling and the catalog, and then the old system still decides for itself.
- **A way to give an agent access to a user's data without that user existing.** Each agent is a real user in the old system, created by the company, with the least privilege that works.
- **A secrets manager.** It holds credentials because it has to use them; see the vault section for what that costs.
- **A browser proxy.** No cookies, sessions, redirects, WebSockets, streaming or CORS.

## Request flow

```
Agent                         Gateway                                     Old system
  |  GET /acme/contacts/42        |                                            |
  |  Authorization: Bearer <AID>  |                                            |
  |------------------------------>|                                            |
  |                  1. target: origin-form only, no .. %2e %2f \ // ; (400)   |
  |                  2. tenant exists (404), is switched on (403)              |
  |                  3. token: issuer, signature, time, audience, agent,       |
  |                     revocations, introspection (verifier)         (401/403)|
  |                  4. agent is set up in this tenant, not disabled      (403)|
  |                  5. per-agent rate limit                              (429)|
  |                  6. catalog: method + path template, deny default     (403)|
  |                     agent holds the entry's permission                (403)|
  |                  7. body within the limit                             (413)|
  |                  8. the agent's own credential from the vault   (502 if none)|
  |                  9. build the outbound request:                            |
  |                     - allow-listed headers only                            |
  |                     - credential set, X-AID-* attribution set              |
  |                     - host = the tenant's fixed upstream                   |
  |                                |  GET /contacts/42                         |
  |                                |  X-API-Key: <lola's key>                  |
  |                                |  X-AID-Agent-Address: lola@acme.example   |
  |                                |------------------------------------------>|
  |                                |                       10. its own check:  |
  |                                |                       lola's permissions  |
  |                                |<------------------------------------------|
  |                 11. response: no redirect followed, allow-listed headers,  |
  |                     size cap, refused if it echoes the credential          |
  |<------------------------------|                                            |
  |                 12. audit record (always, also for every refusal)          |
```

Status codes the agent sees: `400` bad request target, `401` token not good, `403` known agent not allowed (the body carries a short code such as `not_in_catalog`, `insufficient_permissions`, `agent_disabled`, `tenant_disabled`), `404` unknown tenant, `413` body too large, `429` rate limited, `502` the old system or the credential is unavailable, `504` the old system timed out. A `401` body says only `invalid_token`; the reason is in the audit log, not the response.

## Running it

```bash
cd gateway && npm test                     # node --test, no install step, Node 20+
node bin/aid-gateway.js init --dir ./data  # data directory, a sample tenant, a master key and an admin token to keep
export AID_GATEWAY_MASTER_KEY=...          # 32 random bytes, base64: openssl rand -base64 32
export AID_GATEWAY_ADMIN_TOKEN=...         # at least 32 characters
printf %s "$KEY" | node bin/aid-gateway.js add-agent-credential --dir ./data --tenant sample --agent lola@sample.example --type header --header-name X-API-Key
node bin/aid-gateway.js import-openapi crm-openapi.json --out catalog-draft.json
node bin/aid-gateway.js run --dir ./data --host 127.0.0.1 --port 8787     # put TLS in front
```

`run` refuses to start without `AID_GATEWAY_MASTER_KEY` (32 bytes, base64) or without `AID_GATEWAY_ADMIN_TOKEN`. `add-agent-credential` reads the secret from standard input (hidden when typed at a terminal) and refuses any secret-looking option on the command line. `AID_GATEWAY_ALLOW_PRIVATE_UPSTREAM=1` lets a tenant's upstream and issuers be internal addresses, which a gateway running inside the customer's network needs and a shared host must never set.

## Tenant configuration

One JSON file per tenant under `<data>/tenants/<name>.json` (mode 600, replaced atomically), managed with `PUT /_admin/tenants/<name>`. Unknown fields are refused. The file is validated again every time the gateway loads it, so a hand-edited file cannot switch a control off; one that does not validate is not served (`500`, reason `tenant_config_invalid`).

```jsonc
{
  "displayName": "Acme",
  "issuers": [{                                   // exactly the verifier's issuer config (verifier/src/policy.js)
    "issuer": "https://auth.23blocks.com/acme", "kind": "own",
    "jwksUri": "https://auth.23blocks.com/acme/.well-known/jwks.json",
    "audience": ["https://gateway.acme.example/acme"],   // REQUIRED and specific; generic audiences are refused
    "allowAllActiveAgents": true,
    "introspection": { "endpoint": "https://auth.23blocks.com/acme/oauth/introspect", "clientId": "gw", "clientSecret": "..." },
    "introspect": "always",                        // always | for-permissions | never
    "scopeMap": { "contacts:read": ["contacts.read"], "contacts:create": ["contacts.create"] }
  }],
  "grants": [],                                    // verifier grants: required for external issuers, a ceiling for own ones
  "events": { "audience": "https://gateway.acme.example/acme/_events", "maxAgeSec": 300 },
  "upstream": {
    "baseUrl": "https://crm.acme.internal/api",    // the ONLY host this tenant will ever call; https unless the operator allows http
    "tokenUrl": "https://crm.acme.internal/oauth/token",   // only for oauth2_client_credentials agents
    "tokenAuth": "basic",                          // basic | body
    "forwardHeaders": ["x-tenant-code"]            // extra inbound headers to forward (never credentials, cookies, x-aid-*)
  },
  "catalog": [ { "permission": "contacts.read", "method": "GET", "pathTemplate": "/contacts/{id}" } ],
  "agents": {                                      // agent address or id -> its user in the old system
    "lola@acme.example": { "upstreamUser": "lola", "credentialRef": "lola", "issuer": "https://auth.23blocks.com/acme", "disabled": false }
  },
  "limits": { "maxBodyBytes": 1048576, "timeoutMs": 15000, "maxResponseBytes": 5242880, "ratePerMinute": 120, "burst": 30 }
}
```

- **issuers, grants**: unchanged from the profile. The gateway adds: the audience must be specific to this tenant's gateway; `jwksUri` and the introspection endpoint must be https (and not internal) unless the operator allows otherwise.
- **events**: turns on `POST /<tenant>/_events` (see below). Off if absent, and the config warns about it.
- **agents**: an agent that is not listed gets `403 agent_not_configured` even if the issuer vouches for it. With more than one issuer, every entry must name its `issuer`, so the same address from another issuer cannot reach this credential. `credentialRef` defaults to the key; the vault name is `<tenant>/<ref in lower case>`.
- **limits**: the token bucket is per agent (`burst` at once, refilled at `ratePerMinute`), kept in memory in one process.

## Permission catalog

A list of `{ permission, method, pathTemplate }`. A request is allowed when its method and path match an entry and the agent holds that entry's permission (from the verifier's principal: scopes, mapped through `scopeMap`, capped by the grant). No match means `403` and nothing is forwarded.

- Templates are literal segments (letters, digits, `. _ ~ -`) and whole-segment parameters such as `/contacts/{id}`. A parameter matches exactly one non-empty segment. When two templates match, the one with a literal where the other has a parameter wins (`/contacts/search` over `/contacts/{id}`). Two entries with the same method and shape are refused when the catalog is saved.
- Methods: `GET HEAD POST PUT PATCH DELETE`. A method that appears nowhere in the catalog is never forwarded. `/_events` is reserved.
- Matching uses the decoded path and the gateway forwards the canonical re-encoding of what it matched, so what was authorized is what the old system sees.
- **The query string is not part of the catalog.** It is forwarded as sent. An old system that lets a query parameter change what a request does (`?_method=DELETE`, `?action=purge`) needs those cases handled before it is put behind this gateway.

### Importing a draft from OpenAPI

```bash
aid-gateway import-openapi crm-openapi.json --out catalog-draft.json
```

**JSON OpenAPI 3 documents only.** Convert YAML to JSON first. The output is a draft for the company to review and edit, never a policy: nothing it lists authorizes anything until issuer scopes are mapped to its permissions in `scopeMap`.

- Permission = `<resource>.<verb>`. The verb comes from the HTTP method only (`GET`/`HEAD` read, `POST` create, `PUT`/`PATCH` update, `DELETE` delete). The `operationId` is **not** used for the verb, because an operation called `getOrCreateContact` on a `POST` must not make a write look like a read. It is kept as a hint beside the entry.
- The resource is the operation's first tag when it has one, else the literal path segments (versions such as `v1` and `api` dropped) joined with dots: `GET /api/v1/orders/{orderId}/items` becomes `orders.items.read`. `x-aid-permission` on an operation overrides both.
- Skipped, with a note: `OPTIONS`/`TRACE`, `$ref` path items, parameters that are only part of a segment (`/files/{id}.json`), paths that repeat an earlier shape.
- Notes also flag permissions that cover several operations (split them if they should be granted separately) and list the destructive ones.

## Credential vault

Interface: `set(name, credential)`, `get(name)`, `has`, `describe(name)` (the type only), `delete`. A secret is written once and is never returned by any API, CLI output, log or error. Implementations:

- `MemoryVault` for tests.
- `EncryptedFileVault`: one JSON file (mode 600, atomic replace). Each entry is AES-256-GCM with a fresh random 12-byte IV for every write. The encryption key and the entry-name key are derived (HKDF-SHA-256) from the master key, which comes from `AID_GATEWAY_MASTER_KEY` (32 bytes, base64). Entry names are HMACed, so the file shows neither agent addresses nor tenants; the name is also the AEAD associated data, so entries cannot be swapped. A canary entry makes a wrong key fail at start-up instead of at the first request, and any modified entry fails its authentication tag.

Credential types:

| type | sent as |
|---|---|
| `header` | a static header, e.g. `X-API-Key: <value>` (the name cannot be `Cookie`, `Host`, `X-AID-*` and similar) |
| `bearer` | `Authorization: Bearer <token>` |
| `basic` | `Authorization: Basic base64(user:password)` |
| `oauth2_client_credentials` | the agent user's own OAuth client; the gateway fetches an access token from the tenant's fixed `upstream.tokenUrl`, caches it per agent until 30 s before it expires (never longer than an hour), shares one fetch between concurrent requests, and drops it if the old system answers 401 |

Credentials are per agent, which is what keeps attribution intact in the old system: its own log says `lola`, not `the integration`.

### The main risk, stated plainly

**A hosted gateway holds its customers' credentials for their old systems.** Anyone who compromises the gateway host, and gets the master key from its environment or memory, can act in every customer's old system as every agent user. Encryption at rest protects a stolen vault file or backup, not a stolen running host. That is the central risk of this design and it is why the old system's own permissions for each agent user matter so much. Mitigations, from most to least effective:

1. **Self-host in the customer's network.** The customer runs the gateway (it is a single dependency-free Node process). Then the credentials never leave the customer.
2. **Least-privilege agent users.** The agent's user in the old system should be able to do only what the catalog lists. Then a stolen credential is worth only that.
3. **Short-lived credentials** wherever the old system supports OAuth2 client credentials: what the gateway holds is a client secret, and what travels is an hour-or-less access token. Rotating the client secret is a vault write.
4. **Per-tenant isolation.** At minimum one process, one data directory and one master key per tenant (this implementation has one master key per process, so isolation means one process per tenant). A bring-your-own-vault implementation of the vault interface (a customer-controlled KMS or secrets manager, so the gateway fetches the secret only at use) is the next step; the interface was kept small for it. It is not built.
5. **Network controls**: the gateway reaches only each tenant's fixed upstream; the old system should accept the agent users only from the gateway's address.
6. **Monitoring**: the audit trail per agent, and alerts on the old system's side when an agent user acts outside the gateway.

## Hardening that is in the code

- **Request target**: origin-form only. Refused: absolute-form (`http://...`), `*`, `..` and `.` segments, `%2e`/`%2f`/`%5c`/`%00` in any case, double encoding (`%252e`), invalid or overlong UTF-8, backslashes, `;` path parameters, empty segments (`//`, trailing `/`), control characters, fragments. The path forwarded is rebuilt from the decoded segments.
- **Headers in**: an allow-list (`accept`, `accept-language`, `content-type`, `content-language`, `if-*`, `idempotency-key`, plus the tenant's `forwardHeaders`). `Authorization`, `Cookie`, `X-API-Key`, `Proxy-Authorization`, hop-by-hop headers, anything named in `Connection`, `X-Forwarded-*` and everything else is dropped. `Accept-Encoding` is forced to `identity`.
- **Headers set**: the agent's credential, and `X-AID-Agent` (id), `X-AID-Agent-Address`, `X-AID-Issuer` and `X-Request-Id`, all from the verified token or generated; any inbound copies are discarded first.
- **Host**: the only host ever called for a tenant is its `upstream.baseUrl`. Nothing in the request or token can change it. The URL built for the call is checked to have the same origin. Unless the operator allows internal addresses, a destination that is, or resolves to, a private, loopback, link-local, ULA, CGNAT or mapped address is refused at connection time (so a DNS rebinding after validation does not help), and the same rule covers issuer key and introspection fetches.
- **Responses**: redirects are never followed. A `Location` pointing anywhere but back into the same upstream is dropped; one that does is rewritten to go through the gateway. Only an allow-list of response headers is returned, which drops `Set-Cookie`, `WWW-Authenticate` and the rest. The response is buffered up to a cap (5 MiB by default, else `502`), and if the old system echoes the agent's credential in the body or an allowed header, the gateway returns `502 upstream_response_blocked` instead.
- **Limits**: body 1 MiB by default (`413`, also for chunked bodies), upstream timeout 15 s as a hard deadline (`504`), per-agent rate limit (`429` with `Retry-After`), request header and body timeouts on the server. A body on a `GET` or `HEAD` is refused.
- **Logging**: the gateway never logs tokens, credentials, request bodies, response bodies or header values. `Credential` objects and vaults print as `[redacted]` under `JSON.stringify`, `String` and `util.inspect`.

## Audit log

One JSON line per decision, also for every refusal, appended to `<data>/audit.jsonl` (mode 600) and kept in a ring of the last 2000 for the admin API:

```json
{"ts":"2026-10-25T06:12:20.361Z","tenant":"acme","agentAddress":"lola@acme.example","agentId":"ag_ab12cd34","issuer":"https://auth.23blocks.com/acme","jti":"0bf24010-...","method":"GET","pathTemplate":"/contacts/{id}","permission":"contacts.read","decision":"allow","reason":"ok","status":200,"upstreamStatus":200,"latencyMs":6,"requestId":"4f5b3da1-..."}
```

`decision` is `allow` (forwarded; the old system's answer is in `upstreamStatus`, so its own refusals show up), `deny` (the gateway refused) or `error` (authorized, but the old system or the credential failed). When a template matched, the raw path (with its ids) is not recorded; for a request that matched nothing a truncated `pathSample` is. Reasons are short codes (`not_in_catalog`, `bad_audience`, `agent_revoked`, `rate_limited`, `upstream_timeout`, ...). Admin actions are recorded too (`method: "ADMIN"`). The file is not rotated or signed here.

## Staying current: kill switches, status events, introspection

- **Disable an agent or a whole tenant** through the admin API (`POST /_admin/tenants/<t>/agents/<agent>/disable`, `.../tenants/<t>/disable`) or the page. The next request is refused; there is no cache to wait for. A config update that does not mention a disabled agent or tenant does not switch it back on; say `"disabled": false` to do that.
- **Status events**: `POST /<tenant>/_events` with a body that is a signed JWT (RFC 8417 shape, `application/secevent+jwt`). It is accepted only if: RS256 and the signature verifies with the key from the tenant issuer's configured JWKS (via the verifier's `JwksCache`); `iss` is a configured issuer of this tenant; `aud` includes `events.audience`; `iat` is present, not in the future and not older than `maxAgeSec`; `exp`, if present, has not passed; `jti` is present and has not been seen. The `events` claim holds URIs `urn:aid:event:agent-suspended`, `agent-deleted`, `agent-reactivated` (each `{ "subject": { "agent_id": "..." } }`, as in the profile; a flat `agent_id` is still read) or `token-revoked` (`{ "subject": { "jti": "..." } }`). An event type the gateway does not act on (a newer one, or `agent-role-changed`) is **ignored, not an error**; a known event with no subject refuses the whole token. Role changes are therefore not applied by events: where a role change must take effect at once, use introspection or short token lifetimes. Accepted events go to the verifier's `RevocationList` and are appended to `revocations.jsonl`, replayed when the gateway restarts. A disabled tenant still accepts events. Replies: `202`, or `400 { err, description }` with RFC 8935 error names. A retry of an accepted event is refused as a replay.
- **Introspection** (`introspect: always|for-permissions`) is the source of truth the events complement. With `never`, a suspended agent keeps working until the event arrives or its token expires.

The event URIs and the delivery above are this implementation's own subset. They are not yet part of the profile (see [What the profile should change](#what-the-profile-and-verifier-should-change)).

## Admin API and page

Under `/_admin`, with `Authorization: Bearer <AID_GATEWAY_ADMIN_TOKEN>` (compared in constant time; 30 failures a minute from one address and it answers `429`). Only `GET /_admin/health` and `GET /_admin/ui` need no token, and they reveal nothing.

| | |
|---|---|
| `GET /_admin/tenants` | list |
| `GET /_admin/tenants/<t>` | the config, with introspection secrets shown as `[redacted]` |
| `PUT /_admin/tenants/<t>` | create or replace; validated; `[redacted]` in a secret field keeps the stored one |
| `POST /_admin/tenants/<t>/disable` and `/enable` | tenant kill switch |
| `GET /_admin/tenants/<t>/agents` | agents, whether a credential exists and its type, never the credential |
| `PUT /_admin/tenants/<t>/agents/<agent>/credential` | `{ "credential": { "type": "header", ... }, "issuer"?: ... }`; creates the agent entry if needed |
| `DELETE` the same | remove the credential |
| `POST /_admin/tenants/<t>/agents/<agent>/disable` and `/enable` | agent kill switch (`<agent>` URL-encoded) |
| `GET /_admin/audit?tenant=&agent=&decision=&reason=&limit=` | recent records, newest first |

`/_admin/ui` is one static HTML file. It shows tenants, agents, recent records and a count of refusals by reason, and has buttons to disable or enable agents and tenants. The admin token is typed into the page, held in a JavaScript variable only, and lost on reload. The page makes requests only to its own origin, uses `textContent` for all data, and is served with a hash-based Content Security Policy (`default-src 'none'`, no `unsafe-inline`). Keep `/_admin` off the public internet regardless: the gateway serves it on the same listener, so restrict it at the reverse proxy.

## Threat model

| An attacker who has... | can | cannot (and why) |
|---|---|---|
| **an agent's AID token** (stolen in transit or from the agent) | do what that agent can do through the catalog, until the token expires or the agent is suspended, disabled or revoked | read the old system's credential (never in any response; echoes are blocked); act as another agent; reach a path outside the catalog; reach another host; do more than the old system lets that agent's user do. Short token lifetimes and events/introspection bound the time. |
| **an agent's private key** | get fresh tokens for that agent: the same as above, for longer | same limits. The remedy is to suspend the agent at the issuer and rotate its key. |
| **the gateway host** (code execution as the gateway user) | read every tenant's vault file, the master key from the environment or memory, the admin token, the introspection secrets in the tenant files, and then act in every old system as every agent user; forge audit records | nothing is held back from them: this is the main risk. Mitigate by self-hosting, least-privilege agent users, short-lived credentials, one process per tenant. |
| **a stolen vault file or backup (without the master key)** | see how many entries there are | read a credential, learn which agents or tenants have one (names are HMACed), swap or alter entries undetected |
| **the master key without the vault file** | nothing useful | |
| **the admin token** | change any tenant's config (including pointing `upstream.baseUrl` at a host they control, which would send agents' credentials there), set or delete credentials, disable agents, read the audit log | read a stored credential or an introspection secret back (no API returns them). Treat it as equal to full control of the gateway. |
| **the issuer's signing key** (a compromised issuer) | mint tokens for any agent of that issuer, and signed events | get past the catalog, the scope map, the grant ceiling, the agent list or the old system's own permissions |
| **network position between the gateway and the old system** | read credentials and data if the upstream is not https | nothing, if the upstream is https (the default; http is only for tests and demos) |
| **control of a tenant's config as a tenant admin on a shared host** | point issuers and upstream wherever the operator's policy allows | reach internal addresses (refused unless the operator allows them), or other tenants' vault entries (names include the tenant) |
| **the ability to send arbitrary requests to the gateway, with no token** | get `401`s, `400`s, `404`s; fill the audit ring | reach the old system, learn whether an agent exists, or learn the catalog |

## Operations

- **Logs.** Audit lines go to `audit.jsonl` and nothing per-request goes to stdout or stderr. Ship the file; rotate it (it is append-only and not rotated here); the file holds agent addresses, ids, `jti` and paths, which can be personal data.
- **Credential rotation.** Rotate the key in the old system, then `PUT .../credential` (or `add-agent-credential`); the next request uses it (the OAuth cache is keyed by a fingerprint of the credential, so a new client secret is picked up at once). To remove an agent's reach without touching the issuer, disable it or delete its credential.
- **Master key rotation.** Not built. Today: stop the gateway, re-enter every credential into a new vault under the new key, start with the new key. Keep the master key somewhere other than the vault's backups.
- **Backups.** Back up `tenants/` and `vault.json` together, and the master key separately. `revocations.jsonl` should be kept too: without it a restart forgets suspensions delivered by event.
- **Start-up.** Fails fast without the master key or admin token, with a wrong master key, or with an unreadable vault. Tenant configs that do not validate are logged as `tenant_config_invalid` audit records and not served.
- **Scaling.** One process: the rate limiter, the OAuth cache and the replay cache are in memory. Several processes would each keep their own, so limits multiply and a replay could be accepted once per process.
- **TLS.** None here; terminate it in front, and use https for every upstream.

## Security checklist

**Tested in this repository** (`cd gateway && npm test`):

- [x] 401 for no token, malformed token, forged signature, unknown issuer, expired token, token for another audience and for the generic audience; 403 for a known agent not configured, not in the catalog, or without the permission
- [x] Catalog deny by default, method exactness, template specificity, narrowing by token scope, scope map and grant ceiling; the old system's own refusal passes through
- [x] The upstream credential never appears in the agent's response, headers or body: success, errors, redirects, cookies, auth challenges, echoing upstreams (body and header), OAuth client secret and access token
- [x] Inbound `Authorization`, `Cookie`, `X-API-Key`, `Proxy-Authorization`, hop-by-hop headers and spoofed `X-AID-*`/`X-Request-Id` never reach the old system; attribution headers come from the verified token
- [x] 36 request-target attack strings refused over a raw socket with nothing forwarded; canonical re-encoding of accepted paths
- [x] Redirects not followed; foreign `Location` dropped; same-origin `Location` rewritten
- [x] Body limit (`Content-Length` and chunked), upstream timeout, response cap, `GET` with a body
- [x] Fixed upstream host (spoofed `Host`/`X-Forwarded-Host`), internal address policy (literal and resolved), mapped IPv6
- [x] Per-agent credentials give per-agent attribution at the old system; bearer, basic, header, OAuth2 client credentials (single fetch, caching, early refresh, failure)
- [x] Vault: round trip, no plaintext or names in the file, fresh IV per write, wrong key refused, bit flips and swapped entries detected, mode 600, nothing secret in `JSON.stringify`/`inspect`
- [x] Status events: accepted when good (suspend, reactivate, delete, token-revoke); refused for bad signature, wrong or missing audience, unknown issuer, old or future `iat`, expiry, replay, unknown event type, `alg: none`/HS256; survive a restart
- [x] Kill switches take effect on the next request; an update does not silently re-enable
- [x] Rate limit per agent, `429`, refill
- [x] Admin API: authentication (no/wrong/near-miss token, agent token), failure throttling, validation of tenant configs, no secret in any admin response or audit file, page has no external requests or token storage and a strict CSP
- [x] Start-up refusals (master key missing, malformed, wrong length, admin token missing or short), also in a real process
- [x] The OpenAPI importer on a sample
- [x] End to end with a pretend issuer and an old system that accepts only API keys (the demo, also run by `npm test`)

**Needs an independent review before real use:**

- [ ] A security review of the whole `gateway/src` by someone who did not write it; fuzzing of the request-target parser and the catalog matcher
- [ ] HTTP-level behaviour behind a real reverse proxy (request smuggling between the proxy and Node's parser, header size limits, `Expect: 100-continue`, pipelining)
- [ ] The crypto in the vault by a cryptographer (HKDF labels, AAD choice, one canary entry), and master-key handling in a real deployment (environment variables are visible to the same user and to crash dumps)
- [ ] The DNS and address policy under real resolvers (IPv6 transition addresses, split-horizon DNS, `localhost` variants), and TLS settings to the old system (no custom CA or client certificate support here)
- [ ] An old-system-specific review of the catalog: query-string behaviour, method override headers (which are dropped, but a system may honour a query override), and whether its permissions really are narrower than the catalog
- [ ] Load behaviour: the vault file is read synchronously per request, responses are buffered, the audit ring and rate-limit maps are per process
- [ ] A hosted deployment: tenant isolation (this code keeps one master key and one process-wide cache set; it is not a multi-tenant isolation boundary against a malicious tenant admin), operations access, secrets in backups
- [ ] The introspection secret is stored in plaintext in the tenant file (mode 600), not in the vault
- [ ] The audit file is not tamper-evident, rotated or shipped

## What is not built

Master key rotation; bring-your-own-vault adapters (KMS, secrets managers); multi-process or shared state (rate limits, replay cache, OAuth cache); TLS termination and upstream client certificates; streaming, large uploads, WebSockets; query-string rules in the catalog; tenant deletion through the API; signed or rotated audit logs; YAML OpenAPI input; per-tenant master keys.

## What the profile and verifier should change

These came up building this. Nothing in `verifier/` or `federation.md` was edited.

1. **Define status events in the profile (§6).** The event URIs (`urn:aid:event:*`), the signed JWT delivery, the `aud` for events, the `iat` window and `jti` replay rules were invented here. They should be specified there, aligned with the Shared Signals Framework/CAEP.
2. **The verifier should return the principal on a permission failure**, or at least expose it. The gateway wants to audit "lola was refused `orders.delete`" and has to call `verify` with no required permissions, then compare permissions itself.
3. **Export the JWT helpers** (`decodeJwt`, `assertAlgorithm`, `verifySignature`) from the package index. The gateway imports them by file path to verify event tokens.
4. **A strict mode for `normalizeConfig`** that refuses a generic audience instead of warning. The profile says the audience is required; for a gateway that serves many tenants a generic one is not a warning. The gateway re-implements the check.
5. **`RevocationList` persistence and expiry.** The gateway had to write its own log to survive restarts; the list also has no way to expire an entry or to revoke by address.
6. **Document the `fetch` contract** the verifier expects (`ok`, `status`, `json()`), since a deployment needs to inject an SSRF-safe one. The gateway injects its own.
7. **Say in the profile that a kind-B relying party binds an agent to a user in the old system**, that the binding (agent address to credential) belongs to the relying party, and that with several issuers it must include the issuer. Otherwise the same address from a second issuer reaches the first one's credential.
8. **Introspection secrets** are a bearer secret the relying party holds. The profile could suggest that the issuer's introspection endpoint accept a credential limited to answering for that relying party's audience.
