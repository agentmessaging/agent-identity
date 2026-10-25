# AID Federation Profile (draft 0.1)

How a company that does not run its own agent identity server can still know, check and control the agents that work in its systems.

> **Status:** draft for review. The reference verifier in [`verifier/`](../verifier) implements everything below that a relying party does. What an *issuer* must add is listed in [§7](#7-what-an-issuer-must-add) and is not done yet.

## 1. The idea

Acme does not build an agent table, registration flow or token server. It trusts an AID **issuer** (for example 23blocks) to do that: Acme's agents are registered at the issuer, and the issuer authenticates them. Acme either configures its system to trust the issuer (kind A below), or runs a small **verifier** in front of it (kind B, the part of this repo in `verifier/`). For each request the question is: *may the bearer of this token work here, and as whom?*

Two things stay with Acme and never move to the issuer:

1. **Whether an agent may work here at all.** The issuer proves who an agent is. Acme decides whether to let it in.
2. **What it may do here.** The issuer says what the agent may *claim*. Acme maps that to its own permissions and can only narrow it.

This is deliberately not a permission sync. Two copies of "who may do what" drift; here the issuer's scopes are an *input* to Acme's decision, read on every request.

## What this is, and what it is not

**An agent is an identity in your system, like a person, but not a person.** Acme creates a user for the agent in the system it already runs (a CRM, an ERP, a point-of-sale, anything with users): "Lola", with the permissions Lola should have, enforced by that system's own permission model. Lola then gets a token from the issuer and presents it. The system sees "Lola", not a shared account and not a human's password: its own audit log says what Lola did. Nobody shares an account with an agent, and no permissions are copied between systems, because they live on Lola's user in the system itself.

The issuer only answers *is this really Lola?* Everything about what Lola may do stays in Acme's system.

**This works only with systems that can take part.** It does not make an old system modern. A system either supports what is listed under [Which systems this works with](#which-systems-this-works-with), or something small has to sit in front of it, or it has to change. Older systems that support none of it are not covered by this version, and the profile does not pretend otherwise.

## Which systems this works with

Three kinds, by what the system can do today. Check a system's documentation for the words in the first row.

| | **A. Takes the token itself** | **B. Needs something in front** | **C. Not covered yet** |
|---|---|---|---|
| The system can | Accept an **OAuth 2.0 / OpenID Connect access token from an outside identity provider** on its API, and check it: a **signed JWT** (RS256) checked against the provider's published keys (**JWKS**), with `iss`, `aud` and `exp`; and **map a claim in the token to one of its own users** | Call its API with something of its own (an API key, basic auth, its own OAuth client) but **cannot check an outside token** | Neither: no API, a screen-and-password login only, or only old protocols (SOAP with its own security, EDI, file drops) |
| What Acme does | Registers the issuer as a trusted identity provider **in the system** (configuration), creates the user "Lola", and maps the token's identifier to that user | Creates the user "Lola" and gives the **verifier** (in Acme's own API gateway or reverse proxy) or the **23blocks gateway** the credential that user uses; the gateway checks the agent's token and acts as Lola | Changes or replaces something: add an API, add token validation, or put a connector in front. **This version has no answer for it** |
| The system itself | unchanged | unchanged (agents reach it through the gateway) | has to change |
| Who enforces permissions | the system, on Lola's user | the system, on Lola's user (and the gateway may narrow it) | n/a |

In kind B the relying party **binds each agent to a user of the old system**, and the binding includes the issuer: the same agent address at two issuers is two different agents. An agent with no binding is refused, however good its token. The gateway keeps that binding (agent, issuer) to the credential of that user; the old system never learns that a token was involved.

Two things that are *not* enough: a system that only offers **single sign-on in a browser** (SAML or OIDC login pages) does not, by that, accept a token on its API; and a system that checks tokens only from **its own** login server cannot trust this issuer until it can be pointed at another one.

What the issuer must provide for the A kind to work with systems that follow the standards is listed in [§7](#7-what-an-issuer-must-add): above all a token meant for that system (`aud`), a stable identifier to map, and short lifetimes.

## 2. Roles

| Role | Who | Owns |
|---|---|---|
| **Issuer** | an AID authorization server (`https://auth.example/<tenant>`) | agent registration, authentication, the agent's status, the ceiling of scopes it will put in a token, the signing keys |
| **Relying party (RP)** | Acme | the list of issuers it trusts, which agents it authorizes, the scope-to-permission mapping, the final allow/deny, its audit log, its kill switch |
| **Agent** | software holding an Ed25519 identity | its private key |

## 3. Two kinds of agent in Acme

| | **Own** | **External** |
|---|---|---|
| Registered at | Acme's own tenant at the issuer (`https://auth.example/acme`) | any other issuer or tenant (a partner, a contractor, another company) |
| Let in by | the issuer being configured `kind: "own"` with `allowAllActiveAgents` (or a grant per agent) | a **grant** from Acme: issuer, agent, a ceiling of Acme permissions, a **sponsor** (the person at Acme who approved it) and optionally an expiry |
| Default | every active agent of the tenant | nobody |

An agent from an issuer that Acme has not configured is refused before any network call is made.

## 4. The RP's configuration

The RP's whole policy is data it owns (see [`verifier/src/policy.js`](../verifier/src/policy.js)):

```jsonc
{
  "issuers": [
    { "issuer": "https://auth.23blocks.com/acme", "kind": "own",
      "jwksUri": "https://auth.23blocks.com/acme/.well-known/jwks.json",
      "audience": ["acme-api"],                       // REQUIRED: what Acme's APIs are called in `aud`
      "allowAllActiveAgents": true,
      "introspection": { "endpoint": "https://auth.23blocks.com/acme/oauth/introspect", "clientId": "…", "clientSecret": "…" },
      "introspect": "for-permissions", "sensitivePermissions": ["billing.write"],
      "scopeMap": { "files:read": ["docs.read"], "tickets:write": ["tickets.write"] } },
    { "issuer": "https://auth.partner.example/p", "kind": "external", "jwksUri": "…", "audience": ["acme-api"] }
  ],
  "grants": [
    { "issuer": "https://auth.partner.example/p", "address": "helper@p.partner.example",
      "permissions": ["docs.read"], "sponsor": "ana@acme.example", "expiresAt": "2027-01-31T00:00:00Z" }
  ]
}
```

A verifier MUST refuse to start with an issuer that has no `audience`, a grant with no `sponsor`, or `allowAllActiveAgents` on an external issuer.

## 5. Verification

For each request the verifier does these steps, in this order, and stops at the first failure. Any failure is a refusal; nothing is "mostly valid".

1. **Read** the token (at most 8 KiB, three parts, JSON header and payload). Nothing in it is trusted yet.
2. **Algorithm**: `RS256`, exactly. Never `none`, never an HMAC, never another algorithm. Header fields that say where to find a key (`jku`, `x5u`, `jwk`) MUST be ignored.
3. **Issuer**: `iss` MUST equal a configured issuer exactly. An unknown issuer is refused **before any key is fetched**.
4. **Signature**, with the key whose `kid` matches in the JWKS at the issuer's *configured* `jwksUri` (https only; an RSA key under 2048 bits is refused). An unknown `kid` triggers one refresh of the key set, at most once per minimum interval (default 30 s), so a stream of made-up kids cannot make the verifier hammer the issuer. If the issuer cannot be reached the verifier fails closed.
5. **Time**: `exp` is required and must be in the future; `nbf` and `iat` must not be in the future (allowing a small clock skew, default 60 s); optionally `iat` must be no older than `maxTokenAgeSec`.
6. **Audience**: at least one `aud` value MUST be one of the issuer's configured `audience` values.
7. **Agent token**: `token_type` is `agent` and an agent id is present (`agent_id`, or `sub` as `agent:<id>`).
8. **Authorization**: an own issuer with `allowAllActiveAgents` lets the agent in; otherwise a **grant** that names the agent (by id, or by address, ignoring case) and has not expired MUST exist. No grant, no entry.
9. **Revocation**: if the issuer has told the RP that this agent or this token is revoked (see §6), refuse.
10. **Freshness**: ask the issuer (RFC 7662) as often as the issuer's `introspect` mode says (`always`, `for-permissions`, or `never`). Refuse if the answer is not `active`, if its `agent_status` is not `active`, or if it is about a different `sub`. If the issuer cannot be asked, refuse.
11. **Permissions**: map the token's scopes (`scope` string or `scopes` array) through the issuer's `scopeMap` (a scope with no entry grants nothing; with no map the scopes are the permissions), then cap them at the grant's ceiling (which can only narrow). If the request needs permissions the agent does not hold, refuse.

The result is a **principal**: issuer, kind, agent id, address, name, the permissions the agent holds *here*, the issuer's role (when asked), and the grant (with its sponsor) that let it in.

**HTTP mapping.** A token that is not good (steps 1 to 7, 9, 10) is `401` with `WWW-Authenticate: Bearer error="invalid_token"`. A known agent that is not authorized or lacks a permission (steps 8 and 11) is `403` with `error="insufficient_scope"`. The response body says only that; the reason goes to the RP's own log, never to the caller.

## 6. Staying current

A token is a bearer credential and an offline signature check cannot see that an agent was suspended after the token was issued. Three layers, in order of strength:

- **Introspection** (RFC 7662) before the request is served: exact, one round trip. The verifier MUST authenticate to the endpoint (a client id and secret, or a bearer token): an open introspection endpoint answers "is this stolen token still good?" for anyone. The credential SHOULD be issued for that relying party alone and be able to introspect only tokens meant for it, because it is a bearer secret the relying party holds.
- **Status events** pushed by the issuer. The shape below is a **draft**, a deliberate subset to be aligned with the OpenID Shared Signals Framework / CAEP, which has no agent profile yet:
  - *Delivery:* the issuer POSTs a signed JWT (a Security Event Token, RFC 8417 in shape) to the receiver URL the relying party registered (https only).
  - *Claims:* `iss` (the issuer), `aud` (the relying party's own audience), `iat`, `jti`, and `events`: an object whose key is the event type and whose value has a `subject` with the agent's `agent_id` and `agent_address`. Types: `urn:aid:event:agent-suspended`, `urn:aid:event:agent-deleted`, `urn:aid:event:agent-reactivated`, `urn:aid:event:agent-role-changed`, and `urn:aid:event:token-revoked` (subject is the token's `jti`).
  - *The receiver MUST:* verify the signature against the issuer's JWKS (the same configured key set as for tokens), check `iss` and `aud`, refuse an `iat` more than five minutes old or in the future beyond the clock skew, refuse a `jti` it has already seen, and apply events idempotently. An event it does not understand is ignored, not an error. A **reactivation** is only as trustworthy as its signature, which is why it is checked like everything else.
  - *The issuer MUST:* retry with backoff, never block the administrator's action on delivery, and never put secrets in an event.
  The reference verifier keeps what it learns in memory (`RevocationList.apply`); a restart forgets it, which is why introspection or short tokens stay the source of truth. The hosted gateway (`gateway/`) persists them.
- **Short lifetimes**: the fallback when events are lost. Recommended: 15 minutes or less for external agents, an hour for own agents, with refresh by a new token exchange.

The RP's own kill switches need no issuer: remove an issuer from the configuration and everything it issued stops at step 3; delete a grant and that agent stops at step 8.

## 7. What an issuer must add

Checked against the 23blocks gateway (`lib/json_token.rb`, `oidc_controller.rb`, `company.rb`) on 2026-10-24. The profile works today as a one-to-one trust for a tenant's own agents; these gaps decide how safe it is for external agents.

| # | Need | Today | Why |
|---|---|---|---|
| R1 | `aud` is specific to the service the token is for (RFC 8707 `resource` at the token request) | `aud` is `["client_app", "api_service", <tenant api key>]`, the same for every tenant and every service | Without it a token meant for one of Acme's APIs, or for another company's, is accepted by any of them (confused deputy). The verifier requires a configured audience and warns when it is the generic one |
| R2 | A `scope` string claim (RFC 9068), alongside `scopes` | `scopes` array only | The verifier accepts both |
| R3 | Introspection that authenticates the caller | AID does not specify it | See §6 |
| R4 | Status events to registered relying parties | none for agents (no webhook exists for registration or status changes), so a verifier must introspect | See §6 |
| R5 | Key rotation: publish the new key beside the old one for the transition | the JWKS publishes one key; rotation is not specified | The verifier refreshes on an unknown `kid`, but an issuer that swaps keys with no overlap breaks tokens in flight |
| R6 | `agent_role` and the person who registered the agent (its sponsor) in the introspection answer | the role is in the introspection answer; the registering user is stored (`registered_by_user_id`) but not exposed | Lets Acme map and audit without a second call |

The client side of R1 is `aid-token --audience <service>` (it sends `resource`; the token's `aud` is then exactly that service, and the token cache is kept per audience so a token for one service is never reused for another). `--resource` keeps its old meaning, discovery of the auth server.

## 8. Security considerations

- **Token passthrough and confused deputy.** Acme MUST NOT accept a token that was not issued for it: that is what the audience check is (R1).
- **Scope drift.** The issuer may add or widen scopes. The RP's `scopeMap` and grant ceiling mean a new scope grants nothing until Acme maps it, and a ceiling can only narrow.
- **A compromised or malicious issuer** can sign anything for the agents it names, and nothing else: Acme never accepts its tokens for an issuer it has not configured, an external agent still needs a grant, and the grant's ceiling bounds the damage.
- **SSRF.** Keys and introspection come only from configured addresses, never from the token.
- **Logging.** The verifier reports every decision (issuer, agent, permissions or the refusal code) and never the token.
- **Replay.** Tokens are bearer tokens: keep lifetimes short and use TLS. Sender-constraining is DPoP (F014), not part of this profile. `jti` is available for one-time use where needed.

## 9. Out of scope for 0.1

- **Cross-issuer token exchange** (an agent presents Server A's token to Server B for a local token): the full F005. This profile covers the relying party that trusts issuers directly, which is what an app like Acme needs. An ID-JAG-shaped assertion (IETF OAuth `identity-assertion-authz-grant`) is the likely next step.
- Delegation chains (F004), sender-constrained tokens (F014), DIDs (F013, F015), SCIM provisioning of agents.

## 10. Standards this builds on

RFC 7519 (JWT), RFC 9068 (JWT access tokens), RFC 7662 (introspection), RFC 8414 and RFC 9728 (discovery), RFC 8707 (resource indicators). Closest prior work: Okta Cross App Access and the IETF `identity-assertion-authz-grant` draft (the relying party trusts an issuer and keeps the final decision), Microsoft Entra Agent ID (agent identities with a sponsor), the IETF drafts `draft-klrc-aiagent-auth` and `draft-wzdk-scim-agent-resource`. None of those is a neutral, open, agent-first issuer that any company can trust, which is the gap AID fills.
