# Demo: an agent works in an old system

Runs the idea in [`docs/federation.md`](../../docs/federation.md) end to end, on one machine, with nothing to sign up for:

```bash
node examples/legacy-system-demo/run-demo.js        # Node 20+
```

**The story.** Acme runs an old system (a CRM here; it could be an ERP or a till). Acme made a **user "lola"** in it, with permission to read and create contacts. Acme told the old system to trust an outside identity provider. The agent Lola proves she holds her key to that provider, gets a token meant for the old system, and presents it. The old system sees **lola**, not a shared account and not a human's password, and its own permissions decide what she may do. It then shows what should not work: a token for another service, a forged one, an expired one, an agent Acme never made a user for, and a suspended agent.

## What is real and what is pretend

| File | What it is |
|---|---|
| `legacy-system.js` | **Pretend old system.** It stands for a system that already can trust an outside OpenID Connect / OAuth 2.0 provider on its API (kind **A** in the profile). It has no AID code: it checks a signed token against the provider's published keys, maps one claim to one of its own users, and enforces that user's permissions, which are its own. Only configuration ties it to this issuer |
| `issuer.js` | **Pretend AID issuer**, standing in for the 23blocks server: per-tenant issuer, JWKS, the `urn:aid:agent-identity` grant with an Ed25519 proof, introspection. It adds two things the real server does not do yet and the profile needs (§7): a token **meant for one service** (`resource` becomes `aud`) and a `scope` string. Registration is a function call here, not the real approval flow |
| `agent.js` | The agent: its own Ed25519 key, never a password. Simplified from the real client (`scripts/aid-*.sh`), which is not used here |
| `scenario.js` | The steps and the 19 things checked, including that each refusal is for the right reason |

The key checks (signature, algorithm, expiry) reuse the verifier's low-level functions only to avoid writing them twice; a real old system would use its own built-in feature.

## What it shows about the limit

- A system that **takes the token itself** (kind A) learns of a suspension only when the token expires, **unless** it is also told to ask the issuer (introspection): steps 6 and 7 show both.
- Whatever the token claims, **the old system's own permissions are the ceiling**: Lola's token carries `orders:delete`, and she is refused.

This demo says nothing about systems that cannot do this. A system with no way to check an outside token is kind **B** (something in front) or **C** (not covered yet), as the profile states.
