# Agent Identity (AID) — Backlog

Index of features and bugs. Each entry links to a detail file under [`backlog/`](./backlog/).

## Naming Convention

- **Features:** `F###-short-description.md`
- **Bugs:** `B###-short-description.md`
- IDs are zero-padded, sequential, and never reused.

## Status Legend

- `Todo` — Not started
- `In Progress` — Actively being worked on
- `Blocked` — Waiting on a dependency or decision
- `Done` — Shipped / merged
- `Wontfix` — Decided not to pursue

## Features

- **F001** — [Submit AID as IETF Internet-Draft](./backlog/F001-ietf-internet-draft-submission.md) — `Todo` · refined 2026-05-26
- **F002** — [Add refresh token support](./backlog/F002-refresh-token-support.md) — `Todo`
- **F003** — [Agent identity discovery endpoint](./backlog/F003-agent-identity-discovery.md) — `Todo`
- **F004** — [Delegation chains for sub-agents](./backlog/F004-delegation-chains.md) — `Todo`
- **F005** — [Cross-org federation](./backlog/F005-cross-org-federation.md) — `Todo`
- **F006** — [Transaction tokens](./backlog/F006-transaction-tokens.md) — `Todo`
- **F007** — [Opaque API key credential type](./backlog/F007-opaque-credential-types.md) — `Spec+Client Done` · awaiting auth-api server impl
- **F008** — [Propose AID as an auth.md assertion_type](./backlog/F008-auth-md-assertion-type.md) — `Outreach Sent` · awaiting Garrett (WorkOS)
- **F009** — [Map AID to OWASP Agentic Top 10](./backlog/F009-owasp-agentic-mapping.md) — `Done` · *shipped 2026-05-26*
- **F010** — [SPIFFE federation (JWT-SVID + bundle endpoint)](./backlog/F010-spiffe-federation-research.md) — `Phase 1 Done · Phase 2 Pending` · scope refined to partial-go
- **F011** — [Add `aid:` block to OpenGAP agent.yaml](./backlog/F011-opengap-aid-block.md) — `Issue Filed` · [open-gitagent/opengap#87](https://github.com/open-gitagent/opengap/issues/87)
- **F012** — [AID conformance suite v1](./backlog/F012-conformance-suite.md) — `v0.1 Shipped` · [agentmessaging/aid-conformance](https://github.com/agentmessaging/aid-conformance)
- **F013** — [Microsoft AGENTMESH bridge via Ed25519/DID](./backlog/F013-agentmesh-did-bridge.md) — `Todo` · *added 2026-05-27 after F010 research pivot*

## Roadmap clusters

Refined 2026-05-27 after the F010 SPIFFE research findings split the Microsoft-bridge work into a separate item (F013).

- **v1.2 — "Composition release"**: F008 (auth.md PR), ✅ F009 (OWASP mapping), F011 (OpenGAP `aid:` block). Two in-flight, one shipped.
- **v1.3 — "Credibility release"**: ✅ F007 spec+client, F012 (conformance suite v1), F010 phase 2 (JWT-SVID + bundle endpoint).
- **v1.4 — "Interop release" (new)**: F013 (AGENTMESH DID bridge). Independent of SPIFFE work — direct Ed25519/DID format conversion.
- **v2.0 — "Standards release"**: F001 (IETF Internet-Draft). Prerequisites cleared: ✅ F007 (credential format stability), ✅ F009 (OWASP mapping for Security Considerations).

## What's in flight right now

| Item | Status | Waiting on |
|---|---|---|
| F008 auth.md PR | Email sent to authmd@workos.com | Garrett's response (1-2 weeks) |
| F011 OpenGAP block | Issue #87 filed | open-gitagent maintainers' response |
| F007 server-side | Issue #43 filed on blocks-auth-api | API team implementation |

## Bugs

_No bugs logged yet._
