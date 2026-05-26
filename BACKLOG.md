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
- **F008** — [Propose AID as an auth.md assertion_type](./backlog/F008-auth-md-assertion-type.md) — `Todo` · *added 2026-05-26*
- **F009** — [Map AID to OWASP Agentic Top 10](./backlog/F009-owasp-agentic-mapping.md) — `Todo` · *added 2026-05-26*
- **F010** — [SPIFFE federation research](./backlog/F010-spiffe-federation-research.md) — `Todo` · *added 2026-05-26*
- **F011** — [Add `aid:` block to OpenGAP agent.yaml](./backlog/F011-opengap-aid-block.md) — `Todo` · *added 2026-05-26*
- **F012** — [AID conformance suite v1](./backlog/F012-conformance-suite.md) — `Todo` · *added 2026-05-26*

## Roadmap clusters

Refined 2026-05-26 after the agent-auth landscape evaluation (see [research/](./research/) — local-only).

- **v1.2 — "Composition release" (weeks 1-2)**: F008 (auth.md PR), F009 (OWASP mapping), F011 (OpenGAP `aid:` block). Three small wins, parallel.
- **v1.3 — "Credibility release" (weeks 3-8)**: F012 (conformance suite v1), F010 phase 1 (SPIFFE research / go-no-go), F007 (opaque credentials — required for F001).
- **v2.0 — "Standards release" (weeks 6+)**: F001 (IETF Internet-Draft), conditional F010 phase 2 (SPIFFE prototype if Phase 1 = go).

## Bugs

_No bugs logged yet._
