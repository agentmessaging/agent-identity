# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this repo is

A pure-Bash reference client for the **Agent Identity (AID) protocol** — OAuth 2.0 authentication for AI agents using Ed25519 cryptographic identities. It is distributed three ways from this single repo:

1. **Standalone CLI** — `install.sh` copies the `scripts/aid-*.sh` files to `~/.local/bin`.
2. **Claude Code plugin** — see `.claude-plugin/plugin.json` and the `agent-identity` skill at `skills/agent-identity/SKILL.md`.
3. **Remote `curl | bash`** — `install.sh` falls back to downloading scripts from `raw.githubusercontent.com/agentmessaging/agent-identity/main/scripts/` when its sibling `scripts/` dir is absent.

There is no compiled artifact, no package manager, no test suite, no linter. Edits to `scripts/*.sh` are the deliverable.

## Common commands

```bash
# Install locally after edits (also the user-facing install command)
./install.sh                  # → ~/.local/bin
./install.sh /custom/path     # → custom location

# Run any command directly from the repo without installing
./scripts/aid-init.sh --auto
./scripts/aid-request.sh --auth https://auth.example.com/tenant
./scripts/aid-token.sh -a https://auth.example.com/tenant -q

# Worked examples (each is a runnable shell script demonstrating a flow)
./examples/basic-usage.sh
./examples/multi-server.sh
./examples/scoped-tokens.sh
```

There is no `make test`, `npm test`, or equivalent. Validation is by running the example scripts against a live auth server, or by manually exercising the flows described in `README.md`.

## Architecture

### The seven scripts

All scripts under `scripts/` follow the same pattern: `set -e`, `source ./aid-helper.sh`, parse flags, then call helper functions. `aid-helper.sh` is the only shared module — **do not duplicate its logic into the command scripts**.

| Script | Role |
|---|---|
| `aid-helper.sh` | Sourced by every other script. Provides OpenSSL detection, agent-directory resolution, config loading, Ed25519 signing, keypair generation, and RFC 9728/8414 discovery helpers (`fetch_protected_resource_metadata`, `fetch_authorization_server_metadata`, `discover_from_resource`). |
| `aid-init.sh` | Generates the Ed25519 keypair and `config.json` for a new agent. |
| `aid-discover.sh` | Walks RFC 9728 → RFC 8414 to find the AID-enabled auth server for a resource URL. Validates `urn:aid:agent-identity` is advertised and reads the `aid_grant` block. |
| `aid-request.sh` | Agent-initiated registration. Submits a `pending` request, polls with `--poll`. Accepts `--resource` as an alternative to `--auth`. |
| `aid-register.sh` | Admin-initiated registration. Requires an admin JWT to immediately bind the agent to a role. |
| `aid-token.sh` | Exchanges the Agent Identity + proof-of-possession for an RS256 JWT. Caches tokens. Accepts `--resource` as an alternative to `--auth`. |
| `aid-status.sh` | Inspects local identity, registrations, and cached tokens. |

**The `--resource` vs `--auth` convention**: anywhere the user could supply `--auth <auth_server_url>` directly, they can supply `--resource <api_url>` instead — the script runs discovery internally and resolves the auth server. Both flags should never be provided at once; if `--resource` is given without `--auth`, discovery populates `AUTH_URL` before the existing code path runs. Keep the rest of the script logic unchanged below that resolution step.

### Agent storage layout

Every agent lives under `~/.agent-messaging/agents/<name-or-uuid>/`:

```
config.json            # agent metadata (name, address, fingerprint)
IDENTITY.md            # human-readable identity card
keys/private.pem       # Ed25519 private key (chmod 600)
keys/public.pem
api_registrations/<auth-host>.json   # one file per auth server, keyed by hostname
tokens/<sha256-prefix>.json          # cached JWT, keyed by hash of auth URL
```

The per-auth-server registration file carries everything `aid-token.sh` needs to authenticate later. Beyond `agent_unique_id` and `status`, two fields are load-bearing and populated by the server during registration or approval:

- `token_endpoint` — exact URL to POST the grant to. Stored on initial response and re-stored on `aid-request --poll` when the registration flips to `active`. Used in preference to a hardcoded path.
- `oidc_issuer` — the OIDC issuer URL for the tenant (e.g. `https://auth.example.com/apps/tenant-id`). Used as the third line of the proof-of-possession sign input.

Both fall back to the `--auth` URL (with `/oauth/token` appended for the endpoint) when missing, so things work against minimal servers — but a real auth server is expected to return them.

A sibling `~/.agent-messaging/agents/.index.json` maps human names to UUID directories for multi-agent setups.

**This directory is shared with AMP (Agent Messaging Protocol).** One Ed25519 identity serves both protocols. Never assume AMP is installed — AID must work standalone — but never break the layout AMP also reads.

### Agent resolution (the AMP_DIR rule)

`_resolve_agent_dir` in `aid-helper.sh` is the single source of truth for "which agent are we acting as?" Resolution order:

1. `AMP_DIR` env var (set by AMP / AI Maestro)
2. `CLAUDE_AGENT_ID` → `~/.agent-messaging/agents/<uuid>/`
3. `CLAUDE_AGENT_NAME` or tmux session name → index lookup → name dir
4. Single-agent auto-select (only when exactly one agent exists)

If multiple agents exist and none is selected, the function **prints the candidate list to stderr and exits 1** — preserve this behavior. Any new script that touches agent state must call `is_initialized` or `load_config` rather than reading the filesystem directly.

### OpenSSL detection

macOS ships LibreSSL, which **cannot sign Ed25519**. `_detect_openssl` probes the system `openssl` and Homebrew paths (`/opt/homebrew/opt/openssl@3`, `/usr/local/opt/openssl@3`, `linuxbrew`) and exports `OPENSSL_BIN`. Always invoke `$OPENSSL_BIN` (not bare `openssl`) when signing or generating keys, and call `require_openssl` before any crypto operation. `sign_message` writes to tempfiles instead of stdin because OpenSSL 3 has an Ed25519 + stdin bug.

### The two registration flows

The protocol — and therefore the scripts — distinguish two flows. Keep them separate:

- **Admin-initiated (`aid-register.sh`)**: admin presents a JWT + `role_id`, the agent is created `active` immediately. POSTs to `/agent_registrations`.
- **Agent-initiated (`aid-request.sh`)**: no admin token; the agent posts to `/agent_registrations/request` and receives a `pending` registration plus an `authorization_url` (RFC 8628-style device flow) and `user_code` for the admin. The agent polls `/agent_registrations/:unique_id/status` until the admin approves and assigns a role.

The agent never chooses its own role or scopes — that is enforced server-side and must remain true in any client change.

### Token request wire format

`aid-token.sh` builds two artifacts that the server validates:

1. **Signed Agent Identity** — JSON blob (`aid_version`, `address`, `alias`, `public_key`, `key_algorithm`, `fingerprint`, `issued_at`, `expires_at`) emitted as **canonical JSON via `jq -cS .`** (sorted keys, compact, no whitespace), Ed25519-signed, then the `signature` field is appended and the whole thing base64url-encoded. The signed payload is the canonical form *without* `signature` — order matters; do not reformat.
2. **Proof of possession** — Ed25519 signature over `aid-token-exchange\n<unix_ts>\n<oidc_issuer>`, concatenated with the timestamp string and base64url-encoded. The third line is the **`oidc_issuer` from the registration file**, not the `--auth` URL — they often differ (e.g. `--auth https://auth.example.com/tenant` vs `oidc_issuer https://auth.example.com/apps/<uuid>`). Falls back to `--auth` if the field is missing. **5-minute validity window** for replay protection.

Both are POSTed to the **`token_endpoint` from the registration file** (falling back to `<auth>/oauth/token`) with `grant_type=urn:aid:agent-identity`. `aid-token.sh` also accepts `--api-key / -k` to add an `X-Api-Key` header for servers that gate the token endpoint. The response is cached under `tokens/` keyed by the SHA-256 prefix of the auth URL, with a 60-second expiry buffer and scope-aware invalidation (requesting a different `--scope` bypasses cache).

The RFC-style protocol details (scope intersection, introspection fields, polling errors, agent lifecycle states) are normative and live in `README.md`. Changes to client behavior must stay in lockstep with that document.

## Conventions specific to this repo

- **Scripts are the spec implementation.** When the protocol behavior in `README.md` and the script disagree, treat it as a bug — fix one or the other deliberately, don't silently diverge.
- **Self-contained per script.** Each `aid-*.sh` file must run after sourcing only `aid-helper.sh`. No cross-script sourcing.
- **POSIX-leaning Bash + `jq` + `curl` + `openssl` only.** No Python, Node, or other runtimes — they would break the `curl | bash` install path.
- **macOS BSD-sed compatibility.** GNU and BSD `sed` disagree on regex escaping. Use `sed -E 's|https?://||'` (extended regex, no backslash before `?`) — `sed 's|https\?://||'` is GNU-only and was a real bug here. Same goes for any character class extensions: prefer `-E` and POSIX classes.
- **Output style**: human-readable text by default, `--json` for machine output, `--quiet` for the single-value-for-piping case (e.g. just the token string). Errors go to stderr, exit nonzero.
- **No emoji in new output** unless extending an existing message that already uses them (currently only `aid-token.sh` uses `✅`/`❌`).
- **Backlog**: features and bugs are tracked as `backlog/F###-*.md` / `backlog/B###-*.md` with an index in `BACKLOG.md`. IDs are sequential and never reused. Use `TEMPLATE.md` as the starting structure.
