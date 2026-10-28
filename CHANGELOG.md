# Changelog

## 0.4.1

### Security: review and updates, 2026-10-28

Reviewed the shell scripts (shellcheck plus by hand), the verifier and the gateway, searched git history for committed secrets (none found), and ran `npm audit` on `verifier/` and `gateway/` (both have zero dependencies; 0 vulnerabilities). Changes:

- `scripts/aid-token.sh`: the auth server URL was spliced into the jq program text when writing the token cache (`"'"$AUTH_URL"'"`). It is now passed with `--arg`, so a URL containing quotes cannot alter the program.
- `scripts/aid-token.sh`: the token cache file is created `0600` before the token is written (it was written, then chmod-ed), and the cache directory is `0700`.
- `scripts/aid-helper.sh`: the Ed25519 private key is generated under `umask 077`, so it is never world-readable, even briefly.
- `verifier/` and `gateway/`: `engines.node` is now `>=22` (Node 20 is end of life); docs updated. Use Node 22.23.4, 24.22.1 or 26.12.1 or later, which carry the October 2026 Node.js security release.
- Version: `.claude-plugin/plugin.json` 0.4.0 to 0.4.1.

Not changed: `install.sh` downloads scripts from the `main` branch over HTTPS when run through `curl | bash`, with no checksum; pin to a tag if that matters in your environment.
