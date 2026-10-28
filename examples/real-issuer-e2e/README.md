# End to end with the real pieces

Runs the whole idea once, with **nothing about the issuer simulated**:

- the real AID client (`scripts/aid-token.sh`, with the new `--audience`) and a real Ed25519 identity from `aid-init`,
- the real auth server (the Rails app in `23blocks-OS/auth-api`, on the branch with the federation changes), in its **test environment on its own database**,
- the hosted gateway (`gateway/`), and an old system that only knows API keys (`examples/gateway-demo/old-system.js`).

It checks that Lola gets a token whose audience is exactly the old system, works through the gateway and is "lola" in the old system's own log; that a generic-audience token and an unregistered service are refused; that suspending her stops her at once (introspection with the connected app's own credentials); that the issuer's **real signed status event** stops her with introspection off; and that a key rotation keeps both the new and the old key working during the overlap. 19 checks, exit 1 if any fails.

## Run it

You need the `auth-api` checkout on the `feat/aid-federation-issuer` branch (private), Postgres, Ruby 3.4, `bundle install` done, Node 22+ and `jq` and OpenSSL 3 for the client.

```bash
export AUTH_API_DIR=/path/to/auth-api  E2E_DIR=$(mktemp -d)
export DB_HOST=127.0.0.1 DB_PORT=5432 DB_USERNAME=... DB_PASSWORD=...
export RAILS_ENV=test WEB_CONCURRENCY=0           # one Puma process: the clustered mode crashes the pg driver on macOS

# 1. A dedicated database, made from one the specs have already set up (the test company and tenant)
(cd $AUTH_API_DIR && DB_NAME=spec_db bundle exec rspec spec/requests/oidc_spec.rb)   # creates the test tenant once
createdb -T spec_db aid_e2e && export DB_NAME=aid_e2e

# 2. A real agent identity in a throwaway home
export HOME_REAL=$HOME HOME=$E2E_DIR/home; mkdir -p $HOME
scripts/aid-init.sh --name lola

# 3. The fixtures (company issuer URL, role, sponsor, the agent's registration, the connected app) and the issuer
export E2E_HOME=$HOME E2E_AGENT=lola E2E_ISSUER=http://127.0.0.1:3999/test-url-id \
       E2E_RESOURCE=https://crm.acme.example E2E_RECEIVER=http://127.0.0.1:4101/acme/_events
(cd $AUTH_API_DIR && bundle exec rails runner $OLDPWD/examples/real-issuer-e2e/fixtures.rb | tail -1 > $E2E_DIR/fixtures.json
 bundle exec rails server -e test -p 3999 -b 127.0.0.1 &)

# 4. The run
node examples/real-issuer-e2e/run.mjs
```

## What running it showed (and fixed)

- The gateway returned `400` to the issuer's events: it expected the agent id at the top of the event and refused any event type it did not know, while the issuer (as the profile says) nests it under `subject` and also sends `agent-role-changed`. The gateway now reads `subject`, and **ignores** event types it does not act on.
- `rake aid:deliver_pending_events` only queued jobs, which a short-lived process drops; it now delivers in its own process.
- Right after a key rotation, a gateway that refreshed its key list in the last 30 seconds refuses a token signed by the new key until the next refresh (it will not be made to hammer the issuer). The run shows the `401` and then waits it out. A two-step rotation (publish the new key, wait for caches, then start signing with it) would remove the window: noted for the issuer.

## Limits

This proves the pieces fit. It is not a load test, a security review, or a run against production: the issuer is its test environment on a throwaway database, on localhost, over plain http.
