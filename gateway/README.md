# AID gateway (reference, kind B)

The gateway for old systems that have their own credentials (API key, basic auth, their own OAuth client) but cannot check an outside token. The agent calls it with its AID token; it checks the token with the reference [verifier](../verifier/), checks the request against the company's permission catalog, swaps in the credential of the agent's own user in the old system, forwards the request, and writes an audit record. The agent never sees the credential.

Zero dependencies, no build, Node 20 or later. It imports `../verifier/src`, so keep the two directories together.

```bash
npm test                                   # includes the end-to-end demo
node ../examples/gateway-demo/run-demo.js  # the narrated demo
node bin/aid-gateway.js --help
```

Read [docs/gateway.md](../docs/gateway.md) first: what it is and is not, the tenant config, the vault and its risks, the threat model, and what still needs an independent review. This is a reference implementation, not a reviewed product.
