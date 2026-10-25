# AID verifier (reference relying party)

What a company (say Acme) puts in front of its APIs so that it can know, check and control the AI agents that work in them, without running an agent identity server. It implements the relying-party side of the [AID Federation Profile](../docs/federation.md).

Zero dependencies, no build, Node 20 or later.

```js
import { createVerifier, aidMiddleware } from '@agentmessaging/aid-verifier'

const verifier = createVerifier({
  issuers: [{
    issuer: 'https://auth.23blocks.com/acme', kind: 'own',
    jwksUri: 'https://auth.23blocks.com/acme/.well-known/jwks.json',
    audience: ['acme-api'], allowAllActiveAgents: true,
    introspection: { endpoint: 'https://auth.23blocks.com/acme/oauth/introspect', clientId: process.env.AID_CLIENT_ID, clientSecret: process.env.AID_CLIENT_SECRET },
    scopeMap: { 'files:read': ['docs.read'], 'tickets:write': ['tickets.write'] },
  }],
  grants: [],   // agents from other issuers that Acme has authorized, each with a sponsor
}, { onDecision: d => audit.log(d) })

verifier.warnings.forEach(w => console.warn('[aid]', w))   // weak configuration, shown at start-up

app.use('/api/tickets', aidMiddleware(verifier, { permissions: ['tickets.write'] }))   // req.aid is the principal
```

Or without a framework: `const r = await verifier.verify(token, { permissions: ['docs.read'] })`, which returns `{ ok: true, principal }` or `{ ok: false, code, message }`.

Tell the verifier when the issuer says an agent was suspended: `verifier.revocations.apply({ issuer, type: 'agent-suspended', agentId })`.

## Test

```bash
cd verifier && npm test
```

The tests generate their own RSA keys and a pretend issuer; nothing leaves the machine.
